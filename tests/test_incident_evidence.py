import json

import artifact_extractor
import investigation
import lookup_plan
import pattern_synth
import primary_sources
import response_builder
import source_evidence
import supply_chain_hunter
import past_analyses


def test_probed_vendor_hosts_are_not_exfiltration_or_c2():
    hosts = ["support-api.us1.twilio.com", "kafka-ui.au1.twilio.com", "litellm.ai-services.corp.twilio.com"]
    body = "The package was probing various Twilio-related hosts, such as " + ", ".join(hosts) + "."
    items = [{"type": "domain", "value": v} for v in hosts + ["169.254.169.254"]]
    assessed = source_evidence.assess_iocs(items, [{"url": "https://research.test/report", "text": body}])
    assert [a["role"] for a in assessed] == ["recon_target"] * 3 + ["metadata"]
    assert assessed[-1]["type"] == "ipv4"
    assert source_evidence.display_iocs(assessed) == []
    assert source_evidence.lookup_iocs(assessed) == []
    targets = source_evidence.restrict_targets({"domains": hosts}, assessed)
    assert targets["domains"] == []


def test_roles_are_per_observation_not_a_vendor_allowlist():
    hosts = [{"type": "domain", "value": "evil.twilio.com"}, {"type": "domain", "value": "unknown.test"}]
    assessed = source_evidence.assess_iocs(hosts, [{"text": "C2 server at evil.twilio.com. unknown.test is mentioned."}])
    assert assessed[0]["role"] == "c2"
    assert assessed[1]["role"] == "unknown"
    assert source_evidence.display_iocs(assessed) == [assessed[0]]


def test_credential_webhook_is_exfiltration_not_just_an_unknown_domain():
    value = "collector.example"
    assessed = source_evidence.assess_iocs(
        [{"type": "domain", "value": value}],
        [{"text": "The package sends process.env.AUTH_TOKEN to a webhook at " + value}],
    )
    assert assessed[0]["role"] == "exfiltration"
    assert assessed[0]["actionable"] is True


def test_conflicting_roles_do_not_automatically_block():
    assessed = source_evidence.assess_iocs([{"type": "domain", "value": "sample.test"}],
        [{"text": "C2 server at sample.test."}, {"text": "Scanning hosts such as sample.test."}])
    assert assessed[0]["role"] == "unknown"
    assert not assessed[0]["actionable"]


def test_html_chooses_research_not_advertisement_and_keeps_hash_table():
    narrative = "The research describes execution gates, version differences and network observations. " * 14
    html = "<body><article>Subscribe for a trial.</article><main>Title only</main><div>"
    html += "<p>" + narrative + "</p><p>" + narrative + "</p></div>"
    html += "<table><tr><td>test-package</td><td>1.0.4</td><td>" + "a" * 40 + "</td></tr></table></body>"
    text = primary_sources.extract_html(html)
    assert "execution gates" in text
    assert "test-package | 1.0.4 | " + "a" * 40 in text
    assert "Subscribe for a trial" not in text


def test_structured_unscoped_package_is_looked_up_not_background_feed(monkeypatch):
    calls = []
    def lookup(ecosystem, name):
        calls.append((ecosystem, name))
        return {"ecosystem": ecosystem, "name": name, "exists": False, "osv_count": 0}
    monkeypatch.setattr(supply_chain_hunter, "lookup_package", lookup)
    monkeypatch.setattr(supply_chain_hunter, "load_malware_advisories", lambda *a: (_ for _ in ()).throw(AssertionError("unrelated feed")))
    track = investigation._run_supply({"text": "악성 npm 패키지", "title": "npm research", "iocs": [],
                                       "targets": {"packages": ["npm:tw-pkgprobe-7731"]}})
    assert calls == [("npm", "tw-pkgprobe-7731")]
    assert track["registries"] == []
    material = supply_chain_hunter.response_material(track)
    assert material["blocklists"][0]["values"] == ["tw-pkgprobe-7731"]
    assert "tw-pkgprobe-7731" in material["kql"][0]["query"]
    assert all("Remove-Item" not in c["command"] and "npm uninstall" not in c["command"] for c in material["commands"])


def test_background_registry_packages_never_become_incident_iocs():
    material = supply_chain_hunter.response_material({"registries": [{"packages": ["unrelated-package"], "ecosystem": "npm"}], "packages": []})
    assert "unrelated-package" not in json.dumps(material)


def test_response_excludes_recon_and_unknown_and_uses_sha1_column():
    assessed = [{"type": "domain", "value": "victim.test", "role": "recon_target", "actionable": False},
                {"type": "domain", "value": "unknown.test", "role": "unknown", "actionable": False},
                {"type": "sha1", "value": "a" * 40}]
    result = response_builder.build({"indicator_assessments": assessed}, assessed, primary="supply_chain")
    queries = " ".join(q["query"] for q in result["kql"])
    assert "SHA1 in~" in queries and "SHA256 in~" not in queries
    assert "victim.test" not in queries and "unknown.test" not in queries
    assert not any("브라우저에서 터미널" in q["name"] for q in result["kql"])


def test_generic_credentials_do_not_generate_browser_or_index_js_rules():
    result = artifact_extractor.extract("index.js에서 Twilio 자격 증명을 탈취하고 웹훅으로 전송한다.")
    queries = artifact_extractor.kql_from_artifacts(result)
    assert "index.js" not in result["attacker_files"]
    assert not any("브라우저" in q["name"] for q in queries)


def test_source_code_cannot_be_misrepresented_as_process_telemetry():
    query = 'DeviceProcessEvents | where ProcessCommandLine contains "process.env.AUTH_TOKEN"'
    assert not pattern_synth.validate_kql({"query": query})[0]
    assert not pattern_synth.validate_vt({"query": 'behaviour_processes:"process.env.AUTH_TOKEN"'})[0]
    assert pattern_synth.validate_kql({"query": query, "note": "node -e 인라인 명령에 한정"})[0]


def test_metadata_ip_does_not_use_hostname_column():
    assert not pattern_synth.validate_kql({"query": 'DeviceNetworkEvents | where RemoteUrl contains "169.254.169.254"'})[0]
    assert pattern_synth.validate_kql({"query": 'DeviceNetworkEvents | where RemoteIP == "169.254.169.254"'})[0]


def test_related_history_passes_only_verified_network_roles(monkeypatch):
    class FakeRedis:
        def lrange(self, *_):
            return [json.dumps({
                "title": "older npm campaign",
                "analyzed_at": "2026-09-01T00:00:00Z",
                "targets": {"malware": ["same-loader"]},
                "iocs": [
                    {"type": "domain", "value": "source.example"},
                    {"type": "domain", "value": "c2.example", "role": "c2", "actionable": True},
                    {"type": "sha1", "value": "b" * 40},
                ],
            })]

    related = past_analyses.find_related(
        {"malware": ["same-loader"]}, client=FakeRedis())
    assert [item["value"] for item in related[0]["iocs"]] == ["c2.example", "" + "b" * 40]
    history = past_analyses.as_evidence(related)
    assert "c2.example" in history
    assert "source.example" not in history


def test_lookup_plan_cannot_skip_hash_and_package_investigation(monkeypatch):
    monkeypatch.setattr(lookup_plan.common_utils, "llm_generate", lambda *a, **k: json.dumps({
        "run": [], "skip": [{"key": "malware", "why": "시간 절약"},
                              {"key": "supply_chain", "why": "나중에"}],
    }))
    catalog = [{"key": key, "label": key, "consumes": "입력"}
               for key in ("malware", "intel", "supply_chain")]
    result = lookup_plan.plan(
        "패키지 실행·유출 여부 확인", [], catalog,
        {"tracks": ["malware", "intel", "supply_chain"],
         "hashes": ["c" * 40], "domains": [], "ips": []},
        targets={"packages": ["npm:tw-pkgprobe-7731"]})
    assert result["tracks"] == ["malware", "intel", "supply_chain"]
    assert "필수 조회" in " ".join(result["steps"])


def test_lookup_plan_links_only_asked_questions_to_executed_lookups(monkeypatch):
    monkeypatch.setattr(lookup_plan.common_utils, "llm_generate", lambda *a, **k: json.dumps({
        "run": [{"key": "malware", "why": "실행 행위 확인"}],
        "question_lookups": [
            {"question": "샘플이 무엇을 하는가", "lookups": [
                {"key": "malware", "why": "샌드박스 행위 확인"},
                {"key": "web", "why": "실행하지 않은 조회"}]},
            {"question": "묻지 않은 질문", "lookups": [{"key": "malware"}]},
        ],
    }))
    result = lookup_plan.plan(
        "실행 행위 확인", ["샘플이 무엇을 하는가"],
        [{"key": "malware", "label": "VT", "consumes": "파일 해시"},
         {"key": "web", "label": "웹", "consumes": "검색어"}],
        {"tracks": ["malware"], "hashes": ["a" * 40]}, targets={})
    assert result["question_lookups"] == [
        {"question": "샘플이 무엇을 하는가", "lookups": [
            {"key": "malware", "why": "샌드박스 행위 확인"}]}]


def test_intel_uses_selected_hashes_but_keeps_network_indicators(monkeypatch):
    seen = {}
    monkeypatch.setattr(investigation.intel_hunter, "analyze",
                        lambda iocs, targets=None: seen.update(iocs=iocs) or {"findings": []})
    selected = "a" * 40
    investigation._run_intel({
        "route": {"hashes": [selected]},
        "iocs": [{"type": "sha1", "value": selected},
                 {"type": "sha1", "value": "b" * 40},
                 {"type": "domain", "value": "c2.example"}],
        "targets": {},
    })
    assert {item["value"] for item in seen["iocs"]} == {selected, "c2.example"}
