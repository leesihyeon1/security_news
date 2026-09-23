import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import quote

import analysis_worker
import output_critic
import primary_sources
import response_builder
import response_synth
import source_evidence
import repair_threat_report
import pytest


SOURCE = "https://research.checkpoint.com/2026/21st-september-threat-intelligence-report/"
TRACKED = "https://click-tracker-two.vercel.app/api/click?ref=test&url=" + quote(SOURCE, safe="")


def test_source_references_are_not_indicators():
    iocs = [{"type": "url", "value": SOURCE + "#top"},
            {"type": "domain", "value": "research.checkpoint.com"},
            {"type": "url", "value": "https://research.checkpoint.com/compromised.js"},
            {"type": "domain", "value": "research.checkpoint.com.evil.test"},
            {"type": "sha256", "value": "a" * 64}]
    kept, removed = source_evidence.filter_iocs(iocs, [TRACKED])
    assert removed == iocs[:2]
    assert kept == iocs[2:]
    targets = {"urls": [SOURCE], "domains": ["research.checkpoint.com"], "cves": ["CVE-2026-76460"]}
    assert source_evidence.filter_targets(targets, [TRACKED]) == {
        "urls": [], "domains": [], "cves": ["CVE-2026-76460"]}
    assert targets["urls"] == [SOURCE]


def test_source_seed_cannot_reintroduce_hosting_ip_or_cloaked_host():
    block = {"source_urls": [SOURCE], "seeds": [
        {"domain": "research.checkpoint.com", "ip": "3.171.214.45",
         "cloaked_hosts": ["research.checkpoint.com"]}]}
    values = response_builder._collect(block, [{"type": "url", "value": SOURCE}])
    assert values["domains"] == []
    assert values["ips"] == []
    assert values["shared_hosting"] == []


def test_article_body_beats_navigation_and_tracker_is_unwrapped(monkeypatch):
    html = ('<main><a href="https://research.checkpoint.com/2026/">2026</a>'
            + 'navigation ' * 500
            + '<section id="single-post"><div class="text">' + 'Article evidence. ' * 80
            + '<a href="https://vendor.test/report">Vendor report</a></div></section></main>')
    requested = []

    def get(url, **kwargs):
        requested.append(url)
        return SimpleNamespace(content=html.encode(), raise_for_status=lambda: None)

    monkeypatch.setattr(analysis_worker.requests, "get", get)
    monkeypatch.setattr(analysis_worker.network_safety, "_resolve_all", lambda hostname: {"93.184.216.34"})
    text, links = analysis_worker.fetch_article_text(TRACKED)
    assert requested == [SOURCE]
    assert "navigation" not in text
    assert links == [{"url": "https://vendor.test/report", "text": "Vendor report"}]


def test_archive_and_tracking_sources_are_excluded():
    links = [{"url": "https://research.checkpoint.com/2026/"},
             {"url": "https://vendor.test/2026/09/"},
             {"url": "https://vendor.test/advisory/123"}]
    assert primary_sources.pick(links, article_url=TRACKED) == [
        {"url": "https://vendor.test/advisory/123", "host": "vendor.test"}]


def test_single_candidate_is_reviewed(monkeypatch):
    calls = []

    def generate(prompt, **kwargs):
        calls.append(prompt)
        return json.dumps({"spare": [{"value": "cdn.test", "why": "정상 서비스"}]})

    monkeypatch.setattr(output_critic.common_utils, "llm_generate", generate)
    result = output_critic.review({"headline": "정상 서비스"},
                                  {"blocklists": [{"label": "차단 후보", "values": ["cdn.test"]}]})
    assert len(calls) == 1
    assert result[0]["value"] == "cdn.test"


def test_spared_values_remove_stale_queries_commands_and_plans():
    response = {"blocklists": [{"label": "차단 후보", "values": ["cdn.test", "evil.test"]}],
                "kql": [{"query": 'let x = dynamic(["cdn.test", "evil.test"]);'},
                        {"query": "DeviceProcessEvents | take 10"}],
                "actions": ["도메인 2건을 차단한다", "evil.test 조사"],
                "commands": [{"command": "resolve cdn.test"}]}
    spared = [{"value": "cdn.test", "why": "정상 서비스"}]
    assert output_critic.apply(response, spared) == ["cdn.test"]
    assert response["blocklists"][0]["values"] == ["evil.test"]
    assert len(response["kql"]) == 1
    assert response["actions"] == ["evil.test 조사"]
    assert response["commands"] == []
    verdict = {"plan": [{"action": "cdn.test 차단"}, {"action": "도메인 2건 차단"},
                        {"action": "evil.test 조사"}]}
    output_critic.reconcile_plan(verdict, spared)
    assert verdict["plan"] == [{"action": "evil.test 조사"}]


def test_prompts_preserve_sections_and_require_grounding(monkeypatch):
    prompt = analysis_worker.build_prompt("Threat Intelligence Report", "WaterPlum", "악성코드")
    for section in ("[핵심 요약]", "[기술적 세부사항]", "[MITRE ATT&CK]", "[권장 대응]", "[선수 정보]"):
        assert section in prompt
    assert "사건별로 나누어" in prompt
    assert "MFA 직접 우회" in prompt
    monkeypatch.setattr(response_synth.common_utils, "environment_brief", lambda: "")
    monkeypatch.setattr(response_synth.common_utils, "utc_now_iso", lambda: "2026-09-22T00:00:00Z")
    prompt = response_synth.build_prompt("report", "analysis", {}, {})
    assert "2026-09-22" in prompt
    assert "DeviceFileEvents는 파일 읽기·탈취를 증명하지 않는다" in prompt
    assert "KEV 미등재와 낮은 EPSS만으로 위험도를 낮추지 마라" in prompt


def test_review_cannot_remove_observed_malicious_value(monkeypatch):
    monkeypatch.setattr(output_critic.common_utils, "llm_generate", lambda *a, **k:
                        '{"spare":[{"value":"evil.test","why":"mistaken interpretation"}]}')
    response = {"blocklists": [{"label": "차단 후보", "values": ["evil.test"]}]}
    block = {"malware": {"files": [{"behaviour": {"dns": ["evil.test"]}}]}}
    assert output_critic.review({"headline": "정상으로 추정"}, response, block) == []


@pytest.fixture
def correction():
    return json.loads(repair_threat_report.FIXTURE.read_text(encoding="utf-8"))


def test_corrected_record_is_grounded_and_preserves_original(correction):
    record = {"ref": correction["ref"], "title": "21st September - Threat Intelligence Report",
              "analyzed_at": "2026-09-21T23:52:15Z", "investigation": {"seeds": ["old"]}}
    before = deepcopy(record)
    updated = repair_threat_report.corrected_record(record, correction, "2026-09-22T01:00:00Z")
    assert record == before
    assert updated["analyzed_at"] == record["analyzed_at"]
    assert updated["attack_techniques"] == ["T1190"]
    assert updated["iocs"] == []
    assert updated["targets"]["urls"] == []
    assert updated["investigation"]["response"]["blocklists"][0]["label"] == "검토 결과 — 차단 대상 없음"
    assert updated["investigation"]["response"]["kql"] == []
    assert "MFA를 직접 우회하지 않는다" in updated["analysis"]
    assert all("research.checkpoint.com" not in step["action"]
               for step in updated["investigation"]["action_plan"])
    assert all(not link["url"].endswith("/2026/") for link in updated["links"])


def fake_client(correction):
    client, pipe = MagicMock(), MagicMock()
    client.pipeline.return_value = pipe
    pipe.__enter__.return_value = pipe
    record = {"ref": correction["ref"], "title": "21st September - Threat Intelligence Report"}
    raw = json.dumps(record)
    pipe.lrange.return_value = [json.dumps({"ref": "unrelated"}), raw]
    pipe.get.return_value = '{"analysis":"old"}'
    pipe.ttl.return_value = 3600
    return client, pipe, raw


def test_repair_dry_run_never_writes(correction):
    client, pipe, _ = fake_client(correction)
    assert repair_threat_report.repair(client, correction)["status"] == "dry_run"
    pipe.multi.assert_not_called()
    pipe.execute.assert_not_called()
    pipe.set.assert_not_called()


def test_repair_atomically_backs_up_and_updates_only_target(correction):
    client, pipe, raw = fake_client(correction)
    result = repair_threat_report.repair(client, correction, apply=True)
    assert result["status"] == "updated"
    pipe.watch.assert_called_once_with("insights:list", "analysis:" + correction["ref"])
    pipe.multi.assert_called_once()
    pipe.execute.assert_called_once()
    assert pipe.lset.call_args.args[:2] == ("insights:list", 1)
    backup, cached = pipe.set.call_args_list
    assert json.loads(backup.args[1])["insight"] == raw
    assert backup.kwargs["nx"] is True
    assert cached.kwargs["ex"] == 3600
    assert json.loads(cached.args[1])["analysis"] == correction["analysis"]
    pipe.delete.assert_not_called()
    pipe.rpush.assert_not_called()


def test_concurrent_update_is_not_silently_retried(correction):
    from redis.exceptions import WatchError
    client, pipe, _ = fake_client(correction)
    pipe.execute.side_effect = WatchError()
    with pytest.raises(RuntimeError, match="changed concurrently"):
        repair_threat_report.repair(client, correction, apply=True)
    assert pipe.execute.call_count == 1
