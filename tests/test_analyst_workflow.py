import json
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

import analyst_workflow
import investigation
import playbook
import primary_sources
import response_synth
import vuln_hunter
import refresh_analysis_workflow


def complete_plan(**overrides):
    return {"action": "의심 단말 실행 로그 조사", "why": "공개 샘플의 실행 행위 대조",
            "when": "오늘", "owner": "관제 담당자", "trigger": "해당 파일 실행 흔적 확인 시",
            "check": "EDR에서 최근 7일 프로세스·부모 프로세스·통신을 대조",
            "preserve": "원본 이벤트·UTC 시각·샘플 해시 보존",
            "alternative": "EDR 미수집 단말은 호스트 감사 로그와 프록시 로그 대조",
            "done": "수집 범위와 양성 테스트를 검증하고 의심 행위·정상 업무 복구 확인",
            **overrides}


def test_lookup_order_failure_and_missing_response_are_distinct(monkeypatch):
    calls = []

    def failed(ctx):
        calls.append("a")
        raise TimeoutError("offline")

    def empty(ctx):
        calls.append("b")
        return None

    monkeypatch.setattr(investigation, "LOOKUPS", (
        {"key": "a", "label": "A", "run": failed, "consumes": "hash"},
        {"key": "b", "label": "B", "run": empty, "consumes": "domain"}))
    block, steps = {}, []
    investigation.run_lookups({"route": {"tracks": ["b", "a", "b"]}}, block, steps)
    assert calls == ["b", "a"]
    assert [s["status"] for s in block["lookup_status"]] == ["unavailable", "failed"]


def test_summary_receives_all_tracks_and_failed_lookup():
    block = {key: {"findings": [key + " evidence"]} for key in ("intel", "github", "extension", "web")}
    block["lookup_status"] = [{"key": "malware", "status": "failed", "detail": "timeout"}]
    material = response_synth._material(block, {})
    for key in ("intel", "github", "extension", "web"):
        assert key + " evidence" in material
    assert "failed" in material


def test_full_action_fields_are_validated_and_unknown_done_indicator_rejected(monkeypatch):
    invalid = complete_plan(done="Block invented-c2.test and finish")
    payload = {"headline": "공개 실행 행위와 사내 로그 대조 필요", "plan": [invalid, complete_plan()],
               "verdict": "부분 확인"}
    monkeypatch.setattr(response_synth.common_utils, "environment_brief", lambda: "")
    monkeypatch.setattr(response_synth.common_utils, "llm_generate", lambda *a, **k: json.dumps(payload))
    result = response_synth.synthesize("malware", "analysis", {}, {"route": {"label": "malware"}}, article="source")
    assert len(result["plan"]) == 1
    assert result["plan"][0]["alternative"] == complete_plan()["alternative"]
    assert result["plan"][0]["review_gaps"] == []


def test_zero_hits_cannot_close_incident(monkeypatch):
    step = complete_plan(done="스캔 결과 0건이면 종료")
    monkeypatch.setattr(response_synth.common_utils, "environment_brief", lambda: "")
    monkeypatch.setattr(response_synth.common_utils, "llm_generate", lambda *a, **k:
                        json.dumps({"plan": [step], "headline": "검토"}))
    result = response_synth.synthesize("test", "analysis", {}, {"route": {"label": "test"}})
    assert result["plan"][0]["done"].startswith("종료 보류")
    assert result["plan"][0]["review_gaps"]


def test_dns_sinkhole_on_shared_platform_path_needs_review():
    # 실측 2026-10-12(PoeLLM): 저장소 경로에 DNS 싱크홀을 걸라는 대응이 그대로 나갔다.
    step = complete_plan(action="확인된 C2 IP 경계 차단 및 GitHub 리포지터리 도메인 싱크홀",
                         check="github.com/ejejejdfbbebe DNS 싱크홀 적용 후 DNS 쿼리 로그 확인")
    gaps = analyst_workflow.plan_gaps(step)
    assert len(gaps) == 1 and gaps[0].startswith("DNS 싱크홀로 경로 차단 불가")
    assert "github.com/ejejejdfbbebe" in gaps[0] and "프록시" in gaps[0]
    assert analyst_workflow.display_plan(dict(step, review_gaps=gaps))["readiness"] == "review_required"
    assert analyst_workflow.plan_gaps(complete_plan(action="raw.githubusercontent.com DNS 차단"))[0].startswith(
        "공용 플랫폼 DNS 차단 금지")


def test_dns_sinkhole_on_attacker_hosts_and_unnamed_targets_is_feasible():
    for action in ("c2-panel.example DNS 싱크홀 적용", "attacker.github.io DNS 싱크홀",
                   "evil-bucket.s3.amazonaws.com DNS 차단",
                   "협조 불가 시 DNS 싱크홀·프록시 차단 규칙 적용만 먼저 진행",
                   "https://github.com/a/b 저장소는 프록시에서 차단 및 c2-panel.example DNS 싱크홀"):
        assert analyst_workflow.plan_gaps(complete_plan(action=action)) == [], action


def test_placeholder_advisory_number_needs_review():
    gaps = analyst_workflow.plan_gaps(complete_plan(check="Ivanti 보안 권고(SA-2026-xxx) 확인 후 영향 버전 대조"))
    assert gaps == ["자리표시 번호(SA-2026-xxx) — 실제 권고·패치 번호를 확인해 채움"]
    assert analyst_workflow.plan_gaps(complete_plan(check="CVE-2026-1234 패치 확인")) == []


def test_evidence_excerpt_keeps_late_indicators_and_question_terms():
    late_hash = "a" * 64
    text = ("도입 문단. " * 300 + "\n" + "\n".join("일반 배경 설명 문단 {} ".format(i) * 30 for i in range(40))
            + "\nThe loader TestAssembly.dll uses CVE-2026-12345 and drops " + late_hash + "\n")
    excerpt = primary_sources.evidence_excerpt(text, ["TestAssembly.dll은 어떻게 실행되는가"], limit=4000)
    assert len(excerpt) <= 4000
    assert excerpt.startswith("도입 문단.")
    assert late_hash in excerpt and "CVE-2026-12345" in excerpt
    assert primary_sources.evidence_excerpt("짧은 글", limit=4000) == "짧은 글"


def test_extract_html_keeps_the_whole_document_and_hash_rows():
    paragraphs = "".join("<p>{} {}</p>".format("Background paragraph about the campaign.", i) * 3
                         for i in range(120))
    html = ("<html><body><article>" + paragraphs + "<p>Final section: payload contacts late-c2.example "
            "via port 8443 and keeps persistence through RunOnce entries in the registry.</p></article>"
            "<table><tr><td>loader</td><td>" + "b" * 64 + "</td></tr></table></body></html>")
    text = primary_sources.extract_html(html)
    assert len(text) > primary_sources.MAX_CHARS_PER_SOURCE
    assert "late-c2.example" in text
    assert "[원문 해시 표]" in text and "b" * 64 in text


def test_same_source_text_under_another_url_counts_once():
    first = [{"url": "https://vendor.test/blog-post/x", "excerpt_sha256": "same"}]
    more = [{"url": "https://vendor.test/threat-intelligence/x", "excerpt_sha256": "same"},
            {"url": "https://other.test/report", "excerpt_sha256": "other"}]
    merged = primary_sources.merge(first, more)
    assert [source["url"] for source in merged] == ["https://vendor.test/blog-post/x", "https://other.test/report"]


def test_response_prompt_reaches_late_article_details(monkeypatch):
    monkeypatch.setattr(response_synth.common_utils, "environment_brief", lambda: "")
    article = "기사 도입. " * 3000 + "\n후반 IOC 표: CVE-2026-55555 / " + "c" * 64
    prompt = response_synth.build_prompt("t", "analysis", {"questions": ["CVE-2026-55555 영향은?"]}, {},
                                         article=article)
    assert "CVE-2026-55555 / " + "c" * 64 in prompt


def test_prepared_plan_does_not_append_unqualified_material_actions():
    rows = investigation.merge_actions({"plan": [complete_plan()]}, {"actions": ["해시 3건 즉시 차단"]})
    assert len(rows) == 1
    assert "수행 불가 시 대안" in rows[0]["why"]
    assert "보존할 증거" in rows[0]["why"]
    assert rows[0]["readiness"] == "specified"


def test_kql_screen_preserves_lookback_and_does_not_claim_execution():
    valid = "DeviceProcessEvents | where Timestamp > ago(7d) | take 100"
    response = {"kql": [{"name": "good", "query": valid}, {"name": "bad", "query": "MissingTable | take 2"}]}
    analyst_workflow.prepare_queries(response)
    analyst_workflow.prepare_queries(response)
    assert len(response["kql"]) == 1
    assert response["kql"][0]["query"] == valid
    assert response["kql"][0]["validation"]["execution"] == "not_run"
    assert response["kql"][0]["note"].count("사내 실행 미검증") == 1
    assert response["query_review"][0]["name"] == "bad"


def test_final_coverage_uses_actual_read_sources_and_reviewed_material():
    block = {"response": {"blocklists": [{"label": "검토 결과 — 차단 대상 없음", "values": ["설명"]}],
                          "kql": [{"query": "UnknownTable | take 1"}]},
             "intel": {"references": ["https://vendor.test/research"]},
             "coverage": {"done": [{"key": "blocklist"}]},
             "steps": [{"track": "산출물 점검", "text": "목표를 세울 때 선언한 성공기준 3개 중 3개를 냈습니다."}]}
    analyst_workflow.finalize(block, {"criteria": ["external_reports", "blocklist", "hunting_query"]})
    assert block["coverage"]["done"] == []
    assert len(block["coverage"]["missing"]) == 3
    assert not any("3개 중 3개" in s["text"] for s in block["steps"])
    block["primary"] = {"sources": [{"url": "https://vendor.test/research", "chars": 1000}]}
    assert playbook.coverage(block, ["external_reports"])["done"]


def test_kev_failure_is_not_nonlisting_and_low_epss_does_not_deprioritize(monkeypatch):
    monkeypatch.setattr(vuln_hunter, "load_kev", lambda: {})
    monkeypatch.setattr(vuln_hunter.common_utils, "fetch_epss_scores", lambda ids: {ids[0]: 0.005})
    track = vuln_hunter.analyze(["CVE-2026-12345"], with_nvd=False)
    entry = track["cves"][0]
    assert entry["kev_checked"] is False
    text = " ".join(track["findings"])
    assert "KEV 조회 상태 미확인" in text
    assert "순위를 낮춰" not in text
    assert "패치를 미루지" in text
    assert "조회 상태 미확인" in response_synth._material({"vulnerability": track}, {})


def test_no_cves_does_not_generate_empty_patch_queries():
    assert vuln_hunter.response_material({"cves": [], "findings": ["unknown"]}) is None


def test_package_followup_requires_ecosystem_and_retains_npm():
    data = {"followups": [{"type": "package", "value": "plain-name", "ecosystem": "npm"},
                          {"type": "package", "value": "ambiguous"}]}
    result = response_synth.followups(data, "plain-name ambiguous")
    assert len(result) == 1 and result[0]["ecosystem"] == "npm"


def test_completed_failed_response_does_not_count_as_verified():
    result = analyst_workflow.assessment({"lookup_status": [{"key": "web", "status": "partial"}],
                                         "synthesis": {"plan": [complete_plan()]}})
    assert result["internal_telemetry"] == "not_connected"
    assert "실패·부분 조회: 1개" in result["issues"]


@pytest.mark.parametrize("body,status,count", [("", "unavailable", 0), ("research", "returned", 1)])
def test_primary_collection_records_read_status(monkeypatch, body, status, count):
    monkeypatch.setattr(primary_sources, "pick", lambda *a, **k:
                        [{"url": "https://vendor.test/report", "host": "vendor.test"}])
    monkeypatch.setattr(primary_sources, "fetch_text", lambda url: body)
    result = primary_sources.collect([])
    assert len(result["sources"]) == count
    assert result["attempts"][0]["status"] == status
    assert result["attempts"][0]["completed_at"].endswith("Z")


def test_full_build_plans_after_enrichment_and_finalizes_after_review(monkeypatch):
    events = []
    route = {"primary": "malware", "label": "test", "explain": "test", "tracks": ["intel", "malware"],
             "scores": {}, "hashes": ["a" * 64], "domains": [], "cves": [], "products": []}
    monkeypatch.setattr(investigation, "classify", lambda *a, **k: deepcopy(route))
    monkeypatch.setattr(investigation.past_analyses, "stored_axis", lambda *a: "")
    monkeypatch.setattr(investigation.past_analyses, "find_related", lambda *a, **k: [])
    monkeypatch.setattr(investigation.primary_sources, "collect", lambda *a, **k:
                        {"sources": [{"url": "https://vendor.test/report", "chars": 1000, "text": "body"}],
                         "steps": [], "attempts": [{"key": "primary", "status": "unavailable",
                                                      "url": "https://other.test/report"}]})
    monkeypatch.setattr(investigation.common_utils, "extract_iocs", lambda *a, **k: [{"type": "sha256", "value": "a" * 64}])
    monkeypatch.setattr(investigation.lookup_plan, "plan", lambda *a, **k: {"tracks": ["malware"], "steps": []})

    def lookup(ctx):
        events.append("lookup")
        return {"files": [], "findings": ["No dynamic evidence"], "steps": []}

    monkeypatch.setattr(investigation, "LOOKUPS", (
        {"key": "malware", "label": "VT", "consumes": "hash", "run": lookup,
         "merge": lambda b, t: b.update(malware=t)},))
    monkeypatch.setattr(investigation.pattern_synth, "synthesize", lambda *a, **k: {"patterns": [], "steps": []})
    monkeypatch.setattr(investigation.response_builder, "build", lambda *a, **k:
                        {"blocklists": [{"label": "차단 후보", "values": ["cdn.test"]}], "kql": [], "actions": []})
    seen = {}

    def synth(*args, **kwargs):
        seen.update(article=kwargs.get("article"), status=args[3].get("lookup_status"))
        return {"headline": "부분 확인", "plan": [complete_plan()], "followups": []}

    monkeypatch.setattr(investigation.response_synth, "synthesize", synth)
    monkeypatch.setattr(investigation.output_critic, "review", lambda *a, **k: [{"value": "cdn.test", "why": "공용 서비스"}])
    block = investigation.build([], text="analysis", body="original article", links=[{"url": "https://vendor.test/report"}],
                                targets={"objective": "Investigate", "criteria": ["blocklist", "external_reports"]})
    assert events == ["lookup"]
    assert block["route"]["tracks"] == ["malware"]
    assert seen["article"] == "original article"
    assert [(s["key"], s["status"]) for s in seen["status"]] == [
        ("primary", "unavailable"), ("malware", "returned")]
    assert [item["key"] for item in block["coverage"]["done"]] == ["external_reports"]
    assert [item["key"] for item in block["coverage"]["missing"]] == ["blocklist"]


def test_prepared_update_preserves_cache_metadata_and_other_records():
    record = {"ref": "one", "analysis": "original", "investigation": {"quality": {"issues": []}}}
    raw = json.dumps(record)
    artifact = {"ref": "one", "expected_sha256": refresh_analysis_workflow.digest(raw), "record": record}
    client, pipe = MagicMock(), MagicMock()
    client.pipeline.return_value = pipe
    pipe.__enter__.return_value = pipe
    pipe.lrange.return_value = ['{"ref":"unrelated"}', raw]
    pipe.get.return_value = '{"correction_revision":"keep"}'
    pipe.ttl.return_value = 100
    refresh_analysis_workflow.apply_prepared(client, artifact)
    assert pipe.lset.call_args.args[:2] == ("insights:list", 1)
    assert json.loads(pipe.set.call_args_list[-1].args[1])["correction_revision"] == "keep"
    assert pipe.set.call_args_list[0].kwargs["nx"] is True
    pipe.delete.assert_not_called()
    pipe.execute.assert_called_once()
    artifact["expected_sha256"] = "changed"
    pipe.reset_mock()
    with pytest.raises(ValueError, match="changed since preparation"):
        refresh_analysis_workflow.apply_prepared(client, artifact)
    pipe.multi.assert_not_called()


def test_historical_question_paths_require_real_lookup_and_exact_question(monkeypatch):
    monkeypatch.setattr(refresh_analysis_workflow.dashboard_text,
                        "redact_private_environment", lambda block, terms: block)
    monkeypatch.setattr(refresh_analysis_workflow.common_utils,
                        "inventory_product_terms", lambda: [])
    record = {"ref": "one", "targets": {"questions": ["확인할 질문"]},
              "investigation": {"quality": {}, "lookup_status": [
                  {"key": "malware", "status": "returned"}]}}
    mapping = {"ref": "one", "question_lookups": [{
        "question": "확인할 질문", "lookups": [{"key": "malware", "why": "동적 행위 확인"}]}]}
    updated = refresh_analysis_workflow.attach_question_paths(record, deepcopy(mapping))
    assert updated["investigation"]["question_lookups"][0]["source"] == "historical"
    assert "question_lookups" not in record["investigation"]
    mapping["question_lookups"][0]["lookups"][0]["key"] = "web"
    with pytest.raises(ValueError, match="not executed"):
        refresh_analysis_workflow.attach_question_paths(record, mapping)
