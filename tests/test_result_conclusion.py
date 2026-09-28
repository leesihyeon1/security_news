import json

import common_utils
import investigation
import lookup_plan
import lure_hunter
import past_analyses
import response_synth as rs
import web_search

INVESTIGATION = {
    "primary": {"sources": [{"host": "www.ontinue.com"}, {"host": "arcticwolf.com"}, {"host": "amd.com"}]},
    "malware": {"checked": True, "files": [
        {"hash": "6e8b49cf70bf854e8c59c7d27cefa89406caf8978461190dabb86dafcd8554e1",
         "report": {"malicious": 3, "engines": 75, "label": "hacktool.vulndriver/windows"}}]},
    "vulnerability": {"cves": [{"cve": "CVE-2023-20598", "kev": {}}]},
    "seeds": [{"domain": "teamwork-recover-password.com"}],
    "indicator_assessments": [
        {"type": "domain", "value": "account-sams-club.com", "role": "unknown", "actionable": False},
        {"type": "ip", "value": "193.178.159.128", "role": "c2", "actionable": True},
        {"type": "domain", "value": "probe-target.example", "role": "recon_target", "actionable": False},
    ],
}


def test_source_tags_prefer_named_sources_over_value_matching():
    tags = rs._source_tags("공격 체인 입증 (Ontinue 리버스 엔지니어링, Arctic Wolf 1차 자료)", INVESTIGATION)
    assert [t["label"] for t in tags] == ["1차 자료 · ontinue.com", "1차 자료 · arcticwolf.com"]
    tags = rs._source_tags("C2 IP로 샘플이 샌드박스에서 통신 (VT 동적 분석, intel 조회 결과)", INVESTIGATION)
    assert [t["label"] for t in tags] == ["VirusTotal", "교차 인텔"]


def test_windows_registry_is_not_tagged_as_package_registry():
    tags = rs._source_tags("VT 동적 분석으로 레지스트리 Run 키 생성 관측", INVESTIGATION)
    assert [t["label"] for t in tags] == ["VirusTotal"]


def test_source_tags_fall_back_to_values_found_in_the_investigation():
    line = "드라이버 해시 6e8b49cf70bf854e8c59c7d27cefa89406caf8978461190dabb86dafcd8554e1은 취약 드라이버"
    assert [t["key"] for t in rs._source_tags(line, INVESTIGATION)] == ["malware"]
    assert [t["key"] for t in rs._source_tags("CVE-2023-20598 악용 확인", INVESTIGATION)] == ["vulnerability"]
    # "AMD"처럼 짧은 호스트 조각은 제품명과 겹쳐 1차 자료로 보지 않는다.
    assert rs._source_tags("AMD 드라이버가 설치된 단말", INVESTIGATION) == []


def test_block_review_separates_never_block_unconfirmed_and_confirmed_values():
    never_block, unconfirmed = rs._unblockable_hosts(INVESTIGATION)
    assert never_block == {"probe-target.example"}
    assert unconfirmed == {"account-sams-club.com"}
    blocked, doubtful, others = rs._block_review(
        "account-sams-club.com 및 193.178.159.128 차단", never_block, unconfirmed)
    assert (blocked, doubtful, others) == ([], ["account-sams-club.com"], ["193.178.159.128"])
    # 차단 조치가 아니면 따지지 않는다.
    assert rs._block_review("account-sams-club.com 방문 이력 조회", never_block, unconfirmed) == ([], [], [])


def _synth(monkeypatch, plan):
    payload = {"verdict": "부분 확인", "headline": "h", "confirmed": ["샘플이 샌드박스에서 통신 (VT 동적 분석)"],
               "unconfirmed": [], "contradictions": [], "plan": plan, "open_questions": [],
               "exposure": {}, "timeline": [], "followups": [], "question_status": [],
               "campaign_relations": []}
    monkeypatch.setattr(common_utils, "llm_generate",
                        lambda *a, **k: json.dumps(payload, ensure_ascii=False))
    investigation_block = dict(INVESTIGATION, findings=[
        "account-sams-club.com probe-target.example 193.178.159.128 관측"])
    return rs.synthesize("t", "", {}, investigation_block)


def _step(action):
    return {"action": action, "why": "w", "when": "즉시", "owner": "o", "trigger": "t",
            "check": "c", "preserve": "p", "alternative": "a", "done": "d"}


def test_plan_step_blocking_only_never_block_values_is_dropped(monkeypatch):
    result = _synth(monkeypatch, [_step("probe-target.example 도메인 차단"),
                                   _step("193.178.159.128 C2 차단")])
    assert [p["action"] for p in result["plan"]] == ["193.178.159.128 C2 차단"]
    assert any("차단 금지 지표만 막으라는 조치" in line for line in result["steps"])


def test_plan_step_blocking_unconfirmed_values_is_kept_but_marked_for_review(monkeypatch):
    result = _synth(monkeypatch, [_step("피싱 도메인 account-sams-club.com 차단/모니터링")])
    gaps = result["plan"][0]["review_gaps"]
    assert any("차단 근거 미확정 지표(account-sams-club.com)" in gap for gap in gaps)


def test_synthesize_attaches_key_findings_with_sources(monkeypatch):
    result = _synth(monkeypatch, [])
    assert result["key_findings"] == [
        {"fact": "샘플이 샌드박스에서 통신 (VT 동적 분석)", "sources": [{"key": "malware", "label": "VirusTotal"}]}]


def test_summarize_reports_outcomes_not_just_counts():
    block = {
        "synthesis": {"verdict": "부분 확인", "confirmed": ["a", "b"], "unconfirmed": ["c"],
                      "question_status": [{"status": "answered"}, {"status": "open"}]},
        "primary": {"sources": [{"host": "www.ontinue.com"}]},
        "malware": INVESTIGATION["malware"],
        "intel": {"findings": ["해시 06f4는 OTX 커뮤니티 보고서 1건에 실려 있습니다 — 귀속: Psychedelic. 우리만",
                               "이 지표는 ThreatFox에 등재돼 있지 않습니다."]},
        "seeds": [{"domain": "x.example", "dom_confirmed": False,
                   "candidates": [{"domain": "victim.ua",
                                   "reasons": [lure_hunter.INFECTED_SITE_PIVOT]}]}],
        "vulnerability": {"cves": [{"cve": "CVE-1", "kev": {"added": "2026-01-01"}}]},
    }
    summary = investigation.summarize(block)
    assert summary.startswith("판단 부분 확인 — 확인 2건, 미확인 1건, 검증 질문 2개 중 확인 1·부분 0·미해결 1")
    assert "1차 자료 1건 읽음(ontinue.com)" in summary
    assert "hacktool.vulndriver 3/75" in summary
    assert "공개 보고·등재 1건(귀속 Psychedelic)" in summary   # "등재돼 있지 않습니다"는 세지 않는다
    assert "감염 사이트 후보 1곳" in summary
    assert "KEV 등재 1건" in summary


def test_clickfix_boilerplate_only_for_lure_cases(monkeypatch):
    monkeypatch.setattr(lure_hunter, "REQUEST_PAUSE_SECONDS", 0)
    monkeypatch.setattr(lure_hunter, "seed_facts", lambda domain, api_key=None: None)
    monkeypatch.setattr(lure_hunter, "urlscan_search", lambda query, size=100, api_key=None: ([], 0))
    iocs = [{"type": "domain", "value": "panel.example"}]
    boiler = "이 캠페인 유형은 화면을 정상 사이트처럼"
    malware_case = lure_hunter.investigation_for_iocs(iocs, api_key=None, primary="malware")
    assert not any(line.startswith(boiler) for line in malware_case["findings"])
    lure_case = lure_hunter.investigation_for_iocs(iocs, api_key=None, primary="user_action")
    assert any(line.startswith(boiler) for line in lure_case["findings"])


def test_role_confirmed_domains_take_the_seed_slots_first(monkeypatch):
    monkeypatch.setattr(lure_hunter, "REQUEST_PAUSE_SECONDS", 0)
    monkeypatch.setattr(lure_hunter, "seed_facts", lambda domain, api_key=None: None)
    monkeypatch.setattr(lure_hunter, "urlscan_search", lambda query, size=100, api_key=None: ([], 0))
    iocs = [{"type": "domain", "value": "a-unknown.example", "role": "unknown", "actionable": False},
            {"type": "domain", "value": "b-unknown.example", "role": "unknown", "actionable": False},
            {"type": "domain", "value": "c-unknown.example", "role": "unknown", "actionable": False},
            {"type": "domain", "value": "lure-confirmed.example", "role": "distribution", "actionable": True}]
    block = lure_hunter.investigation_for_iocs(iocs, api_key=None, max_seeds=3)
    assert block["seeds"][0]["domain"] == "lure-confirmed.example"


def test_web_research_rounds_exclude_searched_terms_and_do_not_duplicate(monkeypatch):
    monkeypatch.setattr(past_analyses, "stored_axis", lambda title, client=None: "")
    monkeypatch.setattr(past_analyses, "find_related", lambda targets, exclude_title="", client=None: [])
    monkeypatch.setattr(lookup_plan, "plan", lambda *a, **k: {"tracks": [], "steps": []})
    monkeypatch.setattr(investigation, "MAX_INVESTIGATION_ROUNDS", 3)
    still_open = {"verdict": "부분 확인", "headline": "h", "confirmed": ["x"], "plan": [], "followups": [],
                  "question_status": [{"question": "q0", "status": "open", "answer": ""}],
                  "campaign_relations": []}
    monkeypatch.setattr(rs, "synthesize", lambda *a, **k: dict(still_open))
    calls = []

    def fake_analyze(targets, answered=(), open_questions=None):
        calls.append(set(answered))
        return {"findings": ["같은 결과"], "steps": [], "references": [],
                "terms": ["kw{}".format(len(calls))]}

    monkeypatch.setattr(web_search, "analyze", fake_analyze)
    block = investigation.build([], text="", title="", category="", body="",
                                targets={"objective": "o", "questions": ["q0"]})
    assert len(calls) == 2
    assert calls[1] == {"kw1"}                    # 앞 라운드에서 검색한 말은 다시 찾지 않는다
    assert block["web"]["terms"] == ["kw1", "kw2"]
    assert block["web"]["findings"].count("같은 결과") == 1
