import investigation
import lookup_plan
import past_analyses
import primary_sources
import response_synth
import web_search


def _verdict(**overrides):
    base = {
        "verdict": "부분 확인", "headline": "요약", "confirmed": ["뭔가 확인됨"],
        "unconfirmed": [], "contradictions": [], "plan": [], "open_questions": [],
        "exposure": {}, "timeline": [], "followups": [], "question_status": [],
        "campaign_relations": [], "steps": [],
    }
    base.update(overrides)
    return base


def _patch_common(monkeypatch):
    monkeypatch.setattr(past_analyses, "stored_axis", lambda title, client=None: "")
    monkeypatch.setattr(past_analyses, "find_related",
                        lambda targets, exclude_title="", client=None: [])
    monkeypatch.setattr(lookup_plan, "plan",
                        lambda objective, questions, catalog, route, targets=None, timeout=120:
                        {"tracks": [], "reasons": {}, "skipped": [], "steps": []})


def test_followup_results_keep_each_request_with_its_actual_lookup(monkeypatch):
    monkeypatch.setattr(investigation.lure_hunter, "urlscan_search",
                        lambda query, size, api_key: ([{"task": {"time": "2026-09-26T00:00:00Z"}}], 1))
    block = {}
    lines, _ = investigation._run_followups([
        {"type": "ip", "value": "1.2.3.4", "question": "최근 관측은?"}], block=block)
    assert block["followup_results"] == [{
        "type": "ip", "value": "1.2.3.4", "question": "최근 관측은?",
        "lookup": "urlscan", "status": "returned", "result": lines[0],
    }]
    assert "관측 1건" in lines[0]


def test_failed_followup_does_not_borrow_the_next_result(monkeypatch):
    def search(query, size, api_key):
        if "1.2.3.4" in query:
            raise RuntimeError("조회 불가")
        return [], 0

    monkeypatch.setattr(investigation.lure_hunter, "urlscan_search", search)
    block = {}
    lines, _ = investigation._run_followups([
        {"type": "ip", "value": "1.2.3.4", "question": "첫 조회"},
        {"type": "ip", "value": "5.6.7.8", "question": "둘째 조회"}], block=block)
    assert len(lines) == 1
    assert block["followup_results"][0]["status"] == "failed"
    assert block["followup_results"][1]["value"] == "5.6.7.8"
    assert block["followup_results"][1]["result"] == lines[0]


# ---------------------------------------------------------------------------
# _combine_incidents — pure function, no LLM/network involved
# ---------------------------------------------------------------------------

def test_combine_incidents_merges_blocklists_with_incident_labels_already_applied():
    sub_blocks = [
        {"incident_id": "1", "incident_label": "GhostCode 침해",
         "route": {"label": "URL 분석", "tracks": ["user_action"]},
         "source_urls": ["https://a.example/article"], "seeds": [], "patterns": [], "findings": [],
         "steps": [{"track": "[GhostCode 침해] URL 분석", "text": "돌았다"}],
         "response": {"blocklists": [{"label": "[GhostCode 침해] 차단 후보 — 도메인",
                                      "values": ["evil1.example"]}],
                      "kql": [], "actions": [], "commands": [], "provenance": {"evil1.example": {"role": "lure"}}},
         "synthesis": _verdict(headline="사건1 요약")},
        {"incident_id": "2", "incident_label": "WaterPlum 캠페인",
         "route": {"label": "VT 동적분석", "tracks": ["malware"]},
         "source_urls": ["https://a.example/article"], "seeds": [], "patterns": [], "findings": [],
         "steps": [{"track": "[WaterPlum 캠페인] VT 동적분석", "text": "돌았다"}],
         "response": {"blocklists": [{"label": "[WaterPlum 캠페인] 차단 후보 — 해시",
                                      "values": ["deadbeef"]}],
                      "kql": [], "actions": [], "commands": [], "provenance": {"deadbeef": {"role": "hash"}}},
         "synthesis": _verdict(headline="사건2 요약")},
    ]
    combined = investigation._combine_incidents(sub_blocks)
    assert combined["route"]["primary"] == "multi"
    assert set(combined["route"]["tracks"]) == {"user_action", "malware"}
    assert len(combined["response"]["blocklists"]) == 2
    labels = {group["label"] for group in combined["response"]["blocklists"]}
    assert labels == {"[GhostCode 침해] 차단 후보 — 도메인", "[WaterPlum 캠페인] 차단 후보 — 해시"}
    assert combined["response"]["provenance"]["evil1.example"]["role"] == "lure"
    assert combined["response"]["provenance"]["deadbeef"]["role"] == "hash"
    assert combined["incidents"] is sub_blocks
    assert combined["synthesis"]["headline"] == "사건1 요약 / 사건2 요약"
    assert [row["label"] for row in combined["synthesis"]["per_incident"]] == [
        "GhostCode 침해", "WaterPlum 캠페인"]
    assert len(combined["steps"]) == 2
    assert combined["steps_summary"] == (
        "사건별 조사 2건 · GhostCode 침해: 부분 확인 · WaterPlum 캠페인: 부분 확인.")


def test_combine_incidents_handles_a_block_with_no_response_or_synthesis():
    sub_blocks = [
        {"incident_id": "1", "route": {"tracks": []}, "source_urls": [], "seeds": [],
         "patterns": [], "findings": [], "steps": [], "response": None, "synthesis": None},
    ]
    combined = investigation._combine_incidents(sub_blocks)
    assert combined["response"] is None
    assert "synthesis" not in combined


def test_combine_incidents_preserves_dynamic_and_browser_tracks_at_top_level():
    sub_blocks = [{
        "incident_id": "1", "incident_label": "Custom GPT 유포",
        "route": {"tracks": ["user_action", "malware"]},
        "source_urls": [], "seeds": [], "patterns": [], "findings": [], "steps": [],
        "response": None, "synthesis": None,
        "malware": {"checked": True, "files": [{"hash": "a" * 64,
            "behaviour": {"http": ["evil.example"]}}], "findings": ["통신 확인"]},
        "browser_research": {"questions": ["유포지 연결은?"], "results": [
            {"source": "archived_scan", "status": "observed", "evidence": {"target_url": "https://chatgpt.com/g/x"}}
        ]},
        "research_plan": [{"id": "goal-1", "goal": "유포지 연결은?"}],
    }]
    combined = investigation._combine_incidents(sub_blocks)
    assert combined["malware"]["files"][0]["incident_label"] == "Custom GPT 유포"
    assert combined["browser_research"]["results"][0]["incident_label"] == "Custom GPT 유포"
    assert combined["research_plan"][0]["id"] == "goal-1"


# ---------------------------------------------------------------------------
# build_for_article dispatch
# ---------------------------------------------------------------------------

def test_build_for_article_is_a_pure_passthrough_for_a_single_incident(monkeypatch):
    captured = {}

    def fake_build(iocs, **kwargs):
        captured["iocs"] = iocs
        captured["kwargs"] = kwargs
        return {"sentinel": True}

    monkeypatch.setattr(investigation, "build", fake_build)
    iocs = [{"type": "domain", "value": "a.example"}]
    targets = {"objective": "x"}
    result = investigation.build_for_article(iocs, text="t", title="제목", targets=targets)
    assert result == {"sentinel": True}
    assert captured["iocs"] is iocs
    # 단일 사건이면 신규 인자(shared_primary/incident_label)를 안 건드린다 —
    # build()가 오늘과 완전히 같은 기본값으로 불린다.
    assert "shared_primary" not in captured["kwargs"]
    assert "incident_label" not in captured["kwargs"]


def test_build_for_article_splits_and_combines_for_multi_incident(monkeypatch):
    import analysis_targets as at

    multi_text = """
[조사 대상]
사건구분: 사건A, 사건B
도메인: a.example(1), b.example(2)
IP: 없음
해시: 없음
URL: 없음
CVE: 없음
제품: 없음
패키지: 없음
행위자: 없음
악성코드: 없음
파일: 없음
경로: 없음
레지스트리키: 없음
명령: 없음
조사가능: 예
목표1: 목표A
목표2: 목표B
확인질문1: 없음
확인질문2: 없음
성공기준1: 없음
성공기준2: 없음
부족한것1: 없음
부족한것2: 없음
주력1: 없음
주력2: 없음
"""
    targets = at.parse(multi_text)
    iocs = [{"type": "domain", "value": "a.example"}, {"type": "domain", "value": "b.example"}]

    monkeypatch.setattr(primary_sources, "collect",
                        lambda links, article_url="", limit=2: {"sources": [], "steps": []})
    calls = []

    def fake_build(inc_iocs, **kwargs):
        calls.append({"iocs": inc_iocs, "kwargs": kwargs})
        return {"route": {"tracks": []}, "source_urls": [], "seeds": [], "patterns": [],
                "findings": [], "steps": [], "response": None, "synthesis": None}

    monkeypatch.setattr(investigation, "build", fake_build)
    result = investigation.build_for_article(iocs, title="종합기사", targets=targets,
                                              links=[{"url": "https://a.example/x"}])
    assert len(calls) == 2
    assert calls[0]["kwargs"]["incident_label"] == "사건A"
    assert calls[1]["kwargs"]["incident_label"] == "사건B"
    assert calls[0]["kwargs"]["targets"]["objective"] == "목표A"
    assert calls[1]["kwargs"]["targets"]["objective"] == "목표B"
    assert {i["value"] for i in calls[0]["iocs"]} == {"a.example"}
    assert {i["value"] for i in calls[1]["iocs"]} == {"b.example"}
    assert result["incidents"] is not None
    assert len(result["incidents"]) == 2


# ---------------------------------------------------------------------------
# The round loop inside build() itself
# ---------------------------------------------------------------------------

def test_round_loop_stops_as_soon_as_all_questions_are_answered(monkeypatch):
    _patch_common(monkeypatch)
    calls = []

    def fake_synthesize(*a, **k):
        calls.append(k)
        return _verdict(question_status=[
            {"question": "표적은 누구인가", "status": "answered", "answer": "예"}])

    monkeypatch.setattr(response_synth, "synthesize", fake_synthesize)
    block = investigation.build(
        [], text="", title="", category="", body="", targets={
            "objective": "확인한다", "questions": ["표적은 누구인가"]})
    assert len(calls) == 1  # 질문이 1라운드에 풀렸으니 2라운드 판단을 다시 부르지 않는다
    assert block["questions"] == [{"question": "표적은 누구인가", "status": "answered"}]


def test_lure_question_is_not_answered_by_model_text_without_observation(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(response_synth, "synthesize", lambda *a, **k: _verdict(
        question_status=[{"question": "유포지가 살아있는가", "status": "answered", "answer": "예"}]))
    block = investigation.build([], text="", title="", category="", body="",
                                targets={"objective": "확인한다", "questions": ["유포지가 살아있는가"]})
    assert block["questions"] == [{"question": "유포지가 살아있는가", "status": "open"}]
    assert "현재 DOM" in block["goal_evidence"][0]["missing"]


def test_round_loop_runs_a_second_round_on_followups_and_keeps_only_executed_ones(monkeypatch):
    _patch_common(monkeypatch)
    synth_calls = []

    def fake_synthesize(*a, **k):
        synth_calls.append(k)
        if len(synth_calls) == 1:
            return _verdict(followups=[{"type": "hash", "value": "aaa", "question": "q"}],
                            question_status=[{"question": "q0", "status": "partial", "answer": ""}])
        return _verdict(followups=[{"type": "hash", "value": "bbb", "question": "q2"}])

    followup_calls = []

    def fake_run_followups(requests, urlscan_key=None, vt_key=None, block=None):
        followup_calls.append(requests)
        return ["새 증거 한 줄"], ["후속 조회 스텝"]

    monkeypatch.setattr(response_synth, "synthesize", fake_synthesize)
    monkeypatch.setattr(investigation, "_run_followups", fake_run_followups)
    block = investigation.build(
        [], text="", title="", category="", body="",
        targets={"objective": "확인한다", "questions": ["q0"]})
    assert len(synth_calls) == 2  # MAX_INVESTIGATION_ROUNDS(기본 2) = 1차 + 추가 1회
    assert len(followup_calls) == 1
    assert followup_calls[0] == [{"type": "hash", "value": "aaa", "question": "q"}]
    # 2차 판단이 새로 요청한 bbb는 실행되지 않았으니 최종 followups에 안 남는다 —
    # "실행한 것만 남긴다" 불변식.
    assert block["synthesis"]["followups"] == [{"type": "hash", "value": "aaa", "question": "q"}]


def test_round_loop_chains_iocs_from_a_same_campaign_related_report(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(past_analyses, "find_related",
                        lambda targets, exclude_title="", client=None: [
                            {"title": "Past report", "when": "2026-09-01", "why": "같은 이름",
                             "objective": "", "iocs": [{"type": "domain", "value": "c2.example"}]}])
    synth_calls = []

    def fake_synthesize(*a, **k):
        synth_calls.append(k)
        if len(synth_calls) == 1:
            return _verdict(campaign_relations=[
                {"title": "Past report", "relation": "동일 캠페인", "why": ""}])
        return _verdict()

    followup_calls = []

    def fake_run_followups(requests, urlscan_key=None, vt_key=None, block=None):
        followup_calls.append(requests)
        return ["증거"], []

    monkeypatch.setattr(response_synth, "synthesize", fake_synthesize)
    monkeypatch.setattr(investigation, "_run_followups", fake_run_followups)
    investigation.build([], text="", title="", category="", body="",
                        targets={"objective": "확인한다"})
    assert len(followup_calls) == 1
    values = {item["value"] for item in followup_calls[0]}
    assert "c2.example" in values


def test_round_loop_retries_web_search_with_open_questions(monkeypatch):
    _patch_common(monkeypatch)
    synth_calls = []

    def fake_synthesize(*a, **k):
        synth_calls.append(k)
        if len(synth_calls) == 1:
            return _verdict(question_status=[{"question": "q0", "status": "open", "answer": ""}])
        return _verdict()

    web_calls = []

    def fake_web_analyze(targets, answered=(), open_questions=None):
        web_calls.append(open_questions)
        return {"findings": ["새 자료 발견"], "steps": [], "references": []}

    monkeypatch.setattr(response_synth, "synthesize", fake_synthesize)
    monkeypatch.setattr(web_search, "analyze", fake_web_analyze)
    investigation.build([], text="", title="", category="", body="",
                        targets={"objective": "확인한다", "questions": ["q0"]})
    assert len(web_calls) == 1
    assert web_calls[0] == ["q0"]
    assert len(synth_calls) == 2


def test_followup_search_reads_new_source_and_checks_only_supported_indicators(monkeypatch):
    _patch_common(monkeypatch)
    report_url = "https://research.vendor.com/report"
    sample_hash = "a" * 64
    source_text = ("Sample " + sample_hash + " used C2 server at evil.io. "
                   "It probed hosts twilio.com during reconnaissance.")
    calls = []

    def fake_collect(links, article_url="", limit=2, origin="article"):
        calls.append((links, limit, origin))
        return {"sources": [{"url": report_url, "host": "research.vendor.com",
                             "text": source_text, "chars": len(source_text),
                             "retrieved_at": "2026-10-01T00:00:00Z"}],
                "steps": ["후속 원문 읽음"], "attempts": [{"url": report_url,
                "key": "primary", "status": "returned"}]}

    synth_calls = []

    def fake_synthesize(*args, **kwargs):
        synth_calls.append(kwargs)
        if len(synth_calls) == 1:
            return _verdict(question_status=[{"question": "q0", "status": "open"}])
        return _verdict(question_status=[{"question": "q0", "status": "partial"}])

    checked = []

    def fake_followups(requests, urlscan_key=None, vt_key=None, block=None):
        checked.extend(requests)
        return ["후속 지표 관측"], ["조회 완료"]

    monkeypatch.setattr(primary_sources, "collect", fake_collect)
    monkeypatch.setattr(response_synth, "synthesize", fake_synthesize)
    monkeypatch.setattr(investigation.output_critic, "review", lambda *a, **k: [])
    monkeypatch.setattr(investigation, "_run_followups", fake_followups)
    monkeypatch.setattr(web_search, "analyze", lambda *a, **k: {
        "findings": ["새 보고서 발견"], "steps": [], "references": [report_url],
        "terms": ["sample"]})
    block = investigation.build([], text="", title="", category="", body="",
                                targets={"objective": "확인", "questions": ["q0"]})

    assert calls == [([{"url": report_url}], 2, "search")]
    assert len(synth_calls) == 2
    assert report_url in synth_calls[1]["primary"]
    assert sample_hash in synth_calls[1]["primary"]
    assert {item["value"] for item in checked} == {sample_hash, "evil.io"}
    assert "twilio.com" not in str(block["response"].get("blocklists"))
    assert block["source_urls"] == [report_url]


def test_round_loop_stops_when_nothing_new_is_found(monkeypatch):
    _patch_common(monkeypatch)
    synth_calls = []

    def fake_synthesize(*a, **k):
        synth_calls.append(k)
        return _verdict()  # followups=[]·campaign_relations=[]·question_status=[]

    monkeypatch.setattr(response_synth, "synthesize", fake_synthesize)
    investigation.build([], text="", title="", category="", body="",
                        targets={"objective": "확인한다"})
    assert len(synth_calls) == 1  # 더 조회할 것이 없어 1차 판단에서 멈춘다
