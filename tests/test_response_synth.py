import json

import common_utils
import output_critic
import response_synth as rs


def test_question_status_keeps_only_questions_actually_asked():
    questions = ["유포지가 살아있는가", "표적이 누구인가"]
    data = {"question_status": [
        {"question": "유포지가 살아있는가", "status": "answered", "answer": "확인됨"},
        {"question": "지어낸 질문", "status": "answered", "answer": "x"},
    ]}
    out = rs.question_status(data, questions, corpus="확인됨")
    assert [row["question"] for row in out] == questions  # 지어낸 질문은 버린다
    assert out[0]["status"] == "open"  # An answer without cited evidence is incomplete.
    assert "unjudged" not in out[0]
    assert out[1] == {"question": "표적이 누구인가", "status": "open", "answer": "", "unjudged": True}


QS = ["1단계 · 변조된 웹사이트로 방문자를 유도했다: 원문과 공개 보고서·샘플이 제시하는 도구·지표는 무엇인가",
      "C2 도메인은 무엇인가?", "압수된 도메인 목록은 공개됐는가"]


def test_question_status_matches_by_number():
    data = {"question_status": [
        {"id": "Q2", "status": "partial", "answer": "x.example", "evidence": "x.example 관측"},
        {"id": "Q1", "status": "open", "answer": "샘플 없음"},
        {"id": "Q9", "status": "answered", "answer": "범위 밖"},
    ]}
    out = rs.question_status(data, QS, corpus="x.example 관측")
    assert [row["question"] for row in out] == QS  # 원래 질문 문장·순서로 저장
    assert [row["status"] for row in out] == ["open", "partial", "open"]
    assert out[1]["answer"] == "x.example"
    assert out[2].get("unjudged") is True and "unjudged" not in out[0]


def test_question_status_accepts_lightly_rewritten_question_text():
    data = {"question_status": [
        {"question": "Q3. 압수된 도메인 목록은 공개됐는가?", "status": "open", "answer": "미공개"},
        {"question": "C2 도메인은 무엇인가", "status": "open", "answer": "없음"},
        # 긴 질문을 앞부분만 옮겨 쓴 경우
        {"question": "1단계 · 변조된 웹사이트로 방문자를 유도했다", "status": "open", "answer": "원문 서술뿐"},
    ]}
    out = rs.question_status(data, QS, corpus="")
    assert [row["answer"] for row in out] == ["원문 서술뿐", "없음", "미공개"]
    assert not any(row.get("unjudged") for row in out)


def test_question_status_ignores_ambiguous_partial_text():
    questions = ["Gootloader 유포 도메인의 등록 시점은 언제인가", "Gootloader 유포 도메인의 호스팅 위치는 어디인가"]
    data = {"question_status": [{"question": "Gootloader 유포 도메인의", "status": "answered", "answer": "x"}]}
    assert rs.question_status(data, questions, corpus="") == []


def test_question_status_empty_when_model_left_no_judgment():
    assert rs.question_status({"question_status": []}, QS, corpus="") == []


def test_prompt_numbers_the_questions():
    prompt = rs.build_prompt("제목", "분석", {"questions": QS[:2]}, {"findings": ["x"]})
    assert "- [Q1] " + QS[0] in prompt and "- [Q2] " + QS[1] in prompt


def test_question_status_defaults_unknown_status_to_open():
    data = {"question_status": [{"question": "q", "status": "이상한값", "answer": ""}]}
    out = rs.question_status(data, ["q"], corpus="")
    assert out[0]["status"] == "open"


def test_question_status_drops_ungrounded_answer_and_reopens_question():
    data = {"question_status": [
        {"question": "q", "status": "answered", "answer": "evil-not-in-corpus.example"}]}
    out = rs.question_status(data, ["q"], corpus="아무것도 없음")
    assert out[0]["status"] == "open"
    assert out[0]["answer"] == ""


def test_question_status_links_only_retained_plan_and_grounded_evidence():
    data = {"question_status": [
        {"question": "q1", "status": "answered", "answer": "확인됨",
         "evidence": "원문에서 확인됨", "plan_index": 2},
        {"question": "q2", "status": "open", "answer": "미확인", "plan_index": 1},
    ]}
    rows = rs.question_status(data, ["q1", "q2"], "원문에서 확인됨", {2: 1})
    assert rows[0]["plan_index"] == 1
    assert rows[0]["evidence"] == "원문에서 확인됨"
    assert "plan_index" not in rows[1]


def test_followups_reject_lookup_that_cannot_answer_the_question():
    data = {"followups": [
        {"type": "ip", "value": "1.2.3.4", "lookup": "urlscan",
         "question": "연관 추가 샘플과 통신 프로토콜은?"},
        {"type": "domain", "value": "evil.example", "lookup": "virustotal",
         "question": "최근 관측은?"},
        {"type": "ip", "value": "5.6.7.8", "lookup": "urlscan",
         "question": "마지막 공개 스캔 시각은?"},
    ]}
    rows = rs.followups(data, "1.2.3.4 evil.example 5.6.7.8")
    assert len(rows) == 1
    assert rows[0]["value"] == "5.6.7.8"
    assert "urlscan" in rows[0]["question"]


def test_spared_indicator_removes_or_reindexes_question_action_link():
    verdict = {"plan": [
        {"action": "normal.example 차단"}, {"action": "의심 호스트 조사"},
    ], "question_status": [
        {"question": "q1", "plan_index": 1},
        {"question": "q2", "plan_index": 2},
    ]}
    output_critic.reconcile_plan(verdict, [{"value": "normal.example"}])
    assert [row.get("plan_index") for row in verdict["question_status"]] == [None, 1]
    assert len(verdict["plan"]) == 1


def test_campaign_relations_keeps_only_candidate_titles():
    related = [{"title": "Past GhostCode report"}]
    data = {"campaign_relations": [
        {"title": "Past GhostCode report", "relation": "동일 캠페인", "why": "같은 인프라"},
        {"title": "지어낸 제목", "relation": "동일 캠페인", "why": "x"},
    ]}
    out = rs.campaign_relations(data, related, corpus="같은 인프라")
    assert len(out) == 1
    assert out[0]["title"] == "Past GhostCode report"


def test_campaign_relations_drops_invalid_relation_value():
    related = [{"title": "T"}]
    data = {"campaign_relations": [{"title": "T", "relation": "아무말", "why": ""}]}
    assert rs.campaign_relations(data, related, corpus="") == []


def test_campaign_relations_drops_ungrounded_why():
    related = [{"title": "T"}]
    data = {"campaign_relations": [
        {"title": "T", "relation": "무관", "why": "evil-not-in-corpus.example"}]}
    out = rs.campaign_relations(data, related, corpus="아무것도 없음")
    assert out[0]["why"] == ""
    assert out[0]["relation"] == "무관"


def test_campaign_relations_none_related_yields_empty():
    data = {"campaign_relations": [{"title": "T", "relation": "무관", "why": ""}]}
    assert rs.campaign_relations(data, None, corpus="") == []


def test_parse_tolerates_doubled_opening_brace_and_trailing_text():
    data, salvaged = rs.parse_with_status('{\n {"verdict": "부분 확인", "headline": "h"}\n} 끝.')
    assert data == {"verdict": "부분 확인", "headline": "h"}
    assert salvaged is False


def test_parse_salvages_a_response_truncated_mid_list():
    # 실측 형태: max_tokens에서 followups 배열 한가운데가 잘렸다.
    raw = ('{"verdict": "부분 확인", "headline": "h", "confirmed": ["a", "b"], '
           '"followups": [{"type": "ip", "value": "1.2.3.4"}, {"type": "hash", "value": "06f4')
    data, salvaged = rs.parse_with_status(raw)
    assert salvaged is True
    assert data["verdict"] == "부분 확인"
    assert data["confirmed"] == ["a", "b"]
    assert data["followups"] == [{"type": "ip", "value": "1.2.3.4"}]


def test_parse_does_not_split_on_commas_inside_strings():
    raw = '{"headline": "a, b, c", "confirmed": ["x, y"], "plan": [{"action": "z'
    data, salvaged = rs.parse_with_status(raw)
    assert salvaged is True
    assert data["headline"] == "a, b, c"
    assert data["confirmed"] == ["x, y"]


def test_parse_returns_empty_for_non_json():
    assert rs.parse_with_status("모델이 거절했습니다") == ({}, False)


def test_synthesize_retries_with_compact_note_and_passes_larger_token_cap(monkeypatch):
    calls = []
    good = json.dumps({"verdict": "부분 확인", "headline": "x.example 관측",
                       "confirmed": [], "plan": []}, ensure_ascii=False)

    def fake_llm(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return "모델 설명만 있고 JSON 없음" if len(calls) == 1 else good

    monkeypatch.setattr(common_utils, "llm_generate", fake_llm)
    result = rs.synthesize("제목", "", {}, {"findings": ["x.example urlscan 관측"]})
    assert result is not None
    assert len(calls) == 2
    assert rs.COMPACT_RETRY_NOTE in calls[1][0]
    assert all(kw["max_tokens"] == rs.SYNTH_MAX_TOKENS for _, kw in calls)


def test_synthesize_marks_salvaged_truncated_response_in_steps(monkeypatch):
    truncated = ('{"verdict": "부분 확인", "headline": "x.example 관측", "confirmed": [], '
                 '"followups": [{"type": "hash", "value": "06f4')
    monkeypatch.setattr(common_utils, "llm_generate", lambda *a, **k: truncated)
    result = rs.synthesize("제목", "", {}, {"findings": ["x.example urlscan 관측"]})
    assert result is not None
    assert any("잘려" in line for line in result["steps"])


def _mock_llm(monkeypatch, payload):
    raw = json.dumps(payload, ensure_ascii=False)
    monkeypatch.setattr(common_utils, "llm_generate", lambda *a, **k: raw)


def test_synthesize_end_to_end_includes_question_status_and_campaign_relations(monkeypatch):
    payload = {
        "verdict": "부분 확인",
        "headline": "요약",
        "confirmed": ["urlscan에서 evil.example 관측"],
        "unconfirmed": [],
        "contradictions": [],
        "plan": [],
        "open_questions": [],
        "exposure": {},
        "timeline": [],
        "followups": [],
        "question_status": [
            {"question": "유포지가 살아있는가", "status": "answered", "answer": "evil.example 확인",
             "evidence": "evil.example urlscan 관측"}],
        "campaign_relations": [
            {"title": "Past report", "relation": "관련 가능성", "why": "같은 이름"}],
    }
    _mock_llm(monkeypatch, payload)
    investigation = {
        "route": {"label": "URL 분석", "explain": "테스트"},
        "findings": ["evil.example urlscan 관측"],
    }
    targets = {"objective": "확인한다", "questions": ["유포지가 살아있는가"]}
    related = [{"title": "Past report"}]
    result = rs.synthesize("제목", "분석문", targets, investigation,
                           history="evil.example 같은 이름", related=related)
    assert result is not None
    assert result["question_status"] == [
        {"question": "유포지가 살아있는가", "status": "answered", "answer": "evil.example 확인",
         "evidence": "evil.example urlscan 관측"}]
    assert result["campaign_relations"] == [
        {"title": "Past report", "relation": "관련 가능성", "why": "같은 이름"}]


def test_synthesize_without_related_drops_all_campaign_relations(monkeypatch):
    payload = {
        "verdict": "미확인", "headline": "something urlscan 관측", "confirmed": [], "unconfirmed": [],
        "contradictions": [], "plan": [], "open_questions": [], "exposure": {}, "timeline": [],
        "followups": [], "question_status": [],
        "campaign_relations": [{"title": "Anything", "relation": "동일 캠페인", "why": ""}],
    }
    _mock_llm(monkeypatch, payload)
    investigation = {"findings": ["something urlscan 관측"]}
    result = rs.synthesize("제목", "", {}, investigation, related=None)
    assert result is not None
    assert result["campaign_relations"] == []
