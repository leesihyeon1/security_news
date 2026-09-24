import json

import common_utils
import response_synth as rs


def test_question_status_keeps_only_questions_actually_asked():
    questions = ["유포지가 살아있는가", "표적이 누구인가"]
    data = {"question_status": [
        {"question": "유포지가 살아있는가", "status": "answered", "answer": "확인됨"},
        {"question": "지어낸 질문", "status": "answered", "answer": "x"},
    ]}
    out = rs.question_status(data, questions, corpus="확인됨")
    assert len(out) == 1
    assert out[0]["question"] == "유포지가 살아있는가"
    assert out[0]["status"] == "answered"


def test_question_status_defaults_unknown_status_to_open():
    data = {"question_status": [{"question": "q", "status": "이상한값", "answer": ""}]}
    out = rs.question_status(data, ["q"], corpus="")
    assert out[0]["status"] == "open"


def test_question_status_drops_ungrounded_answer_but_keeps_status():
    data = {"question_status": [
        {"question": "q", "status": "answered", "answer": "evil-not-in-corpus.example"}]}
    out = rs.question_status(data, ["q"], corpus="아무것도 없음")
    assert out[0]["status"] == "answered"
    assert out[0]["answer"] == ""


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
            {"question": "유포지가 살아있는가", "status": "answered", "answer": "evil.example 확인"}],
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
        {"question": "유포지가 살아있는가", "status": "answered", "answer": "evil.example 확인"}]
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
