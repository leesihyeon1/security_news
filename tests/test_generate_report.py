import json
from datetime import datetime, timedelta

import pytest

import common_utils
import generate_report as gr


@pytest.fixture(autouse=True)
def _no_real_search_log(monkeypatch):
    """pick_trend_reads()가 실제 data/search_log.jsonl을 읽지 않도록 기본값을 비워둔다 —
    검색어 가산(search_interest)을 직접 테스트하는 케이스만 이걸 다시 monkeypatch한다."""
    monkeypatch.setattr(common_utils, "load_recent_search_terms", lambda **kwargs: [])


def _make_event(event_id, hours_ago, url=None, source="asec"):
    return {
        "id": "{}:{}".format(source, event_id),
        "source": source,
        "title": "t{}".format(event_id),
        "url": url or "http://x/{}".format(event_id),
        "fetched_at": (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat() + "Z",
    }


# ===== load_events =====

def test_load_events_filters_by_time_window(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    legacy_file = tmp_path / "legacy.jsonl"
    legacy_file.write_text("", encoding="utf-8")

    events = [_make_event(1, 100), _make_event(2, 5)]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(gr, "LEGACY_BOANNEWS_EVENTS_FILE", legacy_file)

    since = datetime.utcnow() - timedelta(hours=72)
    result = gr.load_events(since)
    ids = [e["id"] for e in result]
    assert ids == ["asec:2"]


def test_load_events_dedup_keeps_first_chronological_occurrence(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    legacy_file = tmp_path / "legacy.jsonl"
    legacy_file.write_text("", encoding="utf-8")

    # 파일 순서(오래된 것부터)로 같은 url이 두 번 등장 — 먼저 나온 것(id2)이 남아야 함
    events = [_make_event(2, 50, url="http://dup"), _make_event(3, 40, url="http://dup"), _make_event(4, 5)]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(gr, "LEGACY_BOANNEWS_EVENTS_FILE", legacy_file)

    since = datetime.utcnow() - timedelta(hours=72)
    result = gr.load_events(since)
    assert len(result) == 2
    dup_kept = next(e for e in result if e["url"] == "http://dup")
    assert dup_kept["id"] == "asec:2"


# ===== pick_trend_reads: has_insight 품질 게이트 =====

def _trend_candidate_event(event_id, pirs=None, category="", relevance="", confidence="", reliability=""):
    return {
        "id": "asec:{}".format(event_id),
        "source": "asec",
        "title": "t{}".format(event_id),
        "url": "http://x/{}".format(event_id),
        "published_at": datetime.utcnow().isoformat() + "Z",
        "delivery": {},
        "pirs": pirs or [],
        "category": category,
        "relevance": relevance,
        "confidence": confidence,
        "importance": {"reliability": reliability},
    }


def test_pick_trend_reads_excludes_low_relevance_pir_match(monkeypatch):
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {"PIR-1": {"question": "q", "weight": "high"}})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    events = [_trend_candidate_event(1, pirs=["PIR-1"], relevance="low", confidence="high")]
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert result == []


def test_pick_trend_reads_excludes_low_confidence_pir_match(monkeypatch):
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {"PIR-1": {"question": "q", "weight": "high"}})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    events = [_trend_candidate_event(1, pirs=["PIR-1"], relevance="high", confidence="low")]
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert result == []


def test_pick_trend_reads_includes_pir_match_with_unrated_relevance(monkeypatch):
    """미판정(빈 값) relevance는 명시적 low가 아니므로 통과해야 함(하위호환)."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {"PIR-1": {"question": "q", "weight": "high"}})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    events = [_trend_candidate_event(1, pirs=["PIR-1"], relevance="", confidence="")]
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert len(result) == 1


def test_pick_trend_reads_excludes_noise_labeled_events(monkeypatch):
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {"PIR-1": {"question": "q", "weight": "high"}})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {"asec:1": {"label": "noise"}})

    events = [_trend_candidate_event(1, pirs=["PIR-1"], relevance="high", confidence="high")]
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert result == []


def _same_published_at(events):
    """recency 축이 published_at의 미세한 생성 시각 차이로 정렬 순서를 흔들지 않도록,
    두 이벤트의 published_at을 동일하게 맞춰 feedback_useful 축만 순수하게 비교한다."""
    for event in events:
        event["published_at"] = events[0]["published_at"]
    return events


def test_pick_trend_reads_ranks_useful_feedback_higher(monkeypatch):
    """useful 라벨이 붙은 기사는 다른 조건이 동일해도 insight_score 가산으로 먼저 뽑혀야 함."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {"asec:2": {"label": "useful", "via": "slack"}})

    events = _same_published_at([
        _trend_candidate_event(1, category="침해사고", relevance="high"),
        _trend_candidate_event(2, category="침해사고", relevance="high"),
    ])
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert [e["id"] for e in result] == ["asec:2", "asec:1"]


def test_pick_trend_reads_ignores_single_click_feedback(monkeypatch):
    """클릭 기반 useful 라벨은 FEEDBACK_USEFUL_MIN_CLICKS 미만이면 가산되지 않아야 함
    (우연한 클릭 한 번으로 순위가 바뀌면 안 됨)."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {})
    monkeypatch.setattr(
        common_utils, "load_feedback",
        lambda: {"asec:2": {"label": "useful", "via": "click", "click_count": 1}},
    )

    events = _same_published_at([
        _trend_candidate_event(1, category="침해사고", relevance="high"),
        _trend_candidate_event(2, category="침해사고", relevance="high"),
    ])
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert [e["id"] for e in result] == ["asec:1", "asec:2"]


def test_pick_trend_reads_boosts_repeated_click_feedback(monkeypatch):
    """FEEDBACK_USEFUL_MIN_CLICKS 이상 반복 클릭되면 그때부터는 가산돼야 함."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {})
    monkeypatch.setattr(
        common_utils, "load_feedback",
        lambda: {"asec:2": {"label": "useful", "via": "click", "click_count": gr.FEEDBACK_USEFUL_MIN_CLICKS}},
    )

    events = _same_published_at([
        _trend_candidate_event(1, category="침해사고", relevance="high"),
        _trend_candidate_event(2, category="침해사고", relevance="high"),
    ])
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert [e["id"] for e in result] == ["asec:2", "asec:1"]


def test_pick_trend_reads_boosts_search_interest_match(monkeypatch):
    """최근 검색어(단어 전부 매칭)와 겹치는 기사가 다른 조건이 동일해도 먼저 뽑혀야 함."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})
    monkeypatch.setattr(common_utils, "load_recent_search_terms", lambda **kwargs: [["fortigate"]])

    events = _same_published_at([
        _trend_candidate_event(1, category="침해사고", relevance="high"),
        _trend_candidate_event(2, category="침해사고", relevance="high"),
    ])
    events[1]["title"] = "FortiGate 취약점 발견"  # 대소문자 달라도 매칭돼야 함
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert [e["id"] for e in result] == ["asec:2", "asec:1"]


def test_pick_trend_reads_ignores_search_terms_that_dont_match(monkeypatch):
    """검색어 단어 중 하나라도 기사 텍스트에 없으면(AND 매칭 실패) 가산되지 않아야 함."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})
    monkeypatch.setattr(common_utils, "load_recent_search_terms", lambda **kwargs: [["fortigate", "rce"]])

    events = _same_published_at([
        _trend_candidate_event(1, category="침해사고", relevance="high"),
        _trend_candidate_event(2, category="침해사고", relevance="high"),
    ])
    events[1]["title"] = "FortiGate 취약점 발견"  # "rce"는 없어서 AND 매칭 실패해야 함
    result = gr.pick_trend_reads(events, exclude_ids=set())
    assert [e["id"] for e in result] == ["asec:1", "asec:2"]
