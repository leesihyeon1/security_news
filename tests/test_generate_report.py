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


@pytest.fixture(autouse=True)
def _no_real_hn_lookup(monkeypatch):
    """pick_trend_reads()의 Hacker News 화제성 조회가 실제 네트워크·캐시를 타지 않게 한다.
    테스트 URL(http://x/1 등)에 그날그날 다른 포인트가 붙으면 동점 순서가 뒤집혀
    결과가 실행 환경마다 달라진다."""
    monkeypatch.setattr(common_utils, "check_hn_buzz", lambda url: None)


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

    # 같은 id(같은 글의 재수집)가 파일 순서(오래된 것부터)로 두 번 등장 —
    # 먼저 나온 것이 남아야 함. id를 그대로 재사용해 "같은 글을 다시 봤다"를 흉내 낸다.
    dup = _make_event(2, 50, url="http://dup")
    dup_seen_again = _make_event(2, 40, url="http://dup")
    dup_seen_again["title"] = "t2 (재수집)"
    events = [dup, dup_seen_again, _make_event(4, 5)]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(gr, "LEGACY_BOANNEWS_EVENTS_FILE", legacy_file)

    since = datetime.utcnow() - timedelta(hours=72)
    result = gr.load_events(since)
    assert len(result) == 2
    dup_kept = next(e for e in result if e["url"] == "http://dup")
    assert dup_kept["title"] == "t2"


def test_load_events_keeps_distinct_ids_that_share_a_url(tmp_path, monkeypatch):
    """실측(2026-09-22): cisa_kev 이벤트 82건이 전부 같은 카탈로그 페이지 url을 쓴다.

    id는 서로 다른데(각 CVE 하나씩) 예전 dedup 키가 (source, url)이어서 구간마다
    KEV가 1건으로 줄었다 — 82건 중 81건이 조용히 사라졌다. id를 우선하는 지금
    규칙에서는 같은 url이어도 id가 다르면 둘 다 남아야 한다."""
    events_file = tmp_path / "events.jsonl"
    legacy_file = tmp_path / "legacy.jsonl"
    legacy_file.write_text("", encoding="utf-8")

    kev_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    events = [
        {"id": "cisa_kev:CVE-2026-0001", "source": "cisa_kev", "title": "CVE-2026-0001",
         "url": kev_url, "fetched_at": (datetime.utcnow() - timedelta(hours=10)).isoformat() + "Z"},
        {"id": "cisa_kev:CVE-2026-0002", "source": "cisa_kev", "title": "CVE-2026-0002",
         "url": kev_url, "fetched_at": (datetime.utcnow() - timedelta(hours=9)).isoformat() + "Z"},
    ]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(gr, "LEGACY_BOANNEWS_EVENTS_FILE", legacy_file)

    since = datetime.utcnow() - timedelta(hours=72)
    result = gr.load_events(since)
    assert {e["id"] for e in result} == {"cisa_kev:CVE-2026-0001", "cisa_kev:CVE-2026-0002"}


# ===== report_window =====

def test_report_window_uses_last_completed_kst_cutoff_after_cutoff(monkeypatch):
    monkeypatch.setattr(gr, "REPORT_CUTOFF_HOUR_KST", 9)

    since, until = gr.report_window(1, now_utc=datetime(2026, 7, 27, 5, 30))  # KST 14:30

    assert since == datetime(2026, 7, 26, 0, 0)
    assert until == datetime(2026, 7, 27, 0, 0)


def test_report_window_uses_previous_kst_cutoff_before_cutoff(monkeypatch):
    monkeypatch.setattr(gr, "REPORT_CUTOFF_HOUR_KST", 9)

    since, until = gr.report_window(1, now_utc=datetime(2026, 7, 26, 23, 30))  # KST 08:30

    assert since == datetime(2026, 7, 25, 0, 0)
    assert until == datetime(2026, 7, 26, 0, 0)


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


def test_pick_trend_reads_explore_slot_ignores_personalization(monkeypatch):
    """탐색 슬롯(EXPLORE_SLOT_COUNT)은 quality_score만으로 뽑혀야 함 — 개인화(feedback_useful)
    가산으로 전체 insight_score가 더 높아도, 품질 자체가 낮으면 유일한 슬롯을 못 가져가야 함
    (필터버블 방지 가드가 실제로 작동하는지 확인)."""
    monkeypatch.setattr(common_utils, "load_pirs", lambda: {})
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {"asec:1": {"label": "useful", "via": "slack"}})

    events = _same_published_at([
        _trend_candidate_event(1, category="침해사고", relevance="medium", reliability="B"),  # 낮은 품질 + 개인화 가산
        _trend_candidate_event(2, category="침해사고", relevance="high"),  # 높은 품질, 개인화 없음
    ])
    result = gr.pick_trend_reads(events, exclude_ids=set(), max_items=1)
    assert [e["id"] for e in result] == ["asec:2"]


def test_merge_same_story_does_not_join_products_from_one_roundup():
    roundup = {"id": "news:roundup", "source": "news", "cves": ["CVE-2026-88771", "CVE-2026-93616"]}
    citrix = {"id": "news:citrix", "source": "news", "cves": ["CVE-2026-88771"]}
    checkpoint = {"id": "news:checkpoint", "source": "news", "cves": ["CVE-2026-93616"]}
    clusters = [
        {"cves": ["CVE-2026-88771"], "group": [roundup, citrix], "sources": ["news"]},
        {"cves": ["CVE-2026-93616"], "group": [roundup, checkpoint], "sources": ["news"]},
    ]
    assert len(gr.merge_same_story(clusters)) == 2


def test_merge_same_story_keeps_independently_corrobated_chain_together():
    shared = [{"id": "news:a", "source": "news"}, {"id": "news:b", "source": "news"}]
    clusters = [
        {"cves": ["CVE-2026-10001"], "group": shared + [{"id": "nvd:one", "source": "nvd"}], "sources": ["news", "nvd"]},
        {"cves": ["CVE-2026-10002"], "group": shared + [{"id": "nvd:two", "source": "nvd"}], "sources": ["news", "nvd"]},
    ]
    assert gr.merge_same_story(clusters)[0]["cves"] == ["CVE-2026-10001", "CVE-2026-10002"]


def test_public_narrative_retries_generic_action(monkeypatch):
    base = "[총평]\n노출된 Docker API가 악용되고 있습니다.\n[핵심 위협 TOP 3]\n1. Carbonato가 Docker 호스트를 침해합니다.\n[권고 조치]\n1. {}"
    responses = iter([base.format("공식 권고 확인을 권합니다."),
                      base.format("Docker API 2375의 외부 노출을 차단하고 특권 컨테이너를 점검해야 합니다.")])
    calls = []
    def generate(prompt, **kwargs):
        calls.append(prompt)
        return next(responses)
    monkeypatch.setattr(common_utils, "llm_generate", generate)
    cards = [{"cve": "Carbonato", "summary": "Docker API 2375가 노출돼 있습니다."}]
    narrative = gr.ai_public_narrative("오늘", {"total": 1}, cards)
    assert "외부 노출을 차단" in narrative
    assert "공식 권고 확인" not in narrative
    assert len(calls) == 2
    assert "수집된 기사·취약점 레코드 건수" in calls[0]


def test_public_narrative_rejects_repeated_generic_action(monkeypatch):
    response = "[총평]\n위협이 있습니다.\n[핵심 위협 TOP 3]\n1. 악용 중입니다.\n[권고 조치]\n1. 공식 권고 확인을 권합니다."
    monkeypatch.setattr(common_utils, "llm_generate", lambda *args, **kwargs: response)
    with pytest.raises(RuntimeError, match="quality checks"):
        gr.ai_public_narrative("오늘", {"total": 1}, [{"cve": "위협"}])


def test_public_narrative_distinguishes_collected_records_from_incidents():
    narrative = "[총평]\n전체 370건의 이슈가 확인됐습니다.\n[핵심 위협 TOP 3]\n1. 취약점이 악용되고 있습니다.\n[권고 조치]\n1. 영향 자산의 패치를 적용해야 합니다."
    assert "수집 건수" in gr._public_narrative_problem(narrative, 1)
