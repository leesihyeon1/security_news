import json
from datetime import datetime, timedelta
from unittest import mock

import pytest

import common_utils


# ===== tracking_url =====

def test_tracking_url_passthrough_when_not_configured(monkeypatch):
    monkeypatch.setattr(common_utils, "CLICK_TRACK_BASE_URL", "")
    assert common_utils.tracking_url("asec:1", "http://example.com/a") == "http://example.com/a"


def test_tracking_url_passthrough_when_url_missing(monkeypatch):
    monkeypatch.setattr(common_utils, "CLICK_TRACK_BASE_URL", "https://tracker.example.com")
    assert common_utils.tracking_url("asec:1", "") == ""
    assert common_utils.tracking_url("asec:1", None) is None


def test_tracking_url_wraps_with_ref_and_encoded_url(monkeypatch):
    monkeypatch.setattr(common_utils, "CLICK_TRACK_BASE_URL", "https://tracker.example.com")
    result = common_utils.tracking_url("asec:1", "http://example.com/a?x=1&y=2")
    expected_ref = common_utils.event_ref("asec:1")
    assert result.startswith("https://tracker.example.com/api/click?ref={}&url=".format(expected_ref))
    assert "example.com" not in result.split("url=", 1)[1][:20]  # URL이 인코딩돼 원문 그대로 노출되지 않음


def test_tracking_url_strips_trailing_slash_from_base(monkeypatch):
    monkeypatch.setattr(common_utils, "CLICK_TRACK_BASE_URL", "https://tracker.example.com/")
    result = common_utils.tracking_url("asec:1", "http://example.com/a")
    assert "//api/click" not in result


# ===== iter_lines_reverse =====

def test_iter_lines_reverse_basic_order(tmp_path):
    lines = ["line1 한글테스트", "line2", "line3 다국어 콘텐츠", "line4", "line5 마지막"]
    p = tmp_path / "test.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = list(common_utils.iter_lines_reverse(p, chunk_size=5))
    assert result == list(reversed(lines))


def test_iter_lines_reverse_no_trailing_newline(tmp_path):
    lines = ["a", "b", "c 한글"]
    p = tmp_path / "test.jsonl"
    p.write_bytes("\n".join(lines).encode("utf-8"))

    result = list(common_utils.iter_lines_reverse(p, chunk_size=7))
    assert result == list(reversed(lines))


def test_iter_lines_reverse_whole_file_one_chunk(tmp_path):
    lines = ["a", "b 테스트", "c"]
    p = tmp_path / "test.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = list(common_utils.iter_lines_reverse(p, chunk_size=1 << 20))
    assert result == list(reversed(lines))


def test_iter_lines_reverse_empty_file(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert list(common_utils.iter_lines_reverse(p)) == []


def test_iter_lines_reverse_missing_file(tmp_path):
    assert list(common_utils.iter_lines_reverse(tmp_path / "nope.jsonl")) == []


def test_iter_lines_reverse_large_file_early_exit_is_fast(tmp_path):
    """5만 건짜리 파일에서도 최근 몇 건만 추려도 전체를 다 읽지 않고 조기종료되는지 실측."""
    p = tmp_path / "big.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for i in range(50_000):
            f.write("old line {}\n".format(i))
        f.write("recent\n")

    count = 0
    for line in common_utils.iter_lines_reverse(p, chunk_size=4096):
        count += 1
        if line == "recent":
            break
    assert count == 1  # 첫 줄(파일 끝)에서 바로 찾아 멈춤


# ===== _parse_analyst_review =====

def test_parse_analyst_review_valid():
    raw = {
        "technical_detail": "IOC 5개, C2 서버 IP 명시", "technical_substance": 3,
        "actionable_guidance": "해당 IOC 차단", "actionability": 2,
        "credibility_note": "벤더 공식 확인", "credibility": 2,
    }
    result = common_utils._parse_analyst_review(raw)
    assert result == {
        "technical_substance": 3, "actionability": 2, "credibility": 2,
        "reasoning": {
            "technical_detail": "IOC 5개, C2 서버 IP 명시",
            "actionable_guidance": "해당 IOC 차단",
            "credibility_note": "벤더 공식 확인",
        },
    }


def test_parse_analyst_review_empty_dict_returns_none():
    assert common_utils._parse_analyst_review({}) is None


def test_parse_analyst_review_non_dict_returns_none():
    assert common_utils._parse_analyst_review("not a dict") is None
    assert common_utils._parse_analyst_review(None) is None


def test_parse_analyst_review_out_of_range_scores_ignored():
    assert common_utils._parse_analyst_review({"technical_substance": 99}) is None
    assert common_utils._parse_analyst_review({"credibility": -1}) is None


def test_parse_analyst_review_partial_scores_kept():
    result = common_utils._parse_analyst_review({"technical_substance": 2})
    assert result["technical_substance"] == 2
    assert result["actionability"] is None
    assert result["credibility"] is None


# ===== check_hn_buzz 캐싱 =====

@pytest.fixture
def hn_cache_file(tmp_path, monkeypatch):
    cache_path = tmp_path / "hn_buzz_cache.json"
    monkeypatch.setattr(common_utils, "HN_BUZZ_CACHE_FILE", cache_path)
    common_utils._intel_cache.pop("_hn_buzz_cache", None)
    yield cache_path
    common_utils._intel_cache.pop("_hn_buzz_cache", None)


def _fake_hits_response(points=42, num_comments=7, object_id="abc123"):
    class Response:
        status_code = 200

        def json(self):
            return {"hits": [{"points": points, "num_comments": num_comments, "objectID": object_id}]}
    return Response()


def test_check_hn_buzz_caches_result_and_skips_second_network_call(hn_cache_file):
    calls = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_hits_response()

    with mock.patch.object(common_utils.requests, "get", side_effect=fake_get):
        first = common_utils.check_hn_buzz("http://example.com/a")
        second = common_utils.check_hn_buzz("http://example.com/a")

    assert calls["n"] == 1
    assert first == second
    assert first["points"] == 42


def test_check_hn_buzz_refetches_after_ttl_expires(hn_cache_file):
    with mock.patch.object(common_utils.requests, "get", side_effect=lambda *a, **kw: _fake_hits_response()):
        common_utils.check_hn_buzz("http://example.com/a")

    cache = common_utils._hn_buzz_cache()
    cache["http://example.com/a"]["checked_at"] = (
        datetime.utcnow() - timedelta(days=common_utils.HN_BUZZ_CACHE_TTL_DAYS + 1)
    ).isoformat() + "Z"

    calls = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_hits_response()

    with mock.patch.object(common_utils.requests, "get", side_effect=fake_get):
        common_utils.check_hn_buzz("http://example.com/a")

    assert calls["n"] == 1


def test_check_hn_buzz_failure_is_not_cached(hn_cache_file):
    def failing_get(*a, **kw):
        raise RuntimeError("network down")

    with mock.patch.object(common_utils.requests, "get", side_effect=failing_get):
        result = common_utils.check_hn_buzz("http://example.com/b")

    assert result is False
    assert "http://example.com/b" not in common_utils._hn_buzz_cache()


def test_check_hn_buzz_prunes_stale_entries_on_save(hn_cache_file):
    cache = common_utils._hn_buzz_cache()
    cache["http://old.com"] = {
        "result": None,
        "checked_at": (datetime.utcnow() - timedelta(days=common_utils.HN_BUZZ_CACHE_RETENTION_DAYS + 5)).isoformat() + "Z",
    }
    cache["http://recent.com"] = {
        "result": None,
        "checked_at": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
    }
    common_utils.save_json_state(common_utils.HN_BUZZ_CACHE_FILE, cache)

    def fake_get(url, params=None, timeout=None):
        class Response:
            status_code = 200
            def json(self):
                return {"hits": []}
        return Response()

    with mock.patch.object(common_utils.requests, "get", side_effect=fake_get):
        common_utils.check_hn_buzz("http://new-trigger.com")

    with hn_cache_file.open(encoding="utf-8") as f:
        saved = json.load(f)
    assert "http://old.com" not in saved
    assert "http://recent.com" in saved
    assert "http://new-trigger.com" in saved


# ===== _read_recent_events =====

def _make_event(event_id, hours_ago, source="asec"):
    return {
        "id": "{}:{}".format(source, event_id),
        "source": source,
        "title": "t{}".format(event_id),
        "fetched_at": (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat() + "Z",
    }


def test_read_recent_events_respects_time_window(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    events = [_make_event(1, 100), _make_event(2, 80), _make_event(3, 50), _make_event(4, 10), _make_event(5, 1)]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)

    result = common_utils._read_recent_events(72)
    got_ids = sorted(e["id"] for e in result)
    assert got_ids == ["asec:3", "asec:4", "asec:5"]


def test_read_recent_events_excludes_catalog_sources(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    events = [_make_event(1, 1), _make_event(2, 1, source="nvd")]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)

    result = common_utils._read_recent_events(72)
    assert [e["id"] for e in result] == ["asec:1"]
