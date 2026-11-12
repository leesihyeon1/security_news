import json
from datetime import datetime, timedelta, timezone

import collect_x_post_urls as xc

NOW = datetime(2026, 11, 13, 3, 0, tzinfo=timezone.utc)


def test_normalize_post_requires_matching_author():
    assert xc.normalize_post("https://twitter.com/DarkWebInformer/status/123?ref=home", "DarkWebInformer") == (
        "https://x.com/DarkWebInformer/status/123"
    )
    assert xc.normalize_post("https://x.com/other/status/123", "DarkWebInformer") is None
    assert xc.normalize_post("https://example.com/DarkWebInformer/status/123", "DarkWebInformer") is None


def test_extract_posts_deduplicates_and_orders_by_id():
    links = [
        "https://x.com/troyhunt/status/12",
        "https://x.com/troyhunt/status/10",
        "https://x.com/troyhunt/status/12/photo/1",
        "https://x.com/other/status/99",
        "https://x.com/troyhunt/status/11",
    ]
    assert xc.extract_posts(links, "troyhunt", 2) == [
        "https://x.com/troyhunt/status/12",
        "https://x.com/troyhunt/status/11",
    ]


def test_merge_puts_newest_first_and_keeps_old_posts_for_failed_accounts():
    data = {"posts": [
        {"url": "https://x.com/DarkWebInformer/status/5", "author": "DarkWebInformer", "group": "breaking"},
        {"url": "https://x.com/troyhunt/status/7", "author": "troyhunt", "group": "insight",
         "collected_at": "2026-11-01T00:00:00+00:00"},
    ]}
    found = {"troyhunt": ["https://x.com/troyhunt/status/9", "https://x.com/troyhunt/status/7"]}
    merged = xc.merge(data, found, per_account=2, now=NOW)
    assert [p["url"] for p in merged["posts"]] == [
        "https://x.com/troyhunt/status/9", "https://x.com/troyhunt/status/7", "https://x.com/DarkWebInformer/status/5"]
    assert merged["posts"][0]["collected_at"] == NOW.isoformat(timespec="seconds")
    assert merged["posts"][1]["collected_at"] == "2026-11-01T00:00:00+00:00"  # already-seen post keeps its stamp
    assert merged["updated_at"] == NOW.isoformat(timespec="seconds")


def test_merge_drops_posts_that_fell_off_a_loaded_profile():
    data = {"posts": [{"url": "https://x.com/troyhunt/status/1", "author": "troyhunt"}]}
    merged = xc.merge(data, {"troyhunt": ["https://x.com/troyhunt/status/3"]}, per_account=3, now=NOW)
    assert [p["url"] for p in merged["posts"]] == ["https://x.com/troyhunt/status/3"]


def test_is_due_respects_the_minimum_interval():
    assert xc.is_due({}, NOW)
    assert not xc.is_due({"updated_at": (NOW - timedelta(minutes=30)).isoformat()}, NOW)
    assert xc.is_due({"updated_at": (NOW - timedelta(hours=3)).isoformat()}, NOW)


def test_refresh_keeps_the_file_when_nothing_loads(tmp_path, monkeypatch):
    out = tmp_path / "x-posts.json"
    out.write_text(json.dumps({"posts": []}), encoding="utf-8")
    monkeypatch.setattr(xc, "scrape", lambda *args, **kwargs: {})
    try:
        xc.refresh(out, tmp_path, 2, now=NOW)
    except RuntimeError:
        pass
    assert json.loads(out.read_text(encoding="utf-8")) == {"posts": []}
