"""최신 기사 소스 정비(2026-11-20) — 피드 설정·제목 정리·최신 기사 제외 규칙."""
import json
from pathlib import Path

import common_utils
import live_news
import rss_collector

FEEDS = {feed["name"]: feed for feed in json.loads(
    (Path(__file__).resolve().parents[1] / "assets" / "feeds.json").read_text(encoding="utf-8"))}


def test_broken_or_blocked_feeds_are_off_with_a_reason():
    for name in ("inca_isarc", "reddit_netsec", "sophos", "trendmicro"):
        assert FEEDS[name]["enabled"] is False
        assert "2026-11-20" in FEEDS[name]["note"]


def test_bleepingcomputer_comes_from_the_public_aggregator_without_page_fetches():
    feed = FEEDS["bleepingcomputer"]
    assert feed["enabled"] is True
    assert feed["rss_url"].startswith("https://news.google.com/rss/search?q=site:bleepingcomputer.com")
    assert feed["fetch_body"] is False and "body_selector" not in feed
    assert feed["max_age_days"] == 2


def test_rce_research_and_vendor_sources_are_registered():
    for name in ("watchtowr", "horizon3", "zdi_blog", "zdi_published", "ivanti_psirt"):
        assert FEEDS[name]["enabled"] is True
        assert common_utils.source_label(name) != name
    assert {"zdi_published", "ivanti_psirt"} <= common_utils.NON_NEWS_SOURCES
    assert not {"watchtowr", "horizon3", "zdi_blog"} & common_utils.NON_NEWS_SOURCES


def test_aggregator_title_suffix_is_removed(monkeypatch):
    xml = ("<rss><channel><item><title>Drupal patches critical RCE flaw - BleepingComputer</title>"
           "<link>https://news.google.com/rss/articles/x</link><pubDate>Thu, 19 Nov 2026 13:08:08 GMT</pubDate>"
           "</item></channel></rss>").encode()

    class Response:
        content = xml

        def raise_for_status(self):
            return None

    monkeypatch.setattr(rss_collector.requests, "get", lambda *a, **k: Response())
    items = rss_collector.fetch_feed_items(FEEDS["bleepingcomputer"])
    assert items[0]["title"] == "Drupal patches critical RCE flaw"


def _event(source, category):
    return {"id": source + category, "source": source, "category": category, "title": "제목 " + category,
            "url": "https://example.test/" + source + "/" + category, "fetched_at": "2026-11-19T00:00:00Z",
            "published_at": "2026-11-19T00:00:00Z", "summary": "요약"}


def test_latest_feed_drops_product_and_misc_posts_from_the_two_korean_outlets_only():
    events = [_event("dailysecu", "제품행사"), _event("boannews", "기타"), _event("boannews", "취약점"),
              _event("helpnetsecurity", "제품행사"), _event("dailysecu", "미분류")]
    kept = {(row["source"], row["category"]) for row in live_news.latest_articles(events)}
    assert kept == {("boannews", "취약점"), ("helpnetsecurity", "제품행사"), ("dailysecu", "미분류")}
