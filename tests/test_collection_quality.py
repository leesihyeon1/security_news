from datetime import datetime, timezone

import feed_health
import nvd_details
import rss_collector


def test_feed_health_alerts_once_and_announces_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(feed_health, "STATE_FILE", tmp_path / "health.json")
    monkeypatch.setattr(feed_health, "ALERT_AFTER", 3)
    sent = []
    monkeypatch.setattr(feed_health, "_notify", lambda label, recovered, failures=0:
                        sent.append((label, recovered, failures)) or True)
    feed = {"name": "sample", "label": "Sample Feed"}
    for _ in range(4):
        feed_health.record_failure(feed, RuntimeError("invalid XML"))
    assert sent == [("Sample Feed", False, 3)]
    healthy = feed_health.record_success(feed)
    assert healthy["consecutive_failures"] == 0
    assert healthy["last_error"] == ""
    assert sent[-1] == ("Sample Feed", True, 0)
    feed_health.record_failure(feed, RuntimeError("timeout"))
    assert len(sent) == 2


def test_short_rss_content_is_marked_limited_and_fallback_is_conservative():
    article = {"content_html": "", "summary_html": "<p>Short summary</p>"}
    assert rss_collector.resolve_body({}, article) == "Short summary"
    assert article["body_source"] == "rss_summary"
    article["body"] = "Short summary"
    article["enrichment"] = {"category": "기술동향"}
    assert rss_collector.classification_quality(article) == "limited"
    assert rss_collector.fallback_category("CVE-2026-12345 affects Example") == "취약점"
    assert rss_collector.fallback_category("Threat Intelligence Report") == ""


def test_short_scraped_page_does_not_replace_full_rss_body(monkeypatch):
    monkeypatch.setattr(rss_collector, "fetch_article_body", lambda feed, url, article: "Access denied")
    article = {"link": "https://example.test/article", "content_html": "<p>" + "Real report. " * 30 + "</p>",
               "summary_html": "<p>Brief preview</p>"}
    body = rss_collector.resolve_body({"fetch_body": True}, article)
    assert body.startswith("Real report.")
    assert article["body_source"] == "rss_content"


def test_nvd_modified_details_update_existing_event_without_creating_new_one(tmp_path):
    path = tmp_path / "nvd.json"
    cve_id = "CVE-2026-12345"
    modified = [{
        "id": cve_id, "published": "2026-10-01T00:00:00Z",
        "last_modified": "2026-10-05T00:00:00Z", "description": "Updated description",
        "affected_packages": [{"product": "vendor widget", "affected": "< 2.0", "fixed": ""}],
        "references": ["https://vendor.example/advisory"], "score": 8.1, "severity": "HIGH",
    }]
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)
    assert nvd_details.update_cache(modified, {cve_id}, path=path, now=now) == 1
    assert nvd_details.update_cache(modified, {cve_id}, path=path, now=now) == 0
    events = [{"source": "nvd", "cves": [cve_id], "summary": "Initial description",
               "source_updated_at": "2026-10-01T00:00:00Z", "affected_packages": []},
              {"source": "cisa_kev", "cves": [cve_id], "summary": "Keep this record"}]
    updated = nvd_details.enrich_events(events, path=path)
    assert len(updated) == len(events)
    assert updated[0]["affected_packages"][0]["affected"] == "< 2.0"
    assert updated[0]["summary"] == "Updated description"
    assert updated[1] == events[1]
    assert events[0]["affected_packages"] == []


def test_nvd_cache_rejects_old_or_unknown_cves(tmp_path):
    path = tmp_path / "nvd.json"
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)
    rows = [{"id": "CVE-2020-0001", "published": "2020-01-01T00:00:00Z",
             "last_modified": "2026-10-05T00:00:00Z"},
            {"id": "CVE-2026-99999", "published": "2026-10-01T00:00:00Z",
             "last_modified": "2026-10-05T00:00:00Z"}]
    assert nvd_details.update_cache(rows, {"CVE-2020-0001"}, path=path, now=now) == 0
    assert not path.exists()
