from collections import Counter

from dashboard_text import data_status
from entity_names import count_entities, entity_names
import generate_report as report
import publish_trending_titles as trending


def test_entities_split_without_double_counting_aliases():
    rows = [{"malware_family": "Clop, Clop ransomware, CHOSEN BRICK"},
            {"malware_family": "Chosen Brick"}]
    assert count_entities(rows, "malware_family") == Counter({"Clop": 1, "Chosen Brick": 2})
    assert entity_names("Group (alias A, alias B), Other") == ["Group (alias A, alias B)", "Other"]


def test_trending_merges_product_aliases_and_case_across_sources():
    rows = [{"source": "one", "affected_products": ["Cisco Identity Services Engine (ISE)", "Cisco Identity Services Engine"]},
            {"source": "two", "affected_products": ["Cisco Identity Services Engine"]}]
    assert trending.build_trending(rows) == [("Cisco Identity Services Engine", 2)]


def test_actionable_categories_cover_total_including_unclassified():
    events = [{"kev": True, "category": "", "triage": {"level": "P1"}},
              {"kev": True, "category": "취약점", "triage": {"level": "P3"}}]
    stats = report.build_stats(events)
    payload = report.build_dashboard_payload("Report", "daily", "Period", stats, "", [], [], [])
    assert sum(payload["stats"]["actionable_by_category"].values()) == payload["stats"]["actionable"] == 2
    assert payload["stats"]["actionable_by_category"]["미분류"] == 1


def test_status_distinguishes_collection_and_window():
    result = data_status("2026-09-20 00:00 ~ 2026-09-21 00:00 (UTC)", "daily", "2026-09-20T23:00:00Z")
    assert result["period_end"] == "2026-09-21T00:00:00Z"
    assert result["latest_collected_at"] == "2026-09-20T23:00:00Z"
    assert result["stale_after_hours"] == 36
    assert "period_end" not in data_status("Unknown", "weekly")


def test_report_events_exclude_end_boundary(tmp_path, monkeypatch):
    import json
    from datetime import datetime
    path = tmp_path / "events.jsonl"
    rows = [{"source": "nvd", "url": "https://example.com/" + str(i), "fetched_at": timestamp}
            for i, timestamp in enumerate(["2026-09-20T12:00:00Z", "2026-09-21T00:00:00Z"])]
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    monkeypatch.setattr(report.common_utils, "EVENTS_FILE", path)
    monkeypatch.setattr(report, "LEGACY_BOANNEWS_EVENTS_FILE", tmp_path / "missing.jsonl")
    result = report.load_events_between(datetime(2026, 9, 20), datetime(2026, 9, 21))
    assert len(result) == 1
    assert result[0]["url"].endswith("/0")
