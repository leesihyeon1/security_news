"""Rebuild latest local dashboards and Korean AI narratives without publishing."""

import argparse
import json
from pathlib import Path

import generate_report as report
import publish_trending_titles as trending
import common_utils
from dashboard_text import public_narrative


def refresh(repo):
    data_dir = repo / "dashboard/data"
    for period, days in (("daily", 1), ("weekly", 7)):
        path = data_dir / (period + "-latest.json")
        old = json.loads(path.read_text(encoding="utf-8"))
        start, end = report.report_window(days)
        events = report.load_events_between(start, end)
        stats = report.build_stats(events)
        cards = report.correlate_by_cve(events)
        previous_cards = {card["cve"]: card for card in old.get("cards", [])}
        for card in cards:
            previous = previous_cards.get(card["cve"], {})
            card["issue_analysis"] = previous.get("issue_analysis") or ""
        highlights = sorted((event for event in events if event.get("source") not in common_utils.NON_NEWS_SOURCES),
                            key=report.event_sort_key)
        reads = report.pick_trend_reads(events, set(), max_items=len(events), include_alerted=True,
                                        rank_by_importance=True)
        label = "{} ~ {} (UTC)".format(start.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M"))
        trends = None
        if period == "weekly":
            from datetime import timedelta
            previous = report.load_events_between(start - timedelta(days=days), start)
            trends = report.compute_weekly_trends(events, previous)
        narrative = report.ai_public_narrative(label, stats, cards)
        if not narrative:
            raise RuntimeError("Korean narrative generation failed; existing report retained")
        if "한국어 요약을 준비하지 못했습니다" in public_narrative(narrative):
            raise RuntimeError("Korean narrative sections missing; existing report retained")
        payload = report.build_dashboard_payload(old["title"], period, label, stats, narrative, highlights,
                                                 cards, reads, report.fallback_keywords(stats, cards),
                                                 weekly_trends=trends, campaigns=old.get("campaigns") or [],
                                                 cve_items=report.build_cve_items(events, cards))
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        assert sum(payload["stats"]["actionable_by_category"].values()) == payload["stats"]["actionable"]
        print(period, "events", len(events), "actionable", payload["stats"]["actionable"],
              "categories", payload["stats"]["actionable_by_category"])
    ranked = trending.build_trending(trending.load_recent_events())
    # Reset rank deltas because the previous ranking used a different counting rule.
    payload = {"generated_at": common_utils.utc_now_iso(), "items": [
        {"term": term, "count": count, "status": "new", "delta": None} for term, count in ranked]}
    (data_dir / "trending.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    refresh(parser.parse_args().repo)
