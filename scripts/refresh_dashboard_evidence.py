"""Refresh local public report evidence without sending or publishing anything."""

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import common_utils
from dashboard_text import public_evidence, public_text, public_narrative
from publish_web_dashboard import _rebuild_search_index_from_events


def refresh(repo):
    events = {}
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = event.get("url")
        if url and url not in events:
            events[url] = event

    count = 0
    data_dir = repo / "dashboard/data"
    for path in sorted(data_dir.glob("*.json")):
        if not path.name.startswith(("daily-", "weekly-")):
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        for card in payload.get("cards", []):
            evidence = []
            for item in card.get("items", []):
                url = item.get("url") or ""
                parsed = urlsplit(url)
                if parsed.hostname == "click-tracker-two.vercel.app" and parsed.path == "/api/click":
                    url = parse_qs(parsed.query).get("url", [url])[0]
                event = events.get(url)
                if event:
                    evidence.append(public_evidence(event, common_utils.source_label(event.get("source"))))
            card["evidence"] = evidence
            for field in ("summary", "remediation", "issue_analysis"):
                card[field] = public_text(card.get(field) or "")
        for region in ("domestic", "overseas"):
            for rows in (payload.get(region) or {}).values():
                if isinstance(rows, list):
                    for row in rows:
                        row["summary"] = public_text(row.get("summary") or "")
        for row in payload.get("campaigns", []):
            row["summary"] = public_text(row.get("summary") or "")
        payload["narrative"] = public_narrative(payload.get("narrative") or "")
        payload["narrative_basis"] = "AI 분석 · 출처와 수집 시각은 각 카드 참조"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        count += 1
    _rebuild_search_index_from_events(repo)
    print("Refreshed {} report files; no remote publishing.".format(count))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    refresh(parser.parse_args().repo)
