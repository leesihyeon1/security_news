"""Refresh existing campaign cards only; never enqueue, call a model, or publish."""

import argparse
import json
from pathlib import Path

import campaign_radar
import common_utils


def refresh_payload(payload, events):
    """Only use the articles already in this report, without changing its period."""
    for row in payload.get("campaigns") or []:
        refs = {item.get("ref") for item in row.get("items") or []}
        matched = [e for ref, e in events.items() if ref in refs
                   and str(e.get("fetched_at") or "") <= str(payload.get("generated_at") or "")]
        if not matched:
            continue
        group = {"names": row["names"], "first": row.get("first_seen") or "",
                 "events": {e["id"]: e for e in matched}}
        rebuilt = campaign_radar._build_rows([group])
        if rebuilt:
            refreshed = campaign_radar.public_row(rebuilt[0])
            # Preserve fields not being recomputed, including the historical corpus date.
            for key in ("items", "summary", "assessment", "ioc_count"):
                row[key] = refreshed[key]
            row.pop("auto_analysis", None)
            row.pop("analysis_ref", None)
    return payload


def refresh(repo, write=False):
    data = repo / "dashboard" / "data"
    latest = [p for p in (data / "daily-latest.json", data / "weekly-latest.json") if p.exists()]
    periods = {json.loads(p.read_text(encoding="utf-8")).get("generated_at") for p in latest}
    paths = [p for p in data.glob("*.json") if p.name.startswith(("daily-", "weekly-"))]
    payloads = [(p, json.loads(p.read_text(encoding="utf-8"))) for p in paths]
    payloads = [(p, value) for p, value in payloads if value.get("generated_at") in periods]
    wanted = {i.get("ref") for _, payload in payloads for r in payload.get("campaigns") or []
              for i in r.get("items") or []}
    events = {}
    for event in campaign_radar._iter_events(common_utils.EVENTS_FILE):
        ref = common_utils.event_ref(event.get("id"))
        if ref in wanted:
            events.setdefault(ref, event)
    for path, payload in payloads:
        refresh_payload(payload, events)
        if write:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("{}: {} cards{}".format(path.name, len(payload.get("campaigns") or []), " updated" if write else " checked"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    refresh(args.repo, write=args.write)
