"""Publish a small, public GitHub Advisory snapshot for the CVE dashboard."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

GHSA_ID = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", re.I)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
EVENTS_FILE = Path(__file__).resolve().parents[1] / "data" / "events.jsonl"
MAX_ITEMS = 20
RECENT_DAYS = 14


def _date(value):
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def build_snapshot(events_file=None, now=None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RECENT_DAYS)
    latest = None
    recent = {}
    path = Path(events_file or EVENTS_FILE)
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if '"github_advisory"' not in line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("source") != "github_advisory":
                continue
            match = GHSA_ID.fullmatch(str(event.get("id") or "").removeprefix("github_advisory:"))
            published = _date(event.get("published_at"))
            if not match or not published:
                continue
            if latest is None or published > latest:
                latest = published
            if published < cutoff:
                continue
            severity = str(event.get("severity") or "").upper()
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            ghsa = match.group().upper()
            cve = next((str(value).upper() for value in event.get("cves") or []
                        if CVE_ID.fullmatch(str(value))), "")
            row = {"id": ghsa, "title": " ".join(str(event.get("title") or "").split())[:160],
                   "severity": severity, "published_at": published.isoformat(),
                   "url": "https://github.com/advisories/" + ghsa}
            if cve:
                row["cve"] = cve
            recent[ghsa] = row
    items = sorted(recent.values(), key=lambda row: row["published_at"], reverse=True)[:MAX_ITEMS]
    return {"generated_at": now.isoformat(), "last_published_at": latest.isoformat() if latest else "",
            "window_days": RECENT_DAYS, "items": items}


def publish(data_dir, events_file=None, now=None):
    snapshot = build_snapshot(events_file, now)
    path = Path(data_dir) / "github-advisory-feed.json"
    temp = path.with_suffix(".tmp")   # a reader never sees a half-written file
    temp.write_text(json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    temp.replace(path)
    return snapshot
