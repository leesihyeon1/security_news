"""Keep later NVD details without counting a modified CVE as a new event."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import common_utils


CACHE_FILE = common_utils.STATE_DIR / "nvd_details_cache.json"
RETENTION_DAYS = 30
MAX_ITEMS = 5000


def _time(value):
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def load_cache(path=CACHE_FILE):
    data = common_utils.load_json_state(path, dict)
    return data.get("items", {}) if isinstance(data, dict) and isinstance(data.get("items"), dict) else {}


def update_cache(modified, known_ids, path=CACHE_FILE, now=None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RETENTION_DAYS)
    cached = load_cache(path)
    rows = {key: value for key, value in cached.items()
            if isinstance(value, dict) and (_time(value.get("published")) or now) >= cutoff}
    for item in modified:
        cve_id = item.get("id")
        published = _time(item.get("published"))
        modified_at = _time(item.get("last_modified"))
        if cve_id not in known_ids or not published or published < cutoff or not modified_at:
            continue
        prior = rows.get(cve_id) or {}
        if _time(prior.get("last_modified")) and _time(prior["last_modified"]) >= modified_at:
            continue
        rows[cve_id] = {
            "published": item["published"], "last_modified": item["last_modified"],
            "affected_packages": item.get("affected_packages") or [],
            "references": item.get("references") or [],
            "description": item.get("description") or "",
            "score": item.get("score"), "severity": item.get("severity") or "",
        }
    rows = dict(sorted(rows.items(), key=lambda entry: entry[1].get("last_modified") or "",
                       reverse=True)[:MAX_ITEMS])
    if rows == cached:
        return 0
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".tmp")
    try:
        temp.write_text(json.dumps({"items": rows}, ensure_ascii=False), encoding="utf-8")
        os.replace(temp, target)
    finally:
        if temp.exists():
            temp.unlink()
    return sum(rows.get(key) != cached.get(key) for key in rows)


def enrich_events(events, path=CACHE_FILE):
    cached = load_cache(path)
    if not cached:
        return events
    updated = []
    for event in events:
        if event.get("source") != "nvd":
            updated.append(event)
            continue
        cve_id = (event.get("cves") or [""])[0]
        details = cached.get(cve_id)
        if not details or (_time(event.get("source_updated_at")) or datetime.min.replace(
                tzinfo=timezone.utc)) >= (_time(details.get("last_modified")) or datetime.min.replace(
                tzinfo=timezone.utc)):
            updated.append(event)
            continue
        merged = dict(event)
        merged["affected_packages"] = details.get("affected_packages") or []
        merged["references"] = details.get("references") or []
        merged["summary"] = details.get("description") or event.get("summary") or ""
        if details.get("score") is not None:
            merged["score"] = details["score"]
        merged["severity"] = details.get("severity") or event.get("severity") or ""
        merged["source_updated_at"] = details["last_modified"]
        updated.append(merged)
    return updated
