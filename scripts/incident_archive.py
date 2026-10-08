"""Publish reviewed incident records and collect private review candidates, offline."""

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "assets" / "incident_archive.json"
CANDIDATES = ROOT / "state" / "incident_archive_candidates.json"
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TRACKING_KEYS = {"fbclid", "gclid", "curPage", "pageIndex", "pWise", "pWiseSub"}
INCIDENT_RE = re.compile(r"침해\s*사고|개인\s*정보\s*유출|고객\s*정보\s*유출|해킹\s*(?:사고|피해)|디도스|DDoS|랜섬웨어\s*(?:공격|감염|피해)|전산망\s*(?:마비|공격)", re.I)
DOMESTIC_RE = re.compile(r"국내|한국|대한민국|금융위원회|개인정보위|과기정통부")
# 사고 보도가 아닌 글 — 칼럼·기고와 주의보는 사고 이름이 들어가도 새 사고가 아니다(실측: 30일
# 후보 14건 중 칼럼 1건, 피싱 주의보 1건이 섞였다).
EXCLUDE_RE = re.compile(r"모의\s*훈련|모의\s*해킹|웨비나|세미나|채용|제품\s*출시|칼럼|기고|論하다|주의보")
PUBLIC_FIELDS = ("id", "title", "organizations", "sector", "category", "date", "date_basis",
                 "occurred", "discovered_at", "disclosed_at", "summary", "scope_note", "facts",
                 "milestones", "related_ids", "visual", "reviewed_at")


def canonical_url(value):
    try:
        parts = urlsplit(str(value or ""))
        if parts.scheme not in {"https", "http"} or not parts.hostname or parts.username or parts.password:
            return ""
        query = [(key, val) for key, val in parse_qsl(parts.query, keep_blank_values=True)
                 if key not in TRACKING_KEYS and not key.startswith("utm_")]
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/",
                           urlencode(sorted(query)), ""))
    except ValueError:
        return ""


def load_catalog(path=CATALOG):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported incident archive schema")
    sources = data.get("sources", [])
    source_ids = {source["id"] for source in sources}
    if len(source_ids) != len(sources):
        raise ValueError("Duplicate source id")
    for source in sources:
        if not canonical_url(source.get("url")) or not source.get("title") or not source.get("publisher"):
            raise ValueError("Invalid source: " + str(source.get("id")))
        date.fromisoformat(source["published_at"])
    records = data.get("incidents", [])
    ids = {row["id"] for row in records}
    if len(ids) != len(records):
        raise ValueError("Duplicate incident id")
    for row in records:
        if not SLUG.fullmatch(row["id"]):
            raise ValueError("Invalid incident id")
        when = date.fromisoformat(row["date"])
        if when.year < data["start_year"]:
            raise ValueError("Incident precedes archive range")
        date.fromisoformat(row["reviewed_at"])
        if row.get("review_state") not in {"published", "draft"}:
            raise ValueError("Missing review state")
        for key in ("title", "summary", "category", "date_basis", "occurred", "scope_note"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError("Missing incident field: " + key)
        if not row.get("facts") or not row.get("milestones"):
            raise ValueError("Incident requires sourced facts and chronology")
        for fact in row["facts"] + row["milestones"]:
            if not fact.get("source_ids") or not set(fact["source_ids"]) <= source_ids:
                raise ValueError("Unknown or absent source for " + row["id"])
            if not fact.get("text") or not fact.get("label"):
                raise ValueError("Empty incident fact")
        if not set(row.get("related_ids", [])) <= ids:
            raise ValueError("Unknown related incident")
        visual = row.get("visual", {})
        if visual and (not re.fullmatch(r"assets/news-fallbacks/[a-z-]+\.webp", visual.get("image", ""))
                       or not visual.get("caption") or not canonical_url(visual.get("credit_url"))):
            raise ValueError("Invalid archive image")
    return data


def public_payload(catalog):
    records = [row for row in catalog["incidents"] if row["review_state"] == "published"]
    used = {sid for row in records for fact in row["facts"] + row["milestones"] for sid in fact["source_ids"]}
    public = [{key: row[key] for key in PUBLIC_FIELDS if key in row} for row in records]
    published_ids = {row["id"] for row in public}
    for row in public:
        row["related_ids"] = [key for key in row.get("related_ids", []) if key in published_ids]
    return {"schema_version": 1, "start_year": catalog["start_year"],
            "end_year": max(date.today().year, max((int(row["date"][:4]) for row in public), default=2000)),
            "reviewed_at": max((row["reviewed_at"] for row in public), default=""),
            "incidents": sorted(public, key=lambda row: (row["date"], row["id"])),
            "sources": [{key: source[key] for key in ("id", "title", "publisher", "url", "published_at", "kind")}
                        for source in catalog["sources"] if source["id"] in used]}


def write_json(path, data):
    """Keep existing data on disk until its replacement is complete."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    fd, tmp = tempfile.mkstemp(prefix=path.stem + "-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return True


def publish(data_dir, catalog_path=CATALOG):
    payload = public_payload(load_catalog(catalog_path))
    write_json(Path(data_dir) / "incident-archive.json", payload)
    return payload


def _normalized(value):
    return re.sub(r"[\W_]+", "", str(value)).casefold()


def candidate(event, catalog):
    url = canonical_url(event.get("url"))
    title = str(event.get("title") or "").strip()
    if not url or not title or EXCLUDE_RE.search(title):
        return None
    known_urls = {canonical_url(source["url"]) for source in catalog["sources"]}
    if url in known_urls:
        return None
    summary = str(event.get("summary") or "")[:2500]
    text = title + " " + summary
    normalized = _normalized(text)
    matches, reasons = [], []
    organization_seen = False
    for record in catalog["incidents"]:
        organization = any(_normalized(name) in normalized for name in record.get("organizations", []) if len(name) >= 3)
        organization_seen = organization_seen or organization
        alias = next((name for name in record.get("aliases", []) if _normalized(name) in normalized), None)
        year = record["date"][:4]
        # An organization name alone cannot identify which of its incidents is discussed.
        if alias or (organization and re.search(r"(?<!\d)" + year + r"\s*년", text) and INCIDENT_RE.search(text)):
            matches.append(record["id"])
            reasons.append("사건명 일치: " + alias if alias else "기관·사고 연도·사고 표현 일치")
    if not matches and not (INCIDENT_RE.search(title) and (DOMESTIC_RE.search(text) or organization_seen)):
        return None
    return {"id": hashlib.sha256(url.encode()).hexdigest()[:20], "url": url, "title": title[:350],
            "summary": summary, "published_at": str(event.get("published_at") or ""),
            "source": str(event.get("source") or ""), "event_id": str(event.get("id") or ""),
            "possible_incident_ids": sorted(set(matches)), "reasons": sorted(set(reasons)) or ["국내 사고 보도 후보"],
            "kind": "followup" if len(matches) == 1 else "ambiguous" if matches else "new_incident",
            "review_state": "pending"}


def update_candidates(events, catalog, path=CANDIDATES):
    path = Path(path)
    stored = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"schema_version": 1, "candidates": []}
    rows = {row["id"]: row for row in stored["candidates"]}
    added = 0
    for event in events:
        item = candidate(event, catalog)
        if item and item["id"] not in rows:
            item["found_at"] = datetime.now(timezone.utc).isoformat()
            rows[item["id"]] = item
            added += 1
    # Preserve review decisions and the version of the article that was actually reviewed.
    stored["candidates"] = list(rows.values())
    write_json(path, stored)
    return added


def recent_events(path, days=30, max_lines=8000):
    from common_utils import iter_lines_reverse
    cutoff = date.today() - timedelta(days=days)
    for number, line in enumerate(iter_lines_reverse(Path(path))):
        if number >= max_lines:
            break
        try:
            event = json.loads(line)
            fetched = date.fromisoformat(str(event.get("fetched_at") or event.get("published_at") or "")[:10])
        except (ValueError, TypeError, AttributeError):
            continue
        if fetched >= cutoff:
            yield event


def discover(events_path=None, candidates_path=CANDIDATES, catalog_path=CATALOG):
    path = Path(events_path) if events_path else ROOT / "data" / "events.jsonl"
    if not path.exists():
        return 0
    return update_candidates(recent_events(path), load_catalog(catalog_path), candidates_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--output", type=Path, help="Directory for the public JSON; does not commit or push")
    parser.add_argument("--discover", action="store_true", help="Collect review candidates from existing events")
    parser.add_argument("--events", type=Path)
    parser.add_argument("--candidates", type=Path, default=CANDIDATES)
    args = parser.parse_args()
    catalog = load_catalog(args.catalog)
    if args.discover:
        print("New review candidates:", discover(args.events, args.candidates, args.catalog))
    if args.output:
        publish(args.output, args.catalog)
    print("Reviewed incidents:", len(public_payload(catalog)["incidents"]))


if __name__ == "__main__":
    main()
