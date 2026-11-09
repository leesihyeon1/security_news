"""Publish reviewed incident records and collect private review candidates, offline."""

import argparse
import copy
import hashlib
import json
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import incident_archive_review as review

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "assets" / "incident_archive.json"
CANDIDATES = ROOT / "state" / "incident_archive_candidates.json"
DRAFTS = ROOT / "state" / "incident_archive_drafts.json"
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TRACKING_KEYS = {"fbclid", "gclid", "curPage", "pageIndex", "pWise", "pWiseSub"}
PUBLIC_FIELDS = ("id", "title", "organizations", "sector", "category", "date", "date_basis",
                 "occurred", "discovered_at", "disclosed_at", "summary", "scope_note", "facts",
                 "milestones", "related_ids", "visual", "reviewed_at")
FACT_FIELDS = ("label", "text", "source_ids", "status")
MILESTONE_FIELDS = ("date", "label", "text", "source_ids")


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


def validate_catalog(data):
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
        if row["review_state"] == "published":
            selection = row.get("selection") or {}
            if (not selection.get("rationale") or not selection.get("criteria")
                    or not set(selection["criteria"]) <= set(review.policy()["selection"]["criteria"])
                    or not selection.get("source_ids") or not set(selection["source_ids"]) <= source_ids):
                raise ValueError("Published incident requires reviewed selection evidence: " + row["id"])
        visual = row.get("visual", {})
        if visual and (not re.fullmatch(r"assets/news-fallbacks/[a-z-]+\.webp", visual.get("image", ""))
                       or not visual.get("caption") or not canonical_url(visual.get("credit_url"))):
            raise ValueError("Invalid archive image")
    return data


def load_catalog(path=CATALOG):
    return validate_catalog(json.loads(Path(path).read_text(encoding="utf-8")))


def public_payload(catalog):
    records = [row for row in catalog["incidents"] if row["review_state"] == "published"]
    used = {sid for row in records for fact in row["facts"] + row["milestones"] for sid in fact["source_ids"]}
    public = [{key: row[key] for key in PUBLIC_FIELDS if key in row} for row in records]
    published_ids = {row["id"] for row in public}
    for row in public:
        row["related_ids"] = [key for key in row.get("related_ids", []) if key in published_ids]
        # 검토 메모나 인용 원문이 사실 항목에 남아 있어도 공개 JSON에는 정해진 필드만 싣는다.
        row["facts"] = [{key: fact[key] for key in FACT_FIELDS if key in fact} for fact in row["facts"]]
        row["milestones"] = [{key: item[key] for key in MILESTONE_FIELDS if key in item} for item in row["milestones"]]
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


def candidate(event, catalog):
    url = canonical_url(event.get("url"))
    title = review.clean(event.get("title"))
    if not url or not title:
        return None
    assessment = review.assess(dict(event, url=url), catalog)
    if not assessment:
        return None
    item = {"id": hashlib.sha256(url.encode()).hexdigest()[:20], "url": url, "title": title[:350],
            "summary": review.clean(event.get("summary"))[:2500],
            "published_at": str(event.get("published_at") or ""),
            "source_updated_at": str(event.get("source_updated_at") or ""),
            "source": str(event.get("source") or ""), "event_id": str(event.get("event_id") or event.get("id") or ""),
            "review_state": "pending", "classifier_version": review.CLASSIFIER_VERSION, **assessment}
    item["content_fingerprint"] = review.fingerprint(item)
    return item


def _load_candidates(path):
    return json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {
        "schema_version": 2, "candidates": []}


def _merge_candidate(old, item, now):
    if not old:
        return dict(item, found_at=now)
    old_hash = old.get("content_fingerprint") or review.fingerprint(old)
    changed = old_hash != item["content_fingerprint"]
    if old.get("review_state") in {"accepted", "rejected"}:
        # A correction must not overwrite the version a reviewer approved.
        result = copy.deepcopy(old)
        result["classifier_version"] = review.CLASSIFIER_VERSION
        result["latest_revision"] = item
        result["needs_review"] = changed
        result["changed_fields"] = [key for key in ("title", "summary", "published_at", "source_updated_at")
                                    if old.get(key, "") != item.get(key, "")]
        return result
    result = dict(item, found_at=old.get("found_at", now))
    result["revisions"] = old.get("revisions", [])
    if changed:
        result["revisions"] = result["revisions"] + [{key: old.get(key) for key in (
            "title", "summary", "published_at", "source_updated_at", "content_fingerprint")}]
        result["updated_at"] = now
    elif old.get("updated_at"):
        result["updated_at"] = old["updated_at"]
    return result


def update_candidates(events, catalog, path=CANDIDATES, scan_state=None):
    path = Path(path)
    stored = _load_candidates(path)
    rows = {row["id"]: row for row in stored["candidates"]}
    now = datetime.now(timezone.utc).isoformat()
    # Re-evaluate stale queue entries once when selection rules change.
    for key, old in list(rows.items()):
        if old.get("classifier_version") != review.CLASSIFIER_VERSION:
            current = candidate(old.get("latest_revision") or old, catalog)
            if current:
                rows[key] = _merge_candidate(old, current, now)
            else:
                rows[key] = dict(old, kind="excluded", classifier_version=review.CLASSIFIER_VERSION,
                                 exclusion_reason="현행 기준에서 개별 사고 보도가 아님")
    added = 0
    for event in events:
        item = candidate(event, catalog)
        if item:
            old = rows.get(item["id"])
            rows[item["id"]] = _merge_candidate(old, item, now)
            added += int(old is None)
        else:
            key = hashlib.sha256(canonical_url(event.get("url")).encode()).hexdigest()[:20]
            if key in rows:
                old = rows[key]
                replacement = dict(old, title=review.clean(event.get("title")),
                                   summary=review.clean(event.get("summary"))[:2500], kind="excluded")
                replacement["content_fingerprint"] = review.fingerprint(replacement)
                rows[key] = _merge_candidate(old, replacement, now)
    stored["schema_version"] = 2
    stored["candidates"] = list(rows.values())
    if scan_state is not None:
        stored["scan_state"] = scan_state
    write_json(path, stored)
    return added


def read_event_batch(path, previous=None, max_lines=20000):
    """Resume a byte cursor; replay safely on rotation and defer partial lines."""
    previous = previous or {}
    stat = path.stat()
    offset = previous.get("offset", 0)
    with path.open("rb") as stream:
        head_size = min(previous.get("head_size", 4096), stat.st_size)
        head_hash = hashlib.sha256(stream.read(head_size)).hexdigest()
        stream.seek(max(0, min(offset, stat.st_size) - 64))
        tail_hash = hashlib.sha256(stream.read(min(offset, 64))).hexdigest()
        valid = (previous.get("path") == str(path.resolve()) and previous.get("inode") == stat.st_ino
                 and offset <= stat.st_size and previous.get("head_hash") == head_hash
                 and previous.get("tail_hash") == tail_hash)
        if not valid:
            offset = 0
            stream.seek(0)
            head_size = min(4096, stat.st_size)
            head_hash = hashlib.sha256(stream.read(head_size)).hexdigest()
        stream.seek(offset)
        events = []
        for _ in range(max_lines):
            line = stream.readline(max(0, stat.st_size - stream.tell()))
            if not line or not line.endswith(b"\n"):
                break
            offset = stream.tell()
            try:
                event = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(event, dict):
                events.append(event)
        stream.seek(max(0, offset - 64))
        tail_hash = hashlib.sha256(stream.read(min(offset, 64))).hexdigest()
    return events, {"path": str(path.resolve()), "inode": stat.st_ino, "offset": offset,
                    "head_size": head_size, "head_hash": head_hash, "tail_hash": tail_hash,
                    "has_more": offset < stat.st_size, "size": stat.st_size}


def discover(events_path=None, candidates_path=CANDIDATES, catalog_path=CATALOG,
             drafts_path=None, max_lines=20000, reset=False, max_batches=10):
    path = Path(events_path) if events_path else ROOT / "data" / "events.jsonl"
    if not path.exists():
        return 0
    catalog = load_catalog(catalog_path)
    previous = {} if reset else _load_candidates(candidates_path).get("scan_state", {})
    added = 0
    # 한 번에 끝까지 따라잡는다 — 한 묶음만 읽으면 첫 실행 뒤 며칠 동안 오래된 기사만 보고
    # 최신 기사는 늦게 후보에 오른다. 묶음마다 위치를 저장해 중간에 멈춰도 이어서 읽는다.
    for _ in range(max_batches):
        events, cursor = read_event_batch(path, previous, max_lines=max_lines)
        added += update_candidates(events, catalog, candidates_path, scan_state=cursor)
        if not cursor["has_more"] or cursor["offset"] == previous.get("offset"):
            break
        previous = cursor
    drafts_path = Path(drafts_path) if drafts_path else Path(candidates_path).with_name("incident_archive_drafts.json")
    write_json(drafts_path, review.build_drafts(_load_candidates(candidates_path), catalog))
    return added


def apply_reviewed(path, catalog_path=CATALOG):
    """Import explicit reviewed records, never promote a candidate or draft flag."""
    incoming = json.loads(Path(path).read_text(encoding="utf-8"))
    catalog = load_catalog(catalog_path)
    sources = {source["id"]: source for source in catalog["sources"]}
    incidents = {item["id"]: item for item in catalog["incidents"]}
    for source in incoming.get("sources", []):
        if source["id"] in sources and canonical_url(sources[source["id"]]["url"]) != canonical_url(source["url"]):
            raise ValueError("Source id belongs to a different URL: " + source["id"])
        sources[source["id"]] = source
    for item in incoming.get("incidents", []):
        if item.get("review_state") != "published":
            raise ValueError("Only explicitly reviewed published records may be imported")
        incidents[item["id"]] = item
    catalog["sources"], catalog["incidents"] = list(sources.values()), list(incidents.values())
    validate_catalog(catalog)
    write_json(catalog_path, catalog)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--output", type=Path, help="Directory for the public JSON; does not commit or push")
    parser.add_argument("--discover", action="store_true", help="Collect review candidates from existing events")
    parser.add_argument("--events", type=Path)
    parser.add_argument("--candidates", type=Path, default=CANDIDATES)
    parser.add_argument("--drafts", type=Path, default=DRAFTS, help="Private evidence bundles; never exported to the dashboard")
    parser.add_argument("--backfill", action="store_true", help="Replay all saved events, including historical articles")
    parser.add_argument("--apply-reviewed", type=Path, help="Import reviewed incidents and their sources from a JSON file")
    args = parser.parse_args()
    if args.apply_reviewed:
        apply_reviewed(args.apply_reviewed, args.catalog)
    catalog = load_catalog(args.catalog)
    if args.discover or args.backfill:
        added = discover(args.events, args.candidates, args.catalog, args.drafts, reset=args.backfill,
                         max_batches=1000 if args.backfill else 10)
        print("New review candidates:", added)
        print("Private review drafts:", args.drafts)
    if args.output:
        publish(args.output, args.catalog)
    print("Reviewed incidents:", len(public_payload(catalog)["incidents"]))


if __name__ == "__main__":
    main()
