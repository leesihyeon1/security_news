"""Publish a small, recent reading list for first-party security blogs."""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import common_utils


WINDOW_DAYS = 14
MAX_PER_SOURCE = 12
MIN_PER_SOURCE = 3
OUTPUT_NAME = "featured-sources.json"
RESEARCH_FEEDS = {
    "sans_isc", "talos", "unit42", "checkpoint_research", "thedfirreport",
    "securelist", "google_security", "microsoft_security", "mandiant",
    "crowdstrike", "sentinelone", "welivesecurity", "sophos", "trendmicro",
    "rapid7", "elastic_security", "volexity", "jpcert", "estsecurity_alyac",
    "plainbit", "inca_isarc", "s2w", "genians", "proofpoint",
    "malwarebytes", "nshc_threatrecon",
}


def enabled_labels():
    feeds = json.loads((common_utils.ASSETS_DIR / "feeds.json").read_text(encoding="utf-8"))
    labels = {common_utils.source_label(feed["name"]) for feed in feeds
              if feed["name"] in RESEARCH_FEEDS and feed.get("enabled", True)}
    labels.add(common_utils.source_label("asec"))
    return labels


def build(index, latest, labels, now=None):
    today = (now or datetime.now(timezone.utc)).date()
    cutoff = (today - timedelta(days=WINDOW_DAYS)).isoformat()
    images = {row.get("ref"): row for row in latest.get("items", []) if row.get("ref")}
    groups = defaultdict(list)
    seen = set()
    for row in index:
        label = row.get("source_label")
        ref = row.get("ref")
        if (row.get("type") != "article" or label not in labels or
                row.get("category") == "제품행사" or
                not cutoff <= str(row.get("date") or "") <= today.isoformat() or
                not ref or not row.get("title") or not row.get("url") or
                (label, ref) in seen or len(groups[label]) >= MAX_PER_SOURCE):
            continue
        seen.add((label, ref))
        image = images.get(ref, {})
        image_url = image.get("image_url") or ""
        if "WebShareDefaultImage" in image_url:
            image_url = ""
        groups[label].append({
            "ref": ref, "title": row["title"], "url": row["url"],
            "source_label": label, "category": row.get("category") or "보안 소식",
            "published_at": image.get("published_at") or row["date"],
            "image_url": image_url,
            "source_image": image.get("source_image") or "",
        })
    return {"version": 1, "sources": [
        {"label": label, "items": groups[label]} for label in sorted(groups)
        if len(groups[label]) >= MIN_PER_SOURCE
    ]}


def publish(data_dir, labels=None, now=None, output_path=None):
    data_dir = Path(data_dir)
    index = json.loads((data_dir / "search-index.json").read_text(encoding="utf-8"))
    latest = json.loads((data_dir / "latest-news.json").read_text(encoding="utf-8"))
    payload = build(index, latest, labels if labels is not None else enabled_labels(), now)
    target = Path(output_path) if output_path else data_dir / OUTPUT_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = publish(args.data_dir, output_path=args.output)
    print("{} sources".format(len(result["sources"])))
