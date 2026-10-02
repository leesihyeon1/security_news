"""Add full-period article category counts to existing dashboard payloads.

This is a local data refresh only. It does not fetch feeds, call a model, send mail,
or publish the dashboard.
"""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

import generate_report


PERIOD_RE = re.compile(r"(\d{4}-\d{2}-\d{2}) 00:00 ~ (\d{4}-\d{2}-\d{2}) 00:00")


def refresh(path, write=False):
    payload = json.loads(path.read_text(encoding="utf-8"))
    match = PERIOD_RE.search(payload.get("period_label") or "")
    if not match:
        raise ValueError("period_label을 해석할 수 없습니다: {}".format(path.name))
    since = datetime.fromisoformat(match.group(1))
    until = datetime.fromisoformat(match.group(2))
    stats = generate_report.build_stats(generate_report.load_events_between(since, until))
    counts = dict(stats["by_category"].most_common())
    payload.setdefault("stats", {})["category_counts"] = counts
    if write:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("files", nargs="+", help="dashboard/data 아래의 명시적 JSON 파일명")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    for name in args.files:
        path = args.repo / "dashboard" / "data" / name
        counts = refresh(path, write=args.write)
        print("{}: {} categories / {} events{}".format(
            name, len(counts), sum(counts.values()), " updated" if args.write else " checked"))
