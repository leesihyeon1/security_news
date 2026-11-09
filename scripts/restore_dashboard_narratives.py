"""Restore historical AI narrative format from a pre-migration Git revision."""

import argparse
import json
import subprocess

from dashboard_text import public_narrative, is_korean_text
from publish_web_dashboard import _rebuild_search_index_from_events


def restore(repo, revision):
    count = 0
    for path in (repo / "dashboard/data").glob("*.json"):
        if not path.name.startswith(("daily-", "weekly-")):
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        result = subprocess.run(["git", "-C", str(repo), "show", revision + ":dashboard/data/" + path.name],
                                capture_output=True, encoding="utf-8", check=True)
        original = json.loads(result.stdout)
        payload["narrative"] = public_narrative(original.get("narrative") or "")
        payload["narrative_basis"] = "AI 분석 · 출처와 수집 시각은 각 카드 참조"

        def clean_summaries(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "summary" and isinstance(child, str) and not is_korean_text(child):
                        value[key] = "한국어 요약 미제공 · 원문 확인"
                    else:
                        clean_summaries(child)
            elif isinstance(value, list):
                for child in value:
                    clean_summaries(child)

        clean_summaries(payload)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        count += 1
    _rebuild_search_index_from_events(repo)
    print("Updated {} local reports; no publishing.".format(count))


if __name__ == "__main__":
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("revision")
    args = parser.parse_args()
    restore(args.repo, args.revision)
