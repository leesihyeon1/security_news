"""Regenerate only the public Korean narratives of the latest local reports."""

import argparse
import json
from pathlib import Path

from generate_report import ai_public_narrative


def refresh(repo):
    # Prepare both reports before writing so a failed generation keeps the old pair.
    outputs = []
    for period in ("daily", "weekly"):
        path = repo / "dashboard/data" / (period + "-latest.json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["narrative"] = ai_public_narrative(payload["period_label"], payload["stats"], payload["cards"])
        payload["narrative_basis"] = "AI 분석 · 출처와 수집 시각은 각 카드 참조"
        outputs.append((path, payload))
        print(period + " Korean narrative validated", flush=True)
    for path, payload in outputs:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    refresh(parser.parse_args().repo)
