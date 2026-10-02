"""Read-only evaluation of stored deep analyses; no model or investigation calls."""

import argparse
from collections import Counter
import json
from pathlib import Path
import urllib.request

import analyst_workflow
import article_kind


INSIGHTS_URL = "https://click-tracker-two.vercel.app/api/insights"


ATTACK_OUTPUT_RE = ("차단", "격리", "헌팅", "KQL")


def informational_violations(record):
    """정보성 기사에 공격형 산출물이 붙었는가. 붙었으면 무엇인지."""
    block = record.get("investigation") or {}
    targets = record.get("targets") or {}
    if not (article_kind.is_informational(block) or article_kind.is_informational(targets)):
        return []
    found = []
    if block.get("patterns"):
        found.append("탐지 패턴 {}개".format(len(block["patterns"])))
    response = block.get("response") or {}
    if any(response.get(key) for key in ("kql", "commands", "blocklists")):
        found.append("대응 산출물(KQL·명령·차단목록)")
    if block.get("followup_results") or (block.get("synthesis") or {}).get("followups"):
        found.append("지표 후속 조회")
    verdict = (block.get("synthesis") or {}).get("verdict")
    if verdict and verdict != "정보성 기사":
        found.append("판정값 {}".format(verdict))
    for step in (block.get("synthesis") or {}).get("plan") or []:
        if any(word in str(step.get("action") or "") for word in ATTACK_OUTPUT_RE):
            found.append("공격 대응형 조치: {}".format(str(step.get("action"))[:40]))
    return found


def evaluate(records):
    rows = []
    for record in records:
        block = record.get("investigation") or {}
        quality = analyst_workflow.assessment(block)
        violations = informational_violations(record)
        if violations:
            quality = dict(quality, issues=list(quality.get("issues") or [])
                           + ["정보성 기사에 공격형 산출물: " + v for v in violations])
        rows.append({"ref": record.get("ref"), "title": record.get("title"),
                     "collection_failed": bool(record.get("collection_failed")),
                     "has_synthesis": bool(block.get("synthesis")),
                     "unqualified_material_actions": sum(not p.get("done") for p in block.get("action_plan") or []),
                     **quality})
    return {"scope": "구조·완결성 검사. 사실 정확성·탐지 성능·대응 효과는 별도 검증이 필요합니다.",
            "records": len(rows), "collection_failed": sum(r["collection_failed"] for r in rows),
            "missing_synthesis": sum(not r["has_synthesis"] and not r["collection_failed"] for r in rows),
            "unqualified_material_actions": sum(r["unqualified_material_actions"] for r in rows),
            "unqualified_zero_closures": sum(r["unqualified_zero_closures"] for r in rows),
            "issues": dict(Counter(issue for r in rows for issue in r["issues"])), "items": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path)
    source.add_argument("--live", action="store_true")
    parser.add_argument("--limit", type=int, default=15)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.live:
        with urllib.request.urlopen(INSIGHTS_URL, timeout=30) as response:
            data = json.load(response)
    else:
        data = json.loads(args.input.read_text(encoding="utf-8"))
    records = data.get("insights", []) if isinstance(data, dict) else data
    report = evaluate(records[:max(1, args.limit)])
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "items"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
