"""Read-only, offline checks for dashboard data. No LLM or network calls."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

HEADERS = ("총평", "핵심 위협 TOP 3", "권고 조치")
PLACEHOLDERS = ("한국어 요약을 준비하지 못했습니다", "AI 해석을 생성하지 못해")


def check_narrative(text):
    errors = []
    if not isinstance(text, str):
        return ["narrative must be text"]
    markers = list(re.finditer(r"(?m)^\s*\[([^\]\n]+)\][ \t]*", text))
    if tuple(match.group(1) for match in markers) != HEADERS:
        return ["narrative requires the three original sections in order"]
    sizes = []
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        body = text[marker.end():end].strip()
        if len(re.findall(r"[가-힣]", body)) < 4 or any(value in body for value in PLACEHOLDERS):
            errors.append("section {} has no usable Korean summary".format(index + 1))
        for sentence in re.split(r"(?<=[.!?])\s+|\n", body):
            if not re.search(r"[가-힣]", sentence) and len(re.findall(r"[A-Za-z]{2,}", sentence)) >= 6:
                errors.append("section {} contains English prose".format(index + 1))
                break
        if index:
            numbers = re.findall(r"(?m)^\s*(\d+)[.)]\s+(.+)$", body)
            sizes.append(len(numbers))
            if not 1 <= len(numbers) <= 3 or [int(n) for n, _ in numbers] != list(range(1, len(numbers) + 1)):
                errors.append("section {} needs 1-3 consecutive numbered items".format(index + 1))
    if len(sizes) == 2 and sizes[0] != sizes[1]:
        errors.append("threat and action counts differ")
    if re.search(r"자사|당사|자산\s*매칭|\bPIR\b", text, re.I):
        errors.append("narrative contains private-context markers; review required")
    return errors


def parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def check_report(payload):
    if not isinstance(payload, dict):
        return ["report must be an object"]
    errors = check_narrative(payload.get("narrative"))
    stats = payload.get("stats") or {}
    values = [stats.get(key) for key in ("total", "p1", "p2", "info", "actionable")]
    if not all(type(value) is int and value >= 0 for value in values):
        errors.append("stats require nonnegative integer counts")
    elif values[0] != sum(values[1:4]) or values[4] > values[0]:
        errors.append("priority totals or actionable total are inconsistent")
    categories = stats.get("actionable_by_category")
    if not isinstance(categories, dict) or not all(type(v) is int and v >= 0 for v in categories.values()):
        errors.append("actionable category counts are missing or invalid")
    elif sum(categories.values()) != stats.get("actionable"):
        errors.append("actionable category sum does not match total")
    status = payload.get("data_status") or {}
    try:
        start, end = (parse_time(status[key]) for key in ("period_start", "period_end"))
        generated = parse_time(payload["generated_at"])
        if start >= end or generated < end:
            errors.append("report period or generation time is inconsistent")
        collected = status.get("latest_collected_at")
        if collected and not start <= parse_time(collected) < end:
            errors.append("latest collected time is outside the report period")
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append("report period/generation timestamps are missing or invalid")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2] / "boannews_vercel_deploy")
    args = parser.parse_args()
    failed = False
    for name in ("daily-latest.json", "weekly-latest.json"):
        try:
            payload = json.loads((args.repo / "dashboard/data" / name).read_text(encoding="utf-8"))
            errors = check_report(payload)
        except (OSError, ValueError) as error:
            errors = ["cannot read report: " + type(error).__name__]
        failed |= bool(errors)
        print("{}: {}".format(name, "FAIL" if errors else "PASS"))
        for error in errors:
            print("  " + error)
    print("Offline checks only; factual grounding and live UI need separate review.")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
