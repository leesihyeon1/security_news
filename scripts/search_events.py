"""수집된 이벤트 로그(data/events.jsonl)에서 특정 CVE·공격그룹·자산·키워드의 과거 이력을 조회한다.

일간/주간 리포트는 그 기간의 스냅샷만 보여주므로 "이 위협이 처음 보는 건지,
반복되는 패턴인지"를 되짚어볼 방법이 없었다. 이 스크립트는 누적된 이벤트 로그를
그대로 훑어 필터링하고, 기간별 건수 추이를 함께 보여준다.

사용법:
    python scripts/search_events.py --actor Lazarus --since 90d
    python scripts/search_events.py --cve CVE-2026-25089
    python scripts/search_events.py --asset Fortinet --level P1 --since 6m
    python scripts/search_events.py --keyword ransomware --category 공격캠페인 --since 1y
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import common_utils
from generate_report import (
    LEGACY_BOANNEWS_EVENTS_FILE,
    normalize_legacy_boannews,
    parse_iso,
    source_label,
    event_level,
)

# Windows 콘솔(cp949)에서 특수문자 출력이 죽지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


SINCE_RE = re.compile(r"^(\d+)([dwmy])$")
_DAYS_PER_UNIT = {"d": 1, "w": 7, "m": 30, "y": 365}


def parse_relative_or_date(value):
    """'90d'/'12w'/'6m'/'1y' 같은 상대 기간 또는 'YYYY-MM-DD' 절대 날짜를 datetime으로 변환."""
    match = SINCE_RE.match(value.strip().lower())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        return datetime.utcnow() - timedelta(days=_DAYS_PER_UNIT[unit] * amount)
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(
            "'{}' — '90d'/'12w'/'6m'/'1y' 형식이거나 'YYYY-MM-DD' 형식이어야 합니다.".format(value)
        )


def load_all_events(events_file=None, legacy_file=None, include_legacy=True):
    """통합 이벤트 로그와 구 보안뉴스 로그를 함께 읽고 (source, url) 기준으로 중복 제거 — generate_report.load_events와 동일 규칙."""
    events = {}
    sources = [(events_file or common_utils.EVENTS_FILE, False)]
    if include_legacy:
        sources.append((legacy_file or LEGACY_BOANNEWS_EVENTS_FILE, True))
    for path, legacy in sources:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = normalize_legacy_boannews(raw) if legacy else raw
                key = "{}|{}".format(event.get("source"), event.get("url") or event.get("id"))
                events.setdefault(key, event)
    return list(events.values())


def event_timestamp(event):
    """정렬·기간 필터 기준 시각 — 발행일이 있으면 우선, 없으면 수집 시각."""
    return parse_iso(event.get("published_at")) or parse_iso(event.get("fetched_at"))


def matches(event, args):
    if args.actor and args.actor.lower() not in (event.get("threat_actor") or "").lower():
        return False
    if args.malware and args.malware.lower() not in (event.get("malware_family") or "").lower():
        return False
    if args.cve and args.cve.upper() not in [c.upper() for c in (event.get("cves") or [])]:
        return False
    if args.source and args.source.lower() != (event.get("source") or "").lower():
        return False
    if args.category and args.category != (event.get("category") or ""):
        return False
    if args.pir and args.pir.upper() not in [p.upper() for p in (event.get("pirs") or [])]:
        return False
    if args.asset and not any(
        args.asset.lower() in asset.lower() for asset in (event.get("matched_assets") or [])
    ):
        return False
    if args.level and event_level(event) != args.level.upper():
        return False
    if args.keyword:
        haystack = " ".join(
            filter(None, [event.get("title"), event.get("summary"), event.get("ai_summary")])
        ).lower()
        if args.keyword.lower() not in haystack:
            return False

    timestamp = event_timestamp(event)
    if args.since and (timestamp is None or timestamp < args.since):
        return False
    if args.until and (timestamp is None or timestamp > args.until):
        return False
    return True


def bucket_label(timestamp, fine_grained):
    if fine_grained:
        iso_year, iso_week, _ = timestamp.isocalendar()
        return "{}-W{:02d}".format(iso_year, iso_week)
    return timestamp.strftime("%Y-%m")


def print_trend(matched, since):
    """기간별 건수 추이 — 90일 이하로 좁혀 조회했으면 주 단위, 아니면 월 단위로 묶는다."""
    timestamps = [event_timestamp(event) for event in matched]
    timestamps = [ts for ts in timestamps if ts is not None]
    if not timestamps:
        return

    span_days = (max(timestamps) - min(timestamps)).days
    fine_grained = span_days <= 90
    buckets = {}
    for ts in timestamps:
        key = bucket_label(ts, fine_grained)
        buckets[key] = buckets.get(key, 0) + 1

    print()
    print("[추이 — {} 단위]".format("주" if fine_grained else "월"))
    for key in sorted(buckets):
        print("  {}: {}".format(key, "#" * min(buckets[key], 50) + " ({}건)".format(buckets[key])))


def main():
    parser = argparse.ArgumentParser(
        description="이벤트 로그 이력 조회 — 특정 CVE·공격그룹·자산이 과거에 얼마나 나왔는지 되짚어본다.",
    )
    parser.add_argument("--actor", help="공격 그룹명 부분 일치 (예: Lazarus)")
    parser.add_argument("--malware", help="악성코드 계열명 부분 일치")
    parser.add_argument("--cve", help="CVE ID (예: CVE-2026-25089)")
    parser.add_argument("--source", help="소스 ID (예: boannews, nvd, talos)")
    parser.add_argument("--category", help="카테고리 (예: 공격캠페인)")
    parser.add_argument("--pir", help="PIR ID (예: PIR-6)")
    parser.add_argument("--asset", help="매칭 자산명 부분 일치 (예: Fortinet)")
    parser.add_argument("--level", choices=["P1", "P2", "P3"], help="트리아지 레벨")
    parser.add_argument("--keyword", help="제목/요약 키워드 부분 일치")
    parser.add_argument("--since", type=parse_relative_or_date, help="'90d'/'12w'/'6m'/'1y' 또는 'YYYY-MM-DD'")
    parser.add_argument("--until", type=parse_relative_or_date, help="'90d'/'12w'/'6m'/'1y' 또는 'YYYY-MM-DD'")
    parser.add_argument("--limit", type=int, default=50, help="출력할 최대 건수 (기본 50, 추이 집계는 전체 대상)")
    parser.add_argument("--events-file", type=str, help="테스트용 — events.jsonl 경로 오버라이드")
    parser.add_argument("--legacy-events-file", type=str, help="테스트용 — 구 스키마 로그 경로 오버라이드")
    args = parser.parse_args()

    if not any([args.actor, args.malware, args.cve, args.source, args.category,
                args.pir, args.asset, args.level, args.keyword]):
        parser.error("필터를 최소 하나는 지정해야 합니다 (--actor/--cve/--asset/--keyword 등).")

    events_file = Path(args.events_file) if args.events_file else None
    legacy_file = Path(args.legacy_events_file) if args.legacy_events_file else None
    include_legacy = not args.events_file or bool(args.legacy_events_file)
    events = load_all_events(events_file=events_file, legacy_file=legacy_file, include_legacy=include_legacy)
    matched = sorted(
        (event for event in events if matches(event, args)),
        key=lambda event: event_timestamp(event) or datetime.min,
    )

    if not matched:
        print("조건에 맞는 이벤트가 없습니다.")
        return

    print("총 {}건 매칭".format(len(matched)))
    first_ts, last_ts = event_timestamp(matched[0]), event_timestamp(matched[-1])
    if first_ts and last_ts:
        print("최초: {} · 최근: {}".format(first_ts.strftime("%Y-%m-%d"), last_ts.strftime("%Y-%m-%d")))
    print()

    shown = matched[-args.limit:] if args.limit else matched
    if len(matched) > len(shown):
        print("(최근 {}건만 표시 — 전체 {}건, --limit으로 조정)".format(len(shown), len(matched)))
        print()
    for event in shown:
        ts = event_timestamp(event)
        date_str = ts.strftime("%Y-%m-%d") if ts else "????-??-??"
        level = event_level(event)
        level_tag = "[{}] ".format(level) if level in ("P1", "P2") else ""
        print("{} {}[{}] {}".format(date_str, level_tag, source_label(event.get("source")), event.get("title")))
        print("  {}".format(event.get("url") or ""))

    print_trend(matched, args.since)


if __name__ == "__main__":
    main()
