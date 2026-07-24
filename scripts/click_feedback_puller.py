"""Vercel 클릭 추적 서버(Upstash Redis)에 쌓인 클릭 로그를 피드백 라벨로 가져온다.

리포트/알림의 링크는 (CLICK_TRACK_BASE_URL이 설정돼 있으면) common_utils.tracking_url()을
거쳐 나가는데, 그 추적 서버(vercel-click-tracker/)가 클릭마다 {"ref", "url", "ts"}를
Upstash Redis 리스트("clicks")에 RPUSH로 쌓아둔다. 이 스크립트가 그걸 읽어서(LRANGE)
이벤트로 역매핑하고 useful 라벨을 기록한 "다음에만" 리스트에서 지운다(LTRIM) — 라벨
기록에 실패하면 다음 실행에서 그대로 재시도되어 유실되지 않는다.

클릭 = 실제로 읽고 싶어서 눌렀다는 의미 있는 신호라 useful로만 취급한다(noise는
자동화하지 않음 — 안 누른 것이 "별로였다"는 증거는 아니므로).

이미 라벨(수동/자동 불문)이 있는 이벤트는 건드리지 않는다.

필요 설정(.env):
    UPSTASH_REDIS_REST_URL=...
    UPSTASH_REDIS_REST_TOKEN=...

사용법:
    python scripts/click_feedback_puller.py
    python scripts/click_feedback_puller.py --dry-run
"""

import argparse
import json
import os
import sys

import requests

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

UPSTASH_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "").rstrip("/")
UPSTASH_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
CLICKS_KEY = "clicks"
MAX_PULL = 500  # 한 번 실행에 처리할 최대 클릭 로그 수


def _upstash_command(command):
    if not UPSTASH_REST_URL or not UPSTASH_REST_TOKEN:
        return None
    try:
        resp = requests.post(
            UPSTASH_REST_URL,
            headers={"Authorization": "Bearer {}".format(UPSTASH_REST_TOKEN)},
            json=command,
            timeout=10,
        )
        resp.raise_for_status()
        return (resp.json() or {}).get("result")
    except Exception as error:
        print("[-] Upstash 요청 실패({}): {}".format(command[0] if command else "?", error))
        return None


def peek_click_records(limit=MAX_PULL):
    """클릭 로그를 비파괴적으로 조회(LRANGE) — 처리 완료 후에만 trim_processed()로 제거한다."""
    if not UPSTASH_REST_URL or not UPSTASH_REST_TOKEN:
        print("[-] UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN이 설정되지 않아 건너뜁니다.")
        return []
    raw_items = _upstash_command(["LRANGE", CLICKS_KEY, 0, limit - 1]) or []
    records = []
    for raw in raw_items:
        try:
            records.append(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            continue
    return records


def trim_processed(count):
    """처리 완료된 앞의 count개를 리스트에서 제거. 실패해도 다음 실행에서 중복 처리될 뿐 데이터 유실은 없다."""
    if count <= 0:
        return
    result = _upstash_command(["LTRIM", CLICKS_KEY, count, -1])
    if result is None:
        print("[-] Upstash 정리 실패 — 다음 실행에서 같은 클릭이 다시 보일 수 있습니다(라벨은 중복 기록 안 됨).")


def build_ref_map():
    """이벤트 ref 해시 -> 이벤트 id 매핑. slack_feedback_poller.build_ref_map()과 동일한 목적."""
    ref_map = {}
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("id"):
            ref_map.setdefault(common_utils.event_ref(event["id"]), event["id"])
    return ref_map


def main():
    parser = argparse.ArgumentParser(description="클릭 추적 로그를 피드백 useful 라벨로 가져오기")
    parser.add_argument("--dry-run", action="store_true", help="라벨 저장·리스트 정리 없이 대상만 출력")
    args = parser.parse_args()

    click_records = peek_click_records()
    if not click_records:
        print("[*] 새로 가져올 클릭 로그가 없습니다.")
        return

    ref_map = build_ref_map()
    existing_labels = common_utils.load_feedback()

    records = []
    unmatched = 0
    for click in click_records:
        event_id = ref_map.get(click.get("ref"))
        if not event_id:
            unmatched += 1
            continue
        if event_id in existing_labels:
            continue  # 이미 라벨(수동/자동 불문) 있으면 덮어쓰지 않음
        records.append({
            "event_id": event_id,
            "label": "useful",
            "labeled_at": common_utils.utc_now_iso(),
            "via": "click",
            "evidence": "클릭 추적됨({})".format(click.get("ts") or ""),
        })

    print("[*] 클릭 로그 {}건 중 신규 라벨 {}건 (ref 매칭 안 됨 {}건)".format(
        len(click_records), len(records), unmatched
    ))

    if args.dry_run:
        print("[*] dry-run — 저장·리스트 정리 생략")
        return

    if records:
        common_utils.append_feedback(records)
        print("[+] {}건 자동 라벨링 완료".format(len(records)))

    trim_processed(len(click_records))


if __name__ == "__main__":
    main()
