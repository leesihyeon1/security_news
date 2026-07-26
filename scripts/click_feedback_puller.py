"""Vercel 클릭 추적 서버(Redis)에 쌓인 클릭 로그를 피드백 라벨로 가져온다.

리포트/알림의 링크는 (CLICK_TRACK_BASE_URL이 설정돼 있으면) common_utils.tracking_url()을
거쳐 나가는데, 그 추적 서버(boannews_vercel/click-tracker/)가 클릭마다 {"ref", "url", "ts"}를
Redis 리스트("clicks")에 RPUSH로 쌓아둔다. 이 스크립트가 그걸 읽어서(LRANGE) 이벤트로
역매핑하고 useful 라벨을 기록한 "다음에만" 리스트에서 지운다(LTRIM) — 라벨 기록에 실패하면
다음 실행에서 그대로 재시도되어 유실되지 않는다.

클릭 = 실제로 읽고 싶어서 눌렀다는 의미 있는 신호라 useful로만 취급한다(noise는
자동화하지 않음 — 안 누른 것이 "별로였다"는 증거는 아니므로).

이미 라벨(수동/자동 불문)이 있는 이벤트는 건드리지 않는다.

필요 설정(.env):
    REDIS_URL=redis://default:<password>@<host>:<port>   (Vercel Storage에서 발급)

사용법:
    python scripts/click_feedback_puller.py
    python scripts/click_feedback_puller.py --dry-run
"""

import argparse
import json
import os
import sys
from datetime import datetime

import redis

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

REDIS_URL = os.environ.get("REDIS_URL", "")
CLICKS_KEY = "clicks"
MAX_PULL = 500  # 한 번 실행에 처리할 최대 클릭 로그 수
RECENT_LINES = 5000  # ref_map 구축 시 훑을 최대 줄 수 — slack_feedback_poller.py와 동일한 제한
BURST_WINDOW_SECONDS = 2  # 이 시간 창 안에 BURST_MIN_COUNT건 이상 몰리면 자동 스캔으로 간주
BURST_MIN_COUNT = 3


def _connect():
    if not REDIS_URL:
        return None
    try:
        client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=10, socket_timeout=10)
        client.ping()
        return client
    except Exception as error:
        print("[-] Redis 연결 실패: {}".format(error))
        return None


def peek_click_records(client, limit=MAX_PULL):
    """클릭 로그를 비파괴적으로 조회(LRANGE) — 처리 완료 후에만 trim_processed()로 제거한다."""
    if client is None:
        print("[-] REDIS_URL이 설정되지 않았거나 연결할 수 없어 건너뜁니다.")
        return []
    try:
        raw_items = client.lrange(CLICKS_KEY, 0, limit - 1)
    except Exception as error:
        print("[-] Redis 조회 실패: {}".format(error))
        return []
    records = []
    for raw in raw_items:
        try:
            records.append(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            continue
    return records


def trim_processed(client, count):
    """처리 완료된 앞의 count개를 리스트에서 제거. 실패해도 다음 실행에서 중복 처리될 뿐 데이터 유실은 없다."""
    if client is None or count <= 0:
        return
    try:
        client.ltrim(CLICKS_KEY, count, -1)
    except Exception as error:
        print("[-] Redis 정리 실패 — 다음 실행에서 같은 클릭이 다시 보일 수 있습니다(라벨은 중복 기록 안 됨): {}".format(error))


def _parse_ts(value):
    try:
        return datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except ValueError:
        return None


def filter_burst_clicks(click_records):
    """메일/리포트 속 링크 여러 개를 몇 초 안에 한꺼번에 훑는 자동 스캔 패턴을 걸러낸다.

    사람은 기사 하나를 읽고 다음 걸 누르기까지 자연스러운 간격이 있는데, 사전스캔
    봇이나 보안 스캐너는 링크를 순식간에 연달아 방문한다(User-Agent를 브라우저처럼
    위장해도 이 타이밍 패턴까진 못 숨김). 짧은 시간 창 안에 BURST_MIN_COUNT건 이상
    몰려 찍히면 그 구간의 클릭은 라벨링 대상에서만 제외한다(Redis 정리는 그대로 진행).
    """
    parsed = [(_parse_ts(record.get("ts")), record) for record in click_records]
    dated = sorted((pair for pair in parsed if pair[0] is not None), key=lambda pair: pair[0])

    suspicious_ids = set()
    window = []
    for ts, record in dated:
        window = [(t, r) for t, r in window if (ts - t).total_seconds() <= BURST_WINDOW_SECONDS]
        window.append((ts, record))
        if len(window) >= BURST_MIN_COUNT:
            suspicious_ids.update(id(r) for _, r in window)

    if suspicious_ids:
        print("[*] 짧은 시간에 몰려온 클릭 {}건을 자동 스캔으로 간주해 라벨링에서 제외합니다.".format(
            len(suspicious_ids)
        ))

    return [record for record in click_records if id(record) not in suspicious_ids]


def build_ref_map():
    """이벤트 ref 해시 -> 이벤트 id 매핑. slack_feedback_poller.build_ref_map()과 동일한 목적.

    파일 끝에서부터 거슬러 읽어 RECENT_LINES줄만 훑는다 — 로그 전체 크기와
    무관하게 읽는 양이 고정된다.
    """
    ref_map = {}
    count = 0
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        count += 1
        if count > RECENT_LINES:
            break
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

    client = _connect()
    raw_records = peek_click_records(client)
    if not raw_records:
        print("[*] 새로 가져올 클릭 로그가 없습니다.")
        return

    click_records = filter_burst_clicks(raw_records)

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

    print("[*] 클릭 로그 {}건 중 신규 라벨 {}건 (ref 매칭 안 됨 {}건, 자동 스캔 제외 {}건)".format(
        len(raw_records), len(records), unmatched, len(raw_records) - len(click_records)
    ))

    if args.dry_run:
        print("[*] dry-run — 저장·리스트 정리 생략")
        return

    if records:
        common_utils.append_feedback(records)
        print("[+] {}건 자동 라벨링 완료".format(len(records)))

    trim_processed(client, len(raw_records))


if __name__ == "__main__":
    main()
