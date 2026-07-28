"""Vercel 대시보드 검색창에서 입력한 검색어를 Redis에서 읽어와 로컬 로그에 누적한다.

대시보드(boannews_vercel/dashboard/)는 정적 사이트라 자체 서버가 없어서, 검색 이벤트는
click-tracker Vercel 프로젝트의 api/search-log.js가 (click.js와 동일한 REDIS_URL로) 같은
Redis에 쌓아둔다. 이 스크립트가 그걸 읽어서(LRANGE) data/search_log.jsonl에 추가하고,
처리한 만큼 Redis에서 지운다(LTRIM) — 저장에 실패해도 다음 실행에서 그대로 재시도되어
유실되지 않는다.

활용: 자주 검색되는 키워드로 관심사·자산 인벤토리 갱신 필요성을 파악하거나, 결과 0건인
검색어로 수집 공백이나 검색 로직(다중 키워드 AND 매칭) 개선 지점을 찾는다.

필요 설정(.env):
    REDIS_URL=redis://default:<password>@<host>:<port>   (click_feedback_puller.py와 동일한 값)

사용법:
    python scripts/search_log_puller.py
    python scripts/search_log_puller.py --dry-run
"""

import argparse
import json
import os
import sys

import redis

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

REDIS_URL = os.environ.get("REDIS_URL", "")
SEARCH_LOG_KEY = "search_log"
MAX_PULL = 500  # 한 번 실행에 처리할 최대 로그 수
SEARCH_LOG_FILE = common_utils.SEARCH_LOG_FILE


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


def peek_search_log(client, limit=MAX_PULL):
    """검색 로그를 비파괴적으로 조회(LRANGE) — 저장 완료 후에만 trim_processed()로 제거한다."""
    if client is None:
        print("[-] REDIS_URL이 설정되지 않았거나 연결할 수 없어 건너뜁니다.")
        return []
    try:
        raw_items = client.lrange(SEARCH_LOG_KEY, 0, limit - 1)
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
        client.ltrim(SEARCH_LOG_KEY, count, -1)
    except Exception as error:
        print("[-] Redis 정리 실패 — 다음 실행에서 같은 검색 기록이 다시 보일 수 있습니다: {}".format(error))


def main():
    parser = argparse.ArgumentParser(description="대시보드 검색어 로그를 로컬 파일로 가져오기")
    parser.add_argument("--dry-run", action="store_true", help="저장·리스트 정리 없이 개수만 출력")
    args = parser.parse_args()

    client = _connect()
    records = peek_search_log(client)
    if not records:
        print("[*] 새로 가져올 검색 로그가 없습니다.")
        return

    zero_result = sum(1 for record in records if record.get("result_count") == 0)
    print("[*] 검색 로그 {}건 (결과 없음 {}건)".format(len(records), zero_result))

    if args.dry_run:
        print("[*] dry-run — 저장·리스트 정리 생략")
        return

    SEARCH_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SEARCH_LOG_FILE.open("a", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    trim_processed(client, len(records))
    print("[+] {}건 저장 완료 -> {}".format(len(records), SEARCH_LOG_FILE))


if __name__ == "__main__":
    main()
