"""지난 LOOKBACK_DAYS일간 기사 제목·태깅된 개체(위협 행위자·악성코드·제품명)에서
반복되는 것 상위 MAX_ITEMS개를 뽑아 dashboard/data/trending.json으로 발행한다.

daily/weekly 리포트(하루/주 1회)와 달리 "실시간 인기 검색어"처럼 훨씬 자주(예:
30분마다) 갱신하는 게 목적이라 별도 스크립트로 분리했다 — generate_report.py의
무거운 리포트 생성 로직 없이, events.jsonl만 다시 훑어서 가볍게 계산한다.
publish_web_dashboard.py의 git 발행 헬퍼(동기화·커밋·재시도)를 그대로 재사용한다.

스케줄링은 이 저장소 밖(예: 이 스크립트를 돌리는 PC의 작업 스케줄러)에서
30분 주기로 등록해야 한다 — 순위가 실제로 안 바뀌면 커밋을 안 하므로(publish_
web_dashboard.py와 같은 방식), 자주 실행해도 git/Vercel 부담은 순위가 바뀐
횟수만큼만 발생한다.

필요 설정: publish_web_dashboard.py와 동일한 WEB_DASHBOARD_REPO_PATH(.env)
"""

import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import common_utils
import publish_web_dashboard as pub

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

LOOKBACK_DAYS = 7
MAX_ITEMS = 5
MIN_COUNT = 2  # 1건짜리는 "반복"이 아니라 노이즈에 가까우므로 후보에서 제외
TRENDING_FILE = "trending.json"

# 영문 제목에서 연속된 Title-Case 단어(2~4개)를 고유명사 구로 본다 — 한국어는
# 대소문자 구분이 없어 같은 방식으로 못 뽑으므로, 한국어권 기사는 아래 태깅된
# 개체(threat_actor 등)로 보완한다.
TITLE_PHRASE_RE = re.compile(r"\b[A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+){1,3}\b")

# 특정 주제를 안 가리키는 흔한 구 — 필요시 계속 추가.
GENERIC_PHRASES = {
    "zero day", "new york", "united states", "black hat", "def con",
    "read more", "click here",
}


def _extract_title_phrases(title):
    phrases = []
    for match in TITLE_PHRASE_RE.finditer(title or ""):
        phrase = match.group(0).strip()
        if phrase.lower() in GENERIC_PHRASES:
            continue
        phrases.append(phrase)
    return phrases


def _event_candidates(event):
    """한 이벤트에서 랭킹 후보 문구를 뽑는다 — 제목의 고유명사 구 + 이미 태깅된
    위협 행위자·악성코드·영향받는 제품명."""
    candidates = list(_extract_title_phrases(event.get("title") or ""))
    for field in ("threat_actor", "malware_family"):
        value = (event.get(field) or "").strip()
        if value:
            candidates.append(value)
    for product in event.get("affected_products") or []:
        product = (product or "").strip()
        if product:
            candidates.append(product)
    return candidates


def build_trending(events):
    """이벤트 목록에서 (문구, 등장 건수) 상위 MAX_ITEMS개를 반환한다.

    같은 이벤트 안에서 같은 문구가 여러 번 나와도 1건으로만 센다(예: 위협
    행위자명이 제목과 threat_actor 필드에 둘 다 있는 경우) — 실제로 몇 개
    "기사"에 걸쳐 반복됐는지를 보는 게 목적이라서다.
    """
    counter = Counter()
    for event in events:
        seen = set()
        for phrase in _event_candidates(event):
            key = phrase.lower()
            if key in seen:
                continue
            seen.add(key)
            counter[phrase] += 1

    ranked = [(term, count) for term, count in counter.most_common() if count >= MIN_COUNT]
    return ranked[:MAX_ITEMS]


def load_recent_events(lookback_days=LOOKBACK_DAYS):
    cutoff = (datetime.utcnow() - timedelta(days=lookback_days)).isoformat()
    events = []
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        fetched_at = event.get("fetched_at") or ""
        if fetched_at < cutoff:
            break
        events.append(event)
    return events


def main():
    repo_path = os.environ.get("WEB_DASHBOARD_REPO_PATH", "")
    if not repo_path:
        print("[*] WEB_DASHBOARD_REPO_PATH가 설정되지 않아 트렌딩 발행을 건너뜁니다.")
        return
    repo = Path(repo_path)
    if not repo.exists():
        print("[-] WEB_DASHBOARD_REPO_PATH 경로가 없습니다: {}".format(repo))
        return
    if not pub._validate_publish_repo(repo):
        return

    events = load_recent_events()
    ranked = build_trending(events)
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "items": [{"term": term, "count": count} for term, count in ranked],
    }

    trending_relpath = "dashboard/data/" + TRENDING_FILE
    trending_path = repo / trending_relpath

    # generate_report.py의 일간/주간 발행과 같은 로컬 클론에 git 작업을 하므로,
    # 같은 잠금(repo_lock)을 써서 두 발행이 겹치는 걸 막는다 — 이 스크립트가
    # 30분마다 도는 동안 하필 일간/주간 리포트 발행과 타이밍이 겹치면 서로
    # push를 거부당하는 동기화 문제가 생길 수 있다.
    try:
        with pub.repo_lock(repo):
            last_error = None
            for attempt in range(1, pub.PUBLISH_RETRIES + 1):
                try:
                    branch = pub._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).strip()
                    pub._sync_to_remote_head(repo, branch)

                    trending_path.parent.mkdir(parents=True, exist_ok=True)
                    with trending_path.open("w", encoding="utf-8") as file:
                        json.dump(payload, file, ensure_ascii=False, indent=2)

                    pub._run_git(["add", trending_relpath], cwd=repo)
                    if not pub._has_staged_changes(trending_relpath, cwd=repo):
                        print("[*] 트렌딩 변경사항 없음 — 커밋 생략")
                        return

                    pub._run_git(["commit", "-m", "Update trending titles"], cwd=repo)
                    pub._run_git(["push", "origin", branch], cwd=repo)
                    print("[+] trending.json 발행 완료: {}".format([term for term, _ in ranked]))
                    return
                except Exception as error:
                    last_error = error
                    if attempt < pub.PUBLISH_RETRIES:
                        print("[-] 트렌딩 발행 시도 {}/{} 실패({}) — {}초 대기 후 재시도".format(
                            attempt, pub.PUBLISH_RETRIES, error, pub.PUBLISH_RETRY_DELAY_SECONDS
                        ))
                        time.sleep(pub.PUBLISH_RETRY_DELAY_SECONDS)

            print("[-] 트렌딩 발행 실패(무시하고 계속): {}".format(last_error))
    except Exception as error:
        print("[-] 트렌딩 발행 실패(잠금 획득 불가, 무시하고 계속): {}".format(error))


if __name__ == "__main__":
    main()
