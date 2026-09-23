"""지난 LOOKBACK_DAYS일간 기사 제목·태깅된 개체(위협 행위자·악성코드·제품명)에서
반복되는 것 상위 MAX_ITEMS개를 뽑아 dashboard/data/trending.json으로 발행한다.

daily/weekly 리포트(하루/주 1회)와 달리 "최근 화제 키워드"처럼 훨씬 자주(예:
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
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import common_utils
import publish_web_dashboard as pub
from entity_names import canonical_name, entity_names

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

LOOKBACK_DAYS = 7
MAX_ITEMS = 10
MIN_COUNT = 2  # 1건짜리는 "반복"이 아니라 노이즈에 가까우므로 후보에서 제외
MIN_SOURCE_COUNT = 2  # 한 소스(예: MSRC)가 물량으로 밀어붙인 문구가 여러 소스에서
                       # 다뤄진 것처럼 순위를 오염시키는 걸 막기 위해, 최소 이만큼
                       # 서로 다른 출처에서 나와야 후보로 인정한다.
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

# MSRC/CVE류 취약점 제목에 거의 항상 붙는 "취약점 유형" 상용구 — "X Remote Code
# Execution Vulnerability"/"Y Elevation of Privilege Vulnerability"처럼 서로 다른
# 수십 건의 CVE가 전부 같은 문구를 공유해서, 제목 구 추출 방식으로는 이런 상용구가
# 특정 제품·행위자명보다 훨씬 자주 "반복"돼 순위를 오염시킨다(실측: "Privilege
# Vulnerability"/"Execution Vulnerability" 등이 실제 제품명을 밀어내고 상위권 차지).
# 이 단어들로만 구성된 구는 후보에서 제외한다 — generate_report.py의
# _is_generic_keyword()와 같은 원리.
GENERIC_VULN_WORDS = {
    "remote", "code", "execution", "vulnerability", "vulnerabilities",
    "elevation", "privilege", "privileges", "denial", "service", "of",
    "information", "disclosure", "spoofing", "bypass", "feature", "security",
    "escalation", "injection", "overflow", "corruption", "memory", "arbitrary",
    "critical", "high", "important", "moderate", "low", "multiple", "advisory",
    "update", "patch", "issue", "issues", "flaw", "flaws", "exploit", "exploited",
    "attack", "attacks", "and", "the", "in", "for", "to", "cve",
}


def _is_generic_phrase(phrase):
    tokens = re.findall(r"[a-z0-9]+", phrase.lower())
    return not tokens or all(token in GENERIC_VULN_WORDS for token in tokens)


def _extract_title_phrases(title):
    phrases = []
    for match in TITLE_PHRASE_RE.finditer(title or ""):
        phrase = match.group(0).strip()
        if phrase.lower() in GENERIC_PHRASES or _is_generic_phrase(phrase):
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
            names = entity_names(value)
            candidates.extend(common_utils.normalize_threat_actor(name) if field == "threat_actor" else name
                              for name in names)
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

    출처(source)도 같이 세어, 서로 다른 소스에서 최소 MIN_SOURCE_COUNT개
    이상 언급된 문구만 후보로 남긴다 — 소스가 하나뿐이면 그 소스의 발행
    물량이 많아서 반복된 것일 뿐 실제로 "여러 곳에서 화제"인지 알 수 없다.
    """
    counter = Counter()
    labels = {}
    sources = defaultdict(set)
    for event in events:
        seen = set()
        source = (event.get("source") or "").strip()
        for phrase in _event_candidates(event):
            phrase = canonical_name(phrase)
            key = phrase.casefold()
            if key in seen:
                continue
            seen.add(key)
            labels.setdefault(key, phrase)
            counter[key] += 1
            if source:
                sources[key].add(source)

    ranked = [
        (labels[key], count) for key, count in counter.most_common()
        if count >= MIN_COUNT and len(sources[key]) >= MIN_SOURCE_COUNT
    ]
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


def _same_items(path, items):
    """이미 발행된 순위와 같은가. 파일이 없거나 못 읽으면 다르다고 본다."""
    try:
        with path.open("r", encoding="utf-8") as file:
            previous = json.load(file)
    except (OSError, ValueError):
        return False
    return (previous.get("items") or []) == items


def _load_previous_ranks(trending_path):
    """이전에 발행된 trending.json에서 "문구 → 순위(1부터)"를 읽어온다 — 순위 변동
    표시(▲▼/-/NEW)를 계산하는 기준. 파일이 없거나 형식이 안 맞으면 빈 딕셔너리
    (전부 NEW로 표시됨, 최초 발행 시나 오류 시의 안전한 기본값)."""
    try:
        with trending_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        (item.get("term") or "").lower(): idx + 1
        for idx, item in enumerate(data.get("items") or [])
        if item.get("term")
    }


def _rank_change(term, new_rank, previous_ranks):
    """{"status": "new|same|up|down", "delta": 이동 칸수(없으면 None)}."""
    old_rank = previous_ranks.get(term.lower())
    if old_rank is None:
        return {"status": "new", "delta": None}
    delta = old_rank - new_rank
    if delta == 0:
        return {"status": "same", "delta": 0}
    return {"status": "up" if delta > 0 else "down", "delta": abs(delta)}


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

                    # 순위 변동(▲▼/-/NEW)은 지금 원격에 있는(=방금 동기화한) 이전
                    # trending.json을 기준으로 계산한다 — 재시도로 다시 동기화되면
                    # 그때의 최신 이전 상태로 다시 계산되므로 항상 정확하다.
                    previous_ranks = _load_previous_ranks(trending_path)
                    payload = {
                        "generated_at": datetime.utcnow().isoformat() + "Z",
                        "items": [
                            dict({"term": term, "count": count}, **_rank_change(term, idx + 1, previous_ranks))
                            for idx, (term, count) in enumerate(ranked)
                        ],
                    }

                    # 순위가 그대로면 파일을 건드리지 않는다.
                    #
                    # 아래 "변경사항 없음" 검사는 원래 이걸 막으려고 둔 것인데,
                    # generated_at이 매 회차 바뀌니 git에는 늘 변경으로 보여서 한 번도
                    # 걸리지 않았다. 실측(5일, 240회): 순위가 실제로 바뀐 것은 107회고
                    # 나머지 133회는 시각만 바뀐 커밋이었다. 그 커밋 하나하나가 Vercel
                    # 배포를 두 개씩(dashboard·click-tracker) 띄운다.
                    if _same_items(trending_path, payload["items"]):
                        print("[*] 트렌딩 순위 그대로 — 발행 생략")
                        return

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
