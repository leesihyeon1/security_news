# -*- coding: utf-8 -*-
"""보안 연구 자료를 웹에서 검색한다(Google Programmable Search).

왜 사이트를 지정하는가
    Google이 "전체 웹 검색" 옵션을 지원 중단해서 새로 만드는 검색엔진은 지정한
    사이트만 본다. 이 파이프라인에는 그게 오히려 맞다 — 필요한 것은 아무 웹 검색이
    아니라 벤더 연구팀·정부 기관·샌드박스의 1차 자료다. 사이트를 좁히면 뉴스 재게시와
    요약 블로그가 안 걸려서, 이미 읽은 기사를 또 읽는 낭비가 없다.

    검색 결과가 전부 1차 자료라는 점이 primary_sources와 그대로 맞물린다 — 찾은
    링크를 바로 원문으로 읽는다.

한도를 세는 이유
    무료 한도가 하루 100건이고 넘으면 과금된다. 기사당 2회씩 하루 100건을 분석하면
    200회가 되어 한도의 두 배다. 세지 않으면 어느 날 조용히 과금되거나 조용히
    실패한다. 그래서 파일로 날짜별 사용량을 세고, 한도에 닿으면 검색을 건너뛰되
    "한도 소진으로 생략"을 조사 과정에 남긴다.

키가 없으면
    아무 일도 하지 않고 None을 돌려준다. 키 없이 돌아가는 나머지 조회는 그대로 된다.
"""

import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import common_utils

API_URL = ("https://www.googleapis.com/customsearch/v1"
           "?key={}&cx={}&q={}&num={}")
USAGE_FILE = common_utils.DATA_DIR / "cse_usage.json"

# 하루 무료 한도가 100건이다. 90에서 멈춰 손으로 확인할 여유를 남긴다.
DEFAULT_DAILY_CAP = 90
# 기사 하나에 쓰는 검색 횟수. 늘리면 한도가 빨리 마른다.
MAX_QUERIES_PER_ARTICLE = 2
MAX_RESULTS = 5
REQUEST_TIMEOUT = 20
PAUSE_SECONDS = 1.0
# 검색어가 짧으면 무관한 결과가 쏟아진다.
MIN_TERM_CHARS = 5


def log(message):
    print(message)


def available():
    return bool(os.environ.get("GOOGLE_CSE_KEY") and os.environ.get("GOOGLE_CSE_CX"))


def daily_cap():
    try:
        return int(os.environ.get("GOOGLE_CSE_DAILY_CAP") or DEFAULT_DAILY_CAP)
    except ValueError:
        return DEFAULT_DAILY_CAP


def _load_usage():
    try:
        data = json.loads(USAGE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def usage_today():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return int(_load_usage().get(today) or 0)


def _count(n=1):
    """사용량을 센다. 날짜별로만 남기고 오래된 것은 버린다."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    usage = _load_usage()
    usage[today] = int(usage.get(today) or 0) + n
    # 최근 며칠만 남긴다 — 이 파일은 한도 계산용이지 통계용이 아니다.
    for key in sorted(usage)[:-7]:
        usage.pop(key, None)
    try:
        USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        USAGE_FILE.write_text(json.dumps(usage, ensure_ascii=False), encoding="utf-8")
    except OSError as error:
        log("[-] 검색 사용량 기록 실패(검색에는 영향 없음): {}".format(error))


def search(query, num=MAX_RESULTS):
    """검색 한 번. 실패하거나 한도를 넘었으면 (None, 사유)."""
    if not available():
        return None, "키 없음"
    if usage_today() >= daily_cap():
        return None, "하루 한도({}) 소진".format(daily_cap())
    url = API_URL.format(
        urllib.parse.quote(os.environ["GOOGLE_CSE_KEY"]),
        urllib.parse.quote(os.environ["GOOGLE_CSE_CX"]),
        urllib.parse.quote(query), max(1, min(int(num), 10)))
    request = urllib.request.Request(url, headers={
        "User-Agent": "boannews-intel/1.0 (threat research)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception as error:
        # 실패도 호출로 잡힐 수 있으니 센다 — 세지 않으면 한도를 넘겨 계속 실패한다.
        _count(1)
        return None, "조회 실패: {}".format(str(error)[:70])
    _count(1)
    items = []
    for item in data.get("items") or []:
        items.append({
            "title": " ".join(str(item.get("title") or "").split())[:140],
            "link": item.get("link") or "",
            "site": item.get("displayLink") or "",
            "snippet": " ".join(str(item.get("snippet") or "").split())[:220],
        })
    return items, ""


def terms_from(targets, exclude=()):
    """검색할 이름 — 캠페인·악성코드 이름과 CVE. 이미 답이 나온 것은 뺀다."""
    out = []
    lowered = {str(x).lower() for x in exclude}
    for key in ("malware", "actors", "cves"):
        for value in (targets or {}).get(key) or []:
            value = str(value).strip()
            if len(value) < MIN_TERM_CHARS or value.lower() in lowered:
                continue
            if value not in out:
                out.append(value)
    return out[:MAX_QUERIES_PER_ARTICLE]


def analyze(targets=None, answered=()):
    """웹 검색 트랙. 키가 없거나 검색할 이름이 없으면 None.

    answered에는 다른 조회에서 이미 자료를 찾은 이름을 넘긴다 — 같은 것을 또
    검색해서 한도를 쓰지 않으려는 것이다.

    반환에 references를 실어 보낸다. 그 링크들이 1차 자료 수집의 입력이 된다.
    """
    if not available():
        return None
    terms = terms_from(targets, exclude=answered)
    if not terms:
        return None

    findings, steps, references = [], [], []
    failures = []
    for term in terms:
        items, reason = search(term)
        time.sleep(PAUSE_SECONDS)
        if items is None:
            steps.append("\"{}\" 웹 검색을 건너뛰었습니다 — {}.".format(term, reason))
            failures.append(reason)
            continue
        if not items:
            steps.append("\"{}\"로 검색했지만 지정한 연구 사이트에서는 결과가 없었습니다."
                         .format(term))
            findings.append(
                "\"{}\"는 등록된 연구 사이트(벤더·기관·샌드박스)에 자료가 없습니다 — "
                "아직 1차 분석이 공개되지 않았다는 뜻이라, 기사 외에 참고할 것이 "
                "없습니다.".format(term))
            continue
        steps.append("\"{}\"로 연구 자료를 검색해 {}건을 찾았습니다.".format(term, len(items)))
        findings.append("\"{}\" 관련 1차 자료를 {}건 찾았습니다: {}.".format(
            term, len(items), ", ".join(item["site"] for item in items[:3])))
        for item in items[:2]:
            if item["snippet"]:
                findings.append("· {} — {}".format(item["site"], item["snippet"][:150]))
        references.extend(item["link"] for item in items if item["link"])

    if not findings:
        # 검색이 한 번도 성공하지 못한 것과 "찾았는데 없더라"는 다르다. None을
        # 돌려주면 위에서 "결과가 없었습니다"로 덮여, 키 제한 때문에 한 번도 돌지
        # 않았다는 사실이 화면에서 사라진다(실측 2026-09-17: API 키에 Android 앱
        # 제한이 걸려 모든 호출이 403이었는데 카드에는 자료 없음으로 나왔다).
        if failures:
            findings = ["웹 검색이 돌지 않아 공개 자료를 확인하지 못했습니다 — {}. "
                        "자료가 없다는 뜻이 아닙니다.".format(failures[0][:70])]
        else:
            return None
    seen, unique = set(), []
    for link in references:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return {
        "findings": findings,
        "steps": steps,
        "references": unique[:MAX_RESULTS],
        "used_today": usage_today(),
        "cap": daily_cap(),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
