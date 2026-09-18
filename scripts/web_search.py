# -*- coding: utf-8 -*-
"""보안 연구 자료를 웹에서 검색한다(Brave Search 또는 Google Programmable Search).

무엇을 찾는가
    아무 웹 검색이 아니라 벤더 연구팀·정부 기관·샌드박스의 1차 자료다. 찾은 링크를
    primary_sources가 그대로 원문으로 읽으므로, 뉴스 재게시가 섞이면 이미 읽은 기사를
    또 읽는 낭비가 된다.

    검색 제공자마다 그걸 거르는 방법이 다르다. Google은 검색엔진(CX)에 볼 사이트를
    등록해 두는 방식이고, Brave는 웹 전체를 보므로 결과에서 걸러야 한다. 거르는
    기준은 feeds.json의 신뢰도 등급이다 — C등급은 우리가 이미 매일 수집하는 뉴스
    매체라 검색으로 또 만날 이유가 없고, A·B등급(PSIRT·연구팀)은 그대로 둔다.

왜 둘인가
    Google Custom Search JSON API가 프로젝트를 바꾸고 키를 새로 발급해도 계속
    "This project does not have the access"로 거부했다(실측 2026-09-18, 프로젝트
    748683156627·452668394229 둘 다). 콘솔에는 사용 설정됨으로 보이는데도 그랬다.
    검색이 목적이지 Google이 목적이 아니므로 제공자를 하나 더 둔다.

한도를 세는 이유
    무료 한도를 넘으면 과금되거나 조용히 실패한다. 기사당 2회씩 하루 100건을 분석하면
    200회가 되어 어느 쪽 한도든 넘는다. 그래서 파일로 날짜별 사용량을 세고, 한도에
    닿으면 검색을 건너뛰되 "한도 소진으로 생략"을 조사 과정에 남긴다.

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
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search?q={}&count={}"
USAGE_FILE = common_utils.DATA_DIR / "cse_usage.json"

# 하루 무료 한도가 100건이다. 90에서 멈춰 손으로 확인할 여유를 남긴다.
DEFAULT_DAILY_CAP = 90
# Brave 무료는 월 2,000건이다. 날짜별로 세고 있으므로 하루치로 환산해 60으로 둔다
# (2,000 / 31 ≈ 64). 달을 통째로 세지 않는 것은, 어느 날 몰아 쓰다 월말에 말라붙는
# 것보다 매일 쓸 수 있는 편이 낫기 때문이다.
BRAVE_DAILY_CAP = 60
# 기사 하나에 쓰는 검색 횟수. 늘리면 한도가 빨리 마른다.
MAX_QUERIES_PER_ARTICLE = 2
MAX_RESULTS = 5
REQUEST_TIMEOUT = 20
PAUSE_SECONDS = 1.0
# 검색어가 짧으면 무관한 결과가 쏟아진다.
MIN_TERM_CHARS = 5


def log(message):
    print(message)


def provider():
    """쓸 검색 제공자. 둘 다 있으면 Brave를 쓴다(무료 한도가 크고 사이트 제한이 없다)."""
    if os.environ.get("BRAVE_SEARCH_KEY"):
        return "brave"
    if os.environ.get("GOOGLE_CSE_KEY") and os.environ.get("GOOGLE_CSE_CX"):
        return "google"
    return ""


def provider_label():
    return {"brave": "Brave Search", "google": "Google 맞춤검색"}.get(provider(), "")


def available():
    return bool(provider())


def daily_cap():
    if provider() == "brave":
        name, default = "BRAVE_SEARCH_DAILY_CAP", BRAVE_DAILY_CAP
    else:
        name, default = "GOOGLE_CSE_DAILY_CAP", DEFAULT_DAILY_CAP
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


# 우리가 이미 매일 수집하는 뉴스 매체(feeds.json 신뢰도 C). 검색 결과에서 뺀다 —
# 여기서 찾으려는 것은 기사가 아니라 그 기사가 인용한 원문이다. A·B등급(PSIRT·벤더
# 연구팀)은 1차 자료 그 자체라 그대로 둔다.
_news_hosts_cache = None


def news_hosts():
    global _news_hosts_cache
    if _news_hosts_cache is not None:
        return _news_hosts_cache
    hosts = {"thehackernews.com"}  # 피드가 feedburner를 거쳐 와서 주소로는 안 잡힌다
    # C등급이지만 1차 자료인 곳. 등급은 "뉴스 기사로서 얼마나 믿을 만한가"를 매긴
    # 것이라 PoC 저장소·벤더 연구 블로그가 여기 섞여 있다 — 검색에서는 오히려 찾던
    # 것이므로 빼지 않는다. feeds.json 등급은 발송 파이프라인이 쓰므로 건드리지 않는다.
    keep = {"exploit-db.com", "proofpoint.com"}
    try:
        feeds = json.loads((common_utils.ASSETS_DIR / "feeds.json")
                           .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        feeds = []
    for feed in feeds if isinstance(feeds, list) else []:
        if str(feed.get("reliability") or "").upper() != "C":
            continue
        host = urllib.parse.urlparse(str(feed.get("rss_url") or "")).netloc.lower()
        # 배급 서비스 주소는 매체를 가리키지 않는다.
        if host and "feedburner" not in host:
            hosts.add(host[4:] if host.startswith("www.") else host)
    _news_hosts_cache = hosts - keep
    return _news_hosts_cache


def _is_news_site(host):
    host = str(host or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return host in news_hosts()


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


def _fetch(url, headers):
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _search_google(query, num):
    data = _fetch(API_URL.format(
        urllib.parse.quote(os.environ["GOOGLE_CSE_KEY"]),
        urllib.parse.quote(os.environ["GOOGLE_CSE_CX"]),
        urllib.parse.quote(query), max(1, min(int(num), 10))), {
            "User-Agent": "boannews-intel/1.0 (threat research)",
            "Accept": "application/json",
        })
    # CX가 이미 볼 사이트를 좁혀 두므로 여기서 더 거르지 않는다.
    return [{
        "title": " ".join(str(item.get("title") or "").split())[:140],
        "link": item.get("link") or "",
        "site": item.get("displayLink") or "",
        "snippet": " ".join(str(item.get("snippet") or "").split())[:220],
    } for item in data.get("items") or []]


def _search_brave(query, num):
    # 뉴스 매체를 걸러낼 것이므로 넉넉히 받아 온다 — 요청 수는 그대로 1회다.
    data = _fetch(BRAVE_URL.format(urllib.parse.quote(query),
                                   max(1, min(int(num) * 3, 20))), {
        "X-Subscription-Token": os.environ["BRAVE_SEARCH_KEY"],
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    })
    items = []
    for item in ((data.get("web") or {}).get("results") or []):
        link = item.get("url") or ""
        site = urllib.parse.urlparse(link).netloc
        if _is_news_site(site):
            continue
        items.append({
            "title": " ".join(str(item.get("title") or "").split())[:140],
            "link": link,
            "site": site,
            "snippet": " ".join(str(item.get("description") or "").split())[:220],
        })
        if len(items) >= num:
            break
    return items


def search(query, num=MAX_RESULTS):
    """검색 한 번. 실패하거나 한도를 넘었으면 (None, 사유)."""
    which = provider()
    if not which:
        return None, "키 없음"
    if usage_today() >= daily_cap():
        return None, "하루 한도({}) 소진".format(daily_cap())
    try:
        items = _search_brave(query, num) if which == "brave" else _search_google(query, num)
    except Exception as error:
        # 실패도 호출로 잡힐 수 있으니 센다 — 세지 않으면 한도를 넘겨 계속 실패한다.
        _count(1)
        return None, "조회 실패: {}".format(str(error)[:70])
    _count(1)
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
            steps.append("\"{}\"로 {}에 검색했지만 연구 자료가 없었습니다."
                         .format(term, provider_label()))
            findings.append(
                "\"{}\"는 연구 사이트(벤더·기관·샌드박스)에 자료가 없습니다 — "
                "아직 1차 분석이 공개되지 않았다는 뜻이라, 기사 외에 참고할 것이 "
                "없습니다.".format(term))
            continue
        steps.append("\"{}\"로 {}에서 연구 자료 {}건을 찾았습니다.".format(
            term, provider_label(), len(items)))
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
