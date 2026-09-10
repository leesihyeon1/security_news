# -*- coding: utf-8 -*-
"""기사가 인용한 1차 자료를 내려받아 증거로 쓴다.

무엇이 빠져 있었나
    기사에서 외부 링크를 183건 수집해 두고 화면에 표시만 했다(실측 35건 중 33건에
    링크가 있었다). 그 안에 unit42.paloaltonetworks.com 14건, microsoft.com 10건처럼
    벤더·연구기관 원문이 들어 있는데 한 번도 읽지 않았다.

    분석가가 가장 먼저 하는 일이 그 링크를 여는 것이다. 우리는 2차 보도 기사 하나만
    읽고 판단했다. 실제로 그 한계가 드러났다 — Magento 건에서 종합 판단이 "기사는
    패치가 없다는데 CVE는 이미 공개돼 있다"는 모순을 짚었지만 해소하지 못했다.
    Adobe 권고 원문을 읽으면 답이 나오는 문제였다.

무엇을 1차 자료로 보나
    뉴스 매체가 아닌 곳. 벤더 권고, 연구팀 블로그, 정부 기관 페이지가 여기 해당한다.
    매체 목록을 유지하는 대신 "알려진 뉴스 매체가 아니면 1차 자료 후보"로 본다 —
    매체는 수가 적고 잘 바뀌지 않지만, 벤더·연구기관은 매번 새로 나온다.
"""

import re
import urllib.parse

import requests
from bs4 import BeautifulSoup

# 링크당 본문을 이만큼만 쓴다. 벤더 권고는 짧고 연구 블로그는 길어서, 길면 종합 판단
# 프롬프트가 원문 하나로 가득 찬다.
MAX_CHARS_PER_SOURCE = 6000
MAX_SOURCES = 2
FETCH_TIMEOUT_SECONDS = 20
# 이보다 짧으면 본문을 못 읽은 것으로 본다(동의 배너·로그인 벽).
MIN_BODY_CHARS = 600

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept-Language": "en,ko;q=0.8",
}

# 뉴스 매체 — 여기 링크는 2차 보도라 1차 자료가 아니다. 우리가 이미 그 기사를 읽고
# 있으므로 같은 층을 한 번 더 읽을 이유가 없다.
NEWS_HOSTS = {
    "thehackernews.com", "securityweek.com", "bleepingcomputer.com",
    "infosecurity-magazine.com", "therecord.media", "cyberscoop.com",
    "securityaffairs.com", "securityaffairs.co", "darkreading.com",
    "helpnetsecurity.com", "boannews.com", "dailysecu.com", "krebsonsecurity.com",
    "theregister.com", "zdnet.com", "wired.com", "arstechnica.com",
    "bankinfosecurity.com", "scmagazine.com", "hackread.com", "gbhackers.com",
    "malwarebytes.com", "cybernews.com", "techcrunch.com", "reuters.com",
    "bloomberg.com", "forbes.com", "csoonline.com", "infosecurity.com",
}
# 링크로만 남는 것들 — 읽을 본문이 없다.
SKIP_HOSTS = {
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com",
    "youtu.be", "reddit.com", "t.me", "mastodon.social", "bsky.app",
    "click-tracker-two.vercel.app",
}
SKIP_PATH_RE = re.compile(
    r"/(?:tag|tags|category|categories|topic|topics|author|authors|about|"
    r"contact|privacy|subscribe|newsletter|feed|rss|search)(?:/|$)", re.I)
# 본문이 아닌 파일
SKIP_EXT_RE = re.compile(r"\.(?:pdf|zip|gz|xlsx?|docx?|pptx?|png|jpe?g|gif|svg|mp4)$", re.I)


def log(message):
    print(message)


def _host(url):
    try:
        return (urllib.parse.urlparse(str(url)).netloc or "").lower().lstrip("www.")
    except Exception:
        return ""


def _apex(host):
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _link_url(link):
    if isinstance(link, dict):
        return link.get("url") or link.get("href") or ""
    return str(link or "")


def _unwrap(url):
    """클릭 추적 링크에서 원래 주소를 꺼낸다 — 그대로 받으면 추적 클릭이 올라간다."""
    try:
        parsed = urllib.parse.urlparse(str(url))
    except Exception:
        return str(url or "")
    if "click-tracker" in (parsed.netloc or "") or parsed.path.endswith("/api/click"):
        inner = urllib.parse.parse_qs(parsed.query).get("url")
        if inner:
            return inner[0]
    return str(url or "")


def pick(links, article_url="", limit=MAX_SOURCES):
    """1차 자료로 볼 만한 링크를 고른다(뉴스 매체·소셜·목록 페이지 제외)."""
    own = _apex(_host(article_url))
    chosen, seen_apex = [], set()
    for link in links or []:
        url = _unwrap(_link_url(link))
        if not url.startswith("http"):
            continue
        host = _host(url)
        apex = _apex(host)
        if not host or apex == own:
            continue
        if host in SKIP_HOSTS or apex in SKIP_HOSTS:
            continue
        if apex in NEWS_HOSTS or host in NEWS_HOSTS:
            continue
        if SKIP_EXT_RE.search(url) or SKIP_PATH_RE.search(urllib.parse.urlparse(url).path or ""):
            continue
        # 같은 곳에서 여러 개를 읽어도 새로 아는 것이 적다 — 도메인당 하나만.
        if apex in seen_apex:
            continue
        seen_apex.add(apex)
        chosen.append({"url": url, "host": host})
        if len(chosen) >= limit:
            break
    return chosen


def fetch_text(url):
    """본문 텍스트만. 실패하거나 너무 짧으면 빈 문자열."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=FETCH_TIMEOUT_SECONDS)
        response.raise_for_status()
    except Exception as error:
        log("    [-] 원문 조회 실패({}): {}".format(_host(url), str(error)[:60]))
        return ""
    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
        tag.decompose()
    node = soup.find("article") or soup.find("main") or soup.body or soup
    text = " ".join(node.get_text(" ", strip=True).split())
    if len(text) < MIN_BODY_CHARS:
        log("    [-] 원문이 {}자뿐이라 쓰지 않습니다({}).".format(len(text), _host(url)))
        return ""
    return text[:MAX_CHARS_PER_SOURCE]


def collect(links, article_url="", limit=MAX_SOURCES):
    """고른 1차 자료를 실제로 읽어 온다.

    반환: {"sources": [{url, host, chars, text}], "steps": [...]}
    실패도 과정에 남긴다 — 읽지 못한 원문이 있다는 사실이 판단에 영향을 준다.
    """
    candidates = pick(links, article_url=article_url, limit=limit)
    sources, steps = [], []
    if not candidates:
        steps.append("기사가 인용한 1차 자료(벤더 권고·연구 블로그)가 없어 원문 확인은 "
                     "건너뜁니다 — 뉴스 매체 링크만 있었습니다.")
        return {"sources": sources, "steps": steps}

    for item in candidates:
        text = fetch_text(item["url"])
        if not text:
            steps.append("1차 자료 {}를 열지 못했습니다 — 그쪽 내용은 판단에 반영되지 "
                         "않았습니다.".format(item["host"]))
            continue
        sources.append({"url": item["url"], "host": item["host"],
                        "chars": len(text), "text": text})
        steps.append("기사가 인용한 1차 자료 {}를 직접 읽었습니다({:,}자) — 2차 보도가 "
                     "생략한 내용을 확인하려는 것입니다.".format(item["host"], len(text)))
    return {"sources": sources, "steps": steps}


def as_evidence(sources):
    """프롬프트에 넣을 형태. 어디서 온 글인지 밝혀 둔다."""
    blocks = []
    for source in sources or []:
        blocks.append("--- {} ({}) ---\n{}".format(
            source.get("host") or "", source.get("url") or "", source.get("text") or ""))
    return "\n\n".join(blocks)
