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

import hashlib
import re
import urllib.parse

import requests
from datetime import datetime, timezone
from bs4 import BeautifulSoup

import network_safety

# 링크당 본문을 이만큼만 쓴다. 벤더 권고는 짧고 연구 블로그는 길어서, 길면 종합 판단
# 프롬프트가 원문 하나로 가득 찬다.
#
# 다만 앞에서부터 자르면 안 된다. 연구 글은 지표를 맨 뒤 IOC 표에 몰아 싣는데, 그게
# 정확히 우리가 조회에 넣을 값이다. 실측(2026-09-17, 악성 확장 건): socket.dev 원문에
# 확장 ID가 19개 있었고 앞 6,000자에는 0개였다 — 페이지를 받아 놓고 지표를 통째로
# 버린 셈이라, 종합 판단이 "8개 확장의 스토어 상태 미확인(조회 미수행)"으로 끝났다.
# 그래서 앞부분(맥락)과 지표가 몰린 구간을 따로 담는다.
HEAD_CHARS = 4000
IOC_CHARS = 3000
MAX_CHARS_PER_SOURCE = HEAD_CHARS + IOC_CHARS
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
# 확장자 뒤에 쿼리·조각이 붙는 경우도 같은 파일이다(실측: ...pdf?__blob=publicationFile).
SKIP_EXT_RE = re.compile(r"\.(?:pdf|zip|gz|xlsx?|docx?|pptx?|png|jpe?g|gif|svg|mp4)(?:[?#].*)?$", re.I)


def log(message):
    print(message)


def _host(url):
    try:
        # lstrip("www.")은 접두어가 아니라 문자 {w, .}를 지워 www.wired.com을 ired.com으로
        # 만들었다 — 뉴스 매체 제외와 도메인당 1건 규칙이 함께 깨졌다.
        host = (urllib.parse.urlparse(str(url)).netloc or "").lower()
        return host[4:] if host.startswith("www.") else host
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
    own = _apex(_host(_unwrap(article_url)))
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
        if re.fullmatch(r"/(?:\d{4}(?:/\d{1,2}){0,2})?/?", urllib.parse.urlparse(url).path):
            continue
        # 같은 곳에서 여러 개를 읽어도 새로 아는 것이 적다 — 도메인당 하나만.
        if apex in seen_apex:
            continue
        seen_apex.add(apex)
        chosen.append({"url": url, "host": host})
        if len(chosen) >= limit:
            break
    return chosen


# 지표처럼 생긴 것들. 어느 구간에 지표가 몰려 있는지 세는 데만 쓴다 — 여기서 값을
# 뽑아 쓰지는 않는다(그건 analysis_targets와 각 hunter가 한다).
INDICATOR_RE = re.compile(
    r"(?<![a-z0-9])(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-p]{32})(?![a-z0-9])"
    r"|CVE-\d{4}-\d{4,7}"
    r"|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
    r"|(?<![\w@.])[a-z0-9][a-z0-9-]{1,40}(?:\[?\.\]?[a-z0-9-]{2,30})+\[?\.\]?"
    r"(?:com|net|org|io|dev|xyz|top|sbs|cfd|monster|ru|cn|info|site|online|shop)(?![\w])",
    re.I)
# 지표 밀도를 이 크기의 창으로 훑는다.
IOC_WINDOW_STEP = 500


def _indicator_count(chunk):
    return len(INDICATOR_RE.findall(chunk or ""))


def _excerpt(text):
    """앞부분(맥락) + 지표가 실린 조각들을 합쳐 돌려준다.

    제목으로 IOC 절을 찾지 않는 이유: 글마다 "Indicators of Compromise"·"IoCs"·
    "Appendix"·"침해지표"로 제각각이고, 표만 있고 제목이 없는 글도 있다. 지표가 실제로
    있는 곳을 세는 편이 글의 형식과 무관하게 잘 맞는다.

    문서 순서가 아니라 밀도 순으로 고른다. 순서대로 담으면 앞쪽에서 도메인 한두 개가
    스친 조각들이 예산을 먼저 먹고, 정작 표가 있는 끝부분에서 잘린다 — 실측
    (socket.dev): 확장 ID 19개가 전부 문서 끝 1,300자에 몰려 있었는데 순서대로 담으니
    14개에서 끊겼다. 밀도가 높은 조각부터 집은 뒤 원래 순서로 되돌려 읽기 쉽게 한다.
    """
    text = text or ""
    if len(text) <= MAX_CHARS_PER_SOURCE:
        return text
    head, tail = text[:HEAD_CHARS], text[HEAD_CHARS:]
    chunks = []
    for start in range(0, len(tail), IOC_WINDOW_STEP):
        chunk = tail[start:start + IOC_WINDOW_STEP]
        score = _indicator_count(chunk)
        if score:
            chunks.append((score, start, chunk))
    if not chunks:
        return head + tail[:IOC_CHARS]      # 지표가 없으면 그냥 이어 붙인다

    chunks.sort(key=lambda item: (-item[0], item[1]))
    picked, budget = [], IOC_CHARS
    for score, start, chunk in chunks:
        if budget <= 0:
            break
        picked.append((start, chunk[:budget]))
        budget -= len(chunk)

    picked.sort()                           # 원래 순서로 되돌린다
    parts, last_end = [], None
    for start, chunk in picked:
        if last_end is not None and start > last_end:
            parts.append(" … ")             # 건너뛴 구간이 있음을 표시한다
        parts.append(chunk)
        last_end = start + IOC_WINDOW_STEP
    return head + " … " + "".join(parts)


def extract_html(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
        tag.decompose()
    candidates = list(soup.select("article, main, [itemprop=articleBody], .payload-richtext, .rich-text, .prose"))
    for paragraph in soup.find_all("p"):
        if len(paragraph.get_text(" ", strip=True)) >= 100:
            candidates.extend(p for p in list(paragraph.parents)[:3] if p.name in ("div", "section"))
    candidates.append(soup.body or soup)
    scored = [(node, sum(len(p.get_text(" ", strip=True)) for p in node.find_all("p")
                        if len(p.get_text(" ", strip=True)) >= 100)) for node in candidates]
    best_score = max(score for _, score in scored)
    eligible = [node for node, score in scored if score >= max(400, best_score * 0.7)]
    node = min(eligible, key=lambda n: len(n.get_text(" ", strip=True))) if eligible else (soup.body or soup)
    text = "\n".join(" ".join(line.split()) for line in node.get_text("\n", strip=True).splitlines() if line.strip())
    # Keep table rows intact, including tables outside the narrative container.
    rows, seen = [], set()
    for row in soup.select("table tr"):
        cells = [" ".join(cell.get_text(" ", strip=True).split()) for cell in row.find_all(["td", "th"], recursive=False)]
        line = " | ".join(cells)
        if re.search(r"\b[a-fA-F0-9]{40,64}\b", line) and line not in seen:
            rows.append(line)
            seen.add(line)
    return _excerpt(text) + ("\n[원문 해시 표]\n" + "\n".join(rows)[:6000] if rows else "")


def fetch_text(url):
    """본문 텍스트만. 실패하거나 너무 짧으면 빈 문자열."""
    # 이 url은 기사 본문에 실린 링크·웹 검색 결과다 — 우리가 고른 것이 아니다.
    # analysis_worker.fetch_article_text와 같은 이유로 사설망 요청은 막는다.
    try:
        network_safety.check_public_url(url)
    except network_safety.UnsafeUrlError as error:
        log("    [-] 원문 조회 거부({}): {}".format(_host(url), error))
        return ""
    try:
        response = network_safety.safe_get(url, headers=HEADERS, timeout=FETCH_TIMEOUT_SECONDS)
        response.raise_for_status()
    except Exception as error:
        log("    [-] 원문 조회 실패({}): {}".format(_host(url), str(error)[:60]))
        return ""
    text = extract_html(response.text)
    if len(text) < MIN_BODY_CHARS:
        log("    [-] 원문이 {}자뿐이라 쓰지 않습니다({}).".format(len(text), _host(url)))
        return ""
    return text


def collect(links, article_url="", limit=MAX_SOURCES, origin="article"):
    """고른 1차 자료를 실제로 읽어 온다.

    반환: {"sources": [{url, host, chars, text, retrieved_at}], "steps": [...], "attempts": [...]}
    실패도 과정에 남긴다 — 읽지 못한 원문이 있다는 사실이 판단에 영향을 준다.
    """
    candidates = pick(links, article_url=article_url, limit=limit)
    sources, steps, attempts = [], [], []
    if not candidates:
        steps.append(("기사가 인용한 1차 자료" if origin == "article" else "검색 참고 원문")
                     + "가 없어 원문 확인을 건너뜁니다.")
        return {"sources": sources, "steps": steps, "attempts": attempts}

    for item in candidates:
        text = fetch_text(item["url"])
        attempts.append({"key": "primary", "url": item["url"],
                         "status": "returned" if text else "unavailable",
                         "detail": "원문 수집됨" if text else "원문을 읽지 못함; 근거로 사용하지 않음",
                         "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")})
        if not text:
            steps.append("1차 자료 {}를 열지 못했습니다 — 그쪽 내용은 판단에 반영되지 "
                         "않았습니다.".format(item["host"]))
            continue
        sources.append({"url": item["url"], "host": item["host"],
                        "chars": len(text), "text": text,
                        "excerpt_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "origin": origin,
                        "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")})
        label = "기사가 인용한 1차 자료" if origin == "article" else "검색으로 찾은 참고 원문(기사 미인용)"
        steps.append("{} {}를 직접 읽었습니다({:,}자).".format(label, item["host"], len(text)))
    return {"sources": sources, "steps": steps, "attempts": attempts}


def as_evidence(sources):
    """프롬프트에 넣을 형태. 어디서 온 글인지 밝혀 둔다."""
    blocks = []
    for source in sources or []:
        blocks.append("--- {} ({}) ---\n{}".format(
            source.get("host") or "", source.get("url") or "", source.get("text") or ""))
    return "\n\n".join(blocks)
