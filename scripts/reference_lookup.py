# -*- coding: utf-8 -*-
"""정보성 기사의 배경 설명을 위키백과(한국어 → 영어)에서 찾는다. 키가 필요 없다.

제목이 검색어와 정확히 맞는 항목만 쓴다 — 느슨하게 받으면 동음이의어 문서가 "선수 정보"로
들어간다. 사설망 차단을 거치는 network_safety.safe_get으로만 요청한다.
"""

import os
import re
import urllib.parse

import network_safety

SUMMARY_URL = "https://{lang}.wikipedia.org/api/rest_v1/page/summary/{title}"
SEARCH_URL = "https://{lang}.wikipedia.org/w/rest.php/v1/search/title?q={query}&limit=3"
HEADERS = {"User-Agent": "boannews-mail/1.0 (background reference lookup)",
           "Accept": "application/json"}
LANGS = ("ko", "en")
TIMEOUT = 8
MAX_TERMS = 3


def enabled():
    return str(os.environ.get("REFERENCE_LOOKUP_ENABLED", "1")).strip().lower() not in {"0", "false", "no", "off"}


def _names(term):
    """'카테나-X(Catena-X)' → ['카테나-X', 'Catena-X']."""
    term = str(term or "").strip()
    aliases = [a.strip() for a in re.findall(r"\(([^()]+)\)", term) if a.strip()]
    base = re.sub(r"\([^()]*\)", "", term).strip()
    return [name for name in dict.fromkeys([base] + aliases) if name and len(name) <= 80]


def _key(value):
    return re.sub(r"[\W_]+", "", value or "").casefold()


def _get_json(url):
    try:
        response = network_safety.safe_get(url, headers=HEADERS, timeout=TIMEOUT)
        if getattr(response, "status_code", 0) != 200:
            return None
        return response.json()
    except Exception:
        return None


def _summary(lang, title):
    data = _get_json(SUMMARY_URL.format(lang=lang, title=urllib.parse.quote(title.replace(" ", "_"), safe="")))
    if not data or data.get("type") == "disambiguation" or not data.get("extract"):
        return None
    url = ((data.get("content_urls") or {}).get("desktop") or {}).get("page") or ""
    if urllib.parse.urlparse(url).hostname != "{}.wikipedia.org".format(lang):
        return None
    return data


def wikipedia(term, langs=LANGS):
    """정확히 맞는 위키백과 항목 하나. 없으면 None."""
    if not enabled():
        return None
    for lang in langs:
        for name in _names(term):
            # 한국어판은 한글 이름으로, 영어판은 한글이 없는 이름으로만 찾는다.
            if (lang == "ko") != bool(re.search(r"[가-힣]", name)):
                continue
            search = _get_json(SEARCH_URL.format(lang=lang, query=urllib.parse.quote(name)))
            title = ""
            for page in (search or {}).get("pages") or []:
                if _key(page.get("title")) == _key(name):
                    title = page.get("title")
                # 리다이렉트로 맞은 경우는 문서 전체가 그 개념일 때만 쓴다 — 다른 문서의 한
                # 절로 넘어가는 리다이렉트는 요약이 엉뚱한 주제가 된다(예: Digital Product
                # Passport → Produce traceability의 한 절).
                elif (_key(page.get("matched_title")) == _key(name) and not page.get("anchor")):
                    title = page.get("title")
                if title:
                    break
            if not title:
                continue
            data = _summary(lang, title)
            if data:
                return {"term": term, "title": data.get("title") or title, "lang": lang,
                        "summary": data["extract"][:1600],
                        "url": data["content_urls"]["desktop"]["page"]}
    return None


def lookup_many(topics, max_terms=MAX_TERMS):
    found, seen = [], set()
    for term in (topics or [])[:max_terms]:
        item = wikipedia(term)
        if item and item["url"] not in seen:
            seen.add(item["url"])
            found.append(item)
    return found
