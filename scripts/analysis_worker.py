"""대시보드의 "심층분석" 요청을 PC에서 처리하는 워커.

왜 이 스크립트가 필요한가:
    심층분석은 원래 Vercel 서버리스 함수(click-tracker/api/analyze.js)가 직접
    수행했다. 그런데 그 함수를 빠르게 만들던 모델(openai/gpt-oss-120b)이
    폐기(HTTP 410)되면서, 남은 대체 모델이 전부 Vercel 60초 상한에 걸린다
    (실측: openai/gpt-oss-20b 36~61초, nvidia/nemotron-3-ultra 84.9초).
    결과적으로 버튼을 누르면 항상 "분석 시간이 초과되었습니다"로 끝났다.

    그래서 analyze.js는 요청을 Redis 큐(analysis:queue)에 넣고 즉시 202로 답하고,
    실제 분석은 이 워커가 맡는다. 여기는 서버리스가 아니라 시간 제한이 없다
    (llm_generate(timeout=300)).

결과는 analyze.js가 쓰던 것과 같은 자리에 같은 형식으로 기록한다 — 대시보드는
인사이트 탭·드로어를 그대로 재사용하고, 표시 코드를 고칠 필요가 없다:
    analysis:<ref>   분석 결과(JSON, 90일)   — 같은 기사 재요청 시 캐시로 즉시 응답
    insights:list    공유 인사이트 목록       — 모든 방문자가 함께 보는 이력

필요 설정(.env):
    REDIS_URL        click-tracker와 동일한 값
    NVIDIA_API_KEY   기존 리포트 생성과 동일
"""

import contextlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

import analysis_targets
import analysis_flow
import article_kind
import issue_decision
import common_utils
import campaign_radar
import dashboard_text
import investigation
import response_synth
import network_safety
import source_evidence
import worker_progress

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

try:
    import redis
except ImportError:  # requirements.txt에 있지만 설치가 빠진 환경 방어
    redis = None

QUEUE_KEY = "analysis:queue"
SUMMARY_QUEUE_KEY = "report-summary:queue"
SUMMARY_RESULT_TTL_SECONDS = 60 * 60 * 24 * 90
INSIGHTS_LIST_KEY = "insights:list"
# Redis Cloud 무료 30MB 안에 머물게 한다 — 기록 한 건이 평균 61KB라 300건이면 목록만
# 18MB이고 분석 캐시까지 더하면 한도를 넘어 새 결과가 저장되지 않는다(noeviction).
MAX_INSIGHTS_LIST_SIZE = 120          # analyze.js와 같은 값이어야 목록이 어긋나지 않는다
ANALYSIS_CACHE_TTL_SECONDS = 60 * 60 * 24 * 30  # analyze.js와 같은 값

# 한 번 실행에서 처리할 최대 건수. 5분마다 도는데 한 건에 30~90초가 걸리므로,
# 다음 실행과 겹치지 않도록 여유를 두고 끊는다(작업 스케줄러는 IgnoreNew라
# 겹치면 그냥 건너뛰지만, 큐가 밀리는 것보다 매 회차 조금씩 처리하는 게 낫다).
MAX_ITEMS_PER_RUN = 3
# 5분 주기와 겹치지 않도록 여유를 둔다(실측: 본문 수집 1~2초 + LLM 33초 = 건당 35초 안팎).
RUN_BUDGET_SECONDS = 210

BODY_MAX_CHARS = 24000
# 이보다 짧으면 원문을 못 읽은 것으로 본다. 실측 분포: 정상 수집은 2,753~37,460자였고
# 유일한 예외가 봇 차단 페이지(658자)였다.
BODY_MIN_CHARS = 900
# 차단 페이지 판정에 길이 조건을 함께 본다. 표현만 보면 그 표현을 다루는 기사를
# 차단 페이지로 오인한다(실측: ClickFix 캠페인 기사가 본문에 "가짜 CAPTCHA"를
# 설명해서, 29,727자를 정상 수집했는데도 봇 차단으로 판정돼 분석이 취소됐다).
# 실제 차단 페이지는 짧다 — 안내 문구 몇 줄이 전부다.
BLOCKED_PAGE_MAX_CHARS = 3000
# 봇 차단·로그인 벽·자바스크립트 요구 페이지의 표식. 이런 페이지를 기사로 넘기면
# LLM이 제목만 보고 그럴듯한 분석을 만들어 낸다 — 그게 더 위험하다.
BLOCKED_PAGE_RE = re.compile(
    r"are you human|사람인지 확인|captcha|verify you are|attention required|just a moment|"
    r"access denied|접근이 거부|403 forbidden|enable javascript|자바스크립트를 활성화|"
    r"please enable cookies|checking your browser|ddos protection|"
    r"구독자만|로그인 후 이용|subscribers only|paywall",
    re.I,
)
FETCH_TIMEOUT_SECONDS = 20
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ko;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}

DARKREADING_HOSTS = {"darkreading.com", "www.darkreading.com"}
# 기사가 직접 인용한 연구 원문. Dark Reading 본문이 차단됐을 때 이 자료를
# 분석 근거로 쓰며, 결과에 출처 차이를 명시한다.
DARKREADING_PRIMARY_SOURCES = {
    "/threat-intelligence/needymantis-long-term-access-compromised-networks": {
        "url": "https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/",
        "label": "Microsoft Threat Intelligence",
        "marker": "NeedyMantis",
    },
    "/identity-access-management-security/carbonato-botnet-ai-agent-hacked-docker-hosts": {
        "url": "https://www.threatdown.com/blog/carbonato/",
        "label": "ThreatDown",
        "marker": "Carbonato",
    },
    "/cloud-security/jadepuffer-ai-actor-azure-tenant-destructive-cloud-attack": {
        "url": "https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/",
        "label": "Microsoft Security Research",
        "marker": "JADEPUFFER",
    },
}

REPORT_CATEGORIES = "취약점|악성코드|침해사고|개인정보유출|공격캠페인|공급망공격|피싱사기|정책규제|기술동향|제품행사|기타"
CATEGORY_GUIDE = ("실제 공격 사건·악성코드·취약점이 확인되면 해당 위협 분류를 고르고, "
                  "제도·사업 발표·기술 동향을 다룬 정보성 기사에는 위협 분류를 억지로 붙이지 마라.")
# 이 안에 든 것만 "위협/공격"형 — CVSS·공격기법·즉시조치 프레임이 실제로 맞는 기사다.
# 정책규제·기술동향·제품행사·기타에 같은 프레임을 강제하면 모델이 억지로 위험도를 지어낸다.
THREAT_CATEGORIES = {"취약점", "악성코드", "침해사고", "개인정보유출", "공격캠페인", "공급망공격", "피싱사기"}

CATEGORY_RE = re.compile(r"^\s*\[\s*분류\s*[:：]\s*([^\]]+)\]\s*", re.MULTILINE)
BS = chr(92)  # 정규식 리터럴 백슬래시(편집 중 개수가 어긋나는 것을 막는다)

GLOSSARY_SECTION_RE = re.compile(r"\[\s*선수\s*정보\s*\]\s*\n(.*?)(?=\n\s*\[|\Z)", re.S)
# 불릿(-·*)이 붙은 항목만 받으면 대부분 놓친다 — 모델이 "용어: 설명"으로만 쓰는 경우가
# 많다(실측: 최근 분석 4건 중 3건이 불릿 없이 써서 용어 사전이 비었다). 불릿은 있으면
# 벗기고, 없어도 "짧은 용어 + 콜론 + 긴 설명" 형태면 받는다.
# 불릿(-·*)이 붙은 항목만 받으면 대부분 놓친다 — 모델이 "용어: 설명"으로만 쓰는 경우가
# 많다(실측: 최근 분석 4건 중 3건이 불릿 없이 써서 용어 사전이 비었다). 불릿은 있으면
# 벗기고, 없어도 "짧은 용어 + 콜론 + 긴 설명" 형태면 받는다.
GLOSSARY_ITEM_RE = re.compile(
    "^" + BS + "s*(?:[-•*]|" + BS + "d+[.)])?" + BS + "s*([^:：" + BS + "n]{2,40})"
    + BS + "s*[:：]" + BS + "s*(.{20,})" + BS + "s*$",
    re.MULTILINE,
)
MITRE_SECTION_RE = re.compile(r"\[\s*MITRE\s*ATT&CK\s*\]\s*\n?(.*?)(?=\n\s*\[|\Z)", re.S | re.I)
GLOSSARY_TERM_MAX_CHARS = 40


def log(message):
    print(message, flush=True)


def get_client():
    url = os.environ.get("REDIS_URL", "")
    if not url or redis is None:
        return None
    try:
        client = redis.from_url(url, decode_responses=True,
                                socket_connect_timeout=10, socket_timeout=15)
        client.ping()
        return client
    except Exception as error:
        log("[-] Redis 연결 실패: {}".format(error))
        return None


# 공유·구독 링크와 기사 자신을 가리키는 링크는 "관련 링크"가 아니다 — 실측: Microsoft
# 블로그 기사에서 뽑힌 6건이 전부 기사 자신·facebook sharer·twitter intent였다.
JUNK_LINK_RE = re.compile(
    r"facebook\.com/shar|twitter\.com/intent|x\.com/intent|linkedin\.com/shar|"
    r"reddit\.com/submit|news\.ycombinator\.com/submitlink|t\.me/share|wa\.me/|"
    r"/sharer|[?&]share=|/share/?$|mailto:|/feed/?$|/rss",
    re.I,
)
# 태그·카테고리 같은 분류 페이지는 기사가 참조한 자료가 아니라 사이트 내비게이션이다
# (실측: Microsoft 블로그에서 살아남은 6건이 전부 /tag/·/topic/·/product/ 링크였다).
NAV_LINK_RE = re.compile(r"/(?:tag|tags|category|categories|topic|topics|product|"
                         r"content-type|author|page)/", re.I)
MAX_LINKS = 20

# 일부 매체는 한 사건의 보도 끝에 별개 캠페인들을 관련 소식으로 길게 붙인다.
# 이 구간을 본 사건의 IOC/단계로 읽으면 판단과 조회가 사건 수만큼 반복된다.
RELATED_CAMPAIGNS_RE = re.compile(
    r"\bThe findings coincide with the discovery of multiple\b", re.I)


def _focus_article(body, links):
    """Keep a complete lead story; separate a clearly signposted related-campaign tail."""
    marker = RELATED_CAMPAIGNS_RE.search(body or "")
    if not marker or marker.start() < BODY_MIN_CHARS:
        return body, links
    focused = body[:marker.start()].rstrip()
    focused_folded = focused.casefold()
    focused_links = [link for link in links or []
                     if str(link.get("text") or "").casefold() in focused_folded]
    return focused, focused_links


def _normalize_link(anchor, article_url):
    """<a>를 {url, text} 로 정규화. 관련 링크가 아니면 None.

    대시보드는 {url, text} 형태를 기대한다(예전 Vercel 분석 함수가 그렇게 저장했다).
    URL 문자열만 저장하면 링크 카드에 빈 불릿만 찍힌다.
    """
    href = (anchor.get("href") or "").strip()
    if not href.startswith("http") or JUNK_LINK_RE.search(href):
        return None
    if href.rstrip("/") == (article_url or "").rstrip("/"):
        return None
    if NAV_LINK_RE.search(href):
        return None
    from urllib.parse import urlsplit
    if re.fullmatch(r"/(?:\d{4}(?:/\d{1,2}){0,2})?/?", urlsplit(href).path):
        return None
    text = common_utils.clean_text(anchor.get_text(" ", strip=True))[:110]
    if not text:
        return None      # 문구 없는 <a>는 아이콘·배너 같은 껍데기다
    return {"url": href, "text": text}


def _darkreading_primary_source(url):
    try:
        parsed = urlsplit(url)
        if (parsed.hostname or "").lower() in DARKREADING_HOSTS:
            return DARKREADING_PRIMARY_SOURCES.get(parsed.path.rstrip("/"))
    except ValueError:
        pass
    return None


def _response_text(response):
    raw = response.content
    for encoding in ("utf-8", "cp949"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _extract_article_content(raw_html, article_url):
    """Extract the longest article candidate and useful references from one response."""
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
        tag.decompose()

    # 셀렉터를 순서대로 시도해 "처음 맞는 것"을 쓰면 안 된다 — 사이트에 따라 앞쪽
    # 후보가 껍데기만 감싸고 있다(실측: The Hacker News의 <article>은 148자인데
    # .post-body는 19,795자). 후보를 모두 뽑아 본문이 가장 긴 것을 고른다.
    best_text = ""
    best_node = None
    for selector in ("#article-view-content-div", "#articleBody", ".article-body",
                     ".articlebody", ".post-body", ".entry-content", "#single-post .text",
                     "#news_content"):
        for node in soup.select(selector):
            text = common_utils.clean_text(node.get_text(" ", strip=True))
            if len(text) > len(best_text):
                best_text, best_node = text, node
    if len(best_text) < 500:
        for node in soup.select("article, main"):
            text = common_utils.clean_text(node.get_text(" ", strip=True))
            if len(text) > len(best_text):
                best_text, best_node = text, node
    # 어느 후보도 본문답지 않으면 페이지 전체를 쓴다(내비게이션이 섞이지만 없는 것보단 낫다).
    if len(best_text) < 500:
        whole = common_utils.clean_text(soup.get_text(" ", strip=True))
        if len(whole) > len(best_text):
            best_text, best_node = whole, soup

    target = best_node if best_node is not None else soup
    links, seen = [], set()
    for anchor in target.find_all("a", href=True):
        link = _normalize_link(anchor, article_url)
        if not link or link["url"] in seen:
            continue
        seen.add(link["url"])
        links.append(link)
        if len(links) >= MAX_LINKS:
            break
    return best_text, links


def fetch_article_text(url):
    """기사 원문에서 본문 텍스트와 참고 링크를 뽑는다. 실패 시 ("", []).

    등록된 Dark Reading 기사의 차단 응답에서는 각 기사가 직접 인용한 연구 원문을
    읽는다. 원문에서도 근거를 확인할 수 없으면 분석을 실패 처리한다.
    """
    url = source_evidence.article_url(url)
    # 이 url은 인증 없는 공개 API(/api/analyze)가 그대로 넣은 값이다(실측 2026-09-22:
    # 문법 검증만 있었다). 우리 PC가 그 값을 그대로 요청하므로, 사설·루프백·예약
    # 대역을 가리키면 여기서 막는다 — network_safety.py 참고.
    try:
        network_safety.check_public_url(url)
    except network_safety.UnsafeUrlError as error:
        log("[-] 본문 수집 거부({}): {}".format(url[:70], error))
        return "", []
    response = None
    direct_error = None
    try:
        response = network_safety.safe_get(url, headers=REQUEST_HEADERS, timeout=FETCH_TIMEOUT_SECONDS)
        if getattr(response, "status_code", 200) < 400:
            text, links = _extract_article_content(_response_text(response), url)
            blocked = (BLOCKED_PAGE_RE.search(text[:2000])
                       if len(text) < BLOCKED_PAGE_MAX_CHARS else None)
            if len(text) >= BODY_MIN_CHARS and not blocked:
                return text, links
            direct_error = ("봇 차단 페이지({})".format(blocked.group(0)) if blocked
                            else "본문이 짧습니다")
        else:
            direct_error = "HTTP {}".format(getattr(response, "status_code", "?"))
    except Exception as error:
        direct_error = str(error)

    primary = _darkreading_primary_source(url)
    if primary:
        primary_url = primary["url"]
        try:
            response = network_safety.safe_get(
                primary_url, headers=REQUEST_HEADERS, timeout=FETCH_TIMEOUT_SECONDS)
            response.raise_for_status()
            text, links = _extract_article_content(_response_text(response), primary_url)
            if len(text) >= BODY_MIN_CHARS and primary["marker"].lower() in text.lower():
                links = [{"url": primary_url, "text": "분석 근거: {} 원문".format(primary["label"])}] + [
                    item for item in links if item["url"] != primary_url
                ][:MAX_LINKS - 1]
                log("    Dark Reading 인용 원문({}) {:,}자 수집".format(primary["label"], len(text)))
                return text, links
            direct_error = "인용 원문 본문 또는 주제 확인 실패"
        except Exception as error:
            direct_error = "{}; 인용 원문: {}".format(direct_error or "직접 수집 실패", error)

    log("[-] 본문 수집 실패({}): {}".format(url[:70], direct_error or "본문이 짧습니다"))
    return "", []


# 알려진 위협 행위자 이름. 분류가 위협 범주가 아닌 기사에서 "그래도 위협 사건인가"를
# 가리는 데 쓴다. 짧은 별칭은 일반 낱말과 겹쳐서 뺀다("apt", "ta", "cobalt" 같은 것들이
# 본문 아무 데나 걸린다).
_ACTOR_RE = None
ACTOR_MIN_CHARS = 7


def _actor_re():
    global _ACTOR_RE
    if _ACTOR_RE is None:
        aliases = (common_utils._load_intel("threat_actor_aliases") or {}).get("aliases") or {}
        names = sorted((name for name in aliases
                        if isinstance(name, str) and len(name) >= ACTOR_MIN_CHARS),
                       key=len, reverse=True)
        _ACTOR_RE = (re.compile(r"(?<![A-Za-z0-9])(?:"
                                + "|".join(re.escape(name) for name in names)
                                + r")(?![A-Za-z0-9])", re.I)
                     if names else re.compile(r"(?!)"))
    return _ACTOR_RE


def has_threat_substance(title, body):
    """분류가 위협 범주가 아니어도 실제 위협 사건을 다루는 기사인가.

    실측(Anthropic 위협 보고서 기사): 분류가 "기술동향"이라 비위협 분기를 타서
    [기술적 세부사항]·[MITRE ATT&CK]·[영향 범위 및 위험도]·[권장 대응] 네 섹션이
    통째로 빠졌다. 같은 기사에서 조사는 악성코드 2종·행위자 4곳·지표 72건을 찾아냈다.
    분석만 동향 기사처럼 얕게 쓰인 것이다.
    """
    text = " ".join([title or "", body or ""])
    if common_utils.extract_cves(text):
        return True
    if any((item.get("type") or "") in ("md5", "sha1", "sha256")
           for item in common_utils.extract_iocs(text)):
        return True
    return bool(_actor_re().search(text))


def build_prompt(title, body, category_hint):
    """analyze.js의 buildPrompt와 같은 구조 — 출력 형식이 달라지면 대시보드 파싱이 어긋난다."""
    threat = ((category_hint or "").strip() in THREAT_CATEGORIES
              or has_threat_substance(title, body))

    persona = ("당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다."
               if threat else "당신은 보안 전문 매체의 분석 기자다.")

    if threat:
        sections = (
            '[CVSS/심각도] 원문에 명시된 CVSS 점수·벡터 또는 심각도만 인용하라. '
            '없으면 "원문 미기재"로 적고, 종합 기사에는 단일 점수를 부여하지 마라.\n'
            '[기술적 세부사항] 단일 사건이면 원문에서 확인되는 침투·실행·지속화·확산·목적을 '
            '단계별 번호 목록으로 서술하라. 없는 단계는 지어내지 마라. 종합 기사라면 '
            '단계 대신 사건별 번호 목록으로 나누고 각 사건의 행위·수치·미확인 내용을 적어라. '
            'CVE, 제품·버전, 파일·경로, 명령, 지표 등 구체값은 원문대로 쓰라.\n'
            '[MITRE ATT&CK] 한 줄에 "기법 ID (기법 이름) - 사건명과 원문에서 확인되는 행위" '
            '형식으로 쓰라. ID·공식 정의·행위가 일치하는 경우만 포함하고, 세부 기법을 '
            '추정하지 마라. 근거가 없으면 "해당 없음"으로 적어라.\n'
            '[영향 범위 및 위험도] 제품·버전·대상과 규모를 원문 근거로 사건별로 쓰라. '
            '원문 보도, 분석자의 조건부 추론, 사내 영향 미확인을 구분하라.\n'
            '[권장 대응] 원문 근거가 있는 구체적인 조치 3~5개를 대상과 확인 방법으로 쓰라. '
            '원문에 없는 패치 버전·설정·기한을 만들지 말고 벤더 확인이 필요한 것으로 남겨라.\n'
        )
    else:
        sections = '[주요 내용] 본문의 핵심 사실·수치·일정·고유명사를 빠뜨리지 말고 구체적으로 서술하라(위협·공격을 전제로 지어내지 말 것). 5문장 이상.\n[의미와 영향] 보안 업계·기업·이용자에게 어떤 의미·영향이 있는지, 무엇이 달라지는지를 본문 근거로 쓰라. 3문장 이상.\n[참고 사항] 실무자가 확인·검토해볼 점 3개. "1."·"2."·"3." 번호를 붙여 한 줄에 한 항목씩 쓰고(한 줄에 여러 번호를 이어 쓰지 마라), 각 항목에 무엇을 어떻게 확인할지 함께 쓰고, 어느 기사에나 통하는 일반론은 쓰지 마라.\n'

    # 정보성 기사에서는 기사의 핵심 표준·제도·시스템이 곧 선수 지식이다. 실측(카테나-X
    # 기사): "이 기사에만 등장하는 제품·브랜드명 금지·최대 3개" 규칙 때문에 독자가 가장
    # 먼저 알아야 할 카테나-X·DPP 같은 이름이 빠지거나 한두 개로 잘렸다. 위협 기사는
    # 지금 규칙(3개, 기사 고유 제품명 금지)을 그대로 쓴다.
    if threat:
        glossary_rules = '- 고를 것: 특정 기술·기법·표준·시스템의 이름(예: Active Directory, RMM, 횡적 이동, DLL 사이드로딩, KCMVP)\n- 고르지 말 것: 실무자가 이미 아는 보안 상식어(악성코드, 피싱, 랜섬웨어, 자격 증명, 데이터 유출, 취약점, 보안 패치, 공급망 공격 등), 널리 알려진 서비스·회사명(GitHub, npm, AWS, Windows), 이 기사에만 등장하는 제품·브랜드명\n- 최대 3개까지만 쓰고, 개수를 채우려고 상식어를 넣지 마라. 기준에 맞는 용어가 하나도 없으면 항목 대신 "- 해당 없음" 한 줄만 써라.\n'
    else:
        glossary_rules = '- 고를 것: 이 기사의 핵심인 표준·제도·규제·시스템·기술의 이름을 먼저 골라라(예: 카테나-X, 데이터 스페이스, DPP, SBOM, 제로 트러스트). 기사를 이해하는 데 꼭 필요하면 기사에 나온 서비스·플랫폼 이름도 된다.\n- 고르지 말 것: 실무자가 이미 아는 보안 상식어(악성코드, 피싱, 랜섬웨어, 자격 증명, 데이터 유출, 취약점, 보안 패치, 공급망 공격 등), 널리 알려진 서비스·회사명(GitHub, npm, AWS, Windows), 회사·기관 이름 자체\n- 최대 5개까지만 쓰고, 개수를 채우려고 상식어를 넣지 마라. 기준에 맞는 용어가 하나도 없으면 항목 대신 "- 해당 없음" 한 줄만 써라.\n'

    return (persona + ' 아래 보안 관련 기사를 심층 분석해 한국어 존댓말로 작성하라.\n\n제목: ' + title
            + '\n\n출력의 맨 첫 줄에 이 기사가 다음 중 무엇에 해당하는지 정확히 하나만 골라 "[분류: 카테고리명]" 형식으로 써라(목록 밖의 이름을 만들지 마라) — 목록: ' + ", ".join(CATEGORY_CHOICES)
            + '. ' + CATEGORY_GUIDE
            + ' 그 다음 줄부터 아래 형식을 따라라.\n\n출력 형식:\n[핵심 요약] 2~3문장\n'
            + sections
            + '[선수 정보]\n- 용어명1: 이 용어를 모르면 위 분석을 이해할 수 없는 실무자를 위한 1문장 해설\n- 용어명2: 용어명1과 동일한 형태의 해설\n\n섹션 누락 금지: 위 출력 형식의 섹션을 맨 끝의 [조사 대상]까지 하나도 빠짐없이 순서대로 써라 — [권장 대응]이나 [선수 정보]에서 끝내지 마라. [조사 대상]은 도구가 읽는 마지막 섹션이라 빠지면 자동 조사가 통째로 돌지 않는다.\n\n번호 목록 작성 규칙: 번호(예: "1.")만 쓰고 뒤에 설명 문장을 비워두지 마라 — 쓰기로 한 항목은 반드시 같은 줄에 실질적인 문장으로 채우고, 번호는 1부터 순서대로 매겨라.\n\n강조 규칙: 각 섹션에서 가장 핵심적인 용어·수치·행위만 **이렇게** 볼드로 표시하라. 섹션당 2~4개로 제한하고, 문장 전체를 통째로 볼드 처리하지 마라.\n\n선수 정보 작성 규칙: 독자는 보안 실무자다. "이 단어를 모르면 위 분석을 못 읽는가"만 기준으로 삼아라.\n' + glossary_rules + '- 해설에 용어를 그대로 되풀이하지 마라. 그 용어가 무엇을 하는지, 이 기사에서 왜 중요한지를 써라.\n- 용어명은 본문에 나온 표기 그대로 쓰고 볼드(**)나 번호를 붙이지 마라.\n\n주의: 본문에 없는 사실을 지어내지 마라. 본문이 부실하면 그 사실을 그대로 밝혀라. 모든 출력은 한국어로만 쓰고 한자·중국어를 섞지 마라.'
            + '\n\n근거 규칙: 제목의 주된 사건을 중심으로 분석하라. 본문 끝에 관련 동향으로 병기된 별도 캠페인은 주된 사건의 공격 단계·IOC·조사 목표에 합치지 마라. 여러 독립 사건을 주제로 다룬 종합 기사라면 기존 섹션 안에서 사건별로 나누어 쓰고, 하나의 침투·실행·지속화·확산 체인으로 합치지 마라. 원문에 없는 단계는 "원문 미기재"로 남기고 다른 사건의 C2·파일·기법을 옮겨 붙이지 마라. 기사 출처·참고 문서 URL은 IOC나 조사 대상 URL로 넣지 마라. ATT&CK ID와 이름 및 실제 행위가 모두 맞는 경우만 쓰고, 추정 매핑은 생략하라. OAuth 정상 인증 흐름 악용을 비밀번호 탈취나 MFA 직접 우회로 바꾸어 쓰지 마라. 패치 버전·설정·기한을 임의로 보충하지 마라.'
            + analysis_flow.SPEC
            + analysis_targets.indicator_spec()
            + "\n\n본문:\n" + (body or "(본문을 가져오지 못해 제목만으로 분석합니다.)"))


CATEGORY_CHOICES = tuple(REPORT_CATEGORIES.split("|"))
# 분류 값에서 떼어낼 장식 문자 — 모델이 글자 사이에 넣는 구분자들이다.
CATEGORY_NOISE_RE = re.compile("[^가-힣A-Za-z0-9]+")


def normalize_category(raw):
    """모델이 준 분류 문자열을 허용 목록 중 하나로 맞춘다. 못 맞추면 빈 문자열.

    모델이 분류를 글자 단위로 흘려 쓸 때가 있다(실측: "공, 격, 캠, 페, 인",
    "공, 격, 캠, 페, 인, |"). 그대로 저장하면 대시보드 배지에 그 모양으로 찍힌다.
    잘려 오는 경우도 있어서("취약") 앞부분만 맞아도 받아 준다.
    """
    text = (raw or "").strip()
    if text in CATEGORY_CHOICES:
        return text
    # 구분자·공백·마크다운 기호를 걷어낸 뒤 다시 본다 — 글자 단위로 흘려 쓴 경우가
    # 여기서 원래 값으로 복구된다.
    squeezed = CATEGORY_NOISE_RE.sub("", text)
    if squeezed in CATEGORY_CHOICES:
        return squeezed
    if not squeezed:
        return ""
    # 잘렸거나 뒤에 군더더기가 붙은 경우. 한쪽이 다른 쪽으로 시작하면 같은 값으로 본다.
    for choice in CATEGORY_CHOICES:
        if squeezed.startswith(choice) or choice.startswith(squeezed):
            return choice
    return ""


def extract_category(text):
    """맨 앞의 "[분류: X]"를 떼어내 (카테고리, 나머지 본문)으로 나눈다."""
    match = CATEGORY_RE.search(text or "")
    if not match:
        return "", (text or "").strip()
    category = normalize_category(match.group(1))
    rest = (text[:match.start()] + text[match.end():]).lstrip("\n").strip()
    return category, rest


INLINE_NUMBER_RE = re.compile(r"(?<=\s)(\d{1,2})[.)]\s")


def split_inline_numbering(text):
    """한 줄에 이어 쓴 "1. … 2. … 3. …"을 줄로 나눈다.

    프롬프트가 한 줄에 한 항목을 요구해도 모델이 이어 쓸 때가 있다(실측: 카테나-X 건의
    [참고 사항]이 한 줄이라 화면에 항목 하나로 뭉쳤다). 1로 시작하는 줄에서 2, 3…이
    차례대로 나오는 자리만 나눈다 — "버전 1.2" 같은 숫자는 순서가 안 맞아 그대로 둔다.
    """
    out = []
    for line in (text or "").split("\n"):
        head = re.match(r"^(\s*\[[^\]\n]{1,20}\])\s*(?=1[.)]\s)", line)
        if head:
            # "[참고 사항] 1. …"처럼 헤더와 같은 줄에 붙은 목록은 헤더를 떼어 둔다.
            out.append(head.group(1).strip())
            line = line[head.end():]
        if not re.match(r"^\s*1[.)]\s", line):
            out.append(line)
            continue
        cuts, expected = [], 2
        for match in INLINE_NUMBER_RE.finditer(line):
            if int(match.group(1)) == expected:
                cuts.append(match.start())
                expected += 1
        if not cuts:
            out.append(line)
            continue
        start = 0
        for cut in cuts:
            out.append(line[start:cut].rstrip())
            start = cut
        out.append(line[start:].rstrip())
    return "\n".join(out)


def extract_glossary(text):
    """[선수 정보] 섹션을 {용어: 해설}로. 대시보드가 본문에서 용어를 찾아 툴팁을 단다."""
    match = GLOSSARY_SECTION_RE.search(text or "")
    if not match:
        return {}
    glossary = {}
    for term, definition in GLOSSARY_ITEM_RE.findall(match.group(1)):
        term = re.sub(r"^[\s*_`~]+|[\s*_`~]+$", "", term).strip()
        definition = definition.strip()
        if not term or not definition or term == "해당 없음":
            continue
        # 대시보드(normalizeGlossary)와 같은 기준 — 형태가 깨진 건 버린다.
        if len(term) > GLOSSARY_TERM_MAX_CHARS or re.search(r"[\[\]]", term):
            continue
        if re.search(r"[.!?]$", term) or term.isdigit():
            continue
        glossary[term] = definition
    return glossary


# 옛 형식(콤마 나열)으로 생성된 분석에는 기법별 행위 서술이 없다. 그런 기록은 본문
# [기술적 세부사항]에서 그 기법을 설명하는 문장을 찾아 붙인다 — 없는 것보다 낫고,
# 억지로 붙이면 틀리므로 낱말이 2개 이상 겹칠 때만 채택한다.
TECH_SECTION_RE = re.compile(
    "\\[\\s*기술적\\s*세부사항\\s*\\]\\s*(.*?)(?=\\n\\s*\\[|\\Z)",
    re.S,
)
TOKEN_RE = re.compile(r"[가-힣]{2,}|[A-Za-z][A-Za-z0-9._-]{2,}")
STOP_TOKENS = {"기법", "공격", "사용", "이용", "실행", "통해", "위한", "하는", "한다", "된다",
               "그리고", "또는", "등의", "관련", "기반", "형태", "경우", "위해", "with", "from",
               "that", "this", "into", "using", "user", "file", "data"}
MIN_TOKEN_HITS = 2


def _sentences(text):
    parts = re.split("(?<=[.!?다])" + BS + "s+|" + BS + "n+", text or "")
    return [p.strip(" -*•") for p in parts if len(p.strip()) > 20]


def _clean_evidence(text):
    """행위 서술을 화면에 넣을 형태로 다듬는다.

    본문에서 잘라온 문장이라 마크다운 볼드(**)와 백틱이 섞여 있고, 앞에 "3. 지속화:"
    같은 단계 번호가 붙어 있다. 그대로 두면 화면에 별표가 그대로 보인다.
    """
    text = re.sub(r"[*`]+", "", str(text or "")).strip()
    text = re.sub(r"^" + BS + r"d+" + BS + r".\s*", "", text)          # "3. " 제거
    text = re.sub(r"^[가-힣 ]{2,10}[:：]\s*", "", text)                  # "지속화: " 제거
    text = " ".join(text.split())
    if len(text) > 170:
        cut = text.rfind(" ", 0, 170)
        text = (text[:cut] if cut > 100 else text[:170]).rstrip(" ,·") + "…"
    return text


def mitre_evidence_from_body(text, name, official=""):
    """기법 이름과 본문 문장의 낱말 겹침으로 "이 사건에서의 행위" 문장을 찾는다."""
    section = TECH_SECTION_RE.search(text or "")
    if not section or not (name or official):
        return ""
    wanted = {t.lower() for t in TOKEN_RE.findall("{} {}".format(name, official))
              if t.lower() not in STOP_TOKENS}
    if not wanted:
        return ""
    # 낱말 단위 일치로 세면 한국어 조사에 걸린다("예약 작업" vs "예약 작업으로").
    # 포함 여부로 센다.
    def hits(text_block):
        lowered = text_block.lower()
        return [token for token in wanted if token in lowered]

    best, best_hits = "", []
    for sentence in _sentences(section.group(1)):
        matched = hits(sentence)
        if len(matched) > len(best_hits):
            best, best_hits = sentence, matched
    # 낱말 하나만 겹칠 때는 그 낱말이 충분히 특징적일 때만 받는다("사이드로딩" 같은).
    if not best_hits or (len(best_hits) < MIN_TOKEN_HITS
                         and max(len(token) for token in best_hits) < 4):
        return ""
    # 문장이 길면 겹치는 낱말이 있는 절만 남긴다.
    clauses = [c.strip() for c in re.split("(?<=[,·])" + BS + "s*", best) if c.strip()]
    for clause in clauses:
        if len(clause) > 15 and len(hits(clause)) >= len(best_hits):
            return _clean_evidence(clause)
    return _clean_evidence(best)


def extract_mitre(text):
    """[MITRE ATT&CK] 섹션의 기법 ID를 공식 카탈로그로 검증해 반환(환각 차단)."""
    match = MITRE_SECTION_RE.search(text or "")
    if not match:
        return []
    return common_utils.validate_attack_techniques(re.findall(r"T\d{4}(?:\.\d{3})?", match.group(1)))


MITRE_LABEL_RE = re.compile(r"(T" + BS + "d{4}(?:" + BS + ".\d{3})?)" + BS + "s*" + BS + "(([^)]{2,90})" + BS + ")")


def mitre_labels(text):
    """본문 MITRE 섹션의 "T1574.001 (실행 흐름 하이재킹: DLL 사이드로딩)"에서 우리말 라벨을 뽑는다."""
    labels = {}
    for match in MITRE_LABEL_RE.finditer(text or ""):
        label = match.group(2).strip()
        if label and match.group(1) not in labels:
            labels[match.group(1)] = label
    return labels


# "T1574.001 (DLL 사이드로딩) — LockScreenContentServer.exe가 dui70.dll을 로드" 형태에서
# 기법 이름과 "기사에서 관측된 행위"를 나눠 뽑는다. 기법 나열만으로는 그 기법이 이 사건에서
# 무엇으로 나타났는지 알 수 없다.
MITRE_EVIDENCE_RE = re.compile(
    r"(T" + BS + r"d{4}(?:" + BS + r".\d{3})?)"          # 기법 ID
    r"(?:" + BS + r"s*" + BS + r"(([^)]{2,90})" + BS + r"))?"   # (기법 이름)
    r"(?:" + BS + r"s*[-—–:]" + BS + r"s*([^" + BS + r"n]{4,300}))?")  # — 관측된 행위


def mitre_evidence(text):
    """{기법 ID: {"name": 기법 이름, "evidence": 관측된 행위}}.

    행위 서술이 없으면 evidence는 빈 문자열이다 — 옛 형식(콤마 나열)으로 생성된
    분석에서는 이름만 얻는다.
    """
    section = MITRE_SECTION_RE.search(text or "")
    if not section:
        return {}
    found = {}
    for line in section.group(1).splitlines():
        line = line.strip().lstrip("-*• ").strip()
        if not line:
            continue
        for match in MITRE_EVIDENCE_RE.finditer(line):
            technique_id = match.group(1)
            if technique_id in found:
                continue
            evidence = (match.group(3) or "").strip(" .,;")
            # 한 줄에 여러 기법을 콤마로 나열한 옛 형식이면 뒤 내용이 다음 기법이다 —
            # 그건 행위 서술이 아니므로 버린다.
            if evidence and re.match(r"^T" + BS + r"d{4}", evidence):
                evidence = ""
            found[technique_id] = {"name": (match.group(2) or "").strip(),
                                   "evidence": evidence}
    return found


def build_attack_groups(analysis, ids=None):
    """기법을 전술별로 묶고, 각 기법에 "이 사건에서 무엇을 했는지"를 붙인다.

    ids를 주면 그것을 쓴다 — 옛 기록은 본문에 [MITRE ATT&CK] 섹션 형식이 달라
    extract_mitre가 못 찾지만, 저장된 기법 목록은 남아 있다.
    """
    ids = ids or extract_mitre(analysis)
    if not ids:
        return []
    parsed = mitre_evidence(analysis)
    labels, evidence, used_evidence = {}, {}, set()
    for technique_id in ids:
        info = parsed.get(technique_id) or {}
        name = info.get("name") or common_utils.attack_technique_name(technique_id)
        labels[technique_id] = name
        detail = _clean_evidence(info.get("evidence") or "")
        if not detail:
            detail = mitre_evidence_from_body(
                analysis, name, common_utils.attack_technique_name(technique_id))
        # 같은 문장이 여러 기법에 붙으면 같은 말을 반복해 읽게 된다 — 처음 기법에만 둔다.
        # 절만 잘라낸 것과 문장 전체가 따로 잡히므로 앞부분으로 같은 문장인지 판단한다.
        head = re.sub(r"\s+", "", detail)[:30]
        if detail and head and head not in used_evidence:
            used_evidence.add(head)
            evidence[technique_id] = detail

    groups = common_utils.group_attack_techniques(ids, labels=labels)
    for group in groups:
        for item in group["items"]:
            if evidence.get(item["id"]):
                item["evidence"] = evidence[item["id"]]
    return groups


def analyze_one(job):
    """요청 하나를 분석해 저장용 레코드를 만든다. 실패 시 None."""
    url = source_evidence.article_url(job.get("url"))
    title = (job.get("title") or "").strip()
    if not url or not title:
        log("[-] url/title이 없는 요청 — 건너뜁니다")
        return None

    body, links = fetch_article_text(url)
    primary = _darkreading_primary_source(url)
    fallback_url = (primary["url"] if primary and any(
        link.get("url") == primary["url"] and str(link.get("text") or "").startswith("분석 근거:")
        for link in links) else "")
    source = job.get("source_label") or "?"
    if body:
        log("    본문 {:,}자 수집 ({})".format(len(body), source))

    # 원문을 못 읽었으면 분석하지 않는다. 제목만으로 만든 분석은 근거가 없고, 화면에서
    # 정상 분석과 구별되지 않아 더 위험하다 — 실패 사실을 그대로 저장해 보여 준다.
    # 짧은 페이지에서만 차단 표현을 신호로 본다. 긴 본문에 그 표현이 있는 것은
    # 그 주제를 다루는 기사이기 때문이다.
    blocked = (BLOCKED_PAGE_RE.search(body[:2000])
               if body and len(body) < BLOCKED_PAGE_MAX_CHARS else None)
    if not body or len(body) < BODY_MIN_CHARS or blocked:
        reason = ("봇 차단·로그인 벽 페이지가 반환됐습니다({})".format(blocked.group(0))
                  if blocked else
                  "본문이 {}자밖에 수집되지 않았습니다".format(len(body)) if body else
                  "본문을 가져오지 못했습니다")
        log("[-] 원문 수집 실패 — 분석하지 않습니다: {} / {}".format(source, reason))
        return {
            "ref": job.get("ref"),
            "title": title,
            "url": url,
            "source_label": source,
            "analysis": ("[원문 수집 실패]\n{}. 원문을 읽지 못한 상태로 분석하면 제목만 보고 "
                         "지어낸 내용이 되므로 분석을 진행하지 않았습니다. 기사 링크로 직접 "
                         "확인하시고, 사이트가 봇을 막는 경우라면 소스 설정을 조정해야 "
                         "합니다.".format(reason)),
            "links": links,
            "iocs": [],
            "category": job.get("category") or "",
            "attack_techniques": [],
            "attack_grouped": [],
            "glossary": {},
            "investigation": {},
            "collection_failed": True,
            "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    focused_body, focused_links = _focus_article(body, links)
    if focused_body != body:
        log("    관련 캠페인 단락 분리: 주기사 {:,}자 / 별도 사례 {:,}자".format(
            len(focused_body), len(body) - len(focused_body)))
    body, links = focused_body, focused_links
    analysis_body = body[:BODY_MAX_CHARS]
    if fallback_url:
        analysis_body = ("Dark Reading 기사 본문은 접근이 제한되어, 해당 기사가 직접 인용한 "
                         "{}의 연구 원문을 분석 근거로 사용합니다. 이 자료의 내용만 원문 "
                         "사실로 취급하고 Dark Reading 자체의 추가 보도는 추정하지 마세요.\n\n{}"
                         .format(primary["label"], analysis_body))
    prompt = build_prompt(title, analysis_body, job.get("category") or "")

    started = time.time()
    # [조사 대상] 목록은 분석문 맨 끝에 온다. 추론 모델이 기본 8192 토큰에서 잘리면 그
    # 목록부터 잘려 조사 입력이 통째로 빈다(실측 2026-09-26: 같은 기사가 21,635자 →
    # 4,988자로 잘렸다). 판단 호출과 같은 상한을 쓴다.
    stage_client, _ = worker_progress.current()
    base_digest = worker_progress.fingerprint(
        prompt, common_utils.LLM_PROVIDERS, common_utils.NVIDIA_MODEL,
        common_utils.OLLAMA_MODEL, response_synth.SYNTH_MAX_TOKENS)
    raw = worker_progress.load(stage_client, job.get("ref"), "base", base_digest)
    if raw:
        log("    기본 분석 체크포인트 재사용")
    else:
        raw = common_utils.llm_generate(prompt, timeout=response_synth.SYNTH_TIMEOUT,
                                        nvidia_max_attempts=3,
                                        max_tokens=response_synth.SYNTH_MAX_TOKENS)
        if raw:
            worker_progress.save(stage_client, job.get("ref"), "base", base_digest, raw)
    if not raw:
        log("[-] LLM 생성 실패: {}".format(title[:50]))
        return None
    log("    LLM {:.1f}초 / {:,}자".format(time.time() - started, len(raw)))

    category, analysis = extract_category(raw)
    analysis, flow_candidate = analysis_flow.split(analysis)
    # 기계용 목록을 먼저 떼어낸다. 남겨 두면 화면에 "도메인: 없음" 같은 줄이 그대로
    # 보이고, 뒤따르는 섹션 파서들도 이 섹션을 본문으로 오인한다.
    targets = analysis_targets.parse(analysis)
    analysis = analysis_targets.strip(analysis)
    if fallback_url:
        analysis = ("[분석 근거] Dark Reading 본문 접근이 제한되어, 이 기사가 인용한 "
                    "{}의 연구 원문을 분석했습니다.\n\n{}".format(primary["label"], analysis))
    # 섹션이 빠지면 조사 입력이 정규식 추출분만 남아 트랙이 덜 선다. 조용히 넘어가면
    # "조사할 게 없는 기사"와 구별되지 않으므로 로그에 남긴다(실측: 프롬프트가
    # "[선수 정보]까지 쓰라"고 못박고 있어서 모델이 이 섹션을 건너뛴 회차가 있었다).
    if not targets:
        log("[-] [조사 대상] 섹션이 응답에 없습니다 — 조사 입력은 정규식 추출분만 씁니다.")
    else:
        log("    조사 대상: {}".format(", ".join(
            "{} {}개".format(key, len(value))
            for key, value in sorted(targets.items()) if isinstance(value, list) and value)
            or "값 없음"))
    # 정규식 추출과 LLM이 준 목록을 합친다. 정규식은 원문에 문자 그대로 있는 것만
    # 잡고, LLM은 우리말로 풀어 쓴 것까지 잡는다 — 둘의 사각지대가 다르다.
    iocs = analysis_targets.merge_iocs(common_utils.extract_iocs(body), targets)
    source_urls = [url, fallback_url] if fallback_url else [url]
    iocs, _ = source_evidence.filter_iocs(iocs, source_urls)
    targets = source_evidence.filter_targets(targets, source_urls)
    iocs = source_evidence.assess_iocs(iocs, [{"url": fallback_url or url, "text": body}])
    targets = source_evidence.restrict_targets(targets, iocs)

    kind = article_kind.classify(category or job.get("category") or "", targets, iocs,
                                 threat_substance=has_threat_substance(title, body),
                                 text=title + "\n" + analysis)
    targets["article_kind"] = kind["kind"]
    targets["article_subtype"] = kind["subtype"]
    targets["article_kind_reason"] = kind["reason"]
    log("    기사 유형: {} ({})".format(kind["kind"], kind["reason"]))
    flow = analysis_flow.validate(flow_candidate, analysis_body,
                                  category or job.get("category") or "", targets,
                                  fallback_url or url)

    # The article analysis is complete here. Decide which of its issues warrant
    # investigation before choosing external lookups.
    try:
        decisions = issue_decision.decide(title, analysis_body, analysis, targets)
        if decisions:
            targets = issue_decision.apply(targets, decisions)
        else:
            targets["decision_status"] = "failed"
            log("[-] 이슈별 판단 실패 — 기존 조사 후보로 진행합니다.")
    except Exception as error:
        log("[-] 이슈별 판단 예외 — 원문·기본 분석으로 조사 후보를 복구합니다: {}".format(error))
        try:
            targets = issue_decision.apply(
                targets, issue_decision.fallback(title, analysis_body, analysis, targets))
        except Exception as fallback_error:
            targets["decision_status"] = "failed"
            log("[-] 이슈별 판단 복구 실패: {}".format(fallback_error))

    # 조사&대응 — 사건 성격에 따라 조사 방향이 갈린다. 사용자 행위 기반(ClickFix 등)은
    # 유포지를 urlscan으로 추적하고, 악성코드 기반은 VT 동적 분석으로 실제 행위를 본다.
    # 분석 본문이 "기사가 말한 것"이라면 이 블록은 "지금 공개 관측치가 말하는 것"이다.
    # 실패해도 분석 결과는 그대로 저장한다.
    investigation_block = None
    try:
        investigation_digest = worker_progress.fingerprint(
            title, analysis, targets, iocs, body[:BODY_MAX_CHARS],
            os.environ.get("BROWSER_RESEARCH_ENABLED"),
            os.environ.get("BROWSER_RESEARCH_ISOLATED_WORKER"))
        investigation_block = worker_progress.load(
            stage_client, job.get("ref"), "investigation", investigation_digest)
        if investigation_block:
            log("    조사 체크포인트 재사용")
        # 원문 발췌도 함께 넘긴다 — 패턴 합성의 근거 확인은 우리말 분석문만으로는
        # 부족하다(URL·경로·명령줄은 원문에만 원형으로 남는 경우가 있다).
        if investigation_block is None:
            investigation_block = investigation.build_for_article(
                iocs, text=analysis, title=title, category=category or "",
                body=body[:BODY_MAX_CHARS], targets=targets, links=links, article_url=url)
            if investigation_block and (investigation_block.get("synthesis_status") or {}).get("status") != "failed":
                worker_progress.save(stage_client, job.get("ref"), "investigation",
                                     investigation_digest, investigation_block)
        if investigation_block:
            route = investigation_block.get("route") or {}
            log("    조사&대응: {} / 시드 {}개 / 악성코드 {}건".format(
                route.get("label") or "-", len(investigation_block.get("seeds") or []),
                len((investigation_block.get("malware") or {}).get("files") or [])))
    except Exception as error:
        log("[-] 조사&대응 생성 실패(분석 결과에는 영향 없음): {}".format(error))

    analysis = split_inline_numbering(analysis)
    if article_kind.is_informational(targets) and investigation_block:
        reading = investigation_block.get("reading_list") or []
        if reading:
            import briefing
            analysis += "\n\n" + briefing.reading_section(investigation_block)

    return {
        "ref": job.get("ref"),
        "title": title,
        "url": url,
        "source_label": job.get("source_label") or "",
        "source_fallback_url": fallback_url,
        "analysis": analysis,
        "analysis_flow": flow,
        "links": links,
        "iocs": source_evidence.display_iocs(iocs),
        "category": category,
        "attack_techniques": extract_mitre(analysis),
        # 전술(킬체인 단계)별로 묶어 둔다 — 기법 ID를 20개씩 한 줄에 나열하면 읽히지
        # 않는다. 라벨은 본문의 우리말 설명을 먼저 쓰고, 없으면 공식 영문명을 쓴다.
        "attack_grouped": build_attack_groups(analysis),
        "glossary": extract_glossary(analysis),
        "investigation": investigation_block or {},
        # LLM이 뽑아 준 조사 대상. 화면에는 안 쓰지만, 트랙이 왜 섰는지/안 섰는지를
        # 나중에 되짚으려면 이 값이 남아 있어야 한다 — 없으면 프롬프트가 문제인지
        # 파서가 문제인지 구별할 수 없다.
        "targets": targets,
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def store_result(client, record):
    """analyze.js와 같은 키·형식으로 저장 — 대시보드 표시 코드를 그대로 쓴다."""
    # 인증 없는 공개 API(insights.js)가 이 레코드를 그대로 반환한다. analysis·
    # investigation·targets는 모델이 자유 서술로 쓰는 필드라 environment_brief()로
    # 넣어 준 보유 제품군·PIR을 "출력에 쓰지 마라"는 프롬프트 지시 하나에만 기대고
    # 있었다. 실측(2026-09-22): "당사 관리 자산 목록(Arista, Juniper, Citrix,
    # Fortigate 등)", "우리 환경: Windows 단말 보유"가 investigation에, "사내 자산
    # 목록(inventory.yml)과 대조하여"가 [권장 대응] 섹션(analysis)에 그대로 나갔다 —
    # 같은 environment_brief() 출력을 analysis_targets.spec()과 investigation 양쪽이
    # 나눠 쓰므로 두 필드 다 같은 위험을 안는다. 프롬프트 지시는 그대로 두고, 저장
    # 직전에 한 번 더 기계적으로 막는다 — 모델이 지시를 어겨도 새는 문장이 밖으로
    # 안 나가게.
    product_names = common_utils.inventory_product_terms()
    if record.get("analysis"):
        record["analysis"] = dashboard_text.redact_private_environment(
            record["analysis"], product_names)
    if record.get("investigation") is not None:
        record["investigation"] = dashboard_text.redact_private_environment(
            record["investigation"], product_names)
    if record.get("targets") is not None:
        record["targets"] = dashboard_text.redact_private_environment(
            record["targets"], product_names)
    if record.get("analysis_flow") is not None:
        record["analysis_flow"] = dashboard_text.redact_private_environment(
            record["analysis_flow"], product_names)

    # 없는 키는 비워 둔다. 수집 실패 기록처럼 일부 필드가 아예 없는 경우가 있어,
    # 인덱싱으로 꺼내면 저장이 통째로 실패한다(실측: 'targets' KeyError로 기록이
    # 저장되지 않았다).
    cached = {key: record.get(key) for key in
              ("analysis", "links", "iocs", "category", "attack_techniques", "glossary",
               "attack_grouped", "investigation", "targets", "analysis_flow")}
    if record.get("collection_failed"):
        # 원문 접근 실패는 일시적일 수 있다. 실패 문구를 90일 캐시하면 사이트가
        # 복구되어도 같은 기사가 계속 실패 상태로 남으므로, 이력에만 남기고 다음
        # 요청이 다시 수집을 시도하게 한다.
        client.delete("analysis:" + record["ref"])
    else:
        cached["partial"] = (record.get("investigation") or {}).get("synthesis_status", {}).get("status") == "failed"
        client.set("analysis:" + record["ref"], json.dumps(cached, ensure_ascii=False),
                   ex=ANALYSIS_CACHE_TTL_SECONDS)

    # 같은 ref가 이미 있으면 최신 결과로 교체한다(analyze.js의 upsertInsightRecord와 동일).
    existing = client.lrange(INSIGHTS_LIST_KEY, 0, -1)
    kept = []
    for item in existing:
        try:
            if json.loads(item).get("ref") == record["ref"]:
                continue
        except (ValueError, TypeError):
            pass
        kept.append(item)
    kept.append(json.dumps(record, ensure_ascii=False))
    kept = kept[-MAX_INSIGHTS_LIST_SIZE:]

    pipe = client.pipeline()
    pipe.delete(INSIGHTS_LIST_KEY)
    if kept:
        pipe.rpush(INSIGHTS_LIST_KEY, *kept)
    pipe.execute()


# 회차가 겹치는 것을 막는 잠금. 예약 작업 자체는 MultipleInstances=IgnoreNew로 겹치지
# 않지만, 손으로 돌리는 실행과는 겹친다(실측: 개발 중 여러 번 그랬다). 한 기사가
# 분석 150초 + 패턴 합성 60~150초 + 종합 판단 160초로 400초를 넘기니, 같은 큐를 두
# 프로세스가 동시에 pop하면 같은 기사를 두 번 분석하거나 결과를 서로 덮어쓴다.
LOCK_FILE = common_utils.STATE_DIR / "analysis_worker.lock"
# 한 회차가 이보다 오래 걸릴 일은 없다. 프로세스가 죽어 잠금만 남은 경우를 회수한다.
LOCK_STALE_SECONDS = 30 * 60


@contextlib.contextmanager
def run_lock():
    """이미 돌고 있으면 실행하지 않는다(기다리지 않는다).

    기다리게 하면 5분마다 뜨는 회차가 줄줄이 쌓인다 — 큐는 다음 회차에 처리되니
    이번 회차는 그냥 넘기는 것이 맞다.
    """
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    try:
        fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            age = time.time() - LOCK_FILE.stat().st_mtime
        except OSError:
            age = 0
        if age > LOCK_STALE_SECONDS:
            log("[!] 오래된 잠금을 회수합니다(주인 프로세스가 죽은 것으로 판단, {:.0f}분).".format(
                age / 60))
            try:
                LOCK_FILE.unlink()
                fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except OSError:
                pass
        if fd is None:
            log("[*] 앞 회차가 아직 돌고 있어 이번 회차는 건너뜁니다.")
            yield False
            return
    try:
        os.write(fd, str(os.getpid()).encode())
        yield True
    finally:
        os.close(fd)
        try:
            LOCK_FILE.unlink()
        except OSError:
            pass


def main():
    with run_lock() as acquired:
        if not acquired:
            return
        _run_once()


def process_summary_job(client):
    raw = client.lpop(SUMMARY_QUEUE_KEY)
    if raw is None:
        return False
    try:
        job = json.loads(raw)
        report_id = job["id"]
    except (ValueError, KeyError, TypeError):
        log("[-] 일일 요약 요청 형식이 잘못되어 버립니다.")
        return True

    lock_key = "report-summary:lock:" + report_id
    error_key = "report-summary:error:" + report_id
    try:
        base_url = os.environ.get("REPORT_DASHBOARD_URL", "https://boannews-vercel.vercel.app").rstrip("/")
        response = requests.get(base_url + "/data/daily-latest.json", timeout=15)
        response.raise_for_status()
        report = response.json()
        if report.get("period") != "daily" or report.get("generated_at") != report_id:
            raise ValueError("보고서가 갱신되어 이전 요청을 처리하지 않았습니다.")
        from report_briefing import narrative_problem
        if not narrative_problem(report.get("narrative")):
            raise ValueError("현재 보고서에는 이미 AI 요약이 있습니다.")

        from generate_report import refresh_public_summary
        refresh_public_summary(report)
        if report["briefing"]["status"] != "ready":
            raise ValueError("요약할 기사 근거가 부족합니다.")
        result_key = "report-summary:result:" + report_id
        client.set(result_key, json.dumps({"id": report_id, "narrative": report["narrative"],
                                          "briefing": report["briefing"]}, ensure_ascii=False),
                   ex=SUMMARY_RESULT_TTL_SECONDS)
        client.delete(error_key)
        log("[+] 일일 AI 요약 재생성 완료: {}".format(report_id))
    except Exception as error:
        log("[-] 일일 AI 요약 재생성 실패: {}".format(error))
        client.set(error_key, "요약 생성에 실패했습니다. 잠시 후 다시 시도해 주세요.", ex=300)
    finally:
        client.delete(lock_key)
    return True


def _run_once():
    client = get_client()
    if client is None:
        log("[-] REDIS_URL이 없거나 연결할 수 없어 건너뜁니다.")
        return

    deadline = time.time() + RUN_BUDGET_SECONDS
    recovered = worker_progress.recover_expired(client, QUEUE_KEY)
    promoted = worker_progress.promote_retries(client, QUEUE_KEY)
    if recovered or promoted:
        log("[*] 중단 작업 {}건 회수, 재시도 {}건 재등록".format(recovered, promoted))
    if process_summary_job(client) and time.time() >= deadline:
        log("[*] 일일 요약 처리로 이번 회차 예산을 사용했습니다.")
        return

    pending = client.llen(QUEUE_KEY)
    if not pending:
        log("[*] 대기 중인 분석 요청이 없습니다.")
        return
    log("[*] 대기 중인 분석 요청 {}건".format(pending))

    done = 0
    for _ in range(MAX_ITEMS_PER_RUN):
        if time.time() >= deadline:
            log("[*] 이번 회차 예산 소진 — 나머지는 다음 실행에서 처리합니다.")
            break

        raw = worker_progress.claim(client, QUEUE_KEY)
        if raw is None:
            break
        try:
            job = json.loads(raw)
        except ValueError:
            log("[-] 큐 항목 파싱 실패 — 버립니다")
            worker_progress.release(client, raw)
            continue

        log("[*] 분석 시작: {}".format((job.get("title") or "")[:60]))
        campaign_radar.mark_analysis_status(client, job, "running")
        record_digest = worker_progress.fingerprint(
            job.get("ref"), job.get("url"), job.get("title"))
        record = (worker_progress.load(client, job.get("ref"), "record", record_digest)
                  if job.get("_retry_count") else None)
        try:
            if record is None:
                token = worker_progress.activate(client, job.get("ref"))
                try:
                    record = analyze_one(job)
                finally:
                    worker_progress.reset(token)
        except Exception as error:  # 한 건의 실패가 나머지를 막지 않게
            log("[-] 분석 중 예외: {}".format(error))
            record = None

        if not record:
            retry = worker_progress.defer_retry(client, job)
            log("[-] 실패 — {}: {}".format(
                "재시도 예약" if retry else "재시도 한도 도달",
                (job.get("title") or "")[:50]))
            campaign_radar.mark_analysis_status(client, job, "queued" if retry else "failed")
            worker_progress.release(client, raw)
            continue

        try:
            store_result(client, record)
            worker_progress.clear(client, job.get("ref"), "record")
            synthesis_failed = (record.get("investigation") or {}).get(
                "synthesis_status", {}).get("status") == "failed"
            retry = worker_progress.defer_retry(client, job) if synthesis_failed else False
            campaign_radar.mark_analysis_status(
                client, job, "failed" if record.get("collection_failed") or
                (synthesis_failed and not retry) else "queued" if retry else "completed")
            done += 1
            log("[+] 저장 완료: {}".format(record["title"][:60]))
        except Exception as error:
            log("[-] 결과 저장 실패: {}".format(error))
            worker_progress.save(client, job.get("ref"), "record", record_digest, record)
            retry = worker_progress.defer_retry(client, job)
            campaign_radar.mark_analysis_status(client, job, "queued" if retry else "failed")
        finally:
            worker_progress.release(client, raw)

    log("[+] 이번 회차 {}건 처리 (남은 대기 {}건)".format(done, client.llen(QUEUE_KEY)))


if __name__ == "__main__":
    main()
