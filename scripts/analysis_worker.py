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

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

import analysis_targets
import common_utils
import investigation

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

try:
    import redis
except ImportError:  # requirements.txt에 있지만 설치가 빠진 환경 방어
    redis = None

QUEUE_KEY = "analysis:queue"
INSIGHTS_LIST_KEY = "insights:list"
MAX_INSIGHTS_LIST_SIZE = 300          # analyze.js와 같은 값이어야 목록이 어긋나지 않는다
ANALYSIS_CACHE_TTL_SECONDS = 60 * 60 * 24 * 90

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
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 boannews-analyzer/1.0"
    )
}

REPORT_CATEGORIES = "취약점|악성코드|침해사고|개인정보유출|공격캠페인|공급망공격|피싱사기|정책규제|기술동향|제품행사|기타"
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
MAX_LINKS = 6


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
    text = common_utils.clean_text(anchor.get_text(" ", strip=True))[:110]
    if not text:
        return None      # 문구 없는 <a>는 아이콘·배너 같은 껍데기다
    return {"url": href, "text": text}


def fetch_article_text(url):
    """기사 원문에서 본문 텍스트와 참고 링크를 뽑는다. 실패 시 ("", [])."""
    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=FETCH_TIMEOUT_SECONDS)
        response.raise_for_status()
    except Exception as error:
        log("[-] 본문 수집 실패({}): {}".format(url[:70], error))
        return "", []

    # 인코딩은 선언을 우선하되(대부분 utf-8), 구형 국내 페이지(cp949)도 읽는다.
    raw = response.content
    for encoding in ("utf-8", "cp949"):
        try:
            html = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        html = raw.decode("utf-8", errors="replace")

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
        tag.decompose()

    # 셀렉터를 순서대로 시도해 "처음 맞는 것"을 쓰면 안 된다 — 사이트에 따라 앞쪽
    # 후보가 껍데기만 감싸고 있다(실측: The Hacker News의 <article>은 148자인데
    # .post-body는 19,795자). 후보를 모두 뽑아 본문이 가장 긴 것을 고른다.
    best_text = ""
    best_node = None
    for selector in ("#article-view-content-div", "#articleBody", ".article-body",
                     ".articlebody", ".post-body", "#news_content", "article", "main"):
        for node in soup.select(selector):
            text = common_utils.clean_text(node.get_text(" ", strip=True))
            if len(text) > len(best_text):
                best_text, best_node = text, node
    # 어느 후보도 본문답지 않으면 페이지 전체를 쓴다(내비게이션이 섞이지만 없는 것보단 낫다).
    if len(best_text) < 500:
        whole = common_utils.clean_text(soup.get_text(" ", strip=True))
        if len(whole) > len(best_text):
            best_text, best_node = whole, soup

    target = best_node if best_node is not None else soup
    text = best_text
    links, seen = [], set()
    for anchor in target.find_all("a", href=True):
        link = _normalize_link(anchor, url)
        if not link or link["url"] in seen:
            continue
        seen.add(link["url"])
        links.append(link)
        if len(links) >= MAX_LINKS:
            break
    return text, links


def build_prompt(title, body, category_hint):
    """analyze.js의 buildPrompt와 같은 구조 — 출력 형식이 달라지면 대시보드 파싱이 어긋난다."""
    threat = (category_hint or "").strip() in THREAT_CATEGORIES

    persona = ("당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다."
               if threat else "당신은 보안 전문 매체의 분석 기자다.")

    if threat:
        sections = '[CVSS/심각도] 본문에 CVSS 점수·벡터가 명시돼 있으면 그대로 인용하라. 점수는 없고 심각도 등급(Critical/High/Medium/Low)만 언급됐으면 그 등급만 쓰라. 점수도 등급도 본문에 전혀 없으면 공격 벡터·필요 권한·영향 범위를 근거로 하나를 판단하되 반드시 "(본문에 명시 안 됨 — 추정)"이라고 표시하고 근거를 한 문장 덧붙여라 — 공식 수치인 것처럼 지어내지 마라.\n[기술적 세부사항] 공격 체인을 침투 → 실행 → 지속화 → 확산 → 목적 달성 순서로 서술하라. 반드시 단계마다 줄을 바꾸고 번호를 붙여라 — "1. 침투: ..." 형식으로 한 줄에 한 단계씩 쓰고, 여러 단계를 한 문단에 이어 쓰지 마라(화면에서 구분되지 않아 읽을 수 없다). 본문에 나온 구체값(CVE 번호, 영향받는 제품·버전, 파일명·경로, 실행 명령어, 도메인·IP·해시, 포트, 계정·패키지 이름, 수치)은 빠뜨리지 말고 그대로 인용하라. "악성코드를 삽입했습니다" 같은 뭉뚱그린 서술은 쓰지 마라. 단계별 1~3문장.' + '[MITRE ATT&CK] 본문에서 확인되는 공격 기법을 한 줄에 하나씩 쓰라. 형식은 "T1574.001 (DLL 사이드로딩) — LockScreenContentServer.exe가 같은 폴더의 악성 dui70.dll을 로드"처럼 [기법 ID] ([기법 이름]) — [기사에서 관측된 구체적 행위]다. 행위 부분에는 기사에 나온 파일명·경로·명령·서비스·계정 이름을 그대로 넣고, 기법 이름만 되풀이하지 마라. 근거가 없는 기법은 지어내지 말고, 없으면 "해당 없음"이라고 써라.\n[영향 범위 및 위험도] 영향받는 대상(제품·버전·조직 유형·지역)과 규모를 본문의 수치로 명시하고, 공격이 성공하면 실제로 무엇을 잃는지 쓰라. 3문장 이상.\n[권장 대응] 실무자가 바로 실행할 수 있는 조치 3~5개. 각 항목에 대상(무엇을)과 방법(어떻게)을 함께 쓰고, 본문에 패치 버전·설정값·탐지 지표가 있으면 그대로 넣어라. "최신 패치를 적용하십시오"처럼 어느 기사에나 통하는 일반론은 쓰지 마라.\n'
    else:
        sections = '[주요 내용] 본문의 핵심 사실·수치·일정·고유명사를 빠뜨리지 말고 구체적으로 서술하라(위협·공격을 전제로 지어내지 말 것). 5문장 이상.\n[의미와 영향] 보안 업계·기업·이용자에게 어떤 의미·영향이 있는지, 무엇이 달라지는지를 본문 근거로 쓰라. 3문장 이상.\n[참고 사항] 실무자가 확인·검토해볼 점 3개. 각 항목에 무엇을 어떻게 확인할지 함께 쓰고, 어느 기사에나 통하는 일반론은 쓰지 마라.\n'

    return (persona + ' 아래 보안 관련 기사를 심층 분석해 한국어 존댓말로 작성하라.\n\n제목: ' + title
            + '\n\n출력의 맨 첫 줄에 이 기사가 다음 중 무엇에 해당하는지 정확히 하나만 골라 "[분류: 카테고리명]" 형식으로 써라(목록 밖의 이름을 만들지 마라) — 목록: ' + ", ".join(REPORT_CATEGORIES)
            + '. 그 다음 줄부터 아래 형식을 따라라.\n\n출력 형식:\n[핵심 요약] 2~3문장\n'
            + sections
            + '[선수 정보]\n- 용어명1: 이 용어를 모르면 위 분석을 이해할 수 없는 실무자를 위한 1문장 해설\n- 용어명2: 용어명1과 동일한 형태의 해설\n\n섹션 누락 금지: 위 출력 형식의 섹션을 맨 끝의 [조사 대상]까지 하나도 빠짐없이 순서대로 써라 — [권장 대응]이나 [선수 정보]에서 끝내지 마라. [조사 대상]은 도구가 읽는 마지막 섹션이라 빠지면 자동 조사가 통째로 돌지 않는다.\n\n번호 목록 작성 규칙: 번호(예: "1.")만 쓰고 뒤에 설명 문장을 비워두지 마라 — 쓰기로 한 항목은 반드시 같은 줄에 실질적인 문장으로 채우고, 번호는 1부터 순서대로 매겨라.\n\n강조 규칙: 각 섹션에서 가장 핵심적인 용어·수치·행위만 **이렇게** 볼드로 표시하라. 섹션당 2~4개로 제한하고, 문장 전체를 통째로 볼드 처리하지 마라.\n\n선수 정보 작성 규칙: 독자는 보안 실무자다. "이 단어를 모르면 위 분석을 못 읽는가"만 기준으로 삼아라.\n- 고를 것: 특정 기술·기법·표준·시스템의 이름(예: Active Directory, RMM, 횡적 이동, DLL 사이드로딩, KCMVP)\n- 고르지 말 것: 실무자가 이미 아는 보안 상식어(악성코드, 피싱, 랜섬웨어, 자격 증명, 데이터 유출, 취약점, 보안 패치, 공급망 공격 등), 널리 알려진 서비스·회사명(GitHub, npm, AWS, Windows), 이 기사에만 등장하는 제품·브랜드명\n- 최대 3개까지만 쓰고, 개수를 채우려고 상식어를 넣지 마라. 기준에 맞는 용어가 하나도 없으면 항목 대신 "- 해당 없음" 한 줄만 써라.\n- 해설에 용어를 그대로 되풀이하지 마라. 그 용어가 무엇을 하는지, 이 기사에서 왜 중요한지를 써라.\n- 용어명은 본문에 나온 표기 그대로 쓰고 볼드(**)나 번호를 붙이지 마라.\n\n주의: 본문에 없는 사실을 지어내지 마라. 본문이 부실하면 그 사실을 그대로 밝혀라. 모든 출력은 한국어로만 쓰고 한자·중국어를 섞지 마라.'
            + analysis_targets.SPEC
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
    url = (job.get("url") or "").strip()
    title = (job.get("title") or "").strip()
    if not url or not title:
        log("[-] url/title이 없는 요청 — 건너뜁니다")
        return None

    body, links = fetch_article_text(url)
    source = job.get("source_label") or "?"
    if body:
        log("    본문 {:,}자 수집 ({})".format(len(body), source))

    # 원문을 못 읽었으면 분석하지 않는다. 제목만으로 만든 분석은 근거가 없고, 화면에서
    # 정상 분석과 구별되지 않아 더 위험하다 — 실패 사실을 그대로 저장해 보여 준다.
    blocked = BLOCKED_PAGE_RE.search(body[:2000]) if body else None
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

    prompt = build_prompt(title, body[:BODY_MAX_CHARS], job.get("category") or "")

    started = time.time()
    raw = common_utils.llm_generate(prompt, timeout=300, nvidia_max_attempts=3)
    if not raw:
        log("[-] LLM 생성 실패: {}".format(title[:50]))
        return None
    log("    LLM {:.1f}초 / {:,}자".format(time.time() - started, len(raw)))

    category, analysis = extract_category(raw)
    # 기계용 목록을 먼저 떼어낸다. 남겨 두면 화면에 "도메인: 없음" 같은 줄이 그대로
    # 보이고, 뒤따르는 섹션 파서들도 이 섹션을 본문으로 오인한다.
    targets = analysis_targets.parse(analysis)
    analysis = analysis_targets.strip(analysis)
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

    # 조사&대응 — 사건 성격에 따라 조사 방향이 갈린다. 사용자 행위 기반(ClickFix 등)은
    # 유포지를 urlscan으로 추적하고, 악성코드 기반은 VT 동적 분석으로 실제 행위를 본다.
    # 분석 본문이 "기사가 말한 것"이라면 이 블록은 "지금 공개 관측치가 말하는 것"이다.
    # 실패해도 분석 결과는 그대로 저장한다.
    investigation_block = None
    try:
        # 원문 발췌도 함께 넘긴다 — 패턴 합성의 근거 확인은 우리말 분석문만으로는
        # 부족하다(URL·경로·명령줄은 원문에만 원형으로 남는 경우가 있다).
        investigation_block = investigation.build(
            iocs, text=analysis, title=title, category=category or "",
            body=body[:BODY_MAX_CHARS], targets=targets)
        if investigation_block:
            route = investigation_block.get("route") or {}
            log("    조사&대응: {} / 시드 {}개 / 악성코드 {}건".format(
                route.get("label") or "-", len(investigation_block.get("seeds") or []),
                len((investigation_block.get("malware") or {}).get("files") or [])))
    except Exception as error:
        log("[-] 조사&대응 생성 실패(분석 결과에는 영향 없음): {}".format(error))

    return {
        "ref": job.get("ref"),
        "title": title,
        "url": url,
        "source_label": job.get("source_label") or "",
        "analysis": analysis,
        "links": links,
        "iocs": iocs,
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
    cached = {key: record[key] for key in
              ("analysis", "links", "iocs", "category", "attack_techniques", "glossary",
               "attack_grouped", "investigation")}
    if record.get("collection_failed"):
        cached["collection_failed"] = True
    cached["partial"] = False
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


def main():
    client = get_client()
    if client is None:
        log("[-] REDIS_URL이 없거나 연결할 수 없어 건너뜁니다.")
        return

    pending = client.llen(QUEUE_KEY)
    if not pending:
        log("[*] 대기 중인 분석 요청이 없습니다.")
        return
    log("[*] 대기 중인 분석 요청 {}건".format(pending))

    deadline = time.time() + RUN_BUDGET_SECONDS
    done = 0
    for _ in range(MAX_ITEMS_PER_RUN):
        if time.time() >= deadline:
            log("[*] 이번 회차 예산 소진 — 나머지는 다음 실행에서 처리합니다.")
            break

        raw = client.lpop(QUEUE_KEY)
        if raw is None:
            break
        try:
            job = json.loads(raw)
        except ValueError:
            log("[-] 큐 항목 파싱 실패 — 버립니다")
            continue

        log("[*] 분석 시작: {}".format((job.get("title") or "")[:60]))
        try:
            record = analyze_one(job)
        except Exception as error:  # 한 건의 실패가 나머지를 막지 않게
            log("[-] 분석 중 예외: {}".format(error))
            record = None

        if not record:
            # 실패한 요청은 되돌리지 않는다 — 같은 이유로 계속 실패하면 큐가 막힌다.
            # 사용자는 대시보드에서 다시 누르면 된다.
            log("[-] 실패 — 큐에서 제거했습니다: {}".format((job.get("title") or "")[:50]))
            continue

        try:
            store_result(client, record)
            done += 1
            log("[+] 저장 완료: {}".format(record["title"][:60]))
        except Exception as error:
            log("[-] 결과 저장 실패: {}".format(error))

    log("[+] 이번 회차 {}건 처리 (남은 대기 {}건)".format(done, client.llen(QUEUE_KEY)))


if __name__ == "__main__":
    main()
