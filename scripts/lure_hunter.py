"""유포지 헌팅 — 알려진 유인 페이지에서 패턴을 뽑아 다른 유포지를 찾는다.

무엇을 푸는가:
    기사에서 TerminalFix 유포지로 linked-log.com 한 곳을 얻었다. 그런데 이런 캠페인은
    도메인을 며칠 주기로 갈아 쓰기 때문에, 그 한 건을 차단해도 다음 도메인이 뜨면
    다시 처음이다. 알려진 한 곳에서 "이 캠페인이 유포지를 만드는 방식"을 뽑아
    urlscan.io 인덱스 전체에서 같은 방식으로 만들어진 다른 유포지를 찾아낸다.

어떻게 찾는가 (2단계):
    1단계 후보 생성 — urlscan 검색 API. 시드의 인프라 지문(IP·ASN·서버 배너·TLS
        발급자·페이지 제목·도메인 나이)으로 피벗 질의를 만들어 후보를 긁는다.
        API 키 없이 된다.
    2단계 검증 — 후보의 저장된 DOM에서 ClickFix 표식(클립보드 쓰기 + "Win+R 눌러
        붙여넣어라" 안내 + powershell 명령)을 찾는다. urlscan API 키가 필요하다
        (키 없이는 result·dom 엔드포인트가 403, DOM 본문은 검색 인덱스에도 없다).

한계 (설계상 알고 시작해야 하는 것):
    유포지는 클로킹을 한다. 실측: linked-log.com의 urlscan 스캔(2026-08-29, 유일한
    1건)은 ClickFix 오버레이 없이 LinkedIn 클론 화면만 담겼다 — 지역·UA·리퍼러로
    걸러 봇에게는 미끼를 안 보여준 것이다. 그래서
        - 스크린샷·제목만으로는 유포지를 판정할 수 없다(겉모습은 정상 클론이다).
        - DOM 표식도 "있으면 확정, 없으면 미확정"으로만 쓸 수 있다. 없다고 무죄가
          아니다.
    결국 1단계의 인프라 지문이 주력이고, 2단계는 확정 도장을 찍는 용도다.

사용법:
    python scripts/lure_hunter.py linked-log.com
    python scripts/lure_hunter.py linked-log.com --json > candidates.json
    python scripts/lure_hunter.py --queries-only linked-log.com   # 질의만 출력(urlscan UI에 붙여넣기)

    URLSCAN_API_KEY를 .env에 넣으면 2단계 DOM 검증까지 수행한다(무료 키로 충분).
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

import common_utils

SEARCH_URL = "https://urlscan.io/api/v1/search/"
RESULT_URL = "https://urlscan.io/api/v1/result/{}/"
DOM_URL = "https://urlscan.io/dom/{}/"
SCREENSHOT_URL = "https://urlscan.io/screenshots/{}.png"
# urlscan 검색 화면은 해시에 질의를 그대로 담는다 — 대시보드에서 클릭 한 번으로 넘어간다.
SEARCH_UI_URL = "https://urlscan.io/search/#{}"

# 대시보드 "조사&대응" 탭이 읽는 파일. publish_web_dashboard가 발행 때 함께 복사한다.
INVESTIGATIONS_FILE = common_utils.DATA_DIR / "investigations.json"
MAX_INVESTIGATION_CANDIDATES = 12   # 탭에 실을 후보 수(사람이 훑을 수 있는 양)

# 키 없는 검색은 관대하지만 무한하지 않다 — 질의 사이에 쉬고, 질의 수도 제한한다.
REQUEST_PAUSE_SECONDS = 2.0
REQUEST_TIMEOUT = 45
MAX_RESULTS_PER_PIVOT = 100      # urlscan 검색 API의 size 상한
MAX_CANDIDATES = 40              # 사람이 실제로 검토할 수 있는 양
MAX_DOM_FETCHES = 15             # 2단계는 후보 상위 N건만(요청 수·시간 절약)

# 후보 도메인이 이보다 오래됐으면 이 캠페인의 것으로 보지 않는다. 실측: 시드는
# 스캔 시점에 4일, TLS 인증서도 4일이었다 — 등록 즉시 쓰고 버리는 방식이다.
YOUNG_DOMAIN_DAYS = 21

# 스캔 자체가 오래된 것은 이 캠페인과 무관하다. 이 조건이 없으면 정밀도가 무너진다 —
# 실측: 제목 피벗에 2022년·2024년 스캔이 섞여 들어왔고(그때는 이 캠페인이 없었다),
# 그것들이 전부 IP 직접 접속 스캔이라 domainAgeDays=0으로 "신규 도메인" 판정까지 받았다.
# 창을 30일로 걸면 같은 피벗이 시드 1건만 남긴다.
SCAN_WITHIN_DAYS = 30

# IP로 직접 스캔된 항목은 도메인 나이가 항상 0으로 들어온다 — 신규 등록 신호로 쓰면 안 된다.
IP_LITERAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# ClickFix 계열 유인 페이지의 DOM 표식. 세 갈래가 모두 있어야 "붙여넣기 유도"가 성립한다:
# 명령을 클립보드에 넣고(clipboard), 그걸 터미널에 붙여넣으라고 안내하고(instruction),
# 실제 명령이 페이지 안에 있다(command).
CLICKFIX_MARKERS = {
    "clipboard": [
        r"navigator\.clipboard\.writeText",
        r"document\.execCommand\(\s*['\"]copy",
        r"clipboardData\.setData",
    ],
    "instruction": [
        r"Win(?:dows)?\s*\+\s*R\b",
        r"Win(?:dows)?\s*\+\s*X\b",
        r"Ctrl\s*\+\s*V\b",
        r"⊞\s*\+\s*R",
        r"Windows\s*Terminal",
        r"Verification\s*ID",
        r"press\s+(?:the\s+)?enter",
        r"Win\s*R",
    ],
    "command": [
        r"powershell(?:\.exe)?\b",
        r"\bmshta\b",
        r"\bconhost\b",
        r"FromBase64String",
        r"Invoke-(?:WebRequest|RestMethod|Expression)",
        r"\biwr\b|\birm\b",
        r"curl\s+-",
        r"certutil\s+-",
    ],
    # 가짜 CAPTCHA 껍데기 — 단독으로는 근거가 약하지만 위 세 갈래를 보강한다.
    "fake_captcha": [
        r"cf-turnstile",
        r"Verify\s+you\s+are\s+human",
        r"I\s*am\s+not\s+a\s+robot",
        r"Ray\s*ID",
        r"Performance\s*&\s*security\s+by\s+Cloudflare",
        r"human\s+verification",
    ],
}

# 브랜드 사칭 판정용 — 제목에서 뽑은 브랜드 토큰이 도메인에 들어있는데 그 브랜드의
# 정식 도메인이 아니면 타이포스쿼팅이다.
BRAND_APEX = {
    "linkedin": "linkedin.com",
    "microsoft": "microsoft.com",
    "office": "office.com",
    "google": "google.com",
    "cloudflare": "cloudflare.com",
    "github": "github.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "meta": "meta.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "netflix": "netflix.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "booking": "booking.com",
    "telegram": "telegram.org",
}


# 진행 로그는 stderr로 보낸다 — --json으로 표준출력을 파이프에 넘길 때 데이터에 섞이면
# 파싱이 깨진다(실측: 첫 실행에서 JSONDecodeError).
def log(message):
    print(message, file=sys.stderr)
    sys.stderr.flush()


def out(message):
    print(message)
    sys.stdout.flush()


def _api_key():
    return (os.environ.get("URLSCAN_API_KEY") or "").strip()


def _request(url, api_key=None, raw=False):
    request = urllib.request.Request(url, headers={
        "User-Agent": "boannews-intel/1.0 (threat research)",
        "Accept": "application/json",
    })
    if api_key:
        request.add_header("API-Key", api_key)
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        body = response.read()
    if raw:
        return body.decode("utf-8", errors="replace")
    return json.loads(body.decode("utf-8", errors="replace"))


def urlscan_search(query, size=MAX_RESULTS_PER_PIVOT, api_key=None):
    """검색 API 호출. 실패해도 예외를 올리지 않고 빈 결과를 준다(피벗 하나가 죽어도 계속)."""
    url = "{}?{}".format(SEARCH_URL, urllib.parse.urlencode({"q": query, "size": size}))
    try:
        data = _request(url, api_key=api_key)
    except Exception as error:
        log("    [-] 검색 실패: {} ({})".format(query[:60], error))
        return [], 0
    return data.get("results") or [], data.get("total") or 0


def seed_facts(seed, api_key=None):
    """시드(도메인 또는 URL)의 urlscan 스캔에서 인프라 지문을 뽑는다."""
    domain = seed.strip()
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).netloc
    domain = domain.strip("/").lower()

    results, total = urlscan_search('page.domain:"{}"'.format(domain), size=10, api_key=api_key)
    if not results:
        # 페이지가 아니라 리소스로만 등장했을 수도 있다(예: 페이로드 호스트).
        results, total = urlscan_search('domain:"{}"'.format(domain), size=10, api_key=api_key)
    if not results:
        return None

    # 여러 스캔이 있으면 가장 최근 것을 기준으로 삼는다(인프라가 옮겨졌을 수 있다).
    latest = max(results, key=lambda r: (r.get("task") or {}).get("time") or "")
    page = latest.get("page") or {}
    task = latest.get("task") or {}
    return {
        "domain": domain,
        "scan_count": total,
        "uuid": latest.get("_id") or "",
        "scanned_at": (task.get("time") or "")[:19],
        "url": task.get("url") or "",
        "ip": page.get("ip") or "",
        "asn": page.get("asn") or "",
        "asnname": page.get("asnname") or "",
        "server": page.get("server") or "",
        "tls_issuer": page.get("tlsIssuer") or "",
        "title": page.get("title") or "",
        "country": page.get("country") or "",
        "domain_age_days": page.get("domainAgeDays"),
        "requests": (latest.get("stats") or {}).get("requests"),
    }


# 빈 응답의 SHA-256. TDS(트래픽 분배기)가 스캐너에게 아무것도 안 주면 이 값이 찍힌다
# — 해시 피벗 재료로 쓰면 안 되고, 오히려 "클로킹했다"는 증거로 읽어야 한다.
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# 어느 사이트에나 있는 정상 CDN·통계·폰트·소셜 리소스. 피벗 재료가 아니다.
NOISE_RESOURCE_APEXES = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "doubleclick.net", "youtube.com", "ytimg.com",
    "facebook.com", "facebook.net", "fbcdn.net", "instagram.com", "twitter.com",
    "twimg.com", "linkedin.com", "licdn.com", "microsoft.com", "office.com",
    "azureedge.net", "msecnd.net", "clarity.ms", "apple.com", "cloudflare.com",
    "cloudflareinsights.com", "cloudfront.net", "akamai.net", "akamaihd.net",
    "akamaized.net", "fastly.net", "jsdelivr.net", "unpkg.com", "cdnjs.com",
    "bootstrapcdn.com", "jquery.com", "w.org", "wordpress.org", "wp.com",
    "gravatar.com", "hotjar.com", "newrelic.com", "nr-data.net", "sentry.io",
    "segment.com", "hubspot.com", "zendesk.com", "recaptcha.net", "gstatic.cn",
    "shopify.com", "squarespace.com", "wix.com", "typekit.net", "fontawesome.com",
    "adobe.com", "bing.com", "yandex.ru", "naver.com", "naver.net", "kakao.com",
    "daum.net", "pstatic.net", "jsdelivr.com", "bootstrapcdn.net",
    "demdex.net", "tealiumiq.com", "tealium.com", "adobedtm.com", "omtrdc.net",
    "2o7.net", "trustindex.io", "usercentrics.eu", "cookielaw.org", "onetrust.com",
}

# 흔한 파일명은 피벗이 안 된다(수백만 건이 걸린다).
COMMON_FILENAMES = {
    "", "/", "index.html", "index.php", "index.htm", "main.js", "app.js", "script.js",
    "style.css", "styles.css", "main.css", "jquery.js", "bundle.js", "favicon.ico",
    "robots.txt", "sitemap.xml", "logo.png", "analytics.js", "gtag.js", "js", "css",
    "main.min.js", "app.min.js", "jquery.min.js", "bundle.min.js", "vendor.js",
    "utag.js", "loader.js", "common.js", "runtime.js", "polyfills.js", "chunk.js",
}


def _apex(host):
    parts = (host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


def _urlscan_filename(url):
    """urlscan의 filename 필드와 같은 형태로 만든다 — 마지막 경로 조각 + 첫 질의 키.

    실측: https://mytds1029380.com/jsrepo?rnd=64kggrxs&ts=... -> jsrepo?rnd=
    쿼리 값은 매번 랜덤이라 키까지만 쓴다. 이게 사용자가 찾아낸 패턴의 형태다.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return ""
    name = (parsed.path or "").rstrip("/").rsplit("/", 1)[-1]
    if not name or name.lower() in COMMON_FILENAMES or len(name) < 4:
        return ""
    if parsed.query:
        first_key = parsed.query.split("=", 1)[0].split("&", 1)[0]
        if first_key:
            return "{}?{}=".format(name, first_key)
    return name


def resource_facts(uuid, page_host, api_key):
    """스캔이 실제로 주고받은 리소스에서 조사 재료를 뽑는다.

    페이지 레벨 필드(IP·ASN·서버·제목)만 보면 "침해된 정상 사이트에 심긴 스크립트"
    유형을 구조적으로 못 잡는다 — 그 층은 페이지 속성이 아니라 요청에 흔적이 남는다.
    실측: filename:"jsrepo?rnd=" 하나로 같은 스크립트가 심긴 사이트 9,826건이 나오는데,
    그 요청은 미끼 페이지(linked-log.com) 스캔에는 아예 없다. 서로 다른 층이다.
    """
    if not (uuid and api_key):
        return None
    try:
        data = _request(RESULT_URL.format(uuid), api_key=api_key)
    except Exception as error:
        log("    [-] 리소스 조회 실패({}): {}".format(uuid[:8], error))
        return None

    page_apex = _apex(page_host)
    third_party, filenames, hashes, cloaked = {}, {}, {}, []
    requests = (data.get("data") or {}).get("requests") or []
    for entry in requests:
        request = (entry.get("request") or {}).get("request") or {}
        url = request.get("url") or ""
        if not url.startswith("http"):
            continue
        host = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
        if not host or _apex(host) == page_apex or _apex(host) in NOISE_RESOURCE_APEXES:
            continue

        response = (entry.get("response") or {}).get("response") or {}
        body_hash = (entry.get("response") or {}).get("hash") or ""
        info = third_party.setdefault(host, {"count": 0, "types": set(), "empty": 0})
        info["count"] += 1
        if response.get("mimeType"):
            info["types"].add(response["mimeType"])
        if body_hash == EMPTY_BODY_SHA256:
            info["empty"] += 1
            if host not in cloaked:
                cloaked.append(host)

        name = _urlscan_filename(url)
        if name:
            filenames.setdefault(name, {"host": host, "count": 0})
            filenames[name]["count"] += 1
        if body_hash and body_hash != EMPTY_BODY_SHA256 and "script" in (response.get("mimeType") or ""):
            hashes.setdefault(body_hash, host)

    return {
        "request_count": len(requests),
        "third_party": {host: {"count": v["count"], "types": sorted(v["types"]), "empty": v["empty"]}
                        for host, v in third_party.items()},
        "filenames": filenames,
        "script_hashes": hashes,
        "cloaked_hosts": cloaked,
    }


def resource_pivots(resources):
    """리소스 재료를 urlscan 질의로.

    아무 파일명이나 쓰면 못 쓰는 질의가 된다 — main.min.js·loader.js처럼 흔한 이름은
    수백만 건이 걸린다. 쓸 만한 형태는 두 가지다:
      · 질의 키가 붙은 이름(jsrepo?rnd=) — 공격 킷이 만든 고유한 형태다.
      · 스캐너에게 빈 응답을 준 호스트의 파일 — 클로킹했다는 건 숨길 게 있다는 뜻이다.
    """
    cloaked = set(resources["cloaked_hosts"])
    pivots = []

    def filename_rank(item):
        name, info = item
        return (0 if info["host"] in cloaked else 1, -info["count"])

    for name, info in sorted(resources["filenames"].items(), key=filename_rank):
        usable = ("?" in name and name.endswith("=")) or (info["host"] in cloaked and len(name) >= 6)
        if not usable:
            continue
        pivots.append(("같은 파일을 불러오는 사이트 전체", 'filename:"{}"'.format(name), 3))
        if len(pivots) >= 2:
            break

    def host_rank(host):
        info = resources["third_party"][host]
        return (0 if host in cloaked else 1, -info["count"])

    for host in sorted(resources["third_party"], key=host_rank)[:3]:
        pivots.append(("이 호스트를 불러오는 사이트 전체", 'domain:"{}"'.format(host), 3))

    for body_hash, host in list(resources["script_hashes"].items())[:1]:
        pivots.append(("똑같은 스크립트 파일이 있는 사이트", "hash:{}".format(body_hash), 3))
    return pivots


def _looks_like_typosquat(brand, domain):
    """브랜드 이름을 흉내 낸 도메인인가.

    완전 포함만 보면 놓친다 — linked-log.com은 linkedin에서 글자를 뺀 형태라
    "linkedin" in "linked-log.com"이 거짓이다. 이름 앞부분(최소 6자)이 구분자를 뗀
    도메인에 들어 있는지로 본다. 정식 도메인은 당연히 제외한다.
    """
    apex = BRAND_APEX.get(brand, "")
    if not apex or domain == apex or domain.endswith("." + apex):
        return False
    if len(brand) < 6:
        return False       # apple·meta처럼 짧은 이름은 우연히 겹친다
    compact = re.sub(r"[^a-z0-9]", "", domain.lower())
    prefix = brand[:max(6, len(brand) - 2)]
    return prefix in compact


def brand_tokens(title):
    """페이지 제목에서 사칭 대상 브랜드를 추정한다."""
    lowered = (title or "").lower()
    return [brand for brand in BRAND_APEX if brand in lowered]


def build_pivots(facts):
    """인프라 지문에서 피벗 질의를 만든다.

    각 피벗의 weight는 "그 피벗만으로 얼마나 믿을 수 있는가"다 — 같은 IP는 거의
    확정이고(같은 서버에 얹혀 있다), ASN·TLS 발급자는 혼자서는 약하다(정상 사이트도
    같은 호스팅을 쓴다). 그래서 후보 점수는 여러 피벗에 동시에 걸릴 때 올라간다.
    """
    raw = []
    age = YOUNG_DOMAIN_DAYS
    if facts.get("ip"):
        raw.append(("동일 IP", 'page.ip:"{}"'.format(facts["ip"]), 3))
    if facts.get("asn"):
        raw.append(("동일 ASN + 신규 도메인",
                    'page.asn:{} AND page.domainAgeDays:<{}'.format(facts["asn"], age), 2))
    if facts.get("title"):
        raw.append(("동일 제목(클론 킷) + 신규 도메인",
                    'page.title:"{}" AND page.domainAgeDays:<{}'.format(
                        facts["title"].replace('"', ""), age), 2))
    if facts.get("server") and facts.get("asn"):
        raw.append(("동일 서버 배너 + 동일 ASN",
                    'page.server:"{}" AND page.asn:{}'.format(facts["server"], facts["asn"]), 1))
    if facts.get("tls_issuer") and facts.get("asn"):
        raw.append(("동일 TLS 발급자 + 동일 ASN + 신규 도메인",
                    'page.tlsIssuer:"{}" AND page.asn:{} AND page.domainAgeDays:<{}'.format(
                        facts["tls_issuer"], facts["asn"], age), 1))
    return [(name, "{} AND task.time:>now-{}d".format(query, SCAN_WITHIN_DAYS), weight)
            for name, query, weight in raw]


def collect_candidates(facts, api_key=None):
    """피벗을 돌려 후보를 모으고, 어떤 피벗에 걸렸는지 기록한다."""
    candidates = {}
    pivot_stats = []
    for name, query, weight in build_pivots(facts):
        results, total = urlscan_search(query, api_key=api_key)
        pivot_stats.append({"name": name, "query": query, "total": total, "returned": len(results)})
        log("    [{:>5}건] {} — {}".format(total, name, query[:78]))
        for result in results:
            page = result.get("page") or {}
            domain = (page.get("domain") or "").lower()
            if not domain or domain == facts["domain"]:
                continue
            # 사칭 대상의 정식 도메인은 당연히 같은 제목을 쓴다 — 후보가 아니다.
            if any(domain == apex or domain.endswith("." + apex) for apex in BRAND_APEX.values()):
                continue
            entry = candidates.setdefault(domain, {
                "domain": domain,
                "url": (result.get("task") or {}).get("url") or "",
                "uuid": result.get("_id") or "",
                "scanned_at": ((result.get("task") or {}).get("time") or "")[:19],
                "ip": page.get("ip") or "",
                "asn": page.get("asn") or "",
                "asnname": page.get("asnname") or "",
                "server": page.get("server") or "",
                "tls_issuer": page.get("tlsIssuer") or "",
                "title": page.get("title") or "",
                "country": page.get("country") or "",
                "domain_age_days": page.get("domainAgeDays"),
                "pivots": [],
                "pivot_weight": 0,
            })
            if name not in entry["pivots"]:
                entry["pivots"].append(name)
                entry["pivot_weight"] += weight
        time.sleep(REQUEST_PAUSE_SECONDS)
    return candidates, pivot_stats


def score_candidate(candidate, facts):
    """후보 점수와 근거. 인프라 일치 + 신규 도메인 + 브랜드 사칭을 본다."""
    score = candidate["pivot_weight"]
    reasons = list(candidate["pivots"])

    age = candidate.get("domain_age_days")
    is_ip_host = bool(IP_LITERAL_RE.match(candidate["domain"]))
    if isinstance(age, int) and age <= YOUNG_DOMAIN_DAYS and not is_ip_host:
        score += 2
        reasons.append("도메인 {}일".format(age))
    elif is_ip_host:
        reasons.append("IP 직접 접속(도메인 나이 판정 불가)")

    if candidate["ip"] and candidate["ip"] == facts.get("ip"):
        reasons.append("IP {}".format(candidate["ip"]))
    if candidate["asn"] and candidate["asn"] == facts.get("asn"):
        reasons.append(facts.get("asnname") or candidate["asn"])

    if candidate["title"] and candidate["title"] == facts.get("title"):
        score += 2
        reasons.append("제목 동일")

    # 브랜드 토큰이 도메인에 있는데 정식 도메인이 아니면 사칭이다.
    for brand in brand_tokens(candidate["title"]) or brand_tokens(facts.get("title")):
        apex = BRAND_APEX[brand]
        if brand in candidate["domain"] and not candidate["domain"].endswith(apex):
            score += 2
            reasons.append("{} 사칭 도메인".format(brand))
            break

    candidate["score"] = score
    candidate["reasons"] = reasons
    return candidate


def verify_dom(uuid, api_key):
    """저장된 DOM에서 ClickFix 표식을 찾는다. 표식이 있으면 확정, 없으면 미확정이다."""
    try:
        dom = _request(DOM_URL.format(uuid), api_key=api_key, raw=True)
    except Exception as error:
        return {"error": str(error)[:120]}
    hits = {}
    for group, patterns in CLICKFIX_MARKERS.items():
        found = []
        for pattern in patterns:
            match = re.search(pattern, dom, re.I)
            if match:
                found.append(match.group(0)[:40])
        if found:
            hits[group] = sorted(set(found))[:4]
    # 클립보드 쓰기 + (안내문 또는 명령)이 함께 있으면 붙여넣기 유도로 본다.
    confirmed = bool(hits.get("clipboard")) and bool(hits.get("instruction") or hits.get("command"))
    return {"markers": hits, "confirmed": confirmed, "dom_bytes": len(dom)}


def hunt(seed, api_key=None, verify=True):
    api_key = api_key if api_key is not None else _api_key()

    log("[*] 시드 조회: {}".format(seed))
    facts = seed_facts(seed, api_key=api_key)
    if not facts:
        log("[-] urlscan에 이 도메인 스캔 기록이 없습니다. urlscan.io에서 먼저 스캔하거나 다른 시드를 쓰세요.")
        return None

    log("    스캔 {}건 / 최근 {} / 제목 {!r}".format(
        facts["scan_count"], facts["scanned_at"], facts["title"][:50]))
    log("    IP {} / {} / {} / TLS {} / 도메인 {}일".format(
        facts["ip"], facts["asn"], facts["server"], facts["tls_issuer"], facts["domain_age_days"]))

    log("[*] 피벗 검색")
    candidates, pivot_stats = collect_candidates(facts, api_key=api_key)
    log("    후보 {}개 도메인".format(len(candidates)))

    ranked = sorted((score_candidate(c, facts) for c in candidates.values()),
                    key=lambda c: (-c["score"], c.get("domain_age_days") if isinstance(c.get("domain_age_days"), int) else 9999))
    ranked = ranked[:MAX_CANDIDATES]

    if verify and api_key:
        log("[*] DOM 검증 (상위 {}건)".format(min(MAX_DOM_FETCHES, len(ranked))))
        for candidate in ranked[:MAX_DOM_FETCHES]:
            candidate["dom"] = verify_dom(candidate["uuid"], api_key)
            if candidate["dom"].get("confirmed"):
                candidate["score"] += 4
                candidate["reasons"].append("DOM에 붙여넣기 유도 코드")
            time.sleep(REQUEST_PAUSE_SECONDS)
        ranked.sort(key=lambda c: -c["score"])
    elif verify:
        log("[!] URLSCAN_API_KEY가 없어 DOM 검증을 건너뜁니다(후보 생성까지만 수행).")

    for candidate in ranked:
        candidate["screenshot"] = SCREENSHOT_URL.format(candidate["uuid"]) if candidate["uuid"] else ""
        candidate["urlscan"] = "https://urlscan.io/result/{}/".format(candidate["uuid"]) if candidate["uuid"] else ""

    return {"seed": facts, "pivots": pivot_stats, "candidates": ranked,
            "dom_verified": bool(api_key), "generated_at": common_utils.utc_now_iso()}


# 심층분석 1건마다 붙는 조사 블록의 예산. 후보 헌팅(피벗 5회 + DOM 조회)까지 하면
# 워커의 회차 예산(RUN_BUDGET_SECONDS)을 먹으므로, 여기서는 시드당 검색 1회로 관측
# 사실만 확인하고 확장 검색은 "질의"로 만들어 사람에게 넘긴다.
INVESTIGATION_MAX_SEEDS = 3
INVESTIGATION_BUDGET_SECONDS = 45


# ── 도메인 IOC의 역할 구분 ──────────────────────────────────────────────────────
# 랜섬웨어·인포스틸러 기사의 도메인 IOC는 유포지만 있는 게 아니다. 역할을 가리지 않고
# 전부 유포지로 조사하면 정상 서비스에 "복제된 미끼 페이지" 딱지를 붙이고 차단 목록에
# 올린다(실측: DeadLock 기사에서 공용 Polygon RPC 6곳이 그렇게 처리됐다).

# 악성코드가 C2 설정 조회·협상 채널로 "경유"하는 공용 서비스. 공격자 소유가 아니다.
PUBLIC_SERVICE_APEXES = {
    # 블록체인 RPC·탐색기
    "publicnode.com", "drpc.org", "nodies.app", "polygon-rpc.com", "1rpc.io",
    "meowrpc.com", "quiknode.pro", "quicknode.com", "alchemy.com", "alchemyapi.io",
    "infura.io", "ankr.com", "blockpi.network", "llamarpc.com", "chainstack.com",
    "blastapi.io", "tenderly.co", "getblock.io", "nownodes.io", "moralis.io",
    "omniatech.io", "pokt.network", "thirdweb.com", "chainnodes.org", "dwellir.com",
    "onfinality.io", "etherscan.io", "polygonscan.com", "bscscan.com", "arbiscan.io",
    "cloudflare-eth.com", "blockscout.com",
    # 협상·유출 통보에 쓰이는 메신저·메일
    "getsession.org", "tox.chat", "protonmail.com", "proton.me", "tutanota.com",
    "tutamail.com", "telegram.org", "telegram.me", "onionmail.org", "mail2tor.com",
    # 파일 공유·페이스트
    "pastebin.com", "anonfiles.com", "mega.nz", "gofile.io", "transfer.sh",
    "file.io", "catbox.moe", "temp.sh",
}
# 명단에 없는 RPC 엔드포인트도 형태로 알아본다 — 체인 이름 + rpc/node 조합.
PUBLIC_RPC_HINT_RE = re.compile(
    r"(?:^|[.\-])(?:rpc|nodes?|archive)(?:[.\-]|$)|(?:^|[.\-])(?:rpc|nodes?)\d*[.\-]", re.I)
CHAIN_TOKEN_RE = re.compile(
    r"polygon|ethereum|(?:^|[.\-])eth(?:[.\-]|$)|bsc|bnb|matic|arbitrum|avalanche|"
    r"avax|solana|(?:^|[.\-])base(?:[.\-]|$)|optimism|tron|fantom|cronos", re.I)
LEAK_HINT_RE = re.compile(r"blog|leak|news|press|disclos|publish|shame", re.I)


def host_role(host, campaign_tokens=()):
    """도메인 IOC의 역할. lure / public_service / tor / leak_site 중 하나."""
    host = (host or "").lower().strip(".")
    if not host:
        return "lure"
    if host.endswith(".onion"):
        return "tor"
    apex = ".".join(host.split(".")[-2:])
    if apex in PUBLIC_SERVICE_APEXES:
        return "public_service"
    if PUBLIC_RPC_HINT_RE.search(host) and CHAIN_TOKEN_RE.search(host):
        return "public_service"
    # 유출 블로그는 캠페인 이름이 호스트에 들어가고 blog·leak 류 낱말이 붙는다.
    if LEAK_HINT_RE.search(host) and any(token and token in host for token in campaign_tokens):
        return "leak_site"
    return "lure"


def campaign_tokens_from_text(text):
    """기사 제목·본문에서 캠페인/패밀리 이름 후보를 뽑는다(유출 사이트 판정에 쓴다)."""
    tokens = set()
    for word in re.findall(r"[A-Za-z][A-Za-z0-9]{4,20}", text or "")[:400]:
        lowered = word.lower()
        if lowered in {"ransomware", "malware", "campaign", "microsoft", "windows",
                       "threat", "security", "report", "analysis", "attack", "group"}:
            continue
        tokens.add(lowered)
    return tokens


ROLE_LABELS = {
    "lure": "유포지·C2 후보",
    "public_service": "공용 서비스(경유)",
    "tor": "Tor 주소",
    "leak_site": "유출 사이트",
}


def classify_ioc_hosts(iocs, text=""):
    """도메인·URL IOC를 역할별로 나눈다. 조사·차단 판단이 역할마다 다르다."""
    tokens = campaign_tokens_from_text(text)
    roles = {"lure": [], "public_service": [], "tor": [], "leak_site": []}
    for host in _raw_hosts_from_iocs(iocs):
        role = host_role(host, tokens)
        if host not in roles[role]:
            roles[role].append(host)

    # 유출 사이트가 하나 잡히면 같은 도메인의 형제 호스트도 같은 용도다 — 실측:
    # deadlock.liveblog365.com은 유출 사이트로 잡혔는데 dlock.liveblog365.com은
    # 이름이 짧아 유포지 후보로 남았다.
    leak_apexes = {".".join(host.split(".")[-2:]) for host in roles["leak_site"]}
    if leak_apexes:
        moved = [host for host in roles["lure"]
                 if ".".join(host.split(".")[-2:]) in leak_apexes]
        for host in moved:
            roles["lure"].remove(host)
            roles["leak_site"].append(host)
    return roles

def _seed_domains_from_iocs(iocs, text=""):
    """조사할 도메인만 뽑는다 — 공용 서비스·Tor·유출 사이트는 유포지 조사 대상이 아니다."""
    tokens = campaign_tokens_from_text(text)
    return [host for host in _raw_hosts_from_iocs(iocs)
            if host_role(host, tokens) == "lure"]


def _raw_hosts_from_iocs(iocs):
    """IOC에서 호스트를 뽑는다. URL로 기록된 것이 보통 유포지라 먼저 본다."""
    ordered = []
    for want_url in (True, False):
        for ioc in iocs or []:
            kind = (ioc.get("type") or "").lower()
            value = (ioc.get("value") or "").strip()
            if not value:
                continue
            if want_url and kind != "url":
                continue
            if not want_url and kind != "domain":
                continue
            host = value
            if "://" in host:
                host = urllib.parse.urlparse(host).netloc
            host = host.split("@")[-1].split(":")[0].strip("/.").lower()
            if not host or IP_LITERAL_RE.match(host):
                continue
            if common_utils.is_benign_ioc("domain", host):
                continue
            if host not in ordered:
                ordered.append(host)
    return ordered


HUNTING_PATTERNS_FILE = common_utils.ASSETS_DIR / "intel" / "hunting_patterns.json"


def catalog_patterns(iocs=None, text=""):
    """조사 중 손으로 확인한 패턴 목록에서 이 기사에 해당하는 것을 고른다.

    시드에서 자동으로 뽑히는 피벗만으로는 캠페인의 다른 층을 못 찾는 경우가 있다 —
    미끼 페이지 스캔에는 주입 스크립트 요청이 아예 없기 때문이다(실측: linked-log.com
    스캔의 요청 72건은 전부 LinkedIn CDN이고, jsrepo 요청은 한 건도 없다). 그런 패턴은
    사람이 찾아서 여기에 쌓고, 기사 키워드가 맞으면 자동으로 붙는다.
    """
    try:
        data = json.loads(HUNTING_PATTERNS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    blob = " ".join([text or ""] + [str(ioc.get("value") or "") for ioc in (iocs or [])]).lower()
    matched = []
    for pattern in data.get("patterns") or []:
        keywords = [k.lower() for k in pattern.get("applies_to") or []]
        if keywords and not any(keyword in blob for keyword in keywords):
            continue
        query = pattern.get("query") or ""
        matched.append({
            "label": pattern.get("label") or "",
            "query": query,
            "url": SEARCH_UI_URL.format(urllib.parse.quote(query, safe="")) if query else "",
            "what": pattern.get("what") or "",
            "why": pattern.get("why") or "",
            "reading": pattern.get("reading") or "",
            "next": pattern.get("next") or "",
            "observed": pattern.get("observed") or "",
        })
    return matched


def investigation_for_iocs(iocs, api_key=None, max_seeds=INVESTIGATION_MAX_SEEDS, text=""):
    """IOC 도메인을 시드로 "조사&대응" 블록을 만든다(심층분석 결과에 붙는다).

    확인내용은 urlscan의 공개 관측치에서 나온 사실만, 사람이 읽는 문장으로 적는다 —
    각 줄이 "무엇이 관측됐다 + 그게 무슨 뜻이다"까지 담아야 판단에 쓸 수 있다.
    """
    api_key = api_key if api_key is not None else _api_key()
    started = time.time()
    seeds, findings, steps = [], [], []

    # 조사 과정을 그대로 기록한다 — 무엇을 어떤 질의로 조회해서 몇 건이 나왔는지가
    # 남아야, 결론에 동의하지 않는 사람도 같은 경로를 다시 밟아 검증할 수 있다.
    roles = classify_ioc_hosts(iocs, text=text)
    all_domains = roles["lure"]
    steps.append("IOC {}건의 도메인을 역할별로 나눴습니다 — 유포지·C2 후보 {}건, 공용 서비스 "
                 "{}건, 유출 사이트 {}건, Tor 주소 {}건. 조사 대상은 유포지·C2 후보뿐이고 "
                 "그중 앞의 {}건을 봤습니다.".format(
                     len(iocs or []), len(all_domains), len(roles["public_service"]),
                     len(roles["leak_site"]), len(roles["tor"]),
                     min(len(all_domains), max_seeds)))

    # 역할이 다른 도메인은 왜 조사하지 않았는지 밝힌다 — 빠진 이유를 모르면 누락으로 읽힌다.
    if roles["public_service"]:
        findings.append("공용 서비스 {}건({})은 악성코드가 설정 조회·협상 채널로 경유한 정상 "
                        "서비스입니다. 공격자 소유가 아니므로 조사·차단 대상이 아닙니다 — "
                        "차단하면 정상 기능만 막힙니다.".format(
                            len(roles["public_service"]), ", ".join(roles["public_service"][:4])))
    if roles["leak_site"]:
        findings.append("유출 사이트 {}건({})은 피해자 공개용 블로그입니다. 차단보다 우리 조직이 "
                        "게시됐는지 주기적으로 확인하는 모니터링 대상입니다.".format(
                            len(roles["leak_site"]), ", ".join(roles["leak_site"][:3])))
    if roles["tor"]:
        findings.append("Tor 주소 {}건은 DNS·프록시로 차단할 수 없습니다. 사내에서 Tor 자체를 "
                        "쓰는지(브라우저·클라이언트 실행)로 봐야 합니다.".format(len(roles["tor"])))

    for domain in all_domains[:max_seeds]:
        if time.time() - started > INVESTIGATION_BUDGET_SECONDS:
            findings.append("시간이 오래 걸려 나머지 도메인은 조사하지 않았습니다.")
            steps.append("시간 예산({}초)을 넘겨 나머지 도메인 조사를 중단했습니다.".format(
                int(INVESTIGATION_BUDGET_SECONDS)))
            break
        try:
            facts = seed_facts(domain, api_key=api_key)
        except Exception as error:
            findings.append("{} — urlscan 조회에 실패했습니다({}).".format(domain, str(error)[:70]))
            steps.append("{} — urlscan 검색이 실패했습니다({}).".format(domain, str(error)[:60]))
            continue

        steps.append('{} — urlscan 검색 API에 page.domain:"{}"으로 물었습니다. 결과 {}건{}.'.format(
            domain, domain, facts["scan_count"] if facts else 0,
            "이고 가장 최근 스캔({})을 기준으로 삼았습니다".format(facts["scanned_at"][:10])
            if facts else " — 이 도메인은 아무도 스캔한 적이 없습니다"))

        if not facts:
            seeds.append({"domain": domain, "in_urlscan": False,
                          "queries": [_observation_query(domain)]})
            findings.append("{} — urlscan에 스캔 기록이 아예 없습니다. 웹으로 접근하는 유포지가 "
                            "아니라 악성코드가 직접 통신하는 서버(페이로드·C2)일 가능성이 "
                            "큽니다.".format(domain))
            continue

        # 리소스(페이지가 실제로 불러온 파일)까지 본다 — 페이지 속성만 보면 "정상
        # 사이트에 심긴 스크립트" 유형을 놓친다.
        resources = resource_facts(facts["uuid"], domain, api_key) if api_key else None
        if resources:
            hosts = len(resources["third_party"])
            cloaked = len(resources["cloaked_hosts"])
            if hosts:
                tail = "외부 호스트 {}곳을 찾았습니다(정상 CDN·통계 스크립트는 제외).{}".format(
                    hosts, " 그중 {}곳은 스캐너에게 빈 응답을 돌려줬습니다.".format(cloaked)
                    if cloaked else " 빈 응답을 준 곳은 없습니다.")
            else:
                tail = ("이 페이지가 따로 불러오는 외부 호스트는 없었습니다 — 리소스 쪽에서 "
                        "얻을 단서가 없다는 뜻입니다.")
            steps.append("{} — 그 스캔의 결과 JSON을 받아 요청 {}건을 훑었습니다. {}".format(
                domain, resources["request_count"], tail))
        elif api_key:
            steps.append("{} — 결과 JSON을 받지 못해 요청 목록은 보지 못했습니다.".format(domain))
        else:
            steps.append("{} — URLSCAN_API_KEY가 없어 요청 목록·페이지 코드는 조회하지 "
                         "못했습니다(검색 API만 키 없이 됩니다).".format(domain))

        dom = verify_dom(facts["uuid"], api_key) if (api_key and facts.get("uuid")) else {}
        if dom.get("dom_bytes"):
            steps.append("{} — 저장된 페이지 코드 {:,}자를 받아 붙여넣기 유도 표식을 대조했습니다"
                         "(클립보드 쓰기 / 터미널 안내 문구 / 실행 명령 / 가짜 CAPTCHA 4갈래, "
                         "정규식 {}개). 일치 {}갈래.".format(
                             domain, dom["dom_bytes"],
                             sum(len(v) for v in CLICKFIX_MARKERS.values()),
                             len(dom.get("markers") or {})))
        elif dom.get("error"):
            steps.append("{} — 페이지 코드 조회가 실패했습니다({}).".format(domain, dom["error"][:60]))

        headline = "{} — ".format(domain)
        brands = brand_tokens(facts.get("title")) if facts.get("title") else []
        # 사칭이라고 말할 수 있는 건 브랜드 이름이 도메인에도 박혀 있는데 그 브랜드의
        # 정식 도메인이 아닐 때다. 그게 아니면 관측 사실만 적는다 — 실측: 공용 RPC
        # 서비스(PublicNode)에 "정상 사이트 화면을 복제한 페이지"라고 붙었다.
        impersonating = next((brand for brand in brands if _looks_like_typosquat(brand, domain)), "")
        if impersonating:
            headline += "{} 로그인·서비스 화면을 복제한 사칭 페이지입니다(제목: {!r}).".format(
                impersonating.capitalize(), facts["title"])
        elif facts.get("title"):
            headline += "urlscan 스캔 {}건, 페이지 제목은 {!r}입니다.".format(
                facts["scan_count"], facts["title"])
        else:
            headline += "urlscan에 스캔 기록이 {}건 있습니다.".format(facts["scan_count"])
        findings.append(headline)

        age = facts.get("domain_age_days")
        if isinstance(age, int):
            # 나이 구간의 뜻이 다르다 — 며칠짜리는 미끼용으로 급조한 것이고, 몇 년 된
            # 도메인이 이런 IOC에 나오면 보통 정상 사이트가 침해돼 끌려온 것이다.
            if age <= 7:
                findings.append("· 도메인을 스캔 {}일 전에 등록했습니다. 며칠 쓰고 버리는 "
                                "미끼용 도메인입니다.".format(age))
            elif age <= 60:
                findings.append("· 도메인 등록이 {}일 전으로 최근입니다. 이 캠페인을 위해 "
                                "만든 도메인일 수 있습니다.".format(age))
            elif age <= 365:
                findings.append("· 도메인은 {}일 전에 등록됐습니다.".format(age))
            else:
                findings.append("· 도메인이 {}일({:.0f}년) 됐습니다. 공격자가 새로 만든 것이 "
                                "아니라, 원래 운영되던 사이트가 침해돼 유포에 쓰이는 경우가 "
                                "많습니다 — 이 도메인 자체를 차단하면 정상 사이트를 막게 "
                                "됩니다.".format(age, age / 365))
        where = [bit for bit in (facts.get("asnname") or facts.get("asn"), facts.get("server")) if bit]
        if where:
            findings.append("· 어디에 올려져 있나: {}{}.".format(
                " / ".join(where), " (IP {})".format(facts["ip"]) if facts.get("ip") else ""))
        findings.append("· 공개 스캔은 {}건이고 가장 최근이 {}입니다.{}".format(
            facts["scan_count"], (facts.get("scanned_at") or "-")[:10],
            " 관측치가 1건뿐이라 판단 근거가 얇습니다." if facts["scan_count"] <= 1 else ""))

        if resources and resources["cloaked_hosts"]:
            findings.append("· 이 페이지가 뒤에서 불러오는 호스트 중 {}는 스캐너에게 빈 응답을 "
                            "줬습니다. 방문자를 골라서 악성 코드를 내려주는 것(클로킹)이라, "
                            "스캔 결과가 깨끗해도 안전하다는 뜻이 아닙니다.".format(
                                ", ".join(resources["cloaked_hosts"][:3])))
        elif resources and resources["third_party"]:
            findings.append("· 이 페이지가 뒤에서 불러오는 외부 호스트: {}.".format(
                ", ".join(sorted(resources["third_party"])[:4])))

        if dom.get("confirmed"):
            findings.append("· 저장된 페이지 코드에서 붙여넣기 유도 코드를 찾았습니다({}). "
                            "유포지로 확정입니다.".format(
                                ", ".join(sum(dom["markers"].values(), [])[:4])))
        elif dom.get("markers"):
            findings.append("· 페이지 코드에 의심스러운 흔적이 일부 있지만({}) 확정하기엔 "
                            "부족합니다.".format(", ".join(dom["markers"])))
        elif dom.get("dom_bytes"):
            findings.append("· 저장된 페이지 코드 {:,}자를 다 훑었지만 명령을 복사시키는 코드가 "
                            "없습니다. 스캐너에게는 미끼를 감췄거나, 미끼가 이 주소가 아닌 다른 "
                            "경로에 있습니다.".format(dom["dom_bytes"]))

        queries = [_observation_query(domain)]
        page_pivots = build_pivots(facts)
        for name, query, _weight in page_pivots:
            queries.append({"name": name, "query": query,
                            "url": SEARCH_UI_URL.format(urllib.parse.quote(query, safe=""))})
        res_pivots = resource_pivots(resources) if resources else []
        for name, query, _weight in res_pivots:
            queries.append({"name": name, "query": query,
                            "url": SEARCH_UI_URL.format(urllib.parse.quote(query, safe=""))})
        if page_pivots or res_pivots:
            steps.append("{} — 확보한 지문으로 검색 쿼리 {}개를 만들었습니다: 이 도메인 관측 이력 "
                         "1개 + 페이지 속성 기반 {}개(IP·호스팅 ASN·서버 배너·TLS 발급자·제목 조합, "
                         "모두 최근 {}일 스캔으로 한정) + 리소스 기반 {}개(불러온 파일명·호스트·"
                         "스크립트 해시).".format(domain, len(queries), len(page_pivots),
                                             SCAN_WITHIN_DAYS, len(res_pivots)))
        else:
            steps.append("{} — 피벗으로 쓸 지문이 없어(IP·ASN·제목 모두 비어 있음) 이 도메인 "
                         "관측 이력 쿼리 1개만 만들었습니다.".format(domain))

        seeds.append({
            "domain": domain,
            "in_urlscan": True,
            "dom_confirmed": bool(dom.get("confirmed")),
            "dom_markers": dom.get("markers") or {},
            "cloaked_hosts": (resources or {}).get("cloaked_hosts") or [],
            "scanned_at": facts.get("scanned_at") or "",
            "title": facts.get("title") or "",
            "ip": facts.get("ip") or "",
            "asn": facts.get("asn") or "",
            "asnname": facts.get("asnname") or "",
            "server": facts.get("server") or "",
            "tls_issuer": facts.get("tls_issuer") or "",
            "country": facts.get("country") or "",
            "domain_age_days": facts.get("domain_age_days"),
            "urlscan": "https://urlscan.io/result/{}/".format(facts["uuid"]) if facts.get("uuid") else "",
            "screenshot": SCREENSHOT_URL.format(facts["uuid"]) if facts.get("uuid") else "",
            "queries": queries,
        })

    catalog = catalog_patterns(iocs, text=text)
    steps.append("조사 중 손으로 확인해 등록해 둔 패턴 목록과 대조했습니다 — 이 기사에 "
                 "해당하는 패턴 {}개.".format(len(catalog)))
    # 조사할 유포지가 없어도 역할 설명(공용 서비스·유출 사이트·Tor)은 남긴다 — 그게
    # 이 기사에서 나온 결론이다. 예전에는 seeds가 비면 통째로 버려서 확인내용이 사라졌다.
    if not seeds and not catalog and not findings:
        return None

    if seeds:
        findings.append("이 캠페인 유형은 화면을 정상 사이트처럼 꾸며 두기 때문에, 스크린샷이나 "
                        "제목으로는 유포지인지 알 수 없습니다. 어느 서버·어느 스크립트를 쓰는지로 "
                        "찾아야 합니다 — 아래 검색 쿼리가 그 용도입니다.")
    else:
        findings.append("기사의 도메인 IOC에는 조사할 유포지·C2가 없습니다. 이 캠페인은 공용 "
                        "서비스를 경유해 설정을 받고 Tor·블로그로 협상하는 구조라, URL 쪽에서 "
                        "차단할 대상이 나오지 않습니다 — 대응은 파일·행위 탐지로 갑니다.")
    if not api_key:
        findings.append("URLSCAN_API_KEY가 없어 페이지 코드까지는 대조하지 않았습니다. 검색 "
                        "결과로 나온 도메인은 차단 전에 사람이 확인해야 합니다.")
    return {"seeds": seeds, "patterns": catalog, "findings": findings, "steps": steps,
            "generated_at": common_utils.utc_now_iso()}


def _observation_query(domain):
    query = 'page.domain:"{0}" OR domain:"{0}"'.format(domain)
    return {
        "name": "이 도메인 관측 이력",
        "query": query,
        "url": SEARCH_UI_URL.format(urllib.parse.quote(query, safe="")),
    }


def build_investigation(report, campaign="", notes=None):
    """헌팅 결과를 대시보드 "조사&대응" 탭이 쓸 조사 기록으로 정리한다.

    탭에 필요한 건 두 가지다 — 무엇을 확인했는지(findings)와 남이 그대로 재현할 수 있는
    검색 질의(queries). 후보 목록은 그 근거로 함께 싣는다.
    """
    facts = report["seed"]
    candidates = report["candidates"]
    findings = []

    findings.append("urlscan 스캔 {}건, 최근 {} — 이 도메인에 대한 공개 관측치가 그만큼뿐이다.".format(
        facts["scan_count"], facts["scanned_at"] or "-"))
    infra = []
    if facts.get("ip"):
        infra.append("IP {}".format(facts["ip"]))
    if facts.get("asnname") or facts.get("asn"):
        infra.append(facts.get("asnname") or facts["asn"])
    if facts.get("server"):
        infra.append(facts["server"])
    if facts.get("tls_issuer"):
        infra.append("TLS 발급자 {}".format(facts["tls_issuer"]))
    if isinstance(facts.get("domain_age_days"), int):
        infra.append("스캔 시점 도메인 {}일".format(facts["domain_age_days"]))
    if infra:
        findings.append("인프라 지문: {}".format(" / ".join(infra)))
    if facts.get("title"):
        brands = brand_tokens(facts["title"])
        findings.append("페이지 제목 {!r}{} — 정상 사이트를 통째로 복제한 형태다.".format(
            facts["title"], " ({} 사칭)".format(brands[0]) if brands else ""))

    same_asn = [c for c in candidates if c.get("asn") and c["asn"] == facts.get("asn")]
    if candidates:
        findings.append("피벗 검색으로 추린 상위 후보 {}건, 그중 {}건이 시드와 같은 ASN이다.".format(
            len(candidates), len(same_asn)))
    confirmed = [c for c in candidates if (c.get("dom") or {}).get("confirmed")]
    if report.get("dom_verified"):
        findings.append("DOM 검증 완료 — 붙여넣기 유도 코드가 확인된 후보 {}건.".format(len(confirmed)))
    else:
        findings.append("DOM 검증 미수행(URLSCAN_API_KEY 없음) — 후보는 인프라 일치로만 추린 것이라 "
                        "차단 전에 사람이 확인해야 한다.")

    findings.extend(notes or [])

    return {
        "id": "{}-{}".format(
            re.sub(r"[^a-z0-9]+", "-", (campaign or "lure").lower()).strip("-") or "lure",
            facts["domain"]),
        "campaign": campaign or "",
        "seed": {
            "domain": facts["domain"],
            "url": facts.get("url") or "",
            "scanned_at": facts.get("scanned_at") or "",
            "title": facts.get("title") or "",
            "ip": facts.get("ip") or "",
            "asn": facts.get("asn") or "",
            "asnname": facts.get("asnname") or "",
            "server": facts.get("server") or "",
            "tls_issuer": facts.get("tls_issuer") or "",
            "country": facts.get("country") or "",
            "domain_age_days": facts.get("domain_age_days"),
            "urlscan": "https://urlscan.io/result/{}/".format(facts["uuid"]) if facts.get("uuid") else "",
            "screenshot": SCREENSHOT_URL.format(facts["uuid"]) if facts.get("uuid") else "",
        },
        "findings": findings,
        "queries": [
            {
                "name": pivot["name"],
                "query": pivot["query"],
                "total": pivot["total"],
                "url": SEARCH_UI_URL.format(urllib.parse.quote(pivot["query"], safe="")),
            }
            for pivot in report["pivots"]
        ],
        "candidates": [
            {
                "domain": c["domain"],
                "score": c["score"],
                "reasons": c["reasons"][:5],
                "asnname": c.get("asnname") or "",
                "title": c.get("title") or "",
                "scanned_at": c.get("scanned_at") or "",
                "domain_age_days": c.get("domain_age_days"),
                "urlscan": c.get("urlscan") or "",
                "screenshot": c.get("screenshot") or "",
                "confirmed": bool((c.get("dom") or {}).get("confirmed")),
            }
            for c in candidates[:MAX_INVESTIGATION_CANDIDATES]
        ],
        "dom_verified": bool(report.get("dom_verified")),
        "updated_at": common_utils.utc_now_iso(),
    }


def save_investigation(record, path=None):
    """같은 id면 갈아끼우고, 없으면 추가한다(최근 갱신 순으로 정렬)."""
    path = path or INVESTIGATIONS_FILE
    existing = []
    if path.exists():
        try:
            existing = (json.loads(path.read_text(encoding="utf-8")) or {}).get("investigations") or []
        except (ValueError, OSError):
            existing = []
    merged = [item for item in existing if item.get("id") != record["id"]] + [record]
    merged.sort(key=lambda item: item.get("updated_at") or "", reverse=True)
    payload = {"generated_at": common_utils.utc_now_iso(), "investigations": merged}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def print_report(report):
    facts = report["seed"]
    out("")
    out("=" * 96)
    out("유포지 헌팅 결과 — 시드 {}".format(facts["domain"]))
    out("=" * 96)
    if not report["dom_verified"]:
        out("주의: DOM 검증 없이 인프라 지문만으로 추린 후보다. 차단 전에 사람이 확인해야 한다.")
    for candidate in report["candidates"]:
        dom = candidate.get("dom") or {}
        mark = "확정" if dom.get("confirmed") else ("미확정" if dom else "  -  ")
        out("")
        out("[{:>2}점][{}] {}".format(candidate["score"], mark, candidate["domain"]))
        out("    {}".format(" · ".join(candidate["reasons"][:6])))
        out("    {} | {} | {}".format(
            candidate["asnname"][:40] or "-", candidate["server"] or "-", candidate["scanned_at"]))
        if candidate["title"]:
            out("    제목 {!r}".format(candidate["title"][:60]))
        if dom.get("markers"):
            for group, found in dom["markers"].items():
                out("    DOM {}: {}".format(group, ", ".join(found)))
        out("    {}".format(candidate["urlscan"]))
    out("")
    out("후보 {}건 (점수 내림차순). 질의를 urlscan UI에 그대로 붙여 넓게 볼 수도 있다:".format(
        len(report["candidates"])))
    for pivot in report["pivots"]:
        out("  [{:>5}건] {}".format(pivot["total"], pivot["query"]))


def main():
    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="알려진 유포지에서 패턴을 뽑아 다른 유포지를 찾는다")
    parser.add_argument("seed", help="알려진 유포지 도메인 또는 URL")
    parser.add_argument("--json", action="store_true", help="사람용 리포트 대신 JSON 출력")
    parser.add_argument("--queries-only", action="store_true",
                        help="검색은 하지 않고 피벗 질의만 출력(urlscan UI용)")
    parser.add_argument("--no-verify", action="store_true", help="API 키가 있어도 DOM 검증 생략")
    parser.add_argument("--investigation", action="store_true",
                        help="결과를 data/investigations.json에 저장(대시보드 조사&대응 탭)")
    parser.add_argument("--campaign", default="", help="조사 기록에 붙일 캠페인 이름(예: TerminalFix)")
    parser.add_argument("--note", action="append", default=[],
                        help="확인내용에 사람이 추가할 한 줄(여러 번 지정 가능)")
    args = parser.parse_args()

    if args.queries_only:
        facts = seed_facts(args.seed, api_key=_api_key())
        if not facts:
            log("[-] urlscan에 스캔 기록이 없습니다.")
            return 1
        for name, query, _weight in build_pivots(facts):
            print("# {}\n{}\n".format(name, query))
        return 0

    report = hunt(args.seed, verify=not args.no_verify)
    if not report:
        return 1
    if args.investigation:
        record = build_investigation(report, campaign=args.campaign, notes=args.note)
        path = save_investigation(record)
        log("[+] 조사 기록 저장: {} (확인내용 {}줄 / 질의 {}개 / 후보 {}건)".format(
            path, len(record["findings"]), len(record["queries"]), len(record["candidates"])))

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    elif not args.investigation:
        print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
