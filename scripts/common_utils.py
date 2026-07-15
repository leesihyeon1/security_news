import os
import json
import re
import requests
import smtplib
from datetime import datetime
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import urllib.parse
import urllib.request
import html

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent if BASE_DIR.name.lower() == "scripts" else BASE_DIR
STATE_DIR = PROJECT_ROOT / "state"
ASSETS_DIR = PROJECT_ROOT / "assets"
INVENTORY_FILE = ASSETS_DIR / "inventory.yml"
DATA_DIR = PROJECT_ROOT / "data"
EVENTS_FILE = DATA_DIR / "events.jsonl"

def load_env_file(dotenv_path=None):
    if dotenv_path is None:
        dotenv_path = PROJECT_ROOT / ".env"
    else:
        dotenv_path = Path(dotenv_path)
    
    if not dotenv_path.exists():
        return
    
    with dotenv_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                val = val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]
                os.environ[key.strip()] = val

# 모듈 로드 시 즉시 .env 파일을 읽어 환경 변수에 적재합니다.
load_env_file()

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SENDER_EMAIL = os.environ.get("EMAIL_ADDRESS", "")
SENDER_PASSWORD = os.environ.get("EMAIL_APP_PASSWORD", "")
DEFAULT_TO_EMAIL = os.environ.get("TO_EMAIL") or SENDER_EMAIL
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
SLACK_WEBHOOK_URGENT = os.environ.get("SLACK_WEBHOOK_URGENT")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b")

def clean_text(value):
    if value is None:
        return ""
    return " ".join(html.unescape(str(value)).split())

def _parse_inline_list(value):
    value = value.strip()
    if not value.startswith("[") or not value.endswith("]"):
        return []

    items = []
    for item in value[1:-1].split(","):
        item = item.strip().strip("'\"")
        if item:
            items.append(item)
    return items

def load_inventory_terms(inventory_file=None):
    path = Path(inventory_file) if inventory_file else INVENTORY_FILE
    if not path.exists():
        return []

    terms = []
    current_name = ""

    try:
        with path.open("r", encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("- name:"):
                    current_name = line.split(":", 1)[1].strip().strip("'\"")
                    if current_name:
                        terms.append(current_name)
                elif line.startswith("aliases:"):
                    aliases = _parse_inline_list(line.split(":", 1)[1])
                    terms.extend(aliases)
    except OSError:
        return []

    seen = set()
    unique_terms = []
    for term in terms:
        normalized = clean_text(term).lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_terms.append(term)
    return unique_terms

def match_inventory_terms(values, inventory_file=None):
    if isinstance(values, (str, bytes)):
        values = [values]

    haystack = " ".join(clean_text(value).lower() for value in values if value is not None)
    if not haystack:
        return []

    matched = []
    for term in load_inventory_terms(inventory_file):
        normalized = clean_text(term).lower()
        if not normalized:
            continue
        # 단어 경계 매칭: "ADC"가 "broadcast", "Arbor"가 "arboretum"에 매칭되는 오탐 방지
        pattern = r"(?<![0-9a-z가-힣])" + re.escape(normalized) + r"(?![0-9a-z가-힣])"
        if re.search(pattern, haystack):
            matched.append(term)
    return matched

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# MITRE ATT&CK Enterprise 기법 ID (T1566, T1566.001 등). LLM 환각을 피하기 위해 정규식으로만 추출.
# re.ASCII: 한글 조사("T1059를")가 \b에 걸리지 않는 문제 방지
ATTACK_TECHNIQUE_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.ASCII)

def extract_attack_techniques(*texts):
    """텍스트에 명시된 MITRE ATT&CK 기법 ID를 추출해 중복 제거한 목록 반환"""
    found = []
    seen = set()
    for text in texts:
        if not text:
            continue
        for match in ATTACK_TECHNIQUE_RE.findall(str(text)):
            if match not in seen:
                seen.add(match)
                found.append(match)
    return found

def extract_cves(*texts):
    """텍스트(기사 제목·요약·본문 등)에서 CVE 번호를 추출해 정규화·중복 제거한 목록 반환"""
    found = []
    seen = set()
    for text in texts:
        if not text:
            continue
        for match in CVE_ID_RE.findall(str(text)):
            cve = match.upper()
            if cve not in seen:
                seen.add(cve)
                found.append(cve)
    return found

# ===== IOC 추출 (기사·블로그 본문에서 파일 해시 / 공인 IP / 디팽된 도메인·URL) =====
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# re.ASCII: 한글 조사("...net을")가 \w·\b에 걸려 도메인에 붙어 나오는 것을 방지
DEFANGED_DOMAIN_RE = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9-]*(?:(?:\.|\[\.\])[A-Za-z0-9-]+)*\[\.\][A-Za-z]{2,}\b",
    re.ASCII,
)
HXXP_URL_RE = re.compile(r"\bhxxps?://[^\s\"'<>]+", re.IGNORECASE)

_PRIVATE_IP_PREFIXES = ("0.", "10.", "127.", "169.254.", "192.168.", "224.", "255.")

def _is_public_ip(ip):
    if ip.startswith(_PRIVATE_IP_PREFIXES) or ip.endswith(".0"):
        return False
    octets = ip.split(".")
    if octets[0] == "172" and 16 <= int(octets[1]) <= 31:
        return False
    return True

def extract_iocs(*texts, limit=50):
    """텍스트에서 IOC를 추출해 [{"type": "sha256|sha1|md5|ipv4|domain|url", "value": ...}]로 반환.

    MISP/STIX 관행대로 타입을 함께 저장해 리포트에서 타입별 분류·차단 목록 변환이 가능하다.
    일반 도메인·URL은 뉴스 본문 오탐이 많아 제외하고, 작성자가 의도적으로
    디팽(defang)한 것(example[.]com, hxxp://)만 IOC로 간주한다.
    """
    found = []
    seen = set()

    def add(ioc_type, value):
        value = value.strip().strip(".,;:)]}")
        key = value.lower()
        if value and key not in seen:
            seen.add(key)
            found.append({"type": ioc_type, "value": value})

    for text in texts:
        if not text:
            continue
        text = str(text)

        for match in HXXP_URL_RE.findall(text):
            add("url", re.sub(r"^hxxp", "http", match.replace("[.]", "."), flags=re.IGNORECASE))
        # URL로 이미 수집된 구간은 제외하고 디팽된 도메인만 스캔 (중복 방지)
        for match in DEFANGED_DOMAIN_RE.findall(HXXP_URL_RE.sub(" ", text)):
            add("domain", match.replace("[.]", "."))

        refanged = text.replace("[.]", ".")
        for pattern, ioc_type in ((SHA256_RE, "sha256"), (SHA1_RE, "sha1"), (MD5_RE, "md5")):
            for match in pattern.findall(refanged):
                add(ioc_type, match.lower())
        for match in IPV4_RE.findall(refanged):
            if _is_public_ip(match):
                add("ipv4", match)

    return found[:limit]

# ===== LLM 기사 분석 (수집 시점 enrichment — 보안뉴스/ASEC 등 기사형 소스 공용) =====
THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

ENRICH_PROMPT = """당신은 보안관제(SOC) 조직의 위협 인텔리전스 분석가이다.
아래 보안 기사를 분석해 JSON 하나만 출력하라. JSON 외 다른 텍스트를 출력하지 마라.

형식:
{{"summary": "핵심 내용 3문장 이내 요약(한국어)",
  "severity": "critical|high|medium|low|info 중 하나",
  "category": "취약점|악성코드|침해사고|공격캠페인|정책규제|제품행사|기타 중 하나",
  "affected_products": ["영향받는 제품·서비스명. 영문 공식 명칭으로 정규화 (예: Fortinet FortiGate, Apache Tomcat)"],
  "threat_actor": "언급된 공격 그룹명(영문 공식 명칭, 예: Lazarus). 없으면 빈 문자열",
  "malware_family": "언급된 악성코드·랜섬웨어 패밀리명(영문). 없으면 빈 문자열",
  "relevance": "국내 IT·게임 기업 보안팀 관점의 중요도: high|medium|low 중 하나",
  "confidence": "위 분석에 대한 확신도: high|medium|low 중 하나 (기사 정보가 모호하면 low)",
  "recommended_actions": ["보안담당자 권고 조치(최대 3개)"]}}

카테고리 기준: 제품 홍보·전시회·수상·인터뷰 기사는 "제품행사"로 분류하라.
주의: 기사에 없는 사실을 만들어내지 마라. 해당 정보가 없으면 빈 배열/빈 문자열 또는 "info"를 사용하라.

제목: {title}

본문:
{body}
"""

ENRICH_SEVERITIES = ("critical", "high", "medium", "low", "info")
ENRICH_CATEGORIES = ("취약점", "악성코드", "침해사고", "공격캠페인", "정책규제", "제품행사", "기타")
ENRICH_RELEVANCES = ("high", "medium", "low")
ENRICH_BODY_MAX_CHARS = 4000

def _clean_str_list(value, limit):
    if not isinstance(value, list):
        return []
    return [clean_text(item) for item in value if clean_text(item)][:limit]

def ai_enrich_article(title, body):
    """기사 본문을 LLM으로 분석해 구조화된 enrichment를 반환. 실패 시 None."""
    if not body:
        return None

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": ENRICH_PROMPT.format(title=title, body=body[:ENRICH_BODY_MAX_CHARS]),
                "stream": False,
                "format": "json",
            },
            timeout=120,
        )
        if response.status_code != 200:
            print("[-] AI enrichment 실패: HTTP {}".format(response.status_code))
            return None

        text = THINK_TAG_RE.sub("", (response.json() or {}).get("response", "")).strip()
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        data = json.loads(text[start:end + 1])

        severity = str(data.get("severity") or "").lower()
        category = clean_text(data.get("category"))
        relevance = str(data.get("relevance") or "").lower()
        confidence = str(data.get("confidence") or "").lower()
        return {
            "summary": clean_text(data.get("summary"))[:500] or None,
            "severity": severity if severity in ENRICH_SEVERITIES else None,
            "category": category if category in ENRICH_CATEGORIES else ("기타" if category else None),
            "affected_products": _clean_str_list(data.get("affected_products"), 10),
            "threat_actor": clean_text(data.get("threat_actor")) or None,
            "malware_family": clean_text(data.get("malware_family")) or None,
            "relevance": relevance if relevance in ENRICH_RELEVANCES else None,
            "confidence": confidence if confidence in ENRICH_RELEVANCES else None,
            "recommended_actions": _clean_str_list(data.get("recommended_actions"), 3),
        }
    except Exception as error:
        print("[-] AI enrichment 실패: {}".format(error))
        return None

# ===== 긴급도 분류 (CISA SSVC 간소화: 악용 상태 → 자산 매칭 → 기술 영향) =====
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_POC_THRESHOLD = float(os.environ.get("EPSS_POC_THRESHOLD", "0.1"))
EPSS_ACTIVE_THRESHOLD = float(os.environ.get("EPSS_ACTIVE_THRESHOLD", "0.5"))

EXPLOIT_ACTIVE_KEYWORDS = [
    "actively exploited", "exploitation detected", "exploited in the wild",
    "in the wild", "known exploited", "제로데이 공격", "실제 악용", "악용 확인",
]
EXPLOIT_POC_KEYWORDS = [
    "proof of concept", "proof-of-concept", "poc released", "poc 공개",
    "exploit code", "exploit available", "metasploit", "공격 코드 공개",
]
TOTAL_IMPACT_KEYWORDS = [
    "remote code execution", "원격 코드 실행", "원격코드실행",
    "elevation of privilege", "privilege escalation", "권한 상승",
    "authentication bypass", "인증 우회", "unauthenticated",
]

def fetch_epss_scores(cve_ids, timeout=20):
    """FIRST.org EPSS API에서 CVE별 '30일 내 악용될 확률'(0~1)을 일괄 조회. 실패 시 빈 dict."""
    ids = sorted({cve for cve in (cve_ids or []) if cve})
    scores = {}
    for start in range(0, len(ids), 100):
        batch = ids[start:start + 100]
        url = "{}?cve={}".format(EPSS_API_URL, ",".join(urllib.parse.quote(cve) for cve in batch))
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "boannews-mail-triage/1.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            for row in data.get("data", []):
                try:
                    scores[row["cve"]] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        except Exception as error:
            print("[-] EPSS 조회 실패({}건): {}".format(len(batch), error))
    return scores

def classify_urgency(match_values, cvss_score=None, kev=False, exploited=False, poc_public=False, epss=None,
                     exclude_assets=None):
    """SSVC 간소화 트리로 P1/P2/P3 판정.

    P1: 실제 악용 중 + 자사 자산 매칭
    P2: 실제 악용 중 / (PoC 공개 또는 Critical 영향) + 자산 매칭
    P3: 그 외

    exclude_assets: 자산 매칭에서 무시할 용어 목록. 벤더 리서치 블로그가
    본문에 항상 자사명을 넣어(예: Unit 42 → "Palo Alto Networks") 생기는
    상시 오탐을 소스별로 걸러낼 때 사용한다.
    """
    if isinstance(match_values, (str, bytes)):
        match_values = [match_values]
    text = " ".join(clean_text(value).lower() for value in (match_values or []) if value is not None)
    reasons = []

    # 결정점 1: 악용 상태 (none / poc / active)
    exploitation = "none"
    if kev:
        exploitation = "active"
        reasons.append("실제 악용 확인(CISA KEV)")
    elif exploited:
        exploitation = "active"
        reasons.append("실제 악용 확인(MSRC)")
    elif any(keyword in text for keyword in EXPLOIT_ACTIVE_KEYWORDS):
        exploitation = "active"
        reasons.append("악용 정황 키워드")
    elif epss is not None and epss >= EPSS_ACTIVE_THRESHOLD:
        exploitation = "active"
        reasons.append("악용 확률 높음(EPSS {:.0%})".format(epss))
    elif poc_public:
        exploitation = "poc"
        reasons.append("공격 코드 공개")
    elif epss is not None and epss >= EPSS_POC_THRESHOLD:
        exploitation = "poc"
        reasons.append("악용 확률 주의(EPSS {:.0%})".format(epss))
    elif any(keyword in text for keyword in EXPLOIT_POC_KEYWORDS):
        exploitation = "poc"
        reasons.append("PoC 공개 키워드")

    # 결정점 2: 자사 자산 매칭
    matched_assets = match_inventory_terms(match_values or [])
    if exclude_assets:
        excluded = {clean_text(term).lower() for term in exclude_assets}
        matched_assets = [term for term in matched_assets if clean_text(term).lower() not in excluded]
    if matched_assets:
        reasons.append("자사 자산 매칭({})".format(", ".join(matched_assets)))

    # 결정점 3: 기술 영향 (partial / total)
    impact = "partial"
    try:
        score_value = float(cvss_score) if cvss_score not in (None, "") else 0.0
    except (TypeError, ValueError):
        score_value = 0.0
    if score_value >= 9.0:
        impact = "total"
        reasons.append("CVSS {}".format(cvss_score))
    elif any(keyword in text for keyword in TOTAL_IMPACT_KEYWORDS):
        impact = "total"
        reasons.append("고위험 유형(RCE/권한상승 등)")

    # 판정 매트릭스
    if exploitation == "active" and matched_assets:
        level = "P1"
    elif exploitation == "active":
        level = "P2"
    elif matched_assets and (exploitation == "poc" or impact == "total"):
        level = "P2"
    else:
        level = "P3"

    return {
        "level": level,
        "exploitation": exploitation,
        "impact": impact,
        "matched_assets": matched_assets,
        "epss": epss,
        "reasons": reasons,
    }

# ===== 중요도 스코어링 (뉴스 소스 확대에 따른 알림 필터링) =====
# 점수 미달 기사는 즉시 알림을 생략하고 events.jsonl에만 적재해 일간 리포트에서 다룬다.
IMPORTANCE_ALERT_THRESHOLD = int(os.environ.get("NEWS_ALERT_MIN_SCORE", "50"))

_SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 5}
_RELEVANCE_POINTS = {"high": 25, "medium": 10}
_CATEGORY_POINTS = {
    "취약점": 5, "악성코드": 5, "침해사고": 5, "공격캠페인": 5,
    "정책규제": -5, "제품행사": -30,
}

def score_importance(triage=None, enrichment=None, cves=None):
    """기사 중요도를 0~100 점수로 산정해 {"score", "reasons"}를 반환.

    트리아지(악용 상태·자산 매칭·기술 영향)와 LLM enrichment(severity·relevance·
    category)를 합산한다. enrichment가 없어도(LLM 다운) 트리아지 신호만으로
    악용 중인 건은 임계값을 넘도록 가중치를 배분했다.
    """
    triage = triage or {}
    enrichment = enrichment or {}
    score = 0
    reasons = []

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append("{}({:+d})".format(reason, points))

    exploitation = triage.get("exploitation") or "none"
    if exploitation == "active":
        add(40, "실제 악용 정황")
    elif exploitation == "poc":
        add(20, "PoC/악용 가능성")

    if triage.get("matched_assets"):
        add(35, "자사 자산 매칭")

    if triage.get("impact") == "total":
        add(10, "고위험 유형(RCE/권한상승 등)")

    severity = str(enrichment.get("severity") or "").lower()
    if severity in _SEVERITY_POINTS:
        add(_SEVERITY_POINTS[severity], "심각도 {}".format(severity))

    relevance = str(enrichment.get("relevance") or "").lower()
    if relevance in _RELEVANCE_POINTS:
        add(_RELEVANCE_POINTS[relevance], "관련성 {}".format(relevance))

    category = clean_text(enrichment.get("category"))
    if category in _CATEGORY_POINTS:
        add(_CATEGORY_POINTS[category], "분류 {}".format(category))

    if cves:
        add(5, "CVE 언급")

    if enrichment.get("threat_actor") or enrichment.get("malware_family"):
        add(5, "위협 그룹/악성코드 특정")

    return {"score": max(0, min(100, score)), "reasons": reasons}

def should_alert(importance, triage=None, min_score=None):
    """즉시 알림 여부 판정. P1/P2는 점수와 무관하게 항상 알림."""
    if (triage or {}).get("level") in ("P1", "P2"):
        return True
    threshold = IMPORTANCE_ALERT_THRESHOLD if min_score is None else int(min_score)
    return (importance or {}).get("score", 0) >= threshold

def triage_marker(triage):
    level = (triage or {}).get("level")
    if level == "P1":
        return "🚨 *P1* "
    if level == "P2":
        return "⚠️ P2 "
    return ""

def triage_note(triage):
    triage = triage or {}
    if triage.get("level") in ("P1", "P2") and triage.get("reasons"):
        return "\n> 판정: {}".format("; ".join(triage["reasons"]))
    return ""

def pick_webhook(default_webhook, triages):
    """P1 항목이 하나라도 있으면 긴급 채널로 라우팅"""
    p1_triages = [t for t in (triages or []) if (t or {}).get("level") == "P1"]
    if p1_triages and SLACK_WEBHOOK_URGENT:
        reasons = sorted({reason for t in p1_triages for reason in t.get("reasons", [])})
        print("[!] P1 {}건 → 긴급 채널로 발송 ({})".format(len(p1_triages), "; ".join(reasons)))
        return SLACK_WEBHOOK_URGENT
    return default_webhook

def load_json_state(state_file, default_factory=dict):
    path = Path(state_file)
    if not path.exists():
        return default_factory()
    try:
        with path.open("r", encoding="utf-8") as file:
            state = json.load(file)
            if state is None:
                return default_factory()
            return state
    except (json.JSONDecodeError, OSError):
        return default_factory()

def save_json_state(state_file, state_data, max_items=None, keys_to_trim=None):
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # 리스트 데이터의 크기 제한 처리
    if max_items:
        if isinstance(state_data, list):
            state_data = state_data[-max_items:]
        elif isinstance(state_data, dict) and keys_to_trim:
            for key in keys_to_trim:
                if key in state_data and isinstance(state_data[key], list):
                    state_data[key] = state_data[key][-max_items:]

    with path.open("w", encoding="utf-8") as file:
        json.dump(state_data, file, ensure_ascii=False, indent=2)

def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def make_event(source, item_id, title, url="", summary="", severity="", score=None,
               cves=None, published_at="", ai_summary=None, email_sent=False, slack_sent=False,
               triage=None, category="", affected_products=None, epss=None,
               threat_actor="", malware_family="", kev=False, iocs=None, relevance="",
               references=None, fix_available=None, remediation="", due_date="",
               ransomware_use=None, confidence="", attack_techniques=None, importance=None):
    """모든 수집 스크립트가 공유하는 통합 이벤트 스키마. 일간/주간 리포트의 입력이 됩니다.

    epss/exploitation_status는 명시하지 않으면 triage 결과에서 물려받는다.
    iocs는 [{"type": "sha256|sha1|md5|ipv4|domain|url", "value": ...}] 형식(extract_iocs 산출물).
    confidence는 LLM enrichment 분석의 확신도(high/medium/low) — API 소스 사실 필드에는 사용하지 않는다.
    """
    if triage:
        matched_assets = triage.get("matched_assets") or []
        if epss is None:
            epss = triage.get("epss")
    else:
        matched_assets = match_inventory_terms([title, summary])
    return {
        "id": "{}:{}".format(source, item_id),
        "source": source,
        "title": clean_text(title),
        "url": url,
        "summary": clean_text(summary),
        "severity": clean_text(severity),
        "score": score,
        "cves": [cve for cve in (cves or []) if cve],
        "matched_assets": matched_assets,
        "category": clean_text(category),
        "affected_products": [clean_text(p) for p in (affected_products or []) if clean_text(p)],
        "epss": epss,
        "exploitation_status": (triage or {}).get("exploitation") or "none",
        "kev": bool(kev) or source == "cisa_kev",
        "ransomware_use": ransomware_use,
        "threat_actor": clean_text(threat_actor),
        "malware_family": clean_text(malware_family),
        "attack_techniques": [t for t in (attack_techniques or []) if t],
        "iocs": [ioc for ioc in (iocs or []) if ioc],
        "relevance": clean_text(relevance).lower(),
        "references": [r for r in (references or []) if r],
        "fix_available": fix_available,
        "remediation": clean_text(remediation),
        "due_date": clean_text(due_date),
        "confidence": clean_text(confidence).lower(),
        "published_at": published_at or "",
        "fetched_at": utc_now_iso(),
        "ai_summary": ai_summary,
        "triage": triage,
        "importance": importance,
        "delivery": {"email_sent": bool(email_sent), "slack_sent": bool(slack_sent)},
    }

def append_events(events, events_file=None):
    if not events:
        return
    path = Path(events_file) if events_file else EVENTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

def send_email_message(subject, text_body, html_body=None, to_email=None):
    to_email = to_email or DEFAULT_TO_EMAIL

    if not SENDER_EMAIL or not SENDER_PASSWORD or not to_email:
        print("[-] Email skipped: EMAIL_ADDRESS, EMAIL_APP_PASSWORD, or TO_EMAIL is not configured.")
        return False
    
    message = MIMEMultipart("alternative") if html_body else MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = to_email
    message["Subject"] = subject

    if text_body:
        message.attach(MIMEText(text_body, "plain", "utf-8"))
    if html_body:
        message.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, message.as_string())
        print(f"[+] 메일 발송 성공 -> {to_email}")
        return True
    except Exception as e:
        print(f"[-] 메일 발송 실패: {e}")
        return False

# Slack 메시지 하드 리밋: 블록 50개, section 텍스트 3,000자 초과 시 발송 자체가 400으로 실패합니다.
SLACK_MAX_BLOCKS = 50
SLACK_MAX_SECTION_TEXT = 3000

def _sanitize_slack_payload(payload):
    if not isinstance(payload, dict):
        return payload
    blocks = payload.get("blocks")
    if not isinstance(blocks, list):
        return payload

    for block in blocks:
        if not isinstance(block, dict):
            continue
        text = block.get("text")
        if isinstance(text, dict) and isinstance(text.get("text"), str):
            if len(text["text"]) > SLACK_MAX_SECTION_TEXT:
                text["text"] = text["text"][:SLACK_MAX_SECTION_TEXT - 1] + "…"

    if len(blocks) > SLACK_MAX_BLOCKS:
        omitted = len(blocks) - (SLACK_MAX_BLOCKS - 1)
        payload["blocks"] = blocks[:SLACK_MAX_BLOCKS - 1] + [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "⚠️ 메시지 한도 초과로 {}개 블록이 생략되었습니다.".format(omitted),
                },
            }
        ]
    return payload

def send_slack_webhook(payload, webhook_url=None):
    url = webhook_url or SLACK_WEBHOOK_URL
    if not url:
        print("[-] 슬랙 알림 실패: Webhook URL이 설정되지 않았습니다.")
        return False

    payload = _sanitize_slack_payload(payload)

    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url, 
            data=data, 
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("[+] 슬랙 메시지 발송 성공")
                return True
            else:
                print(f"[-] 슬랙 메시지 발송 실패 (Status Code: {response.status})")
                return False
    except Exception as e:
        print(f"[-] 슬랙 발송 중 오류 발생: {e}")
        return False
