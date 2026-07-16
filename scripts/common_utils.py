import hashlib
import ipaddress
import math
import os
import json
import re
import requests
import smtplib
import time
from datetime import datetime, timedelta
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
FEEDBACK_FILE = DATA_DIR / "feedback.jsonl"
LEARNED_WEIGHTS_FILE = DATA_DIR / "learned_weights.json"

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
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").strip().lower()
NVIDIA_API_URL = os.environ.get("NVIDIA_API_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")

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

# ===== 인텔 참조 데이터 (assets/intel/ — update_intel_data.py로 갱신) =====
INTEL_DIR = ASSETS_DIR / "intel"
_intel_cache = {}

def _load_intel(name):
    """assets/intel/<name>.json을 읽어 캐시. 파일이 없거나 깨졌으면 None (기능 자동 비활성)."""
    if name in _intel_cache:
        return _intel_cache[name]
    data = None
    try:
        with (INTEL_DIR / (name + ".json")).open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        pass
    _intel_cache[name] = data
    return data

def normalize_threat_actor(name):
    """위협그룹 명칭을 MISP Galaxy 공식 명칭으로 정규화 (예: Hidden Cobra → Lazarus Group).

    앨리어스 사전에 없으면 원문 그대로 반환. 참조 데이터가 없어도 동작한다.
    """
    name = clean_text(name)
    if not name:
        return ""
    aliases = (_load_intel("threat_actor_aliases") or {}).get("aliases") or {}
    return aliases.get(name.lower(), name)

def validate_attack_techniques(candidates):
    """LLM이 제시한 ATT&CK 기법 ID 후보를 공식 카탈로그로 검증해 환각을 차단.

    카탈로그(assets/intel/attack_techniques.json)가 없으면 전부 폐기한다 —
    검증 불가능한 LLM 출력을 통과시키는 것보다 놓치는 쪽이 안전하다.
    """
    catalog = (_load_intel("attack_techniques") or {}).get("techniques") or {}
    if not catalog or not isinstance(candidates, list):
        return []
    validated = []
    seen = set()
    for candidate in candidates:
        match = ATTACK_TECHNIQUE_RE.search(str(candidate).upper().strip())
        technique = match.group(0) if match else ""
        if technique and technique in catalog and technique not in seen:
            seen.add(technique)
            validated.append(technique)
    return validated

def _benign_ioc_sets():
    """warninglists 기반 벤인 인프라 조회 구조 (ips set / CIDR 네트워크 / domains set)"""
    if "_benign_parsed" in _intel_cache:
        return _intel_cache["_benign_parsed"]
    data = _load_intel("benign_iocs")
    parsed = None
    if data:
        networks = []
        for cidr in data.get("cidrs") or []:
            try:
                networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                continue
        parsed = {
            "ips": set(data.get("ips") or []),
            "networks": networks,
            "domains": set(data.get("domains") or []),
        }
    _intel_cache["_benign_parsed"] = parsed
    return parsed

def _is_benign_domain(domain, benign):
    domain = domain.lower().strip(".")
    return domain in benign["domains"] or any(
        domain.endswith("." + suffix) for suffix in benign["domains"]
    )

def is_benign_ioc(ioc_type, value):
    """공용 DNS·CDN·대형 벤더 도메인 등 차단 지표로 무의미한 값인지 판별 (MISP warninglists)"""
    benign = _benign_ioc_sets()
    if not benign:
        return False
    if ioc_type == "ipv4":
        if value in benign["ips"]:
            return True
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in benign["networks"])
    if ioc_type == "domain":
        return _is_benign_domain(value, benign)
    if ioc_type == "url":
        host = urllib.parse.urlparse(value).hostname or ""
        return bool(host) and _is_benign_domain(host, benign)
    return False

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
    공용 DNS·CDN 등 벤인 인프라(MISP warninglists)는 걸러낸다.
    """
    found = []
    seen = set()

    def add(ioc_type, value):
        value = value.strip().strip(".,;:)]}")
        key = value.lower()
        if not value or key in seen:
            return
        seen.add(key)
        if is_benign_ioc(ioc_type, value):
            return
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

# ===== PIR (우선 정보 요구사항 — assets/pir.json) =====
PIR_FILE = ASSETS_DIR / "pir.json"

def load_pirs():
    """PIR 정의를 {"PIR-1": {"question", "weight"}}로 반환. 파일이 없으면 빈 dict."""
    if "_pirs" not in _intel_cache:
        pirs = {}
        try:
            with PIR_FILE.open("r", encoding="utf-8") as file:
                data = json.load(file)
            for entry in data.get("pirs") or []:
                pid = clean_text(entry.get("id")).upper()
                question = clean_text(entry.get("question"))
                if pid and question:
                    pirs[pid] = {
                        "question": question,
                        "weight": str(entry.get("weight") or "medium").lower(),
                    }
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        _intel_cache["_pirs"] = pirs
    return _intel_cache["_pirs"]

def validate_pirs(candidates):
    """LLM이 판정한 PIR ID 후보를 정의 목록으로 검증·정규화"""
    pir_defs = load_pirs()
    validated = []
    if not isinstance(candidates, list):
        return validated
    for candidate in candidates:
        pid = clean_text(candidate).upper().replace(" ", "")
        if pid in pir_defs and pid not in validated:
            validated.append(pid)
    return validated

# ===== LLM 호출 공용 계층 (LLM_PROVIDER: nvidia = NVIDIA NIM API, ollama = 로컬) =====
THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

def _generate_nvidia(prompt, timeout):
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 8192,
        "stream": False,
    }
    headers = {"Authorization": "Bearer {}".format(NVIDIA_API_KEY)}
    for attempt in (1, 2):
        response = requests.post(NVIDIA_API_URL, headers=headers, json=payload, timeout=timeout)
        if response.status_code == 429 and attempt == 1:
            # 무료 티어 40 RPM 제한 — 한 번만 대기 후 재시도
            time.sleep(15)
            continue
        break
    if response.status_code != 200:
        raise RuntimeError("HTTP {}".format(response.status_code))
    choices = (response.json() or {}).get("choices") or []
    if not choices:
        raise RuntimeError("빈 choices 응답")
    return (choices[0].get("message") or {}).get("content") or ""

def _generate_ollama(prompt, timeout, json_format):
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
    if json_format:
        payload["format"] = "json"
    response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
    if response.status_code != 200:
        raise RuntimeError("HTTP {}".format(response.status_code))
    return (response.json() or {}).get("response", "")

def llm_generate(prompt, timeout=120, json_format=False):
    """설정된 프로바이더로 LLM 텍스트를 생성한다. <think> 태그 제거 후 반환, 실패 시 None.

    LLM_PROVIDER=nvidia 이면 NVIDIA NIM을 먼저 시도하고 실패 시 로컬 Ollama로 폴백한다.
    """
    providers = ["nvidia", "ollama"] if LLM_PROVIDER == "nvidia" else ["ollama"]
    for provider in providers:
        try:
            if provider == "nvidia":
                if not NVIDIA_API_KEY:
                    raise RuntimeError("NVIDIA_API_KEY 미설정")
                text = _generate_nvidia(prompt, timeout)
            else:
                text = _generate_ollama(prompt, timeout, json_format)
            text = THINK_TAG_RE.sub("", text).strip()
            if text:
                return text
            raise RuntimeError("빈 응답")
        except Exception as error:
            print("[-] LLM 생성 실패 ({}): {}".format(provider, error))
    return None

# ===== LLM 기사 분석 (수집 시점 enrichment — 보안뉴스/ASEC 등 기사형 소스 공용) =====

ENRICH_PROMPT = """당신은 보안관제(SOC) 조직의 위협 인텔리전스 분석가이다.
아래 보안 기사를 분석해 JSON 하나만 출력하라. JSON 외 다른 텍스트를 출력하지 마라.

형식:
{{"summary": "핵심 내용 3문장 이내 요약(한국어)",
  "severity": "critical|high|medium|low|info 중 하나",
  "category": "취약점|악성코드|침해사고|개인정보유출|공격캠페인|공급망공격|피싱사기|정책규제|기술동향|제품행사|기타 중 하나",
  "affected_products": ["영향받는 제품·서비스명. 영문 공식 명칭으로 정규화 (예: Fortinet FortiGate, Apache Tomcat)"],
  "threat_actor": "언급된 공격 그룹명(영문 공식 명칭, 예: Lazarus). 없으면 빈 문자열",
  "malware_family": "언급된 악성코드·랜섬웨어 패밀리명(영문). 없으면 빈 문자열",
  "attack_techniques": ["기사에 서술된 공격 기법의 MITRE ATT&CK Enterprise 기법 ID (예: T1566, T1059.001). 기사 내용상 명확한 것만, 최대 5개. 불확실하면 빈 배열"],
  "exploitation": "기사가 보도 시점 기준으로 전하는 악용 상태: active(현재 실제 악용·공격 진행 중을 보도)|poc(공격 코드·PoC 공개까지만 보도)|none(그 외. 과거 사건 회고, 일반 동향, 연구 결과 소개는 none)",
{pir_field}
  "relevance": "국내 IT·게임 기업 보안팀 관점의 중요도: high|medium|low 중 하나",
  "content_depth": "기사 유형: analysis(자체 조사·기술 분석을 담은 심층 분석)|report(보고서·통계·조사 결과 전달)|news(사건·발표 단신)|opinion(칼럼·의견) 중 하나",
  "confidence": "위 분석에 대한 확신도: high|medium|low 중 하나 (기사 정보가 모호하면 low)",
  "recommended_actions": ["보안담당자 권고 조치(최대 3개)"]}}

카테고리 기준:
- 개인정보유출: 개인정보·고객정보 유출이 핵심인 사고 (시스템 침해가 있어도 유출이 본질이면 이쪽)
- 침해사고: 유출 외의 기업·기관 시스템 침해·해킹 피해
- 공급망공격: 오픈소스 패키지·벤더·업데이트 경로를 통한 공격
- 공격캠페인: 조직을 노리는 표적형 캠페인·APT 활동
- 피싱사기: 일반 소비자 대상 스미싱·보이스피싱·사기 (조직 표적 피싱은 공격캠페인)
- 기술동향: 신기술 담론·연구 보고서·통계·컨퍼런스 논의 (양자보안, AI 보안 등)
- 제품행사: 제품 홍보·전시회·수상·인터뷰 기사
- 정책규제: 법·제도·규제·컴플라이언스
주의: 기사에 없는 사실을 만들어내지 마라. 해당 정보가 없으면 빈 배열/빈 문자열 또는 "info"를 사용하라.
{pir_block}
제목: {title}

본문:
{body}
"""

ENRICH_SEVERITIES = ("critical", "high", "medium", "low", "info")
ENRICH_CATEGORIES = (
    "취약점", "악성코드", "침해사고", "개인정보유출", "공격캠페인", "공급망공격",
    "피싱사기", "정책규제", "기술동향", "제품행사", "기타",
)
ENRICH_RELEVANCES = ("high", "medium", "low")
ENRICH_DEPTHS = ("analysis", "report", "news", "opinion")
ENRICH_BODY_MAX_CHARS = 4000

def _clean_str_list(value, limit):
    if not isinstance(value, list):
        return []
    return [clean_text(item) for item in value if clean_text(item)][:limit]

def _build_enrich_prompt(title, body):
    """PIR 정의(있으면)를 프롬프트에 주입해 완성한다"""
    pirs = load_pirs()
    if pirs:
        pir_field = '  "pirs": ["기사가 명확히 답하는 PIR ID 목록 (아래 정의 참조, 예: PIR-1). 해당 없으면 빈 배열"],'
        pir_block = "\n조직의 우선 정보 요구사항(PIR) — 기사가 아래 질문에 답하는 경우에만 해당 ID를 부여하라:\n{}\n".format(
            "\n".join("{}: {}".format(pid, pir["question"]) for pid, pir in pirs.items())
        )
    else:
        pir_field = ""
        pir_block = ""
    return ENRICH_PROMPT.format(
        title=title, body=body[:ENRICH_BODY_MAX_CHARS],
        pir_field=pir_field, pir_block=pir_block,
    )

def ai_enrich_article(title, body):
    """기사 본문을 LLM으로 분석해 구조화된 enrichment를 반환. 실패 시 None."""
    if not body:
        return None

    text = llm_generate(_build_enrich_prompt(title, body), timeout=120, json_format=True)
    if not text:
        return None

    try:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        data = json.loads(text[start:end + 1])

        severity = str(data.get("severity") or "").lower()
        category = clean_text(data.get("category"))
        relevance = str(data.get("relevance") or "").lower()
        confidence = str(data.get("confidence") or "").lower()
        exploitation = str(data.get("exploitation") or "").lower()
        content_depth = str(data.get("content_depth") or "").lower()
        return {
            "summary": clean_text(data.get("summary"))[:500] or None,
            "severity": severity if severity in ENRICH_SEVERITIES else None,
            "exploitation": exploitation if exploitation in ("active", "poc", "none") else None,
            "content_depth": content_depth if content_depth in ENRICH_DEPTHS else None,
            "category": category if category in ENRICH_CATEGORIES else ("기타" if category else None),
            "affected_products": _clean_str_list(data.get("affected_products"), 10),
            "threat_actor": clean_text(data.get("threat_actor")) or None,
            "malware_family": clean_text(data.get("malware_family")) or None,
            "attack_techniques": validate_attack_techniques(data.get("attack_techniques")),
            "pirs": validate_pirs(data.get("pirs")),
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
    "악용 사례", "악용되고", "실제 공격", "공격 확산", "유포 중",
]
EXPLOIT_POC_KEYWORDS = [
    "proof of concept", "proof-of-concept", "poc released", "poc 공개",
    "exploit code", "exploit available", "metasploit", "공격 코드 공개",
    "익스플로잇 공개",
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

    # 결정점 1: 악용 상태 (none / poc / active).
    # basis는 판정 근거 구분 — fact(KEV/MSRC/EPSS/공식 플래그)는 LLM 판정으로도
    # 뒤집히지 않고, keyword는 refine_triage_with_enrichment에서 LLM 판정이 대체한다.
    exploitation = "none"
    basis = "none"
    if kev:
        exploitation, basis = "active", "fact"
        reasons.append("실제 악용 확인(CISA KEV)")
    elif exploited:
        exploitation, basis = "active", "fact"
        reasons.append("실제 악용 확인(MSRC)")
    elif any(keyword in text for keyword in EXPLOIT_ACTIVE_KEYWORDS):
        exploitation, basis = "active", "keyword"
        reasons.append("악용 정황 키워드")
    elif epss is not None and epss >= EPSS_ACTIVE_THRESHOLD:
        exploitation, basis = "active", "fact"
        reasons.append("악용 확률 높음(EPSS {:.0%})".format(epss))
    elif poc_public:
        exploitation, basis = "poc", "fact"
        reasons.append("공격 코드 공개")
    elif epss is not None and epss >= EPSS_POC_THRESHOLD:
        exploitation, basis = "poc", "fact"
        reasons.append("악용 확률 주의(EPSS {:.0%})".format(epss))
    elif any(keyword in text for keyword in EXPLOIT_POC_KEYWORDS):
        exploitation, basis = "poc", "keyword"
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

    return {
        "level": _urgency_level(exploitation, matched_assets, impact),
        "exploitation": exploitation,
        "exploitation_basis": basis,
        "impact": impact,
        "matched_assets": matched_assets,
        "epss": epss,
        "reasons": reasons,
    }

def refine_triage_with_enrichment(triage, enrichment):
    """LLM 악용 판정(enrichment.exploitation)을 반영해 갱신된 트리아지를 반환.

    사실 신호(KEV/MSRC/EPSS/공식 PoC 플래그) 판정은 유지한다. 키워드 판정은
    문맥을 모르므로(과거 사건 회고 기사도 매칭) LLM 판정이 있으면 상향·하향
    모두 LLM을 따르고, LLM 판정이 없으면(실패 등) 키워드 판정이 폴백으로 남는다.
    """
    triage = triage or {}
    llm = str((enrichment or {}).get("exploitation") or "").lower()
    if llm not in ("active", "poc", "none"):
        return triage
    if triage.get("exploitation_basis") == "fact" or llm == triage.get("exploitation"):
        return triage

    updated = dict(triage)
    reasons = [r for r in (triage.get("reasons") or []) if r not in ("악용 정황 키워드", "PoC 공개 키워드")]
    if llm != "none":
        reasons.insert(0, "악용 정황(LLM 판정: {})".format(llm))
    elif triage.get("exploitation") != "none":
        reasons.append("키워드 악용 신호를 LLM이 비진행형(회고·동향)으로 판정 — 하향")
    updated["exploitation"] = llm
    updated["exploitation_basis"] = "llm" if llm != "none" else "none"
    updated["reasons"] = reasons
    updated["level"] = _urgency_level(llm, triage.get("matched_assets"), triage.get("impact"))
    return updated

def _urgency_level(exploitation, matched_assets, impact):
    """SSVC 판정 매트릭스 — classify_urgency와 refine_triage_with_enrichment가 공유"""
    if exploitation == "active" and matched_assets:
        return "P1"
    if exploitation == "active":
        return "P2"
    if matched_assets and (exploitation == "poc" or impact == "total"):
        return "P2"
    return "P3"

# ===== 피드백 라벨 (알림 유용성 학습용 — feedback.py / slack_feedback_poller.py가 기록) =====
def event_ref(event_id):
    """이벤트 ID의 10자리 참조 해시. 슬랙 메시지·CLI에서 긴 ID 대신 사용한다."""
    return hashlib.sha1(str(event_id).encode("utf-8")).hexdigest()[:10]

def load_feedback(feedback_file=None):
    """피드백 라벨을 {event_id: 최신 레코드}로 반환 (같은 이벤트는 마지막 라벨 우선)"""
    path = Path(feedback_file) if feedback_file else FEEDBACK_FILE
    labels = {}
    if not path.exists():
        return labels
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event_id") and record.get("label") in ("useful", "noise"):
                labels[record["event_id"]] = record
    return labels

def append_feedback(records, feedback_file=None):
    path = Path(feedback_file) if feedback_file else FEEDBACK_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

# ===== 중요도 스코어링 (뉴스 소스 확대에 따른 알림 필터링) =====
# 점수 미달 기사는 즉시 알림을 생략하고 events.jsonl에만 적재해 일간 리포트에서 다룬다.
# 기본 45: Moderate 밴드 상한(64)에 신뢰도 C 배수(x0.75)가 적용되면 48이 되므로,
# 50이면 C 소스는 점수로 알림이 불가능해진다. 45는 "Moderate 상단을 채운 C 소스
# 기사"를 알림 경계에 둔다.
IMPORTANCE_ALERT_THRESHOLD = int(os.environ.get("NEWS_ALERT_MIN_SCORE", "45"))

# Recorded Future식 밴드 스코어링: 가장 강한 규칙이 밴드(하한~상한)를 결정하고,
# 나머지 규칙은 밴드 안에서 점수를 밀어올린다. 약한 신호가 아무리 쌓여도
# 강한 신호 없이는 High 밴드(65+)에 못 들어가므로, "65점 이상 = 강한 신호 실재"가 보장된다.
IMPORTANCE_BANDS = {"high": (65, 100), "moderate": (30, 64), "info": (5, 24)}
IMPORTANCE_PUSH = {"high": 15, "moderate": 8, "info": 3}
_BAND_ORDER = {"high": 0, "moderate": 1, "info": 2}
PRODUCT_EVENT_SCORE_CAP = 20  # 제품행사 기사는 다른 신호와 무관하게 이 점수를 넘지 못한다

# Admiralty 간소화(3단계) 소스 신뢰도 → 점수 배수.
# A: 당국·당사자 1차 소스 / B: 자체 텔레메트리 기반 벤더 리서치 / C: 2차 전달 매체.
# 미지정 소스는 중립(1.0)으로 둔다. P1/P2 판정은 사실 신호 기반이라 배수와 무관하게 알림된다.
RELIABILITY_MULTIPLIERS = {"A": 1.0, "B": 0.9, "C": 0.75}

# 학습 모델(train_weights.py)과 규칙 스코어링이 공유하는 이진 특징 정의.
# 새 특징을 추가하면 두 경로 모두 자동 반영되도록 여기서만 정의한다.
IMPORTANCE_FEATURE_LABELS = {
    "exploitation_active": "실제 악용 정황",
    "exploitation_poc": "PoC/악용 가능성",
    "asset_match": "자사 자산 매칭",
    "impact_total": "고위험 유형(RCE/권한상승 등)",
    "severity_critical": "심각도 critical",
    "severity_high": "심각도 high",
    "severity_medium": "심각도 medium",
    "relevance_high": "관련성 high",
    "relevance_medium": "관련성 medium",
    "category_취약점": "분류 취약점",
    "category_악성코드": "분류 악성코드",
    "category_침해사고": "분류 침해사고",
    "category_개인정보유출": "분류 개인정보유출",
    "category_공격캠페인": "분류 공격캠페인",
    "category_공급망공격": "분류 공급망공격",
    "category_피싱사기": "분류 피싱사기",
    "category_정책규제": "분류 정책규제",
    "category_기술동향": "분류 기술동향",
    "category_제품행사": "분류 제품행사",
    "has_cve": "CVE 언급",
    "has_actor": "위협 그룹/악성코드 특정",
    "reliability_a": "소스 신뢰도 A",
    "reliability_b": "소스 신뢰도 B",
    "reliability_c": "소스 신뢰도 C",
    "pir_high": "PIR 매칭(high)",
    "pir_other": "PIR 매칭(medium)",
}

def importance_features(exploitation="none", asset_matched=False, impact="", severity="",
                        relevance="", category="", has_cve=False, has_actor=False, reliability="",
                        pir_ids=()):
    """중요도 판단에 쓰는 신호를 0/1 특징 벡터(dict)로 변환"""
    severity = str(severity or "").lower()
    relevance = str(relevance or "").lower()
    category = clean_text(category)
    reliability = str(reliability or "").strip().upper()
    pir_defs = load_pirs()
    pir_weights = {(pir_defs.get(pid) or {}).get("weight") for pid in (pir_ids or ())}
    features = {
        "pir_high": "high" in pir_weights,
        "pir_other": bool(pir_weights - {"high", None}),
        "exploitation_active": exploitation == "active",
        "exploitation_poc": exploitation == "poc",
        "asset_match": bool(asset_matched),
        "impact_total": impact == "total",
        "severity_critical": severity == "critical",
        "severity_high": severity == "high",
        "severity_medium": severity == "medium",
        "relevance_high": relevance == "high",
        "relevance_medium": relevance == "medium",
        "has_cve": bool(has_cve),
        "has_actor": bool(has_actor),
        "reliability_a": reliability == "A",
        "reliability_b": reliability == "B",
        "reliability_c": reliability == "C",
    }
    for name in ENRICH_CATEGORIES:
        key = "category_{}".format(name)
        if key in IMPORTANCE_FEATURE_LABELS:
            features[key] = category == name
    return {name: int(value) for name, value in features.items()}

def load_learned_weights():
    """train_weights.py가 생성한 학습 가중치. 없으면 None (규칙 기반으로 동작)."""
    if "_learned_weights" not in _intel_cache:
        data = None
        try:
            with LEARNED_WEIGHTS_FILE.open("r", encoding="utf-8") as file:
                loaded = json.load(file)
            if isinstance(loaded.get("weights"), dict):
                data = loaded
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        _intel_cache["_learned_weights"] = data
    return _intel_cache["_learned_weights"]

def _score_with_learned(features, learned, reliability):
    """학습된 로지스틱 회귀로 '유용할 확률'을 0~100 점수로 환산"""
    weights = learned["weights"]
    z = float(learned.get("bias") or 0.0)
    reasons = []
    for name, active in features.items():
        weight = float(weights.get(name) or 0.0)
        if active and weight:
            z += weight
            reasons.append("{}({:+.2f})".format(IMPORTANCE_FEATURE_LABELS.get(name, name), weight))
    score = int(round(100.0 / (1.0 + math.exp(-z))))
    reasons.append("학습 모델 적용(라벨 {}건)".format(learned.get("samples") or "?"))
    return {"score": score, "reasons": reasons, "reliability": reliability, "mode": "learned"}

def _triage_evidence(triage, prefixes):
    """classify_urgency가 남긴 상세 근거(EPSS 수치, 매칭 자산명 등)에서 해당 항목을 찾는다"""
    for reason in (triage or {}).get("reasons") or []:
        if any(reason.startswith(prefix) for prefix in prefixes):
            return reason
    return ""

def _collect_risk_rules(triage, enrichment, cves):
    """트리거된 위험 규칙 목록을 [{"id", "criticality", "label", "evidence"}]로 반환.

    evidence에는 판단 근거 값(EPSS 수치, 매칭된 자산명, LLM 판정값 등)을 담아
    알림·리포트에서 "왜 이 점수인가"를 추적할 수 있게 한다.
    """
    rules = []

    def add(rule_id, criticality, label, evidence=""):
        rules.append({"id": rule_id, "criticality": criticality, "label": label, "evidence": evidence})

    exploitation = triage.get("exploitation") or "none"
    if exploitation == "active":
        add("active_exploitation", "high", "실제 악용 정황",
            _triage_evidence(triage, ("실제 악용", "악용 정황", "악용 확률 높음")))
    elif exploitation == "poc":
        add("poc_available", "moderate", "PoC/악용 가능성",
            _triage_evidence(triage, ("공격 코드", "PoC", "악용 확률 주의")))

    if triage.get("matched_assets"):
        add("asset_match", "moderate", "자사 자산 매칭", ", ".join(triage["matched_assets"]))

    if triage.get("impact") == "total":
        add("impact_total", "moderate", "고위험 유형",
            _triage_evidence(triage, ("CVSS",)) or "RCE/권한상승 등")

    severity = str(enrichment.get("severity") or "").lower()
    if severity in ("critical", "high"):
        add("severity_{}".format(severity), "moderate", "심각도 {}".format(severity), "LLM 판정")
    elif severity == "medium":
        add("severity_medium", "info", "심각도 medium", "LLM 판정")

    relevance = str(enrichment.get("relevance") or "").lower()
    if relevance == "high":
        add("relevance_high", "moderate", "관련성 high", "LLM 판정")
    elif relevance == "medium":
        add("relevance_medium", "info", "관련성 medium", "LLM 판정")

    category = clean_text(enrichment.get("category"))
    if category == "공급망공격":
        # 자산 매칭이 구조적으로 안 되는 유형이라 카테고리 자체를 moderate 신호로 취급
        add("category_supply_chain", "moderate", "분류 공급망공격")
    elif category in ("취약점", "악성코드", "침해사고", "개인정보유출", "공격캠페인"):
        add("category_threat", "info", "분류 {}".format(category))
    elif category in ("정책규제", "피싱사기"):
        add("category_{}".format("policy" if category == "정책규제" else "consumer_scam"),
            "penalty", "분류 {}".format(category))
    elif category == "제품행사":
        add("category_product_event", "suppress", "분류 제품행사")

    if cves:
        cve_list = [cve for cve in cves if cve]
        evidence = ", ".join(cve_list[:3]) + (" 외 {}건".format(len(cve_list) - 3) if len(cve_list) > 3 else "")
        add("cve_present", "info", "CVE 언급", evidence)

    actor = enrichment.get("threat_actor") or ""
    malware = enrichment.get("malware_family") or ""
    if actor or malware:
        add("named_threat", "info", "위협 그룹/악성코드 특정", ", ".join(filter(None, [actor, malware])))

    pir_defs = load_pirs()
    for pid in enrichment.get("pirs") or []:
        pir = pir_defs.get(pid)
        if pir is None:
            continue
        criticality = "moderate" if pir["weight"] == "high" else "info"
        add("pir_{}".format(pid.lower()), criticality, "PIR 매칭 {}".format(pid), pir["question"][:40])

    return rules

def score_importance(triage=None, enrichment=None, cves=None, reliability=None):
    """기사 중요도를 0~100 점수로 산정해 {"score", "reasons", "reliability", "mode"}를 반환.

    기본은 규칙 기반 밴드 스코어링(Recorded Future식): 트리거된 규칙 중 가장 강한
    것이 밴드를 결정하고(High 65~100 / Moderate 30~64 / Info 5~24), 나머지 규칙이
    밴드 안에서 점수를 밀어올린다. 약한 신호 누적만으로는 High 밴드에 못 들어간다.
    각 근거에는 판단 상세(EPSS 수치, 매칭 자산명 등)가 붙는다.

    학습 가중치(data/learned_weights.json — 피드백 라벨로 훈련)가 있으면 규칙 대신
    로지스틱 회귀의 '유용 확률 x100'을 점수로 쓴다. 신뢰도는 특징으로 포함되므로
    학습 모드에서는 배수를 따로 곱하지 않는다.
    """
    triage = triage or {}
    enrichment = enrichment or {}

    normalized_reliability = str(reliability or "").strip().upper() or None
    learned = load_learned_weights()
    if learned:
        features = importance_features(
            exploitation=triage.get("exploitation") or "none",
            asset_matched=bool(triage.get("matched_assets")),
            impact=triage.get("impact") or "",
            severity=enrichment.get("severity"),
            relevance=enrichment.get("relevance"),
            category=enrichment.get("category"),
            has_cve=bool(cves),
            has_actor=bool(enrichment.get("threat_actor") or enrichment.get("malware_family")),
            reliability=normalized_reliability or "",
            pir_ids=enrichment.get("pirs") or (),
        )
        return _score_with_learned(features, learned, normalized_reliability)

    rules = _collect_risk_rules(triage, enrichment, cves)
    reasons = []
    positive = sorted(
        (rule for rule in rules if rule["criticality"] in IMPORTANCE_BANDS),
        key=lambda rule: _BAND_ORDER[rule["criticality"]],
    )

    score = 0
    if positive:
        band = positive[0]["criticality"]
        floor, cap = IMPORTANCE_BANDS[band]
        score = floor + sum(IMPORTANCE_PUSH[rule["criticality"]] for rule in positive[1:])
        score = min(score, cap)
        for rule in positive:
            reasons.append(
                "{} — {}".format(rule["label"], rule["evidence"]) if rule["evidence"] else rule["label"]
            )
        reasons.append("판정 밴드 {}({}~{})".format(band.capitalize(), floor, cap))

    for rule in rules:
        if rule["criticality"] == "penalty":
            score = max(0, score - 5)
            reasons.append("{}(-5)".format(rule["label"]))
        elif rule["criticality"] == "suppress":
            score = min(score, PRODUCT_EVENT_SCORE_CAP)
            reasons.append("{} — 점수 상한 {}".format(rule["label"], PRODUCT_EVENT_SCORE_CAP))

    multiplier = RELIABILITY_MULTIPLIERS.get(normalized_reliability)
    if multiplier is not None and multiplier != 1.0 and score > 0:
        score = int(round(score * multiplier))
        reasons.append("소스 신뢰도 {}(x{})".format(normalized_reliability, multiplier))

    return {"score": score, "reasons": reasons, "reliability": normalized_reliability, "mode": "rules"}

def should_alert(importance, triage=None, min_score=None):
    """즉시 알림 여부 판정. P1/P2는 점수와 무관하게 항상 알림."""
    if (triage or {}).get("level") in ("P1", "P2"):
        return True
    threshold = IMPORTANCE_ALERT_THRESHOLD if min_score is None else int(min_score)
    return (importance or {}).get("score", 0) >= threshold

# ===== 크로스소스 클러스터링 (수집 시점 — 같은 사건의 중복 알림 억제 + 교차 보도 가점) =====
CLUSTER_WINDOW_HOURS = int(os.environ.get("CLUSTER_WINDOW_HOURS", "72"))
CLUSTER_CVE_CONTAINMENT = 0.5   # 겹친 CVE 수 / min(양쪽 CVE 수) — 대형 종합기사의 체인 병합 방지
CLUSTER_TITLE_JACCARD = 0.5     # 제목 토큰 유사도 — 오병합이 미병합보다 해로우므로 보수적
CORROBORATION_CAP = 20
_RECENT_EVENTS_MAX_LINES = 5000

# 취약점 카탈로그형 소스는 "보도"가 아니므로 클러스터링에서 제외
# (NVD는 모든 CVE를 수록하므로 교차 확인 신호가 아니고, 뉴스 알림을 억제해서도 안 된다)
CATALOG_SOURCES = {"nvd", "github_advisory"}

# events.jsonl에 importance.reliability가 없는 소스의 신뢰도 폴백 (교차 보도 가점용)
SOURCE_RELIABILITY_FALLBACK = {
    "cisa_kev": "A", "msrc": "A", "kisa": "A", "asec": "B", "boannews": "C",
}

_TITLE_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "from", "by", "at", "as", "is", "are", "its", "new", "via", "after",
    "amid", "under", "over", "how", "what", "why", "now",
}

def _title_tokens(title):
    tokens = re.findall(r"[0-9a-z가-힣]{2,}", clean_text(title).lower())
    return {token for token in tokens if token not in _TITLE_STOPWORDS}

def _read_recent_events(hours, events_file=None):
    """events.jsonl 뒤쪽에서 시간 창 안의 이벤트만 파싱 (카탈로그형 소스 제외)"""
    path = Path(events_file) if events_file else EVENTS_FILE
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as file:
            lines = file.readlines()[-_RECENT_EVENTS_MAX_LINES:]
    except OSError:
        return []

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (event.get("source") or "") in CATALOG_SOURCES:
            continue
        try:
            fetched = datetime.fromisoformat(str(event.get("fetched_at")).replace("Z", "+00:00")).replace(tzinfo=None)
        except (TypeError, ValueError):
            continue
        if fetched >= cutoff:
            events.append(event)
    return events

def find_related_events(cves, title, hours=None, exclude_source=None, events_file=None):
    """최근 이벤트 중 같은 사건으로 판단되는 것들을 반환.

    매칭 기준(둘 중 하나):
    - CVE containment: 겹친 CVE 수 / min(양쪽 CVE 수) >= 0.5
    - 제목 토큰 Jaccard >= 0.5 (CVE 없는 침해사고·캠페인 보도용)
    같은 소스의 후속 기사는 교차 확인이 아니므로 exclude_source로 제외한다.
    """
    cve_set = {str(cve).upper() for cve in (cves or []) if cve}
    tokens = _title_tokens(title)
    related = []
    for event in _read_recent_events(hours or CLUSTER_WINDOW_HOURS, events_file):
        if exclude_source and event.get("source") == exclude_source:
            continue

        matched = False
        event_cves = {str(cve).upper() for cve in (event.get("cves") or []) if cve}
        if cve_set and event_cves:
            overlap = len(cve_set & event_cves)
            if overlap and overlap / min(len(cve_set), len(event_cves)) >= CLUSTER_CVE_CONTAINMENT:
                matched = True
        if not matched and tokens:
            event_tokens = _title_tokens(event.get("title"))
            union = tokens | event_tokens
            if union and len(tokens & event_tokens) / len(union) >= CLUSTER_TITLE_JACCARD:
                matched = True
        if matched:
            related.append(event)
    return related

def _event_reliability(event):
    reliability = str((event.get("importance") or {}).get("reliability") or "").upper()
    return reliability or SOURCE_RELIABILITY_FALLBACK.get(event.get("source") or "", "")

def _event_delivered(event):
    delivery = event.get("delivery") or {}
    return bool(delivery.get("email_sent") or delivery.get("slack_sent"))

def build_cluster_context(related_events, triage=None):
    """관련 이벤트들로부터 교차 보도 가점과 중복 알림 억제 여부를 판정.

    - bonus: 소스별 최고 신뢰도 기준 A/B +10, C·미상 +5 (순환 보도 할인), 상한 20
    - already_alerted: 클러스터에서 이미 알림이 나갔는가
    - escalated: 새 기사의 트리아지가 기존 알림보다 높으면(P3→P1 등) 억제하지 않고 재알림
    """
    sources = {}
    for event in related_events or []:
        source = event.get("source") or "unknown"
        reliability = _event_reliability(event)
        if reliability in ("A", "B"):
            sources[source] = 10
        else:
            sources.setdefault(source, 5)
    bonus = min(sum(sources.values()), CORROBORATION_CAP)

    alerted = [event for event in related_events or [] if _event_delivered(event)]
    level_rank = {"P1": 0, "P2": 1}
    current_rank = level_rank.get((triage or {}).get("level"), 2)
    best_alerted_rank = min(
        (level_rank.get(((event.get("triage") or {}).get("level")), 2) for event in alerted),
        default=2,
    )
    return {
        "related_ids": [event.get("id") for event in related_events or []],
        "corroborating_sources": sorted(sources),
        "bonus": bonus,
        "already_alerted": bool(alerted),
        "escalated": bool(alerted) and current_rank < best_alerted_rank,
    }

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
               ransomware_use=None, confidence="", attack_techniques=None, importance=None,
               cluster=None, pirs=None, content_depth="", body_chars=None,
               recommended_actions=None):
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
        "threat_actor": normalize_threat_actor(threat_actor),
        "malware_family": clean_text(malware_family),
        "attack_techniques": [t for t in (attack_techniques or []) if t],
        "pirs": [p for p in (pirs or []) if p],
        "iocs": [ioc for ioc in (iocs or []) if ioc],
        "relevance": clean_text(relevance).lower(),
        "content_depth": clean_text(content_depth).lower(),
        "body_chars": body_chars,
        "recommended_actions": _clean_str_list(recommended_actions or [], 3),
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
        "cluster": cluster,
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
