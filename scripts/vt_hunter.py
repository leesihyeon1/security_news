"""악성코드 기반 사건의 조사 재료 — VirusTotal 동적 분석 요약.

왜 별도로 있는가:
    조사 방법이 사건 성격에 따라 갈린다.
      · 사용자 행위 기반(ClickFix처럼 사람이 붙여넣어야 실행되는 것) → 유포지·미끼
        페이지가 핵심이므로 URL 분석(urlscan)으로 본다. lure_hunter.py가 담당한다.
      · 악성코드 기반(파일이 실행돼서 스스로 동작하는 것) → 파일이 핵심이므로 VT의
        동적 분석(샌드박스가 실제로 실행해 본 결과)으로 본다. 이 모듈이 담당한다.
    한 기사에 둘 다 있는 경우도 많다(TerminalFix가 그렇다 — 침투는 사용자 행위,
    이후 단계는 악성코드). 그럴 때는 두 트랙을 같이 보여준다.

무엇을 뽑는가:
    정적 정보(탐지율·분류·서명)만으로는 "무엇을 하는 악성코드인가"를 알 수 없다.
    동적 분석 요약에서 실제로 관측된 행위를 가져온다 — 실행한 프로세스와 명령줄,
    만든 파일, 건드린 레지스트리, 조회한 도메인·접속한 IP, 샌드박스가 매핑한
    ATT&CK 기법. 이게 탐지 룰을 쓰거나 침해 흔적을 찾을 때 쓰는 재료다.

키:
    VT_API_KEY(무료 키로 충분). 없으면 조회는 건너뛰고 VT 화면 링크와 검색 쿼리만
    만든다 — 사람이 브라우저에서 직접 보면 되기 때문이다.

    무료 키는 분당 4회 제한이라 파일 하나당 2회(리포트 + 동적분석) 호출을 쉬면서
    보낸다. 그래서 기본 2개 파일까지만 본다(VT_MAX_FILES로 조정).
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import common_utils
import sandbox_lookup

FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
BEHAVIOUR_URL = "https://www.virustotal.com/api/v3/files/{}/behaviour_summary"
GUI_FILE_URL = "https://www.virustotal.com/gui/file/{}"
GUI_BEHAVIOUR_URL = "https://www.virustotal.com/gui/file/{}/behavior"
GUI_SEARCH_URL = "https://www.virustotal.com/gui/search/{}"

REQUEST_TIMEOUT = 40
# 무료 키 분당 4회 — 두 번 연속 호출 후 쉬는 식으로는 금방 429가 난다. 호출마다 쉰다.
PAUSE_SECONDS = float(os.environ.get("VT_PAUSE_SECONDS", "15.5"))
BUDGET_SECONDS = float(os.environ.get("VT_BUDGET_SECONDS", "80"))
MAX_FILES = int(os.environ.get("VT_MAX_FILES", "2"))
MAX_ITEMS_PER_GROUP = 6          # 행위 목록은 종류별로 이 정도만 보여준다

HASH_TYPES = {"sha256", "sha1", "md5"}
HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)


def _api_key():
    return (os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()


def _request(url, api_key):
    request = urllib.request.Request(url, headers={
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "boannews-intel/1.0 (threat research)",
    })
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def file_hashes_from_iocs(iocs):
    """IOC에서 파일 해시만. sha256을 먼저 본다(VT 조회에 가장 확실하다)."""
    ordered = []
    for want in ("sha256", "sha1", "md5"):
        for ioc in iocs or []:
            if (ioc.get("type") or "").lower() != want:
                continue
            value = (ioc.get("value") or "").strip().lower()
            if HASH_RE.match(value) and value not in ordered:
                ordered.append(value)
    return ordered


def _epoch_date(value):
    if not isinstance(value, (int, float)) or value <= 0:
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")


def _trim(values, limit=MAX_ITEMS_PER_GROUP, width=110):
    out = []
    for value in values or []:
        text = str(value).strip()
        if not text:
            continue
        out.append(text[:width])
        if len(out) >= limit:
            break
    return out


def parse_file_report(payload):
    """GET /files/{hash} 응답에서 필요한 것만."""
    attributes = ((payload or {}).get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    engines = sum(value for value in stats.values() if isinstance(value, int))
    classification = attributes.get("popular_threat_classification") or {}
    signature = attributes.get("signature_info") or {}
    return {
        "malicious": stats.get("malicious") or 0,
        "suspicious": stats.get("suspicious") or 0,
        "engines": engines,
        "label": classification.get("suggested_threat_label") or "",
        "names": _trim(attributes.get("names"), limit=3, width=60),
        "meaningful_name": attributes.get("meaningful_name") or "",
        "type": attributes.get("type_description") or "",
        "size": attributes.get("size") or 0,
        "first_seen": _epoch_date(attributes.get("first_submission_date")),
        "signer": signature.get("signers") or "",
        "verified": signature.get("verified") or "",
        "imphash": attributes.get("imphash") or "",
        "vhash": attributes.get("vhash") or "",
        "tags": _trim(attributes.get("tags"), limit=8, width=30),
        # 유형 판정 재료 — 백신들이 붙인 카테고리(trojan/miner/…)와 패밀리 이름.
        "categories": [entry.get("value") for entry in classification.get("popular_threat_category") or []
                       if entry.get("value")][:4],
        "family_names": [entry.get("value") for entry in classification.get("popular_threat_name") or []
                         if entry.get("value")][:4],
        "reputation": attributes.get("reputation"),
        "yara": [entry.get("rule_name") for entry in attributes.get("crowdsourced_yara_results") or []
                 if entry.get("rule_name")][:4],
    }


def parse_behaviour(payload):
    """GET /files/{hash}/behaviour_summary 응답 — 샌드박스가 실제로 관측한 행위."""
    data = (payload or {}).get("data") or {}
    dns = []
    for entry in data.get("dns_lookups") or []:
        host = (entry or {}).get("hostname")
        if host:
            dns.append(host)
    traffic = []
    for entry in data.get("ip_traffic") or []:
        ip = (entry or {}).get("destination_ip")
        port = (entry or {}).get("destination_port")
        if ip:
            traffic.append("{}:{}".format(ip, port) if port else ip)
    http = []
    for entry in data.get("http_conversations") or []:
        url = (entry or {}).get("url")
        if url:
            http.append(url)
    registry = []
    for entry in data.get("registry_keys_set") or []:
        key = (entry or {}).get("key")
        if key:
            registry.append(key)
    dropped = []
    for entry in data.get("files_dropped") or []:
        path = (entry or {}).get("path")
        if path:
            dropped.append(path)
    techniques = []
    for entry in data.get("mitre_attack_techniques") or []:
        tid = (entry or {}).get("id")
        if tid and tid not in techniques:
            techniques.append(tid)
    # 서술에 쓰는 재료 — 이게 없으면 "무엇을 했다"를 말할 수 없고 경로만 남는다.
    signatures = []
    for entry in data.get("signature_matches") or []:
        description = (entry or {}).get("description") or (entry or {}).get("name")
        if description:
            signatures.append({"desc": str(description)[:180],
                               "severity": (entry or {}).get("severity") or ""})
    technique_details = []
    for entry in data.get("mitre_attack_techniques") or []:
        description = (entry or {}).get("signature_description")
        if description:
            technique_details.append({"id": (entry or {}).get("id") or "",
                                      "desc": str(description)[:180],
                                      "severity": (entry or {}).get("severity") or ""})
    memory_domains = []
    for host in data.get("memory_pattern_domains") or []:
        host = str(host).strip().lower()
        if host and host not in memory_domains:
            memory_domains.append(host)

    return {
        "signatures": signatures[:60],
        "technique_details": technique_details[:60],
        "tags": _trim(data.get("tags"), limit=8, width=30),
        "memory_domains": memory_domains[:12],
        "mutex_count": len(data.get("mutexes_created") or []),
        "services": _trim(data.get("services_started"), limit=6, width=40),
        "terminated": _trim(data.get("processes_terminated"), limit=4, width=80),
        "commands": _trim(data.get("command_executions"), width=160),
        "processes": _trim(data.get("processes_created")),
        "files_written": _trim(data.get("files_written")),
        "files_dropped": _trim(dropped),
        "registry": _trim(registry),
        "dns": _trim(dns),
        "ip_traffic": _trim(traffic),
        "http": _trim(http),
        "mutexes": _trim(data.get("mutexes_created"), limit=3),
        "techniques": techniques[:14],
        "sandboxes": _trim(data.get("verdicts"), limit=3, width=40),
        "has_dynamic": bool(data.get("command_executions") or data.get("processes_created")
                            or data.get("files_written") or dns or traffic
                            or signatures or technique_details),
    }


# ── 샌드박스 환경 자체의 흔적 ────────────────────────────────────────────────────
# 동적 분석 결과를 그대로 옮기면 오분석이 된다. behaviour_summary에는 악성코드의
# 행위와 샌드박스 환경의 동작이 섞여 있다 — 실측: TerminalFix 샘플의 "통신한 곳"에
# api.snapcraft.io(우분투 스냅 스토어)와 185.125.188.x(캐노니컬)가 들어 있었고,
# 만든 파일은 /dev/tty·/dev/ptmx(터미널 장치), 띄운 프로세스는 xterm이었다. 전부
# 리눅스 샌드박스가 스크립트를 돌리려고 만든 것이고 IOC가 아니다.
# 정규식에 리터럴 백슬래시가 필요한 곳은 이 상수를 이어 붙여 만든다 — 소스에 백슬래시를
# 직접 쓰면 편집 단계에서 개수가 어긋나 조용히 다른 패턴이 된다.
BS = chr(92)

SANDBOX_ENV_DOMAIN_RE = re.compile(
    r"(?:^|\.)(?:snapcraft\.io|ubuntu\.com|canonical\.com|debian\.org|archlinux\.org|"
    r"lencr\.org|letsencrypt\.org|digicert\.com|verisign\.com|globalsign\.com|"
    r"sectigo\.com|amazontrust\.com|godaddy\.com|starfieldtech\.com|entrust\.net|"
    r"pki\.goog|symantec\.com|microsoft\.com|windowsupdate\.com|windows\.com|"
    r"msftconnecttest\.com|msftncsi\.com|live\.com|office\.net|office\.com|"
    r"apple\.com|icloud\.com|mzstatic\.com|gvt1\.com|googleapis\.com|gstatic\.com|"
    r"google\.com|mozilla\.com|mozilla\.net|mozilla\.org|akamaiedge\.net|"
    r"akamaitechnologies\.com|edgesuite\.net|cloudflare\.com|amazonaws\.com|"
    # 인터프리터·런타임 바이너리에 원래 박혀 있는 주소들. 메모리 문자열로 잡히지만
    # C2가 아니다 — 실측: Python 샘플의 C2 후보로 python.org·iana.org가 올라왔다.
    r"python\.org|iana\.org|w3\.org|openssl\.org|curl\.se|gnu\.org|kernel\.org|"
    r"ietf\.org|unicode\.org|sourceforge\.net|nginx\.org|sqlite\.org|zlib\.net|"
    r"oracle\.com|java\.com|nodejs\.org|npmjs\.com|rust-lang\.org|golang\.org)$",
    re.I,
)
SANDBOX_ENV_HOST_PREFIX_RE = re.compile(r"^(?:ocsp|crl|ctldl|time|ntp|pool)\b", re.I)
# 터미널·프로세스 장치, 인증서 캐시 등 실행 뒷바라지용 경로.
SANDBOX_ENV_PATH_RE = re.compile(
    "^/(?:dev|proc|sys|run)/|/dev/(?:tty|ptmx|pts)|"
    + BS + BS + "Device" + BS + BS + "ConDrv"
    + "|snap/|/etc/(?:resolv|ssl)|msdownload/update|authroot|disallowedcert|pinrules"
    + "|" + BS + ".cache/|Temp/hp_[0-9a-f]+" + BS + ".mp4",
    re.I,
)
# 샌드박스가 샘플을 띄우기 위해 쓰는 껍데기 프로세스.
SANDBOX_HARNESS_RE = re.compile(
    r"\b(?:xterm|gnome-terminal|konsole|x-terminal|systemd|dbus|conhost\.exe|"
    r"WerFault\.exe|wermgr\.exe|SearchIndexer\.exe|MpCmdRun\.exe|"
    r"backgroundTaskHost\.exe|CompatTelRunner\.exe|sihost\.exe)\b",
    re.I,
)

# 행위를 공격 단계로 묶는다 — 나열이 아니라 "무엇을 하려던 것인가"로 읽히게.
STAGE_RULES = [
    ("지속성", re.compile("schtasks|Register-ScheduledTask|TaskCache|RunOnce|Startup"
                       + "|CurrentVersion" + BS + BS + "Run"
                       + "|/etc/cron|systemd/system|LaunchAgents", re.I)),
    ("방어 회피", re.compile(r"Defender|MpPreference|windowsupdate|wuauserv|attrib\s+\+|"
                          r"Set-MpPreference|netsh\s+advfirewall|taskkill|sc\s+(?:stop|config)|"
                          r"bcdedit|vssadmin", re.I)),
    ("정찰", re.compile(r"nltest|net\s+(?:group|user|view)|whoami|systeminfo|ipconfig|"
                      r"Get-ADUser|arp\s+-a|tasklist|wmic", re.I)),
    ("자격증명·수집", re.compile(r"wallet|mnemonic|seed\s*phrase|Login\s*Data|cookies|"
                             r"password|keychain|\.kdbx|clipboard|Local\s*State", re.I)),
    ("실행", re.compile(r"powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|"
                      r"python|node|curl|wget", re.I)),
]


def _clean_hosts(hosts):
    """샌드박스 환경 통신을 걷어낸다."""
    kept, dropped = [], []
    for host in hosts or []:
        host = str(host).strip().lower().rstrip(".")
        if not host:
            continue
        if SANDBOX_ENV_DOMAIN_RE.search(host) or SANDBOX_ENV_HOST_PREFIX_RE.search(host):
            dropped.append(host)
        elif host not in kept:
            kept.append(host)
    return kept, dropped


def _clean_paths(paths):
    kept, dropped = [], []
    for path in paths or []:
        text = str(path).strip()
        if not text:
            continue
        if SANDBOX_ENV_PATH_RE.search(text):
            dropped.append(text)
        elif text not in kept:
            kept.append(text)
    return kept, dropped


def _clean_processes(items):
    kept, dropped = [], []
    for item in items or []:
        text = str(item).strip()
        if not text:
            continue
        if SANDBOX_HARNESS_RE.search(text):
            dropped.append(text)
        elif text not in kept:
            kept.append(text)
    return kept, dropped


def _platform(behaviour):
    """샌드박스가 어느 OS에서 돌렸는지 — 기사와 다르면 그대로 옮겨 쓸 수 없다."""
    blob = " ".join((behaviour.get("commands") or []) + (behaviour.get("processes") or [])
                    + (behaviour.get("files_written") or []) + (behaviour.get("files_dropped") or []))
    if re.search("[A-Za-z]:" + BS + BS + "|%WINDIR%|" + BS + BS + "Windows" + BS + BS + "|HKEY_", blob):
        return "windows"
    if re.search(r"^/|/usr/|/tmp/|/dev/|/Library/", blob):
        return "macos" if "/Library/" in blob or "LaunchAgents" in blob else "linux"
    return ""


def _stage_of(text):
    for stage, pattern in STAGE_RULES:
        if pattern.search(text):
            return stage
    return ""


def interpret(behaviour, iocs=None, report=None):
    """관측된 행위를 걸러 공격 단계로 묶고, IOC와 겹치는지 대조한다.

    그대로 나열하면 두 가지 문제가 생긴다 — 샌드박스 환경의 통신·파일이 IOC로
    올라가고(오분석), 행위가 단계 구분 없이 쏟아져 무엇이 중요한지 알 수 없다.
    """
    behaviour = behaviour or {}
    ioc_values = {str(i.get("value") or "").strip().lower().rstrip("/")
                  for i in (iocs or [])}
    ioc_hosts = {value.split("//")[-1].split("/")[0] for value in ioc_values if value}

    hosts, dropped_hosts = _clean_hosts(behaviour.get("dns"))
    traffic, dropped_traffic = [], []
    for entry in behaviour.get("ip_traffic") or []:
        ip, _, port = str(entry).partition(":")
        if port == "53":
            dropped_traffic.append(str(entry))
        else:
            traffic.append(str(entry))
    commands, dropped_cmd = _clean_processes(behaviour.get("commands"))
    processes, dropped_proc = _clean_processes(behaviour.get("processes"))
    files, dropped_files = _clean_paths((behaviour.get("files_dropped") or [])
                                       + (behaviour.get("files_written") or []))
    registry, _ = _clean_paths(behaviour.get("registry"))

    corroborated = [host for host in hosts
                    if host in ioc_hosts or any(host in value for value in ioc_values)]
    unconfirmed = [host for host in hosts if host not in corroborated]

    stages = {}
    for text in commands + processes + files + registry:
        stage = _stage_of(text)
        if stage:
            stages.setdefault(stage, [])
            if text not in stages[stage] and len(stages[stage]) < 4:
                stages[stage].append(text)

    return {
        "platform": _platform(behaviour),
        "stages": stages,
        "hosts": hosts,
        "corroborated_hosts": corroborated,
        "unconfirmed_hosts": unconfirmed,
        "traffic": traffic,
        "dropped": {
            "hosts": dropped_hosts,
            "traffic": dropped_traffic,
            "files": dropped_files,
            "processes": dropped_cmd + dropped_proc,
        },
        "techniques": behaviour.get("techniques") or [],
        "sandboxes": behaviour.get("sandboxes") or [],
        "has_dynamic": bool(behaviour.get("has_dynamic")),
    }


# ── 동적 분석 서술 ──────────────────────────────────────────────────────────────
# 행위를 나열하는 것은 분석이 아니다. "어떤 유형의 악성코드이고, 무엇을 하며, C2는
# 어디인가"로 정리해야 쓸 수 있다. VT가 주는 재료 중 이 서술에 쓰는 것:
#   · signature_matches       — 샌드박스가 붙인 행위 설명문(심각도 포함, 실측 81건)
#   · mitre_attack_techniques — 기법별 signature_description(무엇을 했는지 문장, 70건)
#   · tags                    — PERSISTENCE·OBFUSCATED 같은 행위 태그
#   · memory_pattern_domains  — 메모리에서 발견된 도메인(설정에 박힌 C2 후보)
# 예전에는 이 중 아무것도 쓰지 않고 파일 경로·명령줄만 잘라 붙였다.

FAMILY_RULES = [
    ("정보 탈취(스틸러)", re.compile(r"stealer|infostealer|redline|lumma|vidar|raccoon|atomic|"
                                r"browser credential|login data|cookies|wallet|keychain|"
                                r"credential (?:theft|access|dump)", re.I)),
    ("암호화폐 채굴", re.compile(r"miner|xmrig|coinhive|monero|cryptonight|mining pool", re.I)),
    ("랜섬웨어", re.compile(r"ransom|encrypts? files|shadow cop|vssadmin delete", re.I)),
    ("원격제어(RAT·백도어)", re.compile(r"backdoor|remote access trojan|(?:^|[^a-z])rat(?:[^a-z]|$)|"
                                  r"reverse shell|remote shell", re.I)),
    ("터널·프록시", re.compile(r"socks|reverse (?:tunnel|proxy)|websocket tunnel|port forward", re.I)),
    ("로더·드로퍼", re.compile(r"loader|dropper|downloader|drops (?:a |an )?(?:file|executable|pe)|"
                          r"second stage", re.I)),
    ("클립보드 하이재킹", re.compile(r"clipbanker|clipboard (?:hijack|monitor|steal)", re.I)),
    ("웜·자기전파", re.compile(r"worm|spreads via|removable drive|usb propagation", re.I)),
]

# 행위 설명문(영문)과 명령줄을 같은 분류기로 다룬다. 샌드박스 설명문이 영어라서
# 한글 키워드만으로는 하나도 안 걸린다.
BEHAVIOUR_STAGES = [
    ("지속성", re.compile(r"scheduled task|run key|runonce|autostart|startup folder|"
                       r"registry .{0,20}(?:run|autorun)|service (?:install|creat)|"
                       r"schtasks|systemd|launchagent|persistence", re.I)),
    ("방어 회피·안티분석", re.compile(r"defender|antivirus|amsi|etw|disable[sd]? (?:security|update|"
                                r"firewall)|windows update|obfuscat|packed|vmprotect|"
                                r"anti-?(?:vm|debug)|checks? (?:available memory|virtual|"
                                r"debugger|sandbox)|long sleep|delay(?:s|ed)? execution|"
                                r"hidden window|attrib|injects? into|process injection|"
                                r"hollow|unhook", re.I)),
    ("정찰", re.compile(r"queries (?:computer|user|os|process|disk|volume|installed|the mount)|"
                      r"enumerat|systeminfo|whoami|ipconfig|nltest|domain trust|"
                      r"privilege|uac|lists? (?:running processes|files)", re.I)),
    ("자격증명·데이터 수집", re.compile(r"credential|password|login data|cookie|wallet|mnemonic|"
                                r"keylog|screenshot|clipboard|keychain|browser data|"
                                r"collects? (?:files|data)", re.I)),
    ("통신·유출", re.compile(r"c2|command and control|http (?:post|request)|exfiltrat|"
                        r"uploads? |downloads? (?:a )?(?:file|payload)|dns (?:query|tunnel)|"
                        r"connects? to|resolves? (?:a )?domain", re.I)),
    ("실행·전개", re.compile(r"powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32|"
                        r"executes?|spawns?|launches?|creates? (?:a )?process|"
                        r"writes? (?:a )?(?:file|executable)|drops?", re.I)),
]

SEVERITY_ORDER = {"IMPACT_SEVERITY_HIGH": 0, "IMPACT_SEVERITY_MEDIUM": 1,
                  "IMPACT_SEVERITY_LOW": 2, "IMPACT_SEVERITY_INFO": 3}
MAX_PER_STAGE = 3
STAGE_ORDER = ["실행·전개", "지속성", "방어 회피·안티분석", "정찰",
               "자격증명·데이터 수집", "통신·유출"]


def _clip_sentence(text, limit=130):
    """문장 또는 단어 경계에서 자른다 — 130자에서 무작정 끊으면 뜻이 사라진다."""
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    head = text[:limit]
    for mark in (". ", "; ", ", "):
        cut = head.rfind(mark)
        if cut > limit * 0.5:
            return head[:cut + 1].rstrip()
    cut = head.rfind(" ")
    return (head[:cut] if cut > limit * 0.5 else head).rstrip() + "…"


def _stage_of_description(text):
    for stage, pattern in BEHAVIOUR_STAGES:
        if pattern.search(text or ""):
            return stage
    return ""


def _describe_behaviour(behaviour):
    """샌드박스 설명문을 심각도 순으로 모아 공격 단계별로 묶는다."""
    entries = []
    for item in behaviour.get("signatures") or []:
        text = (item.get("desc") or "").strip()
        if text:
            entries.append((SEVERITY_ORDER.get(item.get("severity"), 3), text))
    for item in behaviour.get("technique_details") or []:
        text = (item.get("desc") or "").strip()
        if text:
            entries.append((SEVERITY_ORDER.get(item.get("severity"), 3), text))

    seen, stages = set(), {}
    for _severity, text in sorted(entries, key=lambda pair: pair[0]):
        key = text.lower()[:60]
        if key in seen:
            continue
        seen.add(key)
        stage = _stage_of_description(text)
        if not stage:
            continue
        bucket = stages.setdefault(stage, [])
        if len(bucket) < MAX_PER_STAGE:
            bucket.append(_clip_sentence(text))
    return stages


def _family_guess(report, behaviour, described):
    """어떤 유형의 악성코드인가 — 분류명·태그·행위 설명을 한꺼번에 본다."""
    blob = " ".join([
        report.get("label") or "", " ".join(report.get("names") or []),
        " ".join(report.get("tags") or []), " ".join(report.get("categories") or []),
        " ".join(report.get("family_names") or []),
        " ".join(sum(described.values(), [])),
        " ".join(behaviour.get("tags") or []),
    ])
    return [name for name, pattern in FAMILY_RULES if pattern.search(blob)][:3]


def _c2_candidates(behaviour, view):
    """C2로 볼 수 있는 통신처. 출처와 신뢰도를 붙여 돌려준다."""
    corroborated = list(view.get("corroborated_hosts") or [])
    items = [{"value": host, "why": "기사 IOC와 일치", "confidence": "high"}
             for host in corroborated]
    for url in behaviour.get("http") or []:
        host = str(url).split("//")[-1].split("/")[0].lower()
        if host and host not in corroborated and not SANDBOX_ENV_DOMAIN_RE.search(host):
            items.append({"value": str(url)[:120], "why": "HTTP 요청 관측", "confidence": "medium"})
    for host in view.get("unconfirmed_hosts") or []:
        items.append({"value": host, "why": "DNS 조회 관측(기사 IOC에는 없음)",
                      "confidence": "medium"})
    for host in behaviour.get("memory_domains") or []:
        host = str(host).lower()
        if host in corroborated or SANDBOX_ENV_DOMAIN_RE.search(host):
            continue
        items.append({"value": host, "why": "메모리에서 발견(설정에 박힌 주소일 수 있음)",
                      "confidence": "low"})
    seen, out = set(), []
    for item in items:
        if item["value"] in seen:
            continue
        seen.add(item["value"])
        out.append(item)
    return out[:8]


def analyze_dynamic(report, behaviour, view):
    """동적 분석을 서술로 정리한다 — 유형 / 행위 / C2."""
    report = report or {}
    behaviour = behaviour or {}
    described = _describe_behaviour(behaviour)
    ports = sorted({str(entry).split(":")[-1] for entry in behaviour.get("ip_traffic") or []
                    if ":" in str(entry)} - {"53"})
    return {
        "families": _family_guess(report, behaviour, described),
        "stages": described,
        "c2": _c2_candidates(behaviour, view),
        "ports": ports[:6],
        "tags": behaviour.get("tags") or [],
        "mutex_count": behaviour.get("mutex_count") or 0,
        "services": (behaviour.get("services") or [])[:4],
    }


# ── 보강 재료 ──────────────────────────────────────────────────────────────────
# 동적 분석이 부실해 보이는 이유는 VT가 준 것을 다 안 쓰기 때문이다. 실측(REVSTEALER
# 샘플): behaviour_summary 하나만 봤는데, 그 뒤에 샌드박스별 리포트 7건(C2AE, CAPE,
# Dr.Web vxCube, VirusTotal Jujubox …)과 커뮤니티 코멘트가 따로 있었다. 코멘트 첫
# 줄이 "File found on MalwareBazaar"였다 — 외부에 샘플이 올라와 있다는 사실을 VT가
# 이미 알려주고 있었던 것이다.
BEHAVIOURS_URL = "https://www.virustotal.com/api/v3/files/{}/behaviours?limit=12"
COMMENTS_URL = "https://www.virustotal.com/api/v3/files/{}/comments?limit=10"
GUI_SANDBOX_URL = "https://www.virustotal.com/gui/file/{}/behavior/{}"

# 외부 샌드박스·저장소. 전부 조회에 키가 필요해서(실측: tria.ge 401, MalwareBazaar
# Unauthorized, Hybrid Analysis 301) 링크를 준다. 다만 VT 커뮤니티 코멘트가 그 서비스를
# 가리키면 "샘플이 올라와 있음"으로 확정 표시한다.
EXTERNAL_SERVICES = [
    ("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=sha256%3A{}",
     r"malwarebazaar|bazaar\.abuse\.ch"),
    ("Triage", "https://tria.ge/s?q={}", r"tria\.ge|recorded\s*future\s*triage|hatching"),
    ("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query={}",
     r"hybrid[\s-]*analysis"),
    ("ANY.RUN", "https://app.any.run/submissions/#filehash:{}", r"any\.run|anyrun"),
    ("Joe Sandbox", "https://www.joesandbox.com/search?q={}", r"joe\s*sandbox|joesandbox"),
    ("Filescan.io", "https://www.filescan.io/search-result?query={}", r"filescan"),
]
URL_IN_TEXT_RE = re.compile(r"https?://[^\s)\]]{10,120}")
# 보강 조회는 파일당 2회를 더 쓴다 — 무료 키 분당 4회 제한 때문에 대표 파일에만 한다.
ENRICH_FILES = int(os.environ.get("VT_ENRICH_FILES", "1"))


def fetch_sandboxes(hash_value, api_key):
    """샌드박스별 리포트 목록. 어느 샌드박스가 무슨 판정을 냈는지."""
    try:
        data = _request(BEHAVIOURS_URL.format(hash_value), api_key=api_key)
    except Exception:
        return []
    out = []
    for item in data.get("data") or []:
        attributes = item.get("attributes") or {}
        name = attributes.get("sandbox_name") or ""
        if not name:
            continue
        verdicts = [v for v in (attributes.get("verdicts") or []) if v and v != "UNKNOWN_VERDICT"]
        out.append({
            "name": name,
            "verdict": verdicts[0] if verdicts else "",
            "has_network": bool(attributes.get("ip_traffic") or attributes.get("dns_lookups")),
            "url": GUI_SANDBOX_URL.format(hash_value, urllib.parse.quote(name)),
        })
    return out


def fetch_community(hash_value, api_key):
    """커뮤니티 코멘트. 외부 서비스 언급·링크를 함께 뽑는다."""
    try:
        data = _request(COMMENTS_URL.format(hash_value), api_key=api_key)
    except Exception:
        return []
    out = []
    for item in data.get("data") or []:
        attributes = item.get("attributes") or {}
        text = " ".join(str(attributes.get("text") or "").split())
        if not text:
            continue
        out.append({
            "text": text[:400],
            "tags": [t for t in (attributes.get("tags") or [])][:6],
            "date": _epoch_date(attributes.get("date")),
            "links": URL_IN_TEXT_RE.findall(text)[:3],
        })
    return out


def external_reports(hash_value, comments):
    """외부 샌드박스·저장소 링크. 커뮤니티가 그 서비스를 가리키면 확정 표시."""
    blob = " ".join([c.get("text", "") + " " + " ".join(c.get("links") or [])
                     for c in comments or []]).lower()
    out = []
    for name, template, pattern in EXTERNAL_SERVICES:
        out.append({
            "name": name,
            "url": template.format(hash_value),
            "confirmed": bool(re.search(pattern, blob, re.I)),
        })
    # 확정된 것을 앞으로 — 눌러볼 가치가 있는 순서로.
    out.sort(key=lambda item: (0 if item["confirmed"] else 1, item["name"]))
    return out


def enrich_file(hash_value, api_key, pause=True):
    """샌드박스별 리포트·커뮤니티·외부 샌드박스 조회를 한 번에.

    외부 샌드박스(Triage·MalwareBazaar·Hybrid Analysis)는 각자 키가 있으면 실제로
    조회해 판정·추출 C2까지 가져오고, 키가 없으면 검색 링크만 만든다.
    """
    # 외부 조회는 VT 키와 무관하다 — VT 키가 없어도 이쪽은 돌린다.
    outside = sandbox_lookup.lookup_all(hash_value, pause=pause)

    if not api_key:
        return {"sandboxes": [], "comments": [],
                "external": external_reports(hash_value, []),
                "outside": outside}
    sandboxes = fetch_sandboxes(hash_value, api_key)
    if pause:
        time.sleep(PAUSE_SECONDS)
    comments = fetch_community(hash_value, api_key)
    return {"sandboxes": sandboxes, "comments": comments,
            "external": external_reports(hash_value, comments),
            "outside": outside}


def _enrichment_findings(hash_value, enrichment):
    """보강 재료를 확인내용 문장으로."""
    lines = []
    sandboxes = enrichment.get("sandboxes") or []
    if sandboxes:
        # 판정 값에는 CLEAN·HARMLESS도 온다 — 전부 "악성 판정"으로 묶으면 반대로 읽힌다.
        bad = [s for s in sandboxes
               if re.search(r"malware|malicious|suspicious", s["verdict"], re.I)]
        clean = [s for s in sandboxes if re.search(r"clean|harmless|goodware", s["verdict"], re.I)]
        if bad:
            tail = "그중 {}가 악성으로 판정했습니다.".format(
                ", ".join("{}({})".format(s["name"], s["verdict"]) for s in bad[:3]))
            if clean:
                tail += " {}는 정상으로 봤습니다 — 판정이 갈리면 행위 자체를 봐야 합니다.".format(
                    ", ".join(s["name"] for s in clean[:2]))
        elif clean:
            tail = ("{}는 정상으로 판정했습니다. 나머지는 판정 없이 실행 결과만 남겼으니, "
                    "탐지율만 보지 말고 아래 행위를 확인하십시오.".format(
                        ", ".join(s["name"] for s in clean[:3])))
        else:
            tail = "명시적 판정을 낸 곳은 없습니다 — 실행 결과만 남겼습니다."
        lines.append("· 샌드박스 {}곳이 이 파일을 실행해 봤습니다({}). {}".format(
            len(sandboxes), ", ".join(s["name"] for s in sandboxes[:5]), tail))

    comments = enrichment.get("comments") or []
    if comments:
        first = comments[0]
        lines.append("· 커뮤니티 코멘트 {}건이 있습니다{}. 첫 코멘트: \"{}\"".format(
            len(comments), "(태그 {})".format(", ".join(first["tags"])) if first["tags"] else "",
            first["text"][:150]))

    outside = enrichment.get("outside") or []
    if outside:
        # 실제 조회 결과(판정·추출 C2·다른 서비스 판정)를 그대로 붙인다.
        lines.extend(sandbox_lookup.findings(outside))
    else:
        confirmed = [e["name"] for e in enrichment.get("external") or [] if e["confirmed"]]
        if confirmed:
            lines.append("· 외부 저장소·샌드박스에 샘플이 올라와 있습니다: {}. 아래 링크에서 "
                         "그쪽 분석 결과를 함께 보면 VT 동적분석에 없는 행위가 나올 수 "
                         "있습니다.".format(", ".join(confirmed)))
    return lines


def _queries(hash_value, report):
    """VT에서 관련 샘플·유포지를 넓히는 검색. 유료(Intelligence)가 필요한 것은 표시한다."""
    # query에는 복사해서 바로 쓸 값(해시 또는 검색식)만 넣는다 — 복사 버튼이 붙는 칸이다.
    queries = [{
        "name": "이 파일의 VT 리포트",
        "query": hash_value,
        "url": GUI_FILE_URL.format(hash_value),
        "link_label": "VT 리포트 열기",
        "paid": False,
    }, {
        "name": "이 파일의 동적 분석(샌드박스 실행 결과)",
        "query": hash_value,
        "url": GUI_BEHAVIOUR_URL.format(hash_value),
        "link_label": "VT 동적 분석 열기",
        "paid": False,
    }]
    if report and report.get("imphash"):
        query = 'imphash:"{}"'.format(report["imphash"])
        queries.append({"name": "같은 임포트 구조를 가진 다른 샘플", "query": query,
                        "url": GUI_SEARCH_URL.format(urllib.parse.quote(query, safe="")),
                        "link_label": "VT에서 검색", "paid": True})
    if report and report.get("vhash"):
        query = 'vhash:"{}"'.format(report["vhash"])
        queries.append({"name": "구조가 비슷한 변종", "query": query,
                        "url": GUI_SEARCH_URL.format(urllib.parse.quote(query, safe="")),
                        "link_label": "VT에서 검색", "paid": True})
    return queries


def short_hash(value):
    return str(value or "")[:12]


def _external_queries(enrichment):
    """샌드박스별 리포트와 외부 서비스를 링크 행으로. 확정된 것은 문구로 구분한다."""
    rows = []
    for sandbox in (enrichment or {}).get("sandboxes") or []:
        rows.append({
            "name": "{} 리포트{}".format(sandbox["name"],
                                      " · {}".format(sandbox["verdict"]) if sandbox["verdict"] else ""),
            "query": sandbox["name"],
            "url": sandbox["url"],
            "link_label": "VT에서 열기",
            "paid": False,
        })
    outside = (enrichment or {}).get("outside") or []
    if outside:
        rows.extend(sandbox_lookup.link_rows(outside))
        # 실조회 대상이 아닌 서비스(ANY.RUN·Joe Sandbox 등)는 링크만 남긴다.
        looked_up = {r["service"] for r in outside}
        for service in (enrichment or {}).get("external") or []:
            if service["name"] in looked_up:
                continue
            rows.append({
                "name": "{}{}".format(service["name"],
                                      " — 샘플 확인됨" if service["confirmed"] else " — 검색만"),
                "query": service["url"], "url": service["url"],
                "link_label": "{} 열기".format(service["name"]), "paid": False,
            })
        return rows

    for service in (enrichment or {}).get("external") or []:
        rows.append({
            "name": "{}{}".format(service["name"],
                                  " — 샘플 확인됨" if service["confirmed"] else " — 검색만"),
            "query": service["url"],
            "url": service["url"],
            "link_label": "{} 열기".format(service["name"]),
            "paid": False,
        })
    return rows


def analyze_hashes(hashes, api_key=None, max_files=None, iocs=None):
    """해시 목록으로 악성코드 트랙을 만든다. 키가 없으면 링크·검색만 담는다."""
    api_key = api_key if api_key is not None else _api_key()
    max_files = max_files or MAX_FILES
    hashes = list(hashes or [])
    if not hashes:
        return None

    started = time.time()
    files, findings, steps = [], [], []
    calls = 0

    # 조사 과정을 남긴다 — 몇 건 중 몇 건을 왜 조회했는지가 없으면 "이 파일은 안전한가"를
    # 잘못 읽는다(조회하지 않은 것과 깨끗한 것은 다르다).
    steps.append("IOC에서 파일 해시 {}건을 뽑았습니다(sha256 우선). {}".format(
        len(hashes),
        "VT 무료 키는 분당 4회 제한이라 앞의 {}건만 조회했습니다.".format(min(len(hashes), max_files))
        if api_key else "VT_API_KEY가 없어 자동 조회 없이 링크만 만들었습니다."))

    for hash_value in hashes[:max_files]:
        report, behaviour, error = None, None, ""
        if api_key:
            if time.time() - started > BUDGET_SECONDS:
                findings.append("시간이 오래 걸려 나머지 파일은 VT에서 조회하지 않았습니다.")
                steps.append("시간 예산({}초)을 넘겨 나머지 파일 조회를 중단했습니다.".format(
                    int(BUDGET_SECONDS)))
                break
            try:
                if calls:
                    time.sleep(PAUSE_SECONDS)   # 무료 키 분당 4회 제한
                report = parse_file_report(_request(FILE_URL.format(hash_value), api_key))
                calls += 1
                steps.append("{}… — VT 파일 리포트를 조회했습니다(GET /files/{{해시}}). "
                             "백신 {}개 결과와 분류·서명·imphash를 확인했습니다.".format(
                                 hash_value[:12], report.get("engines") or 0))
                time.sleep(PAUSE_SECONDS)
                behaviour = parse_behaviour(_request(BEHAVIOUR_URL.format(hash_value), api_key))
                calls += 1
                steps.append("{}… — 동적 분석 요약을 조회했습니다"
                             "(GET /files/{{해시}}/behaviour_summary). 샌드박스가 실제로 실행해 본 "
                             "결과에서 명령 {}건·프로세스 {}건·통신 {}건·ATT&CK {}개를 "
                             "가져왔습니다.".format(
                                 hash_value[:12], len(behaviour.get("commands") or []),
                                 len(behaviour.get("processes") or []),
                                 len(behaviour.get("dns") or []) + len(behaviour.get("ip_traffic") or []),
                                 len(behaviour.get("techniques") or [])))
            except Exception as exc:
                error = str(exc)[:120]
                steps.append("{}… — VT 조회가 실패했습니다({}).".format(hash_value[:12], error[:60]))

        # 보강(샌드박스별 리포트·커뮤니티·외부 링크)은 조회를 2회 더 쓴다 — 무료 키
        # 제한 때문에 대표 파일 몇 건에만 붙인다. 키가 없으면 링크만 만든다.
        enrichment = {}
        # 조회에 성공한 파일 기준으로 센다 — 인덱스로 세면 첫 파일이 404였을 때
        # (실측: TerminalFix의 기사 해시가 VT에 없다) 보강이 아예 안 붙는다.
        enriched_so_far = sum(1 for f in files if (f.get("enrichment") or {}).get("sandboxes"))
        if enriched_so_far < ENRICH_FILES and not error:
            if api_key:
                time.sleep(PAUSE_SECONDS)
            enrichment = enrich_file(hash_value, api_key)
            if enrichment.get("sandboxes") or enrichment.get("comments"):
                steps.append("{}… — 샌드박스별 리포트 {}건과 커뮤니티 코멘트 {}건을 추가로 "
                             "조회했습니다.".format(short_hash(hash_value),
                                              len(enrichment.get("sandboxes") or []),
                                              len(enrichment.get("comments") or [])))

        files.append({
            "hash": hash_value,
            "report": report or {},
            "behaviour": behaviour or {},
            "interpreted": interpret(behaviour, iocs=iocs, report=report) if behaviour else {},
            "enrichment": enrichment,
            "error": error,
            "queries": _queries(hash_value, report) + _external_queries(enrichment),
        })
        findings.extend(_findings_for_file(hash_value, report, behaviour, error, iocs=iocs,
                                           enrichment=enrichment))

    if not api_key:
        findings.append("VT_API_KEY가 없어 자동 조회는 하지 않았습니다. 아래 링크로 VT 화면에서 "
                        "직접 보면 됩니다 — 무료 키를 넣으면 탐지율과 동적 분석 결과를 여기에 "
                        "바로 정리해 줍니다.")
    return {"files": files, "findings": findings, "steps": steps, "checked": bool(api_key),
            "total_hashes": len(hashes), "generated_at": common_utils.utc_now_iso()}


def _findings_for_file(hash_value, report, behaviour, error, iocs=None, enrichment=None):
    """파일 하나에 대한 동적 분석 서술.

    "어떤 유형이고, 무엇을 하며, C2는 어디인가"로 적는다. 행위를 나열하는 것은 분석이
    아니다 — 예전에는 명령줄과 파일 경로를 잘라 붙였을 뿐이어서, 읽는 사람이 스스로
    다시 해석해야 했다.
    """
    short = hash_value[:12]
    if error:
        if "404" in error:
            return ["{}… — VirusTotal에 이 해시가 없습니다. 아직 아무도 올리지 않은 파일이라 "
                    "동적 분석 결과도 없습니다(기사에만 실린 해시).".format(short)]
        return ["{}… — VT 조회에 실패했습니다({}). 아래 링크로 직접 확인하세요.".format(short, error)]
    if not report:
        return ["{}… — 파일 해시입니다. VT에서 탐지율과 동적 분석 결과를 확인하세요.".format(short)]

    view = interpret(behaviour, iocs=iocs, report=report)
    story = analyze_dynamic(report, behaviour, view)
    lines = []

    # ① 무엇인가 — 유형·분류·보호 수단
    kind = ", ".join(story["families"]) if story["families"] else ""
    head = "{}… — ".format(short)
    if kind:
        head += "{} 유형입니다. ".format(kind)
    if report.get("engines"):
        head += "백신 {}개 중 {}개가 악성으로 판정".format(report["engines"], report["malicious"])
        head += "했고, 분류는 {}입니다.".format(report["label"]) if report.get("label") else "했습니다."
    elif report.get("label"):
        head += "분류는 {}입니다.".format(report["label"])
    lines.append(head)

    detail = []
    if report.get("type"):
        detail.append(report["type"])
    if report.get("size"):
        detail.append("{:,}바이트".format(report["size"]))
    if report.get("first_seen"):
        detail.append("VT 최초 등록 {}".format(report["first_seen"]))
    packed = [tag for tag in (report.get("tags") or []) + story["tags"]
              if re.search(r"packed|obfuscat|vmprotect|themida|upx|protector", tag, re.I)]
    if detail or packed:
        lines.append("· 파일: {}{}".format(
            " / ".join(detail) or "정보 없음",
            ". {}로 보호돼 있어 정적 분석이 어렵습니다".format(", ".join(sorted(set(packed))[:3]))
            if packed else ""))
    if report.get("signer"):
        lines.append("· 디지털 서명이 '{}' 이름으로 붙어 있습니다{}. 서명이 있다고 정상은 "
                     "아닙니다 — 훔친 인증서이거나 정상 파일을 끼워 쓰는 경우가 많습니다.".format(
                         report["signer"], "(검증됨)" if report.get("verified") == "Signed" else ""))

    if not view["has_dynamic"]:
        lines.append("· 동적 분석 결과가 없습니다. 샌드박스가 실행 조건을 못 맞췄거나, 샘플이 "
                     "샌드박스를 탐지해 동작을 멈춘 것일 수 있습니다 — 무해하다는 뜻은 아닙니다.")
        return lines

    if view["platform"] and view["platform"] != "windows":
        lines.append("· 이 샌드박스는 {}에서 실행했습니다. 기사가 다루는 Windows 공격 단계와 "
                     "다른 환경이라, 아래 행위를 그대로 Windows 탐지에 옮겨 쓸 수 없습니다."
                     .format({"linux": "리눅스", "macos": "macOS"}.get(view["platform"], view["platform"])))

    # ② 무엇을 하는가 — 실행 순서대로
    described = story["stages"]
    if described:
        for stage in STAGE_ORDER:
            items = described.get(stage)
            if items:
                lines.append("· {}: {}".format(stage, " / ".join(items)))
        artifacts = []
        for stage_items in view["stages"].values():
            for item in stage_items:
                task = re.search(r'/tn\s+"?([^"\s]+)', item)
                if task:
                    artifacts.append("예약 작업 '{}'".format(task.group(1)))
        if story["mutex_count"]:
            artifacts.append("뮤텍스 {}개 생성(중복 실행 방지)".format(story["mutex_count"]))
        if story["services"]:
            artifacts.append("서비스 사용: {}".format(", ".join(story["services"])))
        if artifacts:
            lines.append("· 남기는 흔적: {}".format(" / ".join(sorted(set(artifacts))[:4])))
    else:
        lines.append("· 샌드박스가 설명을 붙인 행위가 없습니다 — 실행되자마자 종료됐거나 "
                     "조건을 기다리는 유형입니다.")

    # ③ C2는 무엇인가
    if story["c2"]:
        high = [item for item in story["c2"] if item["confidence"] == "high"]
        rest = [item for item in story["c2"] if item["confidence"] != "high"]
        if high:
            lines.append("· C2: {}. 기사 IOC와 일치하므로 이 캠페인의 통신으로 봅니다{}.".format(
                ", ".join(item["value"] for item in high),
                ", 포트 " + "/".join(story["ports"]) if story["ports"] else ""))
        if rest:
            lines.append("· C2 후보(확인 필요): {}. {}".format(
                ", ".join("{}({})".format(item["value"], item["why"]) for item in rest[:4]),
                "정상 서비스일 수 있어 차단 전에 사내 통신 실태를 봐야 합니다."))
    else:
        lines.append("· C2로 볼 통신처가 관측되지 않았습니다. 샌드박스에서 통신 단계까지 "
                     "가지 못했거나, C2가 이미 내려간 상태일 수 있습니다.")

    dropped = view["dropped"]
    dropped_count = sum(len(dropped[key]) for key in ("hosts", "traffic", "files", "processes"))
    if dropped_count:
        sample = (dropped["hosts"] + dropped["files"] + dropped["processes"])[:2]
        lines.append("· 샌드박스 환경 흔적 {}건은 제외했습니다{}. 이런 값이 IOC로 섞이면 "
                     "정상 서비스를 차단하게 됩니다.".format(
                         dropped_count,
                         "(예: {})".format(", ".join(s[:40] for s in sample)) if sample else ""))

    lines.extend(_enrichment_findings(hash_value, enrichment or {}))

    if view["techniques"]:
        # 코드만 나열하면 읽히지 않는다 — 전술(킬체인 단계)로 묶어 이름과 함께 적는다.
        groups = common_utils.group_attack_techniques(view["techniques"])
        summary = " / ".join(
            "{} {}".format(group["label"],
                           ", ".join(item["label"] or item["id"] for item in group["items"][:3]))
            for group in groups[:6])
        lines.append("· 샌드박스가 매핑한 ATT&CK({}개): {}".format(
            len(view["techniques"]), summary))
    return lines
