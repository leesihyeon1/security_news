# -*- coding: utf-8 -*-
"""LLM으로 헌팅 패턴을 합성하고, 기계로 검증해서 살아남은 것만 남긴다.

왜 필요한가
    조사&대응의 쿼리는 지금까지 두 가지 방식으로만 나왔다. (1) IOC 값을 그대로 넣은
    쿼리 — 인프라가 바뀌면 바로 죽는다. (2) 사람이 hunting_patterns.json에 손으로
    적어둔 패턴 — 적어둔 것만 나온다. 정작 필요한 것은 그 사이다. 기사 본문에는
    "C:\\ProgramData\\f47f2a8c21c9df4e"처럼 이번 사건에서만 쓰인 값이 적혀 있고,
    거기서 "ProgramData 아래 16자 hex 폴더"라는 불변식을 뽑아내면 다음 캠페인도
    잡힌다. 그 일반화가 규칙으로는 안 되고 LLM으로는 된다.

왜 검증이 필수인가
    LLM에게 쿼리를 만들라고 하면 문법이 맞는 그럴듯한 문자열을 반드시 만들어 낸다 —
    본문에 없는 도메인, 실제로는 한 건도 안 잡히는 파일명, 전체 인터넷을 긁는 와일드
    카드까지. 그래서 생성물을 그대로 쓰지 않는다.

      1) 근거 확인: 쿼리에 박힌 리터럴이 본문·분석·IOC에 실제로 있는 문자열인가.
      2) 실사 조회: urlscan은 키 없이 검색이 되므로 히트 수를 직접 센다. 0건이면
         그 패턴은 실재하지 않고, 지나치게 많으면 캠페인 지문이 아니라 웹 전체다.
      3) 형식 확인: MDE KQL은 실행해 볼 수 없으니 테이블 화이트리스트·구조만 본다.

    폐기 사유는 버리지 않고 조사 과정에 남긴다 — "후보 7개 중 3개 채택, 4개 폐기
    (0건 2, 근거 없음 2)"가 보이지 않으면 통과한 3개도 믿을 수 없다.
"""

import json
import re
import urllib.parse

import common_utils
import lure_hunter

BS = chr(92)  # 정규식 리터럴 백슬래시(편집 중 개수가 어긋나는 것을 막는다)

SEARCH_UI_URL = "https://urlscan.io/search/#{}"
VT_SEARCH_UI_URL = "https://www.virustotal.com/gui/search/{}"

# urlscan 검색 인덱스는 넓어서, 히트가 이 이상이면 캠페인 지문이 아니라 웹 전체의
# 흔한 문자열이다(실측: filename:".js"는 수백만 건). 이 위는 정제가 필요하다고 본다.
URLSCAN_TOO_BROAD = 30000
# 반대로 이만큼도 안 되면 오타이거나 존재하지 않는 문자열이다.
URLSCAN_MIN_HITS = 1

# KQL은 실행 검증을 할 수 없다. 최소한 아는 테이블만 쓰게 한다 — 없는 테이블을 쓴
# 쿼리는 붙여넣는 순간 오류가 나므로 내보내지 않는 것이 낫다.
KQL_TABLES = {
    "DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents",
    "DeviceRegistryEvents", "DeviceImageLoadEvents", "DeviceEvents",
    "DeviceLogonEvents", "DeviceFileCertificateInfo", "DeviceInfo",
    "DeviceTvmSoftwareVulnerabilities", "DeviceTvmSoftwareInventory",
    "EmailEvents", "EmailUrlInfo", "UrlClickEvents", "IdentityLogonEvents",
}

PLATFORMS = ("mde_kql", "urlscan", "virustotal", "google_dork")

# dork에서 근거를 확인할 필요가 없는 연산자들.
DORK_OPERATORS = {
    "intitle", "inurl", "intext", "filetype", "site", "ext", "allintitle",
    "allinurl", "related", "cache", "download", "index", "of",
}

# 근거 확인 대상만 남기기 위해, 문법 토큰은 리터럴로 보지 않는다.
QUERY_KEYWORDS = {
    "and", "or", "not", "in", "has", "has_any", "has_all", "contains",
    "startswith", "endswith", "matches", "regex", "where", "project", "summarize",
    "extend", "let", "join", "union", "count", "by", "asc", "desc", "true", "false",
    "dynamic", "tolower", "toupper", "datetime", "ago", "between", "timestamp",
    "distinct", "top", "sort", "order", "limit", "take", "on", "kind", "any",
    "page", "task", "filename", "hash", "domain", "ip", "asn", "server", "url",
    "title", "time", "behaviour_files", "behaviour_processes", "behaviour_registry",
    "behaviour_network", "content", "imphash", "vhash", "entity", "type",
    "intitle", "inurl", "intext", "filetype", "ext", "allintitle", "allinurl",
}
# 근거 확인에서 빼는 흔한 시스템 이름 — 본문에 없어도 쓸 수 있어야 하는 것들이다.
COMMON_TOKENS = {
    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "schtasks.exe", "reg.exe", "attrib.exe",
    "explorer.exe", "svchost.exe", "programdata", "appdata", "temp", "windows",
    "http", "https", "com", "net", "org", "exe", "dll", "js", "php", "png", "zip",
}

# 브라우저 확장 API의 최상위 이름. 이 아래 이름들(chrome.runtime.sendMessage 등)은
# 점으로 이어져 있어 도메인 정규식에 그대로 걸린다 — "sendmessage"가 TLD처럼 보이기
# 때문이다. 실측(2026-09-16, 악성 확장 프로그램 건): manifest.json과
# chrome.runtime.sendMessage, chrome.webRequest.onHeadersReceived 때문에 확장 행위
# 탐지 쿼리가 통째로 폐기됐다. MDE 컬럼·열거형을 플랫폼 어휘로 봐주는 것과 같은 이유로
# 이것도 봐준다 — 기사에 API 이름이 적혀 있을 이유가 없다.
#
# 이름 전체를 열거하지 않고 최상위 이름만 두는 이유는 API가 수백 개라서다. 대신
# 범위를 좁게 잡는다 — 이 세 이름으로 시작하는 값만 면제되므로, 지어낸 C2가 여기로
# 새어 나가려면 chrome.으로 시작하는 도메인이어야 한다.
API_NAMESPACES = {"chrome", "browser", "manifest"}

# 플랫폼 어휘 — 컬럼 이름과 열거형 값이다. 기사에 있을 이유가 없고, 없다고 폐기하면
# 정상 쿼리가 죽는다(실측: ScheduledTaskCreated 때문에 예약 작업 탐지 쿼리가 폐기됨).
PLATFORM_VOCAB = {
    # MDE 컬럼
    "filename", "folderpath", "processcommandline", "initiatingprocessfilename",
    "initiatingprocesscommandline", "initiatingprocessfolderpath", "accountname",
    "devicename", "remoteurl", "remoteip", "remoteport", "localport", "registrykey",
    "registryvaluename", "registryvaluedata", "actiontype", "sha256", "sha1", "md5",
    "timestamp", "deviceid", "reportid", "initiatingprocessparentfilename",
    "additionalfields", "protocol", "initiatingprocesssha256", "filesize",
    "signeddevicebuild", "issigned", "signer", "certificatecountersignaturetime",
    # MDE ActionType 열거형(자주 쓰는 것)
    "scheduledtaskcreated", "scheduledtaskupdated", "processcreated",
    "filecreated", "filemodified", "filerenamed", "registryvalueset",
    "registrykeycreated", "connectionsuccess", "connectionattempt",
    "connectionfailed", "dnsqueryresponse", "imageloaded", "namedpipeevent",
    "servicerinstalled", "serviceinstalled", "asrblocked", "powershellcommand",
    # urlscan / VT 필드(점 포함 형태까지)
    "page.domain", "page.url", "page.title", "page.server", "page.asn",
    "page.domainageddays", "page.domainagedays", "page.ip", "page.country",
    "task.time", "task.url", "entity", "entity:file", "behaviour_files",
    "behaviour_processes", "behaviour_registry", "behaviour_network",
}

# OS 구조 — 공격자 산출물이 아니라 윈도우가 원래 갖고 있는 경로·키다. 기사에 안 적혀
# 있어도 쿼리에 쓰는 것이 맞다.
OS_STRUCTURE_RE = re.compile(
    "^(?:[a-z]:" + BS + BS + "?(?:windows|program files|programdata|users)|"
    "%(?:appdata|localappdata|programdata|temp|windir|userprofile)%|"
    "hk(?:cu|lm|u|cr)" + BS + BS + "?|" + BS + BS + "?(?:device|" + BS + BS + "?" + "\\?" + ")|"
    "software" + BS + BS + BS + BS + "?microsoft)", re.I)

# 지어냈을 때 실제로 위험한 것들 — 도메인·IP·해시·고유 파일명이다. 이것만 폐기한다.
# 점 하나짜리(invented-c2.top)도 도메인이다 — 두 개 이상을 요구하면 지어낸 도메인이
# "일반 지식" 쪽으로 새어 나간다.
RISKY_DOMAIN_RE = re.compile(
    "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:" + BS + ".[a-z0-9-]+)*"
    + BS + ".[a-z]{2,18}$", re.I)
RISKY_IP_RE = re.compile("^" + BS + "d{1,3}(?:" + BS + "." + BS + "d{1,3}){3}$")
RISKY_HASH_RE = re.compile("^[a-f0-9]{32}(?:[a-f0-9]{8})?(?:[a-f0-9]{24})?$", re.I)
RISKY_FILENAME_RE = re.compile(
    "^[a-z0-9_.-]{3,60}" + BS + ".(?:exe|dll|bat|cmd|ps1|py|vbs|js|jar|scr|sys|zip|"
    "rar|7z|iso|lnk|hta|msi|apk|dmg|pkg)$", re.I)
# 파일 확장자 목록 — 이 확장자로 끝나면 도메인이 아니라 파일명으로 판정한다.
FILE_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "ps1", "py", "vbs", "js", "jar", "scr", "sys",
    "zip", "rar", "7z", "iso", "lnk", "hta", "msi", "apk", "dmg", "pkg", "tmp",
    "log", "txt", "dat", "bin", "cab", "msu", "chm", "jse", "wsf", "reg", "inf",
}

# 어느 환경에나 있는 정상 실행 파일은 위험 파일명으로 보지 않는다.
KNOWN_BINARIES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "schtasks.exe", "reg.exe",
    "attrib.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe",
    "python.exe", "pythonw.exe", "node.exe", "msiexec.exe", "wmic.exe",
    "net.exe", "net1.exe", "nltest.exe", "whoami.exe", "tasklist.exe",
    "rundll.exe", "explorer.exe", "svchost.exe", "dllhost.exe", "conhost.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe",
    # 랜섬웨어 대응 쿼리에 반드시 나오는 기본 도구들. 기사에 이름이 안 적혀 있어도
    # 쿼리에 쓰는 것이 맞다(실측: sc.exe·wevtutil.exe가 "지어낸 지표"로 폐기됐다).
    "sc.exe", "wevtutil.exe", "vssadmin.exe", "bcdedit.exe", "wbadmin.exe",
    "taskkill.exe", "fsutil.exe", "cipher.exe", "icacls.exe", "takeown.exe",
    "netsh.exe", "wusa.exe", "diskshadow.exe", "esentutl.exe", "makecab.exe",
    "expand.exe", "extrac32.exe", "findstr.exe", "forfiles.exe", "ftp.exe",
    "hh.exe", "ie4uinit.exe", "odbcconf.exe", "pcalua.exe", "presentationhost.exe",
    "print.exe", "replace.exe", "runonce.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
    "verclsid.exe", "xwizard.exe", "at.exe", "arp.exe", "route.exe", "ipconfig.exe",
    "systeminfo.exe", "quser.exe", "query.exe", "klist.exe", "dsquery.exe",
    "adfind.exe", "reg.exe", "regedit.exe", "control.exe", "mmc.exe", "wsl.exe",
}

# 리터럴에 알파벳·숫자가 이만큼도 없으면 정규식 파편이다(실측: "://." 가 폐기 사유로
# 올라왔다) — 근거 확인 대상에서 뺀다.
MIN_ALNUM_IN_LITERAL = 3

LITERAL_RE = re.compile('"([^"]{2,120})"' + "|'([^']{2,120})'")
BARE_TOKEN_RE = re.compile("[A-Za-z0-9][A-Za-z0-9._" + BS + BS + "/?=" + BS + "-]{3,}")
DEFANG_RE = re.compile(r"hxxps|hxxp|\(dot\)", re.I)
REGEX_PIECE_RE = re.compile("[" + BS + "[" + BS + "]{}()+*?^$|" + BS + BS + "]+")
HAS_REGEX_CHARS_RE = re.compile("[" + BS + "[" + BS + "]{}()+*?^$|]")
# 문자클래스([0-9a-f])와 수량자({16})의 내용은 기사에 있을 수 없는 문법이다 —
# 근거를 확인하기 전에 떼어낸다. 떼지 않으면 정상적인 정규식 쿼리가 "본문에 없는
# 문자열: 0-9a-f"로 잘못 폐기된다.
REGEX_SYNTAX_RE = re.compile("(?:" + BS + "[[^" + BS + "]]*" + BS + "]|{[0-9,]*})")
NESTED_FIELD_RE = re.compile("(behaviour_" + BS + "w+|content|entity)"
                              + BS + "s*:" + BS + "s*[a-z_]+" + BS + "s*:", re.I)
TIME_FILTER_RE = re.compile("^\|?\s*where\s+\w*[Tt]ime\w*\s*[<>=!]+\s*ago\(", re.I)
TIME_FILTER_INLINE_RE = re.compile("\|\s*where\s+\w*[Tt]ime\w*\s*[<>=!]+\s*ago\([^)]*\)\s*", re.I)
DORK_RE = re.compile("(?:" + "|".join(sorted(DORK_OPERATORS)) + ")" + BS + "s*:", re.I)
VT_FIELD_RE = re.compile("(behaviour_" + BS + "w+|content|imphash|vhash|entity)" + BS + "s*:")


def log(message):
    print(message)


# ── 프롬프트 ──────────────────────────────────────────────────────────────────
# 플랫폼 문법을 프롬프트에 직접 넣는다. 넣지 않으면 LLM이 문법을 섞어 쓴다
# (urlscan 쿼리에 KQL 파이프를 붙이거나 Splunk의 index=를 쓴다).
PLATFORM_SPEC = """
[플랫폼별 문법 — 이 문법만 쓰라]

1) mde_kql — Microsoft Defender 고급 헌팅(Kusto)
   쓸 수 있는 테이블: DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents,
   DeviceRegistryEvents, DeviceImageLoadEvents, DeviceEvents, DeviceLogonEvents,
   DeviceFileCertificateInfo, DeviceTvmSoftwareVulnerabilities
   형식: 테이블 이름으로 시작하고 파이프(|)로 이어간다. 시간 범위는 넣지 마라.
   정규식이 필요하면 matches regex "..." 를 쓰라.

2) urlscan — urlscan.io 검색(Elasticsearch query string)
   쓸 수 있는 필드: page.domain, page.url, page.title, page.server, page.asn,
   page.domainAgeDays, filename, hash, domain, ip, asn, task.time
   형식: 필드:"값" 을 AND/OR/NOT으로 잇는다. 와일드카드는 *를 값 뒤에만 붙인다.
   값 앞에 *를 붙이면(예: page.title:*Turnstile*) 검색이 거부된다(HTTP 403).
   문구를 찾을 때는 page.title:"Verify you are human" 처럼 따옴표로 감싸라.

3) virustotal — VT Intelligence 검색
   쓸 수 있는 필드: behaviour_files, behaviour_processes, behaviour_registry,
   behaviour_network, content, imphash, vhash, entity:file

4) google_dork — 검색 연산자로 가짜 배포 페이지를 찾는다
   쓸 수 있는 연산자: intitle:, inurl:, intext:, filetype:, site:, -site:, "따옴표"
   가짜 설치 파일·트로이목마화된 도구가 어디에 더 뿌려져 있는지 발굴하는 용도다.
   정상 배포처는 -site:로 빼야 결과가 쓸모 있다.
   예) intitle:"Download" intext:"설치 파일 이름" -site:정상배포처.com
   예) inurl:download "제품명" filetype:exe -site:벤더도메인.com
"""

TASK_SPEC = """
[해야 하는 일]

기사에 적힌 "이번 사건에만 쓰인 구체값"을 "다음 사건에도 남을 불변식"으로 올려서
헌팅 쿼리를 만들라. 값을 그대로 넣는 쿼리는 만들지 마라 — 그건 이미 따로 만든다.

일반화의 뜻(예):
  나쁨: 특정 폴더 이름 하나를 그대로 비교          -> 그 폴더만 잡힌다
  좋음: 그 폴더 이름의 생성 규칙을 정규식으로      -> 같은 방식 전부 잡힌다
  나쁨: 유포 도메인 하나를 그대로 검색             -> 그 도메인만
  좋음: 그 도메인이 내려주던 리소스 파일명 규칙    -> 같은 유포 방식 전부

불변식이 될 수 있는 것: 파일명·경로의 생성 규칙, URL 경로·쿼리스트링 이름, 페이지
제목·문구, 예약 작업·서비스·뮤텍스 이름 규칙, 정상 바이너리와 악성 DLL의 조합,
프로세스 부모-자식 관계, 특이한 포트·프로토콜 조합, 명령줄 인자 조합.

지켜야 할 것:
  - 쿼리에 넣는 문자열은 기사에 실제로 적힌 것이어야 한다. 없는 도메인·파일명·해시를
    지어내면 그 항목은 버려진다.
  - 같은 것을 잡는 쿼리를 여러 개로 쪼개지 마라. 3~6개만, 서로 다른 층을 잡는 것으로.
  - 정상 활동도 같이 잡히는 쿼리라면 confidence를 low로 적고, reading에 무엇을 보고
    걸러야 하는지 쓰라.

[출력 형식 — JSON 배열 하나만. 설명 문장을 앞뒤에 붙이지 마라]
[
  {
    "platform": "mde_kql | urlscan | virustotal",
    "label": "패턴 이름(우리말 12자 내외)",
    "query": "쿼리 본문",
    "literals": ["쿼리에 넣은 문자열 중 기사에서 가져온 것들"],
    "invariant": "공격자가 이것을 바꾸기 어려운 이유(한 문장)",
    "what": "무엇이 잡히는가(한 문장)",
    "why": "왜 이걸 봐야 하는가(한 문장)",
    "reading": "결과를 어떻게 읽고 오탐을 어떻게 걸러내는가",
    "next": "잡힌 뒤 무엇을 하는가",
    "confidence": "high | medium | low"
  }
]
"""


def _objective_block(targets):
    """목표를 프롬프트에 넣는다.

    목표를 안 주면 본문에 눈에 띄는 값 위주로 패턴이 나와서, 목표에 적힌 요소가
    산출물 없이 남는다(실측: TerminalFix 목표 4요소 중 "스테가노그래피 PNG 다운로드"만
    탐지 쿼리가 없었다 — 나머지 셋은 패턴으로 나왔다).
    """
    targets = targets or {}
    objective = targets.get("objective") or ""
    if not objective:
        return ""
    questions = targets.get("questions") or []
    return (
        "\n\n[이 건의 대응 목표]\n" + objective
        + ("\n\n[확인해야 할 질문]\n" + "\n".join("- " + q for q in questions[:6])
           if questions else "")
        + "\n\n목표에 적힌 요소마다 최소 하나씩 쿼리가 나오게 하라. 목표에 있는데 "
          "탐지 수단이 없으면 그 요소는 대응에서 빠진다. 본문에 눈에 띄는 값만 쫓지 마라."
    )


def build_prompt(title, analysis, body, iocs, targets=None):
    ioc_lines = "\n".join(
        "- {}: {}".format(item.get("type") or "?", item.get("value") or "")
        for item in (iocs or [])[:40])
    return (
        "당신은 위협 헌팅 엔지니어다. 아래 기사 분석을 읽고 헌팅 쿼리를 만든다.\n"
        + TASK_SPEC + PLATFORM_SPEC
        + "\n[기사 제목]\n" + (title or "")
        + "\n\n[분석 본문]\n" + (analysis or "")[:6000]
        + ("\n\n[원문에서 뽑은 지표]\n" + ioc_lines if ioc_lines else "")
        + ("\n\n[원문 발췌]\n" + (body or "")[:6000] if body else "")
        + _objective_block(targets)
        + "\n\nJSON 배열만 출력하라."
    )


# ── 생성물 파싱 ───────────────────────────────────────────────────────────────
def parse_candidates(raw):
    """LLM 응답에서 JSON 배열을 꺼낸다. 앞뒤 설명이 붙어 있어도 살려 낸다."""
    if not raw:
        return []
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start = text.find("[")
    end = text.rfind("]")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        # 배열 안의 객체를 하나씩 건져 본다 — 한 항목이 깨져도 나머지는 쓸 수 있다.
        data = []
        for match in re.finditer(r"\{[^{}]*\}", text[start:end + 1], re.S):
            try:
                data.append(json.loads(match.group(0)))
            except ValueError:
                continue
    return [item for item in data if isinstance(item, dict)]


# ── 근거 확인 ────────────────────────────────────────────────────────────────
def _normalize(text):
    """디팽·대소문자·역슬래시 개수 차이를 무시하고 비교하기 위한 정규화."""
    text = DEFANG_RE.sub("", text or "")
    text = text.replace("[.]", ".").replace("[:]", ":").replace("[/]", "/")
    text = text.replace("(dot)", ".")
    text = text.replace(BS + BS, BS).replace("**", "").replace("`", "")
    # 양끝 공백을 반드시 떼야 한다 — 떼지 않으면 "LockScreenContentServer_ "가
    # 본문의 "LockScreenContentServer_MuODG5yBM"과 부분일치하지 않는다.
    return re.sub(r"\s+", " ", text).strip().lower()


def _skippable(value):
    """근거를 확인할 필요가 없는 문자열인가 — 문법·플랫폼 어휘·OS 구조·파편."""
    low = value.strip().lower()
    if not low or len(low) < 4:
        return True
    if low in QUERY_KEYWORDS or low in COMMON_TOKENS or low in PLATFORM_VOCAB:
        return True
    if low in KNOWN_BINARIES:
        return True
    # 필드 이름(점 포함)과 접두 형태
    if low.split(".")[0] in QUERY_KEYWORDS and "." in low:
        return True
    # 브라우저 확장 API 이름(chrome.runtime.sendMessage, manifest.json 등)
    if "." in low and low.split(".")[0] in API_NAMESPACES:
        return True
    if OS_STRUCTURE_RE.match(low):
        return True
    if len(re.findall("[a-z0-9가-힣]", low)) < MIN_ALNUM_IN_LITERAL:
        return True
    return False


def _risky(value):
    """기사에 없을 때 폐기해야 하는 종류인가 — 지어낸 도메인·IP·해시·고유 파일명.

    이 구분이 필요한 이유: 기사에 없는 문자열을 전부 폐기하면 정상 쿼리가 죽는다
    (실측: MDE의 ScheduledTaskCreated, C:\\Windows\\SystemApps\\ 때문에 폐기됨).
    반대로 전부 통과시키면 지어낸 C2 도메인이 차단 목록에 실린다. 위험한 종류만
    막는다.
    """
    low = value.strip().lower()
    # 아는 도구 이름이 먼저다. 뒤로 미루면 도메인 판정에 걸린다 — "sc.exe"는 점이
    # 하나뿐이라 도메인 정규식에도 맞는다(실측: sc.exe가 "지어낸 지표"로 폐기됨).
    if low in KNOWN_BINARIES or low in COMMON_TOKENS:
        return False
    if RISKY_IP_RE.match(low) or RISKY_HASH_RE.match(low):
        return True
    # 확장자가 파일 확장자면 파일명이지 도메인이 아니다.
    suffix = low.rsplit(".", 1)[-1] if "." in low else ""
    if suffix in FILE_EXTENSIONS:
        return bool(RISKY_FILENAME_RE.match(low))
    if RISKY_DOMAIN_RE.match(low):
        return True
    return False


def _dedupe(values):
    seen, unique = set(), []
    for value in values:
        key = value.strip().lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(value.strip())
    return unique


def extract_tokens(query):
    """쿼리를 (확인 대상 리터럴, 앵커)로 나눈다.

    확인 대상은 지어냈는지 따져야 하는 값이고, 앵커는 문법·OS 구조·흔한 이름이라
    따질 필요가 없는 것들이다. 앵커도 버리지 않고 돌려주는 이유는, 값이 하나도 없는
    구조 쿼리(예: FolderPath matches regex "ProgramData[0-9a-f]{16}")가 이 기사와
    무관한지 판단할 근거가 앵커밖에 없기 때문이다 — "ProgramData"가 기사에 있으면
    그 쿼리는 이 기사에 걸려 있는 것이다.

    필드 이름은 값이 아니다 — page.title:"..." 에서 확인해야 하는 것은 값 쪽이다.
    """
    text = query or ""
    found = []
    for quoted in LITERAL_RE.finditer(text):
        value = quoted.group(1) or quoted.group(2) or ""
        if value:
            found.append(value)
    if not found:
        # 인용부호 없이 쓴 경우(예: filename:jsrepo). 필드 접두는 떼고 값만 본다.
        for token in BARE_TOKEN_RE.findall(text):
            found.append(token.split(":")[-1] if ":" in token else token)

    literals, anchors = [], []
    for value in found:
        # 값 안에 필드:값이 또 들어 있는 경우(behaviour_network:gitnow.dev)
        if ":" in value and value.split(":")[0].lower() in QUERY_KEYWORDS | PLATFORM_VOCAB:
            value = value.split(":", 1)[1]
        # 정규식 조각은 문자 그대로 본문에 없다 — 조각으로 쪼개 각각 판정한다.
        pieces = ([p for p in REGEX_PIECE_RE.split(REGEX_SYNTAX_RE.sub(" ", value))]
                  if HAS_REGEX_CHARS_RE.search(value) else [value])
        for piece in pieces:
            piece = piece.strip()
            if not piece:
                continue
            (anchors if _skippable(piece) else literals).append(piece)
    return _dedupe(literals), _dedupe(anchors)


def query_literals(query):
    """확인 대상 리터럴만."""
    return extract_tokens(query)[0]


def grounded(candidate, corpus_norm):
    """쿼리가 기사 근거 위에 서 있는지 본다.

    (1) 기사에 없는 문자열 중 위험한 종류(도메인·IP·해시·고유 파일명)가 있으면 폐기 —
        지어낸 C2가 차단 목록에 실리는 것을 막는다.
    (2) 기사에 걸린 데가 한 군데도 없으면 폐기 — 리터럴이든 앵커든 하나는 기사에
        있어야 이 기사의 대응이다. 앵커까지 보는 이유는 값 대신 생성 규칙으로 만든
        쿼리(정규식 구조 패턴)가 가장 쓸모 있는데, 그런 쿼리에는 확인할 값이 없기
        때문이다 — "ProgramData 아래 16자 hex"는 값이 아니라 규칙이다.
    통과하면 (True, 기사에 없었지만 허용한 문자열 목록)을 준다 — 화면에 밝힌다.
    """
    literals, anchors = extract_tokens(candidate.get("query") or "")

    def present(value):
        # strcat(FolderPath, "\dui70.dll")처럼 경로 구분자가 앞에 붙어 오는 경우가
        # 있다 — 그대로 비교하면 본문의 dui70.dll과 안 맞는다.
        norm = _normalize(value).strip(BS + "/\"' ")
        return bool(norm) and norm in corpus_norm

    missing = [value for value in literals if not present(value)]
    invented = [value for value in missing if _risky(value)]
    if invented:
        return False, "기사에 없는 지표를 지어냄: " + ", ".join(invented[:3])

    hit_literals = [value for value in literals if present(value)]
    hit_anchors = [value for value in anchors if present(value)]
    if not hit_literals and not hit_anchors:
        return False, "기사에 걸린 값이 하나도 없음(일반 지식으로만 만든 쿼리)"
    note = ""
    if missing:
        note = "일반 지식으로 보탠 값: " + ", ".join(missing[:3])
    elif not hit_literals:
        # 값 없이 규칙으로만 만든 쿼리 — 어디에 걸려 있는지 밝힌다.
        note = "본문 값이 아니라 생성 규칙으로 만든 구조 쿼리({} 기준)".format(
            ", ".join(hit_anchors[:2]))
    return True, note


# ── 실사 검증 ────────────────────────────────────────────────────────────────
def _search_urlscan(query, api_key=None):
    """검색 결과와 함께 "조회 자체가 실패했는지"를 돌려준다.

    lure_hunter.urlscan_search는 실패를 빈 결과로 바꿔 주는데, 여기서는 그 구분이
    필요하다 — 문법 오류·차단으로 403이 온 것을 "0건이라 실재하지 않는 패턴"으로
    적으면 폐기 사유가 거짓이 된다(실측: 선행 와일드카드 쿼리에 403).
    """
    url = "{}?{}".format(lure_hunter.SEARCH_URL,
                         urllib.parse.urlencode({"q": query, "size": 5}))
    try:
        data = lure_hunter._request(url, api_key=api_key)
    except Exception as error:
        return None, 0, str(error)
    return (data.get("results") or []), (data.get("total") or 0), ""


def validate_urlscan(candidate, api_key=None):
    """urlscan에서 실제로 몇 건 잡히는지 센다. 0건·과다는 폐기."""
    query = (candidate.get("query") or "").strip()
    if not query:
        return False, "쿼리 없음", {}
    results, total, error = _search_urlscan(query, api_key=api_key)
    if error:
        return False, "urlscan 조회 실패({}) — 쿼리 문법을 확인해야 합니다".format(
            error[:60]), {}
    if total < URLSCAN_MIN_HITS:
        return False, "urlscan 0건 — 실재하지 않는 패턴", {"hits": 0}
    if total > URLSCAN_TOO_BROAD:
        return False, "urlscan {:,}건 — 캠페인 지문이 아니라 웹 전체".format(total), {"hits": total}
    hosts = []
    for item in results:
        host = ((item.get("page") or {}).get("domain") or "").strip()
        if host and host not in hosts:
            hosts.append(host)
    return True, "", {"hits": total, "hosts": hosts[:4]}


def strip_time_filter(query):
    """헌팅 쿼리에서 시간 창 필터를 뺀다.

    프롬프트에서 넣지 말라고 해도 LLM은 "| where Timestamp > ago(1h)"를 붙인다.
    한 시간짜리 창은 이미 벌어진 침해를 찾는 데 쓸모가 없고, 붙여넣는 사람은 그 줄이
    있는 줄 모르고 "결과가 없다"고 판단한다. 포털이 조회 기간을 따로 받으므로 뺀다.
    """
    kept = []
    for line in (query or "").splitlines():
        stripped = line.strip()
        if TIME_FILTER_RE.match(stripped):
            continue
        kept.append(line)
    out = "\n".join(kept)
    # 한 줄로 붙여 쓴 경우(| where Timestamp > ago(7d) | where ...)도 지운다.
    return TIME_FILTER_INLINE_RE.sub("", out).strip()


def validate_kql(candidate):
    """실행해 볼 수 없으니 형식만 본다 — 붙여넣는 순간 오류가 날 쿼리는 안 내보낸다."""
    query = strip_time_filter(candidate.get("query") or "")
    if query and query != (candidate.get("query") or "").strip():
        candidate["query"] = query      # 화면·복사에 쓰이는 값도 정리된 것으로
    if not query:
        return False, "쿼리 없음", {}
    first = re.split(r"[\s|]+", query, 1)[0].strip()
    if first not in KQL_TABLES:
        return False, "알 수 없는 테이블: {}".format(first[:40]), {}
    if "|" not in query:
        return False, "필터 절이 없음(테이블 전체 조회)", {}
    if ";" in query or chr(0) in query:
        return False, "허용되지 않는 문자 포함", {}
    return True, "", {}


def validate_dork(candidate):
    """검색 연산자 쿼리. 실행해 볼 수 없으니 형식만 본다.

    연산자가 하나도 없으면 그냥 검색어라 dork가 아니다 — 그건 웹 검색 트랙이 할 일이고,
    여기서 내보내면 "탐지 패턴"이라는 이름값을 못 한다.
    """
    query = (candidate.get("query") or "").strip()
    if not query:
        return False, "쿼리 없음", {}
    if not DORK_RE.search(query):
        return False, "검색 연산자가 없음(그냥 검색어)", {}
    # 정상 배포처를 빼지 않으면 결과가 벤더 공식 페이지로 가득 찬다.
    if "-site:" not in query.replace(" ", ""):
        return True, "정상 배포처를 -site:로 빼지 않아 공식 페이지가 섞일 수 있습니다", {}
    return True, "", {}


def validate_vt(candidate):
    """VT Intelligence 검색은 유료 키가 필요해 조회로 확인할 수 없다 — 형식만 본다."""
    query = (candidate.get("query") or "").strip()
    if not query:
        return False, "쿼리 없음", {}
    if not VT_FIELD_RE.search(query):
        return False, "VT 검색 필드가 없음", {}
    # behaviour_files:name:*.png 같은 중첩 형태는 VT가 받지 않는다 — 붙여넣어도
    # 결과가 안 나오므로 내보내지 않는다.
    if NESTED_FIELD_RE.search(query):
        return False, "VT가 받지 않는 중첩 필드 문법", {}
    return True, "", {}


def _query_url(platform, query):
    if platform == "google_dork":
        return GOOGLE_SEARCH_UI_URL.format(urllib.parse.quote(query, safe=""))
    if platform == "urlscan":
        return SEARCH_UI_URL.format(urllib.parse.quote(query, safe=""))
    if platform == "virustotal":
        return VT_SEARCH_UI_URL.format(urllib.parse.quote(query, safe=""))
    return ""


PLATFORM_LABEL = {
    "mde_kql": "MDE 고급 헌팅",
    "urlscan": "urlscan.io",
    "virustotal": "VirusTotal Intelligence",
    "google_dork": "검색 연산자",
}
LINK_LABEL = {
    "urlscan": "urlscan에서 열기",
    "virustotal": "VT에서 열기",
    "google_dork": "구글에서 열기",
}
GOOGLE_SEARCH_UI_URL = "https://www.google.com/search?q={}"


def synthesize(title, analysis, body="", iocs=None, api_key=None, timeout=240,
               targets=None):
    """LLM으로 패턴을 만들고 검증해 통과한 것만 돌려준다.

    반환: {"patterns": [...], "steps": [...], "rejected": [...]}
    patterns는 renderPatternBlock이 그리는 형식과 같다 — 대응 섹션이 손으로 등록한
    패턴과 나란히 보여 준다.
    """
    steps, rejected, out = [], [], []
    prompt = build_prompt(title, analysis, body, iocs, targets)
    raw = common_utils.llm_generate(prompt, timeout=timeout)
    candidates = parse_candidates(raw)
    if not candidates:
        # 같은 입력에도 JSON이 아닌 답이 올 때가 있다(실측: 같은 기사에 6개/0개).
        # 한 번은 더 받아 본다 — 여기서 포기하면 그 기사에는 패턴이 통째로 없다.
        raw = common_utils.llm_generate(
            prompt + "\n\n반드시 JSON 배열만 출력하라.", timeout=timeout)
        candidates = parse_candidates(raw)
    if not candidates:
        steps.append("LLM 패턴 합성: 쓸 수 있는 후보가 나오지 않았습니다.")
        return {"patterns": [], "steps": steps, "rejected": []}

    corpus_norm = _normalize(" ".join(
        [analysis or "", body or ""] +
        [str(item.get("value") or "") for item in (iocs or [])]))

    for candidate in candidates[:8]:
        platform = (candidate.get("platform") or "").strip().lower()
        if platform not in PLATFORMS:
            rejected.append((candidate.get("label") or "?", "알 수 없는 플랫폼"))
            continue

        ok, note = grounded(candidate, corpus_norm)
        if not ok:
            rejected.append((candidate.get("label") or "?", note))
            continue

        if platform == "urlscan":
            ok, reason, facts = validate_urlscan(candidate, api_key=api_key)
        elif platform == "mde_kql":
            ok, reason, facts = validate_kql(candidate)
        elif platform == "google_dork":
            ok, reason, facts = validate_dork(candidate)
        else:
            ok, reason, facts = validate_vt(candidate)
        if not ok:
            rejected.append((candidate.get("label") or "?", reason))
            continue

        query = (candidate.get("query") or "").strip()
        observed = candidate.get("invariant") or ""
        if facts.get("hits"):
            observed = ("urlscan에서 {:,}건 관측{}. ".format(
                facts["hits"],
                "(예: " + ", ".join(facts.get("hosts") or []) + ")"
                if facts.get("hosts") else "") + observed)
        elif platform == "mde_kql":
            observed = "실행 검증은 불가 — 본문 근거와 테이블·문법만 확인했습니다. " + observed
        elif platform == "virustotal":
            observed = "VT Intelligence 검색은 유료 키가 필요합니다(문법만 확인). " + observed
        elif platform == "google_dork":
            observed = ("검색 결과 수는 확인하지 않았습니다(형식과 본문 근거만 확인) — "
                        "링크를 눌러 직접 결과를 보십시오. " + observed)
        # 기사에 없던 값을 보탠 경우 반드시 밝힌다 — 어디까지가 이 기사의 근거인지
        # 구분되지 않으면 쿼리 결과를 잘못 해석한다.
        if note:
            observed = (observed + " " if observed else "") + note + "."

        out.append({
            "label": "{} — {}".format(candidate.get("label") or "패턴",
                                      PLATFORM_LABEL.get(platform, platform)),
            "query": query,
            "url": _query_url(platform, query),
            "linkLabel": LINK_LABEL.get(platform, ""),
            "what": candidate.get("what") or "",
            "why": candidate.get("why") or "",
            "reading": candidate.get("reading") or "",
            "next": candidate.get("next") or "",
            "observed": observed.strip(),
            "source": "ai",
            "confidence": (candidate.get("confidence") or "").lower(),
            "platform": platform,
        })

    steps.append("LLM 패턴 합성: 후보 {}개 중 {}개 채택, {}개 폐기했습니다.".format(
        len(candidates), len(out), len(rejected)))
    for label, reason in rejected[:6]:
        steps.append("· 폐기 \"{}\": {}".format(label[:24], reason))
    return {"patterns": out, "steps": steps,
            "rejected": [{"label": l, "reason": r} for l, r in rejected]}
