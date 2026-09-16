"""분석 본문에서 대응에 쓸 구체값을 뽑는다 — IOC 목록이 비어도 대응이 나오게.

왜 필요한가:
    대응(차단 목록·탐지 쿼리)을 IOC 목록만으로 만들면 대부분의 기사에서 아무것도
    나오지 않는다. 실측: 저장된 심층분석 31건 중 25건이 IOC 0건이다(기사에 지표를
    싣지 않는 짧은 뉴스가 많다). 그런데 LLM이 정리한 본문에는 쓸 수 있는 값이 남아
    있다 — 실측 4건에서 배포 파일명 14개, 확장자 1개, 명령 10개, 행위 단서 14개가
    나왔다. "Fake Claude Opus 5" 기사는 IOC가 0건인데 본문에
    ClaudeOpus5-desktop.zip과 "AppData를 Defender 제외 목록에 추가"가 있다 — 후자는
    정상 업무에서 거의 없는 고신뢰 탐지 지점이다.

무엇을 구분하는가:
    · 공격자 파일 — 차단·헌팅 대상
    · 악용된 정상 바이너리(LOLBin) — 차단하면 OS가 망가진다. "이 바이너리가 이상한
      경로/부모에서 뜨는지"로 봐야 한다. 실측: 본문에서 뽑힌 파일명에
      svchost.exe·ntdll.dll·nslookup.exe·CMSTP.exe·LockScreenContentServer.exe가
      섞여 있었다 — 전부 정상 Windows 구성요소다.
    · 행위 단서 — 문장으로만 있는 것(예: 섀도 복사본 삭제)을 탐지 쿼리로 바꾼다.
"""

import re

BS = chr(92)  # 정규식 리터럴 백슬래시(편집 중 개수가 어긋나는 것을 막는다)

FILE_RE = re.compile(
    r"[" + BS + r"w.\-]{3,60}" + BS + r".(?:exe|dll|sys|bat|cmd|ps1|psm1|vbs|js|jse|hta|scr|"
    r"msi|lnk|zip|rar|7z|iso|img|py|jar|apk|dmg|pkg|chm|inf|reg)(?![A-Za-z0-9_])", re.I)
PATH_RE = re.compile(
    r"(?:[A-Za-z]:" + BS + BS + r"|%[A-Za-z]+%" + BS + BS + r"|/(?:usr|tmp|etc|opt|var)/)"
    r"[^" + BS + r"s`'" + '"' + r"*()]{3,90}")
REGISTRY_RE = re.compile(r"HK(?:LM|CU|CR|U|EY_[A-Z_]+)[" + BS + BS + r"/][^" + BS + r"s`'" + '"' + r"*()]{3,90}")
EXTENSION_RE = re.compile(
    r"" + BS + r".([a-z0-9]{3,10})(?=" + BS + r"s*(?:확장자|파일로|로 변경|로 바꾸|를 붙))", re.I)
REPO_RE = re.compile(
    r"(?:github|gitlab|bitbucket|npm|pypi|vscode\s*marketplace)[^" + BS + r"s`*]{0,6}"
    r"[" + BS + r"w./\-]{3,60}", re.I)

# 정상 Windows 구성요소·상용 도구. 차단 목록에 올리면 사고가 난다.
SYSTEM_BINARIES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "svchost.exe", "explorer.exe", "ntdll.dll",
    "kernel32.dll", "user32.dll", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe", "nslookup.exe", "cmstp.exe", "schtasks.exe",
    "wevtutil.exe", "wevtapi.dll", "vssadmin.exe", "attrib.exe", "wscript.exe",
    "cscript.exe", "msiexec.exe", "wmic.exe", "forfiles.exe", "conhost.exe",
    "taskkill.exe", "net.exe", "netsh.exe", "reg.exe", "sc.exe", "wusa.exe",
    "fodhelper.exe", "computerdefaults.exe", "dllhost.exe", "wbengine.exe",
    "lockscreencontentserver.exe", "dui70.dll", "python.exe", "pythonw.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "odbcconf.exe",
    "control.exe", "mmc.exe", "werfault.exe", "searchindexer.exe", "onedrive.exe",
    "msmpeng.exe", "securityhealthservice.exe", "wuauclt.exe", "taskhostw.exe",
}
# 너무 흔해서 그 자체로는 탐지가 안 되는 이름 — 참고로만 남긴다.
GENERIC_FILENAMES = {"1.bat", "a.exe", "setup.exe", "install.exe", "update.exe",
                     "main.py", "client.py", "server.py", "test.exe", "temp.exe"}

# 문장으로만 서술된 행위를 탐지 쿼리로 바꾼다. (이름, 본문 패턴, KQL 본문, 설명)
BEHAVIOUR_RULES = [
    ("Defender 제외 경로 추가",
     r"defender\s*제외|제외\s*목록|exclusionpath|add-mppreference|set-mppreference",
     ["DeviceProcessEvents",
      "| where Timestamp > ago(30d)",
      '| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference", "ExclusionPath",',
      '                                    "ExclusionExtension", "ExclusionProcess")',
      "| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine",
      "| order by Timestamp desc"],
     "정상 업무에서 거의 나오지 않는다. 히트가 있으면 그 단말을 우선 조사한다."),
    ("볼륨 섀도 복사본 삭제",
     r"섀도\s*복사본|shadow\s*cop|vssadmin|wbadmin|bcdedit.*recovery",
     ["DeviceProcessEvents",
      "| where Timestamp > ago(30d)",
      '| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe", "powershell.exe")',
      '| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "delete catalog",',
      '                                    "recoveryenabled no", "Win32_Shadowcopy")',
      "| project Timestamp, DeviceName, FileName, ProcessCommandLine",
      "| order by Timestamp desc"],
     "랜섬웨어가 암호화 직전에 하는 동작이다 — 탐지되면 이미 실행 단계다. 즉시 격리."),
    ("이벤트 로그 삭제·무력화",
     r"이벤트\s*로그.*(?:삭제|무력화|비활성)|wevtutil|clear-eventlog|winevt.*channels",
     ["union",
      '  (DeviceProcessEvents | where Timestamp > ago(30d)',
      '   | where ProcessCommandLine has_any ("wevtutil cl", "wevtutil clear-log", "Clear-EventLog",',
      '                                       "Remove-EventLog")',
      '   | project Timestamp, DeviceName, Signal = "명령", Detail = ProcessCommandLine),',
      '  (DeviceRegistryEvents | where Timestamp > ago(30d)',
      '   | where RegistryKey has "WINEVT" and RegistryValueName =~ "Enabled"',
      '   | project Timestamp, DeviceName, Signal = "레지스트리", Detail = RegistryKey)',
      "| order by Timestamp desc"],
     "로그를 지우는 것 자체가 침해 증거다. 채널 비활성화(레지스트리)까지 같이 본다."),
    ("예약 작업 등록",
     r"예약\s*작업|schtasks|scheduled\s*task|register-scheduledtask",
     ["DeviceProcessEvents",
      "| where Timestamp > ago(30d)",
      '| where (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create")',
      '   or ProcessCommandLine has "Register-ScheduledTask"',
      '| where ProcessCommandLine has_any ("AppData", "ProgramData", "Temp", "Public")',
      "| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
      "| order by Timestamp desc"],
     "사용자 쓰기 가능 경로를 실행하는 예약 작업만 골라 본다 — 정상 소프트웨어와 갈린다."),
    ("UAC 우회",
     r"uac\s*우회|bypass\s*uac|권한\s*상승.*(?:우회|프롬프트)|fodhelper|cmstp|computerdefaults",
     ["DeviceProcessEvents",
      "| where Timestamp > ago(30d)",
      '| where InitiatingProcessFileName in~ ("fodhelper.exe", "computerdefaults.exe",',
      '                                       "cmstp.exe", "sdclt.exe", "eventvwr.exe",',
      '                                       "slui.exe", "wsreset.exe")',
      "| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine",
      "| order by Timestamp desc"],
     "이 바이너리들이 무언가를 실행하는 것은 대부분 UAC 우회다. 차단이 아니라 감시 대상."),
    ("브라우저 자격증명 탈취",
     r"app-?bound|login\s*data|local\s*state|"
     r"브라우저.{0,20}(?:자격\s*증명|비밀번호|쿠키).{0,12}(?:탈취|수집|훔치|유출|접근)|"
     r"(?:자격\s*증명|비밀번호|쿠키).{0,12}(?:탈취|수집|훔치|유출)|"
     r"(?:steal|dump|exfiltrat)\w*\s+(?:browser\s+)?(?:credential|cookie|password)",
     ["DeviceFileEvents",
      "| where Timestamp > ago(30d)",
      '| where FileName in~ ("Login Data", "Local State", "Cookies", "Web Data",',
      '                      "logins.json", "key4.db", "key3.db")',
      '| where not(InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe",',
      '                                           "whale.exe", "brave.exe", "opera.exe"))',
      "| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath",
      "| order by Timestamp desc"],
     "브라우저가 아닌 프로세스가 자격증명 저장소를 여는 것만 남긴다 — 스틸러의 공통 동작이다."),
    ("암호화폐 지갑 탈취",
     r"(?:지갑|wallet).{0,14}(?:탈취|수집|접근|훔치|유출|steal|theft|drain|exfiltrat)|"
     r"(?:탈취|수집|훔치).{0,10}(?:지갑|wallet)|니모닉|mnemonic|seed\s*phrase|"
     r"crypto\s*wallet|wallet\.dat",
     ["DeviceFileEvents",
      "| where Timestamp > ago(30d)",
      '| where FolderPath has_any ("Ethereum", "Exodus", "Electrum", "Ledger Live", "Atomic",',
      '                            "Coinbase", "MetaMask", "wallet.dat", "keystore")',
      '| where ActionType in ("FileCreated", "FileModified", "FileRenamed")',
      "| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath",
      "| order by Timestamp desc"],
     "지갑 폴더에 접근하는 프로세스를 본다. 정상 지갑 앱은 자기 폴더만 만지므로 구분된다."),
    ("자기 삭제",
     r"자기\s*삭제|self-?delete|흔적을\s*지우|스스로\s*삭제",
     ["DeviceProcessEvents",
      "| where Timestamp > ago(30d)",
      '| where ProcessCommandLine has_any ("del %~f0", "del \\"%~f0\\"", "-Command Remove-Item",',
      '                                    "timeout /t", "ping -n") ',
      '| where ProcessCommandLine has_any ("del ", "Remove-Item", "erase ")',
      "| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine",
      "| order by Timestamp desc"],
     "실행 후 자신을 지우는 패턴이다. 오탐이 있으니 다른 신호와 함께 볼 것."),
    ("Windows Update·보안 서비스 중지",
     r"windows\s*update.*(?:무력화|중지|비활성)|wuauserv|windefend|백신\s*무력화|"
     r"보안\s*서비스.*(?:중지|비활성)",
     ["DeviceProcessEvents",
      "| where Timestamp > ago(30d)",
      '| where ProcessCommandLine has_any ("wuauserv", "windefend", "WinDefend", "MsMpEng",',
      '                                    "SecurityHealthService", "sppsvc")',
      '| where ProcessCommandLine has_any ("stop", "disabled", "delete", "config")',
      "| project Timestamp, DeviceName, FileName, ProcessCommandLine",
      "| order by Timestamp desc"],
     "보안 제품을 끄는 동작이다. 히트는 거의 전부 침해이거나 관리자 실수다."),
]

MAX_ITEMS = 12


HANGUL_TAIL_RE = re.compile(r"[가-힣]+$")


DECOR_CHARS = "`*'" + chr(34) + "()[]，,"


# 기사가 값 대신 쓰는 자리표시자. 그대로 차단 목록이나 헌팅 쿼리에 넣으면 영원히
# 안 맞는다 — 실측(2026-09-17): DeadLock 건에서 "C:\ProgramData\<UID>.bmp"가
# 차단 대상 값으로 들어갔다.
#
# 꺾쇠는 그 자체로 판정 근거가 된다. 윈도우 파일명에 < > 는 쓸 수 없으므로, 경로에
# 들어 있으면 실제 값일 수가 없다. 대괄호·중괄호는 파일명에 쓸 수 있어서 안쪽 낱말이
# 자리표시자로 흔히 쓰는 말일 때만 본다.
PLACEHOLDER_WORDS = {
    "uid", "guid", "id", "random", "rand", "n", "x", "xx", "xxx", "xxxx",
    "username", "user", "victim", "hostname", "computername", "hash", "sha256",
    "md5", "timestamp", "date", "number", "숫자", "임의", "사용자명", "사용자",
}
BRACKETED_RE = re.compile(r"[" + BS + r"[{]([^" + BS + r"]}]{1,20})[" + BS + r"]}]")


def has_placeholder(value):
    """값이 아니라 자리표시자인가."""
    text = str(value or "")
    if "<" in text or ">" in text:
        return True
    for inner in BRACKETED_RE.findall(text):
        if inner.strip().lower().strip("._-") in PLACEHOLDER_WORDS:
            return True
    return False


def _clean(value):
    """앞뒤 장식과 뒤에 붙은 한글 조사를 떼어낸다("...df4e에" -> "...df4e").

    조사를 뗀 뒤에 한 번 더 떼는 이유: 장식을 먼저 떼면 조사에 가려져 있던 구두점이
    그대로 남는다. 실측(2026-09-17) — 본문의 "…DefaultIcon(기본값)에"에서 값이
    "…DefaultIcon(" 으로 나와, 레지스트리 헌팅 쿼리가 맞을 수 없는 문자열을 찾았다.
    """
    text = str(value or "").strip().strip(DECOR_CHARS)
    text = HANGUL_TAIL_RE.sub("", text).rstrip(".,·")
    return text.strip(DECOR_CHARS).rstrip(".,·")


def extract(text):
    """분석 본문에서 대응 재료를 뽑는다."""
    text = str(text or "")
    attacker_files, system_files, generic_files = [], [], []
    for match in FILE_RE.findall(text):
        name = _clean(match)
        lowered = name.lower()
        if not name or len(name) < 5:
            continue
        bucket = (system_files if lowered in SYSTEM_BINARIES
                  else generic_files if lowered in GENERIC_FILENAMES
                  else attacker_files)
        if name not in bucket and not has_placeholder(name):
            bucket.append(name)

    extensions = []
    for match in EXTENSION_RE.findall(text):
        value = "." + match.lower()
        if value not in extensions and len(match) >= 3:
            extensions.append(value)

    paths = [p for p in {_clean(m) for m in PATH_RE.findall(text)}
             if p and not has_placeholder(p)]
    registry = [p for p in {_clean(m) for m in REGISTRY_RE.findall(text)}
                if p and not has_placeholder(p)]
    repos = [p for p in {_clean(m) for m in REPO_RE.findall(text)} if "/" in p or "." in p]

    behaviours = []
    for name, pattern, query_lines, note in BEHAVIOUR_RULES:
        if re.search(pattern, text, re.I):
            behaviours.append({"name": name, "query": "\n".join(query_lines), "note": note})

    return {
        "attacker_files": sorted(attacker_files)[:MAX_ITEMS],
        "system_files": sorted(system_files)[:MAX_ITEMS],
        "generic_files": sorted(generic_files)[:6],
        "extensions": extensions[:6],
        "paths": sorted(paths)[:MAX_ITEMS],
        "registry": sorted(registry)[:MAX_ITEMS],
        "repos": sorted(repos)[:6],
        "behaviours": behaviours,
    }


def has_enough_material(found):
    """대응을 만들 만큼 재료가 있는가.

    구체값(파일명·경로·확장자·레지스트리)이 하나도 없고 행위 단서도 한 갈래뿐이면
    낱말 하나에 걸린 것일 가능성이 크다 — 실측: "지갑" 한 단어로 지갑 탈취 쿼리만
    붙은 기사가 3건 있었다. 그런 블록은 도움이 되지 않으니 만들지 않는다.
    """
    concrete = (len(found["attacker_files"]) + len(found["paths"]) + len(found["registry"])
                + len(found["extensions"]) + len(found["repos"]) + len(found["system_files"]))
    return concrete > 0 or len(found["behaviours"]) >= 2


def kql_from_artifacts(found):
    """뽑은 값으로 만드는 탐지 쿼리. 값이 없는 쿼리는 만들지 않는다."""
    from response_builder import _kql_list, LOOKBACK

    if not has_enough_material(found):
        return []
    queries = []
    names = found["attacker_files"] + found["extensions"]
    if names:
        queries.append({
            "name": "본문에 나온 파일명·확장자가 단말에 있는지",
            "durable": False,
            "note": "기사가 이름만 알려준 경우다(해시가 없어 VT로는 확인할 수 없다). 이름이 "
                    "바뀌면 죽는 쿼리지만, 지금 감염된 단말을 찾는 데는 바로 쓸 수 있다.",
            "query": "\n".join([
                "let artifactNames = {};".format(_kql_list(names)),
                "union",
                "  (DeviceFileEvents | where Timestamp > ago({})".format(LOOKBACK),
                "   | where FileName has_any (artifactNames)",
                '   | project Timestamp, DeviceName, Source = "파일", Name = FileName, FolderPath,',
                "             InitiatingProcessFileName),",
                "  (DeviceProcessEvents | where Timestamp > ago({})".format(LOOKBACK),
                "   | where FileName has_any (artifactNames) or ProcessCommandLine has_any (artifactNames)",
                '   | project Timestamp, DeviceName, Source = "실행", Name = FileName, FolderPath,',
                "             InitiatingProcessFileName)",
                "| order by Timestamp desc",
            ]),
        })

    if found["system_files"]:
        queries.append({
            "name": "악용된 정상 바이너리가 이상한 경로에서 실행되는지",
            "durable": True,
            "note": "차단 대상이 아니다(OS 구성요소다). 정상 위치가 아닌 곳에서 실행되거나 "
                    "사용자 폴더에서 뜨는 경우만 걸러 본다 — 사이드로딩·LOLBin 남용이 그렇게 보인다.",
            "query": "\n".join([
                "let abusedBinaries = {};".format(_kql_list(found["system_files"])),
                "DeviceProcessEvents",
                "| where Timestamp > ago({})".format(LOOKBACK),
                "| where FileName has_any (abusedBinaries)",
                '| where FolderPath has_any ("\\\\AppData\\\\", "\\\\ProgramData\\\\", "\\\\Temp\\\\",',
                '                            "\\\\Users\\\\Public\\\\", "\\\\Downloads\\\\")',
                "| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,",
                "          InitiatingProcessFileName",
                "| order by Timestamp desc",
            ]),
        })

    if found["registry"] or found["paths"]:
        values = (found["registry"] + found["paths"])[:MAX_ITEMS]
        queries.append({
            "name": "본문에 나온 경로·레지스트리 키 흔적",
            "durable": False,
            "note": "기사가 특정한 위치다. 그 자리에 무언가 생겼는지로 감염 단말을 찾는다.",
            "query": "\n".join([
                "let locations = {};".format(_kql_list(values)),
                "union",
                "  (DeviceFileEvents | where Timestamp > ago({})".format(LOOKBACK),
                "   | where FolderPath has_any (locations)",
                '   | project Timestamp, DeviceName, Kind = "파일", Detail = FolderPath,',
                "             InitiatingProcessFileName),",
                "  (DeviceRegistryEvents | where Timestamp > ago({})".format(LOOKBACK),
                "   | where RegistryKey has_any (locations)",
                '   | project Timestamp, DeviceName, Kind = "레지스트리", Detail = RegistryKey,',
                "             InitiatingProcessFileName)",
                "| order by Timestamp desc",
            ]),
        })

    for behaviour in found["behaviours"]:
        queries.append({
            "name": behaviour["name"],
            "durable": True,
            "note": behaviour["note"],
            "query": behaviour["query"],
        })
    return queries
