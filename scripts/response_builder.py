"""조사 결과를 대응 재료로 바꾼다 — 차단 목록과 MDE 고급 헌팅 쿼리.

조사와 대응은 쓰는 사람이 다르고 쓰는 시점이 다르다. 조사 결과(어느 인프라를 쓰는지,
샌드박스에서 무엇을 했는지)는 읽고 판단하는 것이고, 대응은 그걸 차단 목록과 탐지
쿼리로 바꿔 손에 쥐는 것이다. 그래서 화면에서도 나눠 놓는다.

무엇을 만드는가:
    · 차단 후보 — 기사가 IOC로 제시한 도메인·IP·해시. 이건 바로 넣어도 되는 값이다.
    · 확인 후 판단 — 샌드박스가 관측한 통신처럼 정상 서비스가 섞여 있는 값(실측:
      Atomic Stealer 샘플의 관측 통신에 api.snapcraft.io가 있었다). 분리해서 표시한다.
    · MDE 고급 헌팅 쿼리 — 값 기반(IOC가 바뀌면 죽는다)과 행위 기반(기법이 남는 동안
      유효하다)을 구분해 만든다. 값이 없으면 그 쿼리는 아예 만들지 않는다.

왜 KQL인가:
    자산 인벤토리에 EDR 항목이 없어 어떤 제품을 쓰는지 확정할 수 없지만, 이 캠페인
    보고서가 Microsoft 것이고 권고도 Defender 기준이라 MDE 고급 헌팅을 기본으로 둔다.
    다른 SIEM을 쓰면 테이블·필드 이름만 바꾸면 된다(주석에 대응 관계를 적어 둔다).
"""

import ipaddress
import re

import artifact_extractor
import common_utils
import lure_hunter
import supply_chain_hunter
import vuln_hunter

# 샌드박스 관측 통신에 섞이는 공용 리졸버·정상 서비스. 차단 후보로 올리면 안 된다.
NOISE_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "162.159.36.2", "162.159.46.2",
    "168.63.129.16", "169.254.169.254",
}
NOISE_DOMAIN_RE = re.compile(
    r"(?:^|\.)(?:microsoft\.com|windows\.com|windowsupdate\.com|msftconnecttest\.com|"
    r"msftncsi\.com|snapcraft\.io|ubuntu\.com|canonical\.com|debian\.org|"
    r"digicert\.com|verisign\.com|globalsign\.com|sectigo\.com|letsencrypt\.org|"
    r"google\.com|gstatic\.com|googleapis\.com|apple\.com|icloud\.com|"
    r"cloudflare\.com|akamai\.net|amazonaws\.com|azure\.com|office\.com)$",
    re.I,
)

# CDN·클라우드 뒤에 숨은 유포지의 IP는 그 CDN의 것이다 — 차단하면 정상 사이트가
# 같이 막힌다. 실측: REVSTEALER 유포 도메인의 urlscan page.ip가 172.67.161.55
# (Cloudflare)이었다.
SHARED_HOSTING_RE = re.compile(
    r"cloudflare|akamai|fastly|amazon|aws|google|azure|microsoft|oracle|"
    r"digitalocean|linode|ovh|hetzner|godaddy|hostinger|namecheap|wix|squarespace|"
    r"shopify|cloudfront|incapsula|imperva|sucuri|stackpath|bunny",
    re.I,
)

MAX_VALUES_PER_LIST = 40
MAX_KQL_QUERIES = 10       # 이보다 많으면 아무도 다 안 본다
LOOKBACK = "30d"

# ClickFix 계열 초기 침투 탐지에 쓰는 고정 목록 — 관측값이 아니라 기법 자체다.
UI_PARENTS = ["chrome.exe", "msedge.exe", "firefox.exe", "whale.exe", "iexplore.exe",
              "explorer.exe", "WindowsTerminal.exe", "wt.exe"]
SHELLS = ["powershell.exe", "pwsh.exe", "cmd.exe", "wt.exe", "WindowsTerminal.exe", "mshta.exe"]
DOWNLOAD_MARKERS = ["Invoke-WebRequest", "Invoke-RestMethod", "DownloadString", "DownloadFile",
                    "FromBase64String", "-w hidden", "-WindowStyle Hidden", "-enc ",
                    "EncodedCommand", "curl ", "certutil", "Expand-Archive", "ProgramData"]


def _kql_list(values):
    """KQL dynamic() 리터럴. 큰따옴표만 이스케이프하면 충분하다(값이 경로·해시·도메인)."""
    escaped = ['"{}"'.format(str(value).replace('\\', '\\\\').replace('"', '\\"'))
               for value in values]
    return "dynamic([{}])".format(", ".join(escaped))


def _is_noise_ip(value):
    if value in NOISE_IPS:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return address.is_private or address.is_loopback or address.is_multicast or address.is_reserved


def _collect(block, iocs, text=""):
    """대응에 쓸 값을 모은다. 출처를 구분해 담는다 — 신뢰도가 다르기 때문."""
    seeds = block.get("seeds") or []
    malware = block.get("malware") or {}

    # 도메인은 역할별로 나눠 받는다 — 공용 서비스·Tor·유출 사이트를 차단 후보에 섞으면
    # 정상 서비스를 막거나(공용 RPC), 막을 수도 없는 것(.onion)을 목록에 넣게 된다.
    host_roles = lure_hunter.classify_ioc_hosts(iocs, text=text)

    ioc_domains, ioc_ips, ioc_hashes = [], [], []
    for ioc in iocs or []:
        kind = (ioc.get("type") or "").lower()
        value = (ioc.get("value") or "").strip()
        if not value:
            continue
        if kind in ("sha256", "sha1", "md5"):
            if value.lower() not in ioc_hashes:
                ioc_hashes.append(value.lower())
        elif kind in ("domain", "url"):
            host = value
            if "://" in host:
                from urllib.parse import urlparse
                host = urlparse(host).netloc
            host = host.split("@")[-1].split(":")[0].strip("/.").lower()
            if host and not NOISE_DOMAIN_RE.search(host) and not common_utils.is_benign_ioc("domain", host):
                if host in host_roles["lure"] and host not in ioc_domains:
                    ioc_domains.append(host)
        elif kind in ("ip", "ipv4", "ip-dst", "ip-src"):
            if not _is_noise_ip(value) and value not in ioc_ips:
                ioc_ips.append(value)

    # 유포지 조사에서 확인한 호스팅 IP는 기사 IOC와 같은 급으로 본다(그 페이지가 실제로
    # 그 IP에 있었다는 관측이다).
    shared_hosting = []
    for seed in seeds:
        if seed.get("ip") and not _is_noise_ip(seed["ip"]) and seed["ip"] not in ioc_ips:
            if SHARED_HOSTING_RE.search(seed.get("asnname") or ""):
                # CDN·대형 클라우드 IP는 차단 후보가 아니다 — 도메인으로 막아야 한다.
                shared_hosting.append("{} ({})".format(seed["ip"], seed.get("asnname") or ""))
            else:
                ioc_ips.append(seed["ip"])
        for host in seed.get("cloaked_hosts") or []:
            host = host.lower()
            if host not in ioc_domains and not NOISE_DOMAIN_RE.search(host):
                ioc_domains.append(host)

    # 샌드박스 관측값 — 정상 서비스가 섞이므로 따로 담는다.
    observed_hosts, observed_ips, artifacts = [], [], []
    for file_entry in malware.get("files") or []:
        behaviour = file_entry.get("behaviour") or {}
        # 해석 단계에서 샌드박스 환경 통신을 걷어낸 목록을 쓴다 — 원본 dns 목록을 그대로
        # 쓰면 OS 업데이트·인증서 검사 도메인이 차단 후보로 올라간다.
        view = file_entry.get("interpreted") or {}
        hosts = view.get("hosts") if view else behaviour.get("dns")
        for host in hosts or []:
            host = str(host).strip().lower()
            if host and host not in observed_hosts and host not in ioc_domains:
                observed_hosts.append(host)
        for entry in behaviour.get("ip_traffic") or []:
            ip, _, port = str(entry).partition(":")
            if port == "53" or _is_noise_ip(ip):
                continue
            if ip not in observed_ips and ip not in ioc_ips:
                observed_ips.append(ip)
        for path in (behaviour.get("files_dropped") or []) + (behaviour.get("files_written") or []):
            name = str(path).replace("/", "\\").rsplit("\\", 1)[-1].strip()
            if 4 < len(name) < 60 and name not in artifacts:
                artifacts.append(name)
        for key in behaviour.get("registry") or []:
            name = str(key).replace("/", "\\").rsplit("\\", 1)[-1].strip()
            if 4 < len(name) < 60 and name not in artifacts:
                artifacts.append(name)

    return {
        "public_service": host_roles["public_service"][:MAX_VALUES_PER_LIST],
        "leak_site": host_roles["leak_site"][:MAX_VALUES_PER_LIST],
        "tor": host_roles["tor"][:MAX_VALUES_PER_LIST],
        "shared_hosting": shared_hosting[:10],
        "domains": ioc_domains[:MAX_VALUES_PER_LIST],
        "ips": ioc_ips[:MAX_VALUES_PER_LIST],
        "hashes": ioc_hashes[:MAX_VALUES_PER_LIST],
        "observed_hosts": observed_hosts[:MAX_VALUES_PER_LIST],
        "observed_ips": observed_ips[:MAX_VALUES_PER_LIST],
        "artifacts": artifacts[:20],
    }


def _kql_queries(values, primary):
    """값이 있는 것만 만든다. 값 기반/행위 기반을 구분해 표시한다."""
    queries = []

    if values["domains"] or values["ips"]:
        conditions = []
        header = []
        if values["domains"]:
            header.append("let campaignDomains = {};".format(_kql_list(values["domains"])))
            conditions.append("RemoteUrl has_any (campaignDomains)")
        if values["ips"]:
            header.append("let campaignIPs = {};".format(_kql_list(values["ips"])))
            conditions.append("RemoteIP in (campaignIPs)")
        queries.append({
            "name": "캠페인 인프라와의 통신",
            "durable": False,
            "note": "IOC 기반이라 공격자가 도메인·IP를 바꾸면 죽는다. 히트가 나오면 그 단말은 "
                    "실행까지 갔다고 보고 즉시 격리·조사한다.",
            "query": "\n".join(header + [
                "DeviceNetworkEvents",
                "| where Timestamp > ago({})".format(LOOKBACK),
                "| where {}".format(" or ".join(conditions)),
                "| project Timestamp, DeviceName, InitiatingProcessFileName,",
                "          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort",
                "| order by Timestamp desc",
            ]),
        })

    if values["hashes"]:
        queries.append({
            "name": "캠페인 파일이 단말에 있었는지",
            "durable": False,
            "note": "파일 생성·실행 양쪽을 본다. 변종이 나오면 해시가 바뀌므로 이 쿼리만 "
                    "믿으면 안 된다.",
            "query": "\n".join([
                "let campaignHashes = {};".format(_kql_list(values["hashes"])),
                "union",
                "  (DeviceFileEvents",
                "   | where Timestamp > ago({}) | where SHA256 in~ (campaignHashes)".format(LOOKBACK),
                "   | project Timestamp, DeviceName, Action = ActionType, FileName, FolderPath,",
                "             SHA256, InitiatingProcessFileName),",
                "  (DeviceProcessEvents",
                "   | where Timestamp > ago({}) | where SHA256 in~ (campaignHashes)".format(LOOKBACK),
                '   | project Timestamp, DeviceName, Action = "ProcessCreated", FileName, FolderPath,',
                "             SHA256, InitiatingProcessFileName)",
                "| order by Timestamp desc",
            ]),
        })

    if values["observed_hosts"] or values["observed_ips"]:
        conditions, header = [], []
        if values["observed_hosts"]:
            header.append("let observedHosts = {};".format(_kql_list(values["observed_hosts"])))
            conditions.append("RemoteUrl has_any (observedHosts)")
        if values["observed_ips"]:
            header.append("let observedIPs = {};".format(_kql_list(values["observed_ips"])))
            conditions.append("RemoteIP in (observedIPs)")
        queries.append({
            "name": "샌드박스가 관측한 통신처 (확인 후 사용)",
            "durable": False,
            "note": "샌드박스 실행 중 관측된 목적지라 정상 서비스가 섞여 있을 수 있다. 차단 "
                    "목록에 바로 넣지 말고 이 쿼리로 사내 통신 실태를 먼저 확인한다.",
            "query": "\n".join(header + [
                "DeviceNetworkEvents",
                "| where Timestamp > ago({})".format(LOOKBACK),
                "| where {}".format(" or ".join(conditions)),
                "| summarize Devices = dcount(DeviceName), Hits = count(),",
                "            SampleProcess = any(InitiatingProcessFileName)",
                "          by RemoteUrl, RemoteIP",
                "| order by Hits desc",
            ]),
        })

    if values["artifacts"]:
        queries.append({
            "name": "관측된 파일·레지스트리 흔적",
            "durable": False,
            "note": "샌드박스가 만든 파일 이름과 레지스트리 값 이름이다. 이름을 그대로 쓰는 "
                    "변종에 걸린다.",
            "query": "\n".join([
                "let artifacts = {};".format(_kql_list(values["artifacts"])),
                "union",
                "  (DeviceFileEvents",
                "   | where Timestamp > ago({}) | where FileName has_any (artifacts)".format(LOOKBACK),
                "   | project Timestamp, DeviceName, Table = \"File\", Name = FileName, FolderPath,",
                "             InitiatingProcessFileName),",
                "  (DeviceRegistryEvents",
                "   | where Timestamp > ago({})".format(LOOKBACK),
                "   | where RegistryKey has_any (artifacts) or RegistryValueName has_any (artifacts)",
                "   | project Timestamp, DeviceName, Table = \"Registry\", Name = RegistryValueName,",
                "             FolderPath = RegistryKey, InitiatingProcessFileName)",
                "| order by Timestamp desc",
            ]),
        })

    # 행위 기반 — 값이 바뀌어도 남는다. 사용자 행위 기반 사건에서 특히 중요하다.
    if primary == "user_action" or values["domains"]:
        queries.append({
            "name": "브라우저에서 터미널로 이어지는 명령 실행 (행위 기반)",
            "durable": True,
            "note": "ClickFix 계열의 초기 침투 형태 자체를 본다 — 도메인·해시가 바뀌어도 "
                    "유효하다. 개발자가 설치 스니펫을 붙여넣는 정상 작업도 걸리니, 먼저 "
                    "1~2주 돌려 사내 정상 패턴을 예외 처리한 뒤 알림으로 올린다.",
            "query": "\n".join([
                "let uiParents = {};".format(_kql_list(UI_PARENTS)),
                "let shells = {};".format(_kql_list(SHELLS)),
                "let markers = {};".format(_kql_list(DOWNLOAD_MARKERS)),
                "DeviceProcessEvents",
                "| where Timestamp > ago({})".format(LOOKBACK),
                "| where InitiatingProcessFileName in~ (uiParents)",
                "| where FileName in~ (shells)",
                "| where ProcessCommandLine has_any (markers)",
                "| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,",
                "          FileName, ProcessCommandLine",
                "| order by Timestamp desc",
            ]),
        })

    return queries


def build(block, iocs, primary="", text=""):
    """대응 섹션. 만들 게 없으면 None.

    IOC 목록만 쓰면 대부분의 기사에서 아무것도 못 만든다(실측 31건 중 25건이 IOC 0건).
    분석 본문에 남아 있는 구체값(파일명·확장자·경로·레지스트리)과 문장으로 서술된
    행위(섀도 복사본 삭제, Defender 제외 추가 등)까지 재료로 쓴다.
    """
    values = _collect(block or {}, iocs, text=text)
    found = artifact_extractor.extract(text)
    if not artifact_extractor.has_enough_material(found):
        found = {key: ([] if isinstance(value, list) else value) for key, value in found.items()}
    queries = _kql_queries(values, primary) + artifact_extractor.kql_from_artifacts(found)

    # 이름이 같은 쿼리는 하나만 남기고, 개수는 사람이 훑을 수 있는 선에서 자른다.
    seen, deduped = set(), []
    for query in queries:
        if query["name"] in seen:
            continue
        seen.add(query["name"])
        deduped.append(query)
    queries = deduped[:MAX_KQL_QUERIES]

    blocklists = []
    if values["domains"]:
        blocklists.append({
            "label": "차단 후보 — 도메인",
            "note": "기사가 IOC로 제시한 것과 조사에서 응답을 감춘 것으로 확인된 호스트다. "
                    "프록시·DNS 필터·방화벽(PAN-OS EDL, FortiGate Threat Feed)에 그대로 넣는다.",
            "values": values["domains"],
        })
    if values["ips"]:
        blocklists.append({
            "label": "차단 후보 — IP",
            "note": "유포지가 실제로 올라가 있던 IP다. 공유 호스팅이면 정상 사이트가 같은 IP에 "
                    "있을 수 있으니, 도메인 차단을 우선하고 IP는 함께 쓸 때만 막는다.",
            "values": values["ips"],
        })
    if values["hashes"]:
        blocklists.append({
            "label": "차단 후보 — 파일 해시(SHA-256)",
            "note": "게이트웨이 AV·EDR 차단 목록과 헌팅에 쓴다.",
            "values": values["hashes"],
        })
    if values["public_service"]:
        blocklists.append({
            "label": "차단 금지 — 공용 서비스(악성코드가 경유)",
            "note": "블록체인 RPC·메신저처럼 악성코드가 설정 조회나 협상 채널로 쓴 정상 "
                    "서비스다. 공격자 소유가 아니므로 차단하면 정상 기능만 막힌다. 대신 "
                    "사내에서 이 서비스로 나가는 통신이 업무상 필요한지 점검한다.",
            "values": values["public_service"],
        })
    if values["leak_site"]:
        blocklists.append({
            "label": "모니터링 — 유출 사이트",
            "note": "피해자를 공개하는 블로그다. 차단보다 우리 조직·거래처가 게시됐는지 "
                    "주기적으로 확인하는 것이 목적이다.",
            "values": values["leak_site"],
        })
    if values["tor"]:
        blocklists.append({
            "label": "차단 불가 — Tor 주소",
            "note": "DNS·프록시로 막을 수 없다. 사내 단말에서 Tor 브라우저·클라이언트가 "
                    "실행되는지로 탐지한다.",
            "values": values["tor"],
        })
    if values["shared_hosting"]:
        blocklists.append({
            "label": "차단 금지 — CDN·공용 호스팅 IP",
            "note": "유포지가 이 IP 뒤에 숨어 있지만 IP 자체는 CDN·클라우드 것이다. 막으면 "
                    "정상 사이트가 같이 막힌다 — 도메인으로 차단한다.",
            "values": values["shared_hosting"],
        })
    if values["observed_hosts"] or values["observed_ips"]:
        blocklists.append({
            "label": "확인 후 판단 — 샌드박스 관측 통신처",
            "note": "정상 서비스가 섞여 있을 수 있다(실측: 스틸러 샘플의 관측 통신에 정상 "
                    "업데이트 서버가 포함됐다). 차단하기 전에 아래 KQL로 사내 통신 실태를 본다.",
            "values": values["observed_hosts"] + values["observed_ips"],
        })

    # 본문에서 얻은 값도 목록으로 낸다 — 해시가 없어 VT로 확인할 수 없는 기사에서
    # 유일한 대응 재료가 되는 경우가 많다.
    if found["attacker_files"] or found["extensions"]:
        blocklists.append({
            "label": "차단·헌팅 후보 — 본문에 나온 파일명·확장자",
            "note": "기사가 이름만 알려준 것이다(해시가 없어 VT 대조는 불가). 이름은 쉽게 "
                    "바뀌니 지금 감염된 단말을 찾는 용도로 쓰고, 상시 탐지는 아래 행위 기반 "
                    "쿼리에 맡긴다.",
            "values": found["attacker_files"] + found["extensions"],
        })
    if found["system_files"]:
        blocklists.append({
            "label": "차단 금지 — 악용된 정상 바이너리",
            "note": "OS 구성요소다. 차단하면 시스템이 망가진다 — 이상한 경로에서 실행되는지로 "
                    "봐야 한다(아래 LOLBin 쿼리).",
            "values": found["system_files"],
        })
    if found["paths"] or found["registry"]:
        blocklists.append({
            "label": "점검 위치 — 본문에 나온 경로·레지스트리",
            "note": "감염 단말에서 이 자리를 직접 확인한다. 제거할 때도 이 목록을 쓴다.",
            "values": (found["paths"] + found["registry"])[:MAX_VALUES_PER_LIST],
        })
    if found["repos"]:
        blocklists.append({
            "label": "모니터링 — 배포 채널",
            "note": "공격자가 페이로드를 올린 곳이다. 사내에서 이 저장소·패키지를 내려받은 "
                    "이력이 있는지 확인한다.",
            "values": found["repos"],
        })

    supply_material = supply_chain_hunter.response_material(block.get("supply_chain"))
    vuln_material = vuln_hunter.response_material(block.get("vulnerability"))
    if not blocklists and not queries and not vuln_material and not supply_material:
        return None

    actions = []
    if values["domains"]:
        actions.append("도메인 {}건을 차단하고, 차단 로그에서 이미 접속한 단말을 뽑아 조사 "
                       "대상으로 올린다.".format(len(values["domains"])))
    if values["hashes"]:
        actions.append("해시 {}건을 EDR·게이트웨이 차단 목록에 넣고, 아래 파일 헌팅 쿼리로 "
                       "이미 내려온 단말이 있는지 확인한다.".format(len(values["hashes"])))
    if primary == "user_action":
        actions.append("이 유형은 사용자가 명령을 붙여넣어야 실행된다 — 접속 기록이 있는 "
                       "단말은 실행 여부를 프로세스 로그로 반드시 확인한다. 접속만으로는 "
                       "감염이 아니다.")
    if primary == "malware":
        actions.append("파일이 실행되면 스스로 동작한다 — 실행 흔적이 있는 단말은 지속성"
                       "(예약 작업·Run 키)까지 제거해야 재감염이 끊긴다.")
    if found["behaviours"]:
        actions.append("기사가 서술한 행위 {}가지를 탐지 쿼리로 만들어 뒀다 — IOC가 바뀌어도 "
                       "남는 신호이니 예외 처리 후 상시 탐지로 올리는 것을 권한다: {}."
                       .format(len(found["behaviours"]),
                               ", ".join(b["name"] for b in found["behaviours"][:4])))
    actions.append("값 기반 쿼리는 인프라가 바뀌면 죽는다. 행위 기반 쿼리를 예외 처리한 뒤 "
                   "상시 탐지로 남기는 것이 오래 쓰는 방법이다.")

    # 공급망 재료를 맨 앞에 둔다 — 이 축이 주력인 기사에서 가장 먼저 볼 것이 "무엇이
    # 우리 쪽에 들어왔나"이기 때문이다.
    commands = []
    if supply_material:
        blocklists = supply_material["blocklists"] + blocklists
        queries = (supply_material["kql"] + queries)[:MAX_KQL_QUERIES]
        actions = supply_material["actions"] + actions
        # 단말에서 직접 도는 명령이라 KQL과 섞지 않는다 — 붙여넣는 곳이 다르다.
        commands = supply_material.get("commands") or []

    # 취약점 재료는 맨 앞에 둔다 — 취약점 기사에서 가장 먼저 봐야 하는 것이 패치
    # 우선순위와 노출 자산이다.
    if vuln_material:
        blocklists = vuln_material["blocklists"] + blocklists
        queries = (vuln_material["kql"] + queries)[:MAX_KQL_QUERIES]
        actions = vuln_material["actions"] + actions

    return {"blocklists": blocklists, "kql": queries, "actions": actions,
            "commands": commands, "generated_at": common_utils.utc_now_iso()}
