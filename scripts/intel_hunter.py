# -*- coding: utf-8 -*-
"""같은 IOC를 다른 인텔리전스에서 교차 조회한다.

무엇이 빠져 있었나
    지표 종류마다 정해진 한 곳만 봤다 — 도메인은 urlscan, 해시는 VirusTotal, CVE는
    NVD. 그래서 "다른 연구자가 이 지표에 대해 무엇을 발표했나", "이 IP가 실제로
    무엇인가"를 물어본 적이 없었다. 조사가 아니라 조회 한 번이었다.

    그 한계가 실측으로 드러났다. Magento 건에서 종합 판단이 "185.125.188.55가 실제 C2
    인프라인지"를 남은 질문으로 적었다. OTX와 Shodan에 물어보니 ASN이 canonical group
    limited이고 호스트명이 api.snapcraft.io·api.charmhub.io였다 — Ubuntu 인프라이고
    C2가 아니다. 한 번의 조회로 답이 나오는 질문을 미확인으로 남기고 있었다.

무엇을 조회하나
    OTX(AlienVault)  — 이 지표를 담은 커뮤니티 보고서(pulse)와 그 참고 링크, 악성코드
                       패밀리·행위자 귀속. "다른 곳에서 뭐라고 했나"가 여기 있다.
    Shodan InternetDB — IP의 열린 포트·호스트명·알려진 취약점. 정상 서비스인지 공격자
                       인프라인지 가르는 데 이만큼 값싼 신호가 없다.
    RDAP             — 도메인 등록일·등록기관. urlscan의 domainAgeDays보다 원본에 가깝다.
    abuse.ch         — URLhaus·ThreatFox. 신고 기반이라 OTX와 답하는 질문이 다르다.
                       OTX는 "누가 이 지표를 보고서에 실었나", abuse.ch는 "이것이 실제
                       유포지·악성 파일로 신고됐고 지금도 살아 있나"를 답한다. URL을
                       물어보면 그 URL이 떨군 파일 해시까지 돌려주므로, 기사에 해시가
                       없어도 샌드박스 조회로 이어갈 수 있다. (abusech 참고)

    OTX·Shodan·RDAP는 키가 필요 없다(실측 2026-09-10). abuse.ch는 통합 키가 있어야
    하고 없으면 그 부분만 실패로 남는다 — 트랙 전체가 죽지는 않는다. OTX는 응답이
    크고 느려서 타임아웃을 넉넉히 준다.

pulse 참고 링크가 다음 단계로 이어진다
    pulse에 달린 참고 링크는 벤더·연구팀 원문이다. 그것을 primary_sources로 넘기면
    "공개 웹에서 이 IOC에 대해 쓴 글을 찾아 읽는" 흐름이 완성된다.
"""

import json
import time
import urllib.parse
import urllib.request

import abusech
import common_utils
import research_entities

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/{}/{}/general"
SHODAN_URL = "https://internetdb.shodan.io/{}"
RDAP_URL = "https://rdap.org/domain/{}"

# OTX 응답은 수십만 자까지 온다 — 넉넉히 기다리되 지표 수를 줄인다.
OTX_TIMEOUT = 60
# 큰 응답이 읽는 중에 끊기는 일이 잦아 한 번은 다시 받아 본다.
OTX_ATTEMPTS = 2
OTHER_TIMEOUT = 20
PAUSE_SECONDS = 2.0
# 지표 종류별 조회 상한. 전부 돌리면 기사 하나에 수 분이 더 든다.
MAX_PER_KIND = 2
MAX_PULSES = 4
MAX_REFERENCES = 4

# OTX 지표 종류 이름
OTX_KINDS = {"domain": "domain", "ip": "IPv4", "sha256": "file",
             "sha1": "file", "md5": "file"}


def log(message):
    print(message)


def _get_json(url, timeout=OTHER_TIMEOUT):
    request = urllib.request.Request(url, headers={
        "User-Agent": "boannews-intel/1.0 (threat research)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _try(url, timeout=OTHER_TIMEOUT, label="", attempts=1):
    """실패하면 지정 횟수만큼 다시 받아 본다.

    OTX 응답은 200KB를 넘어 읽는 중에 끊기는 일이 잦다(실측: 해시 3건 중 1건이
    타임아웃으로 비었다). 한 번 더 받으면 대개 들어온다.
    """
    last = ""
    for attempt in range(1, attempts + 1):
        try:
            return _get_json(url, timeout=timeout)
        except Exception as error:
            last = str(error)[:60]
            if attempt < attempts:
                time.sleep(PAUSE_SECONDS)
    log("    [-] {} 조회 실패({}회 시도): {}".format(label or url[:40], attempts, last))
    return None


def otx(kind, value):
    """OTX 조회. 다른 곳에서 이 지표를 뭐라고 했는지가 pulse에 있다."""
    otx_kind = OTX_KINDS.get(kind)
    if not otx_kind:
        return None
    data = _try(OTX_URL.format(otx_kind, urllib.parse.quote(str(value))),
                timeout=OTX_TIMEOUT, label="OTX {}".format(value[:24]),
                attempts=OTX_ATTEMPTS)
    if not isinstance(data, dict):
        return None
    info = data.get("pulse_info") or {}
    related = (info.get("related") or {}).get("alienvault") or {}
    pulses, references = [], []
    for pulse in (info.get("pulses") or [])[:MAX_PULSES]:
        if not isinstance(pulse, dict):
            continue
        pulses.append({
            "name": " ".join(str(pulse.get("name") or "").split())[:120],
            "created": (pulse.get("created") or "")[:10],
            "tags": [str(t) for t in (pulse.get("tags") or [])][:5],
        })
        for ref in pulse.get("references") or []:
            ref = str(ref)
            # csv 파일명 같은 것이 참고 링크에 섞여 온다 — 읽을 수 있는 주소만 남긴다.
            if ref.startswith("http") and ref not in references:
                references.append(ref)
    return {
        "count": info.get("count") or 0,
        "pulses": pulses,
        "references": references[:MAX_REFERENCES],
        "malware_families": [str(x) for x in (related.get("malware_families") or [])][:5],
        "adversary": [str(x) for x in (related.get("adversary") or [])][:5],
        "reputation": data.get("reputation"),
        "asn": " ".join(str(data.get("asn") or "").split()) or "",
        "country": data.get("country_name") or "",
    }


def shodan(ip):
    """열린 포트·호스트명·알려진 취약점. 정상 서비스인지 가르는 데 쓴다."""
    data = _try(SHODAN_URL.format(urllib.parse.quote(str(ip))), label="Shodan {}".format(ip))
    if not isinstance(data, dict):
        return None
    return {
        "ports": data.get("ports") or [],
        "hostnames": [str(h) for h in (data.get("hostnames") or [])][:6],
        "vulns": [str(v) for v in (data.get("vulns") or [])][:6],
        "cpes": [str(c) for c in (data.get("cpes") or [])][:6],
    }


def rdap(domain):
    """등록일·등록기관. urlscan의 나이 추정보다 원본에 가깝다."""
    data = _try(RDAP_URL.format(urllib.parse.quote(str(domain))),
                label="RDAP {}".format(domain))
    if not isinstance(data, dict):
        return None
    registered = ""
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            registered = str(event.get("eventDate") or "")[:10]
            break
    registrar = ""
    for entity in data.get("entities") or []:
        roles = (entity.get("roles") or []) if isinstance(entity, dict) else []
        if "registrar" in roles:
            for item in entity.get("vcardArray") or []:
                if isinstance(item, list):
                    for field in item:
                        if isinstance(field, list) and field and field[0] == "fn":
                            registrar = str(field[-1])[:60]
            break
    return {"registered": registered, "registrar": registrar}


def _pick(iocs, kinds):
    out = []
    for item in iocs or []:
        kind = (item.get("type") or "").lower()
        value = (item.get("value") or "").strip()
        if kind in kinds and value and value not in out:
            out.append(value)
        if len(out) >= MAX_PER_KIND:
            break
    return out


def analyze(iocs=None, targets=None):
    """교차 조회 트랙. 볼 지표가 없으면 None.

    반환에 references를 실어 보낸다 — 그 링크들이 1차 자료 수집의 입력이 된다.
    """
    domains = _pick(iocs, {"domain"})
    ips = _pick(iocs, {"ip", "ipv4", "ip-dst", "ip-src"})
    hashes = _pick(iocs, {"sha256", "sha1", "md5"})
    # URL은 예전에 교차 조회 대상이 아니었다. urlscan이 페이지 모양을 보는 것으로
    # 끝냈기 때문인데, "이 주소가 유포지로 신고됐나"는 다른 질문이고 답하는 곳도
    # 다르다(URLhaus).
    urls = _pick(iocs, {"url"})
    if not (domains or ips or hashes or urls):
        return None

    findings, steps, references, named_ips = [], [], [], []
    # URLhaus가 URL에서 알려 준 페이로드 해시. 기사에 없던 해시라도 여기서 나오면
    # 샌드박스·VirusTotal 조회로 이어진다.
    discovered = []

    def cross_check(kind, value):
        """abuse.ch에 같은 값을 물어본다. 키가 없거나 거부되면 그 사실만 남는다."""
        if not abusech.available():
            return
        try:
            result = abusech.describe(kind, value)
        except Exception as error:
            steps.append("abuse.ch 조회 중 오류가 나 이 지표는 건너뜁니다 — {}.".format(
                str(error)[:80]))
            return
        steps.extend(result["steps"])
        findings.extend(result["findings"])
        references.extend(result["references"])
        for value_hash in result["hashes"]:
            if value_hash not in discovered:
                discovered.append(value_hash)

    for value in urls:
        cross_check("url", value)

    for value in hashes:
        result = otx("sha256", value)
        time.sleep(PAUSE_SECONDS)
        if not result:
            steps.append("해시 {}를 OTX에 물었지만 응답을 받지 못했습니다.".format(value[:16]))
            continue
        steps.append("해시 {}를 OTX에 조회했습니다 — 이 지표를 담은 커뮤니티 보고서를 "
                     "찾으려는 것입니다.".format(value[:16]))
        if result["count"]:
            findings.append(
                "해시 {}는 OTX 커뮤니티 보고서 {}건에 실려 있습니다{}. 우리만 보고 있는 "
                "것이 아니라는 뜻이라, 기사 밖의 분석을 함께 읽을 수 있습니다.".format(
                    value[:16], result["count"],
                    " — 귀속: " + ", ".join(result["malware_families"])
                    if result["malware_families"] else ""))
            for pulse in result["pulses"][:2]:
                findings.append("· 보고서 \"{}\"({}) · 태그 {}".format(
                    pulse["name"], pulse["created"] or "?", ", ".join(pulse["tags"][:3])))
        else:
            findings.append(
                "해시 {}는 OTX에 등록된 보고서가 없습니다 — 아직 공개 분석이 없는 "
                "것이라, 기사 외에 참고할 자료가 없다는 뜻입니다.".format(value[:16]))
        references.extend(result["references"])
        cross_check("sha256", value)

    for value in ips:
        result = otx("ip", value)
        time.sleep(PAUSE_SECONDS)
        exposure = shodan(value)
        time.sleep(PAUSE_SECONDS)
        steps.append("IP {}를 OTX와 Shodan InternetDB에 조회했습니다 — 공격자 인프라인지 "
                     "정상 서비스인지 가르려는 것입니다.".format(value))
        if exposure and exposure.get("hostnames"):
            named_ips.append({"ip": value,
                              "hostnames": exposure["hostnames"][:4],
                              "asn": (result or {}).get("asn") or ""})
        parts = []
        if result and result.get("asn"):
            parts.append("ASN {}".format(result["asn"]))
        if exposure and exposure.get("hostnames"):
            parts.append("호스트명 {}".format(", ".join(exposure["hostnames"][:3])))
        if exposure and exposure.get("ports"):
            parts.append("열린 포트 {}".format(", ".join(str(p) for p in exposure["ports"][:6])))
        if parts:
            findings.append("IP {} — {}.".format(value, " / ".join(parts)))
            # 호스트명이 붙어 있으면 정상 서비스일 가능성이 크다. 차단 판단이 갈린다.
            if exposure and exposure.get("hostnames"):
                findings.append("· 역방향 호스트명이 붙어 있어 공격자가 급히 띄운 서버가 "
                                "아니라 운영 중인 서비스로 보입니다 — 차단 전에 무엇인지 "
                                "확인해야 합니다.")
        if exposure and exposure.get("vulns"):
            findings.append("· Shodan이 이 IP에서 알려진 취약점 {}건을 표시합니다({}).".format(
                len(exposure["vulns"]), ", ".join(exposure["vulns"][:3])))
        if result:
            references.extend(result["references"])
        cross_check("ip", value)

    # 개별 콘텐츠 URL(chatgpt.com/g/...)이 도메인 칸에 들어오면 RDAP가 404를 낸다. 호스트로
    # 바꾸고, 공용 플랫폼은 등록일이 캠페인과 무관하므로 조회하지 않는다.
    hosts = []
    for value in domains:
        host = common_utils.host_from_indicator(value) or str(value)
        if host and host not in hosts and not research_entities.shared(host):
            hosts.append(host)
    for value in hosts:
        registration = rdap(value)
        time.sleep(PAUSE_SECONDS)
        if registration and registration.get("registered"):
            steps.append("도메인 {}의 등록 정보를 RDAP에서 조회했습니다.".format(value))
            findings.append("도메인 {}은 {}에 등록됐습니다{}.".format(
                value, registration["registered"],
                " (등록기관 " + registration["registrar"] + ")"
                if registration.get("registrar") else ""))
        cross_check("domain", value)

    # 조회가 전부 실패했으면 findings는 비지만 steps에 실패가 남는다. 그때도 돌려줘야
    # "못 물어봤다"가 화면에 남는다 — 안 물어본 것과 등재가 없는 것은 다르다.
    if not (findings or steps):
        return None
    seen, unique_refs = set(), []
    # named_ips는 차단 판단으로 넘어간다. "정상이다"라고 단정하지 않는다 — 공격자도
    # 역방향 DNS를 붙일 수 있다. 다만 확인 없이 막으면 안 되는 대상이다(실측:
    # 기사가 C2로 지목한 99.84.67.186이 sellingpartnerapi-eu.amazon.com이었다).
    for ref in references:
        if ref not in seen:
            seen.add(ref)
            unique_refs.append(ref)
    from datetime import datetime, timezone
    return {
        "findings": findings,
        "steps": steps,
        "named_ips": named_ips,
        # URLhaus가 알려 준 페이로드 해시. 후속 조회에서 샌드박스로 이어진다.
        "discovered_hashes": discovered,
        "references": unique_refs[:MAX_REFERENCES],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
