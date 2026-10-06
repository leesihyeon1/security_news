"""Keep publication references separate from actionable indicators."""

from urllib.parse import parse_qs, urlsplit, urlunsplit
import ipaddress
import re
import analysis_trace
import research_entities

REPORT_URL_RE = re.compile(r"https?://[^\s<>\"'`]+", re.I)
REPORT_HOST_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                            r"[a-z][a-z0-9-]{1,23}(?![\w-]|\.[a-z0-9])", re.I)


NETWORK_KINDS = {"domain", "url", "ip", "ipv4", "ip-dst", "ip-src"}
ATTACK_ROLES = {"c2", "exfiltration", "distribution"}
CONTEXT_ROLES = {"recon_target", "metadata", "non_public", "reference"}
ROLE_LABELS = {"c2": "명령·제어 후보", "exfiltration": "유출 수신지 후보",
               "distribution": "유포지 후보", "recon_target": "정찰 대상·차단 제외",
               "metadata": "클라우드 메타데이터·외부 C2 아님", "non_public": "비공인 주소·외부 조회 제외",
               "unknown": "악성 여부 미확인", "sample": "샘플 해시·출처 대조 필요"}
ROLE_PATTERNS = {
    "recon_target": re.compile(r"(?:prob(?:e[ds]?|ing)|scann(?:ed|ing)|정찰|탐색).{0,90}(?:hosts?|호스트|domains?|도메인)|(?:정찰|공격)\s*대상", re.I),
    "exfiltration": re.compile(r"(?:exfiltrat\w*|유출|탈취).{0,100}(?:to|via|수신지|전송지|목적지|webhook)|(?:send|sent|post|upload|전송)\w*.{0,100}(?:credential|secret|token|environment|process\.env|data|자격\s*증명|토큰|환경\s*변수).{0,100}(?:to|via|수신지|전송지|목적지|webhook|endpoint)|(?:exfiltration|유출)\s*(?:endpoint|url|server|address|주소)", re.I),
    "c2": re.compile(r"(?:command.and.control|c2)\s*(?:server|domain|address|endpoint|서버|주소)?\s*(?:at|is|:|로|는)?\s*$", re.I),
    "distribution": re.compile(r"(?:payload|malware|악성코드|페이로드).{0,70}(?:downloaded?\s+from|hosted\s+(?:at|on)|유포지|다운로드\s*주소)|(?:유포지|malware\s+distribution\s+(?:url|domain))\s*[:：]?", re.I),
}


SUFFIX_ROLE_PATTERNS = {
    "distribution": re.compile(
        r"lure\s*(?:urls?|domains?|pages?|sites?)|fake\s+(?:captcha|verification)\s+pages?|"
        r"미끼\s*(?:페이지|도메인|URL|주소)|유포지", re.I),
}


def _plain(value):
    return str(value or "").replace("[.]", ".").replace("hxxp", "http").replace("[:]", ":")


@analysis_trace.step("IOC 문맥·역할·조회 가능 여부 판정", kind="validation", inputs=("iocs", "documents"))
def assess_iocs(iocs, documents):
    """Classify a mention's role, not its owner's reputation. Unknown stays unknown."""
    result = []
    for original in iocs or []:
        item = dict(original)
        value = _plain(item.get("value")).strip()
        kind = str(item.get("type") or "").lower()
        item["value"] = value
        if kind not in NETWORK_KINDS:
            result.append(item)
            continue
        host = urlsplit(value).hostname if "://" in value else value
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address:
            if kind == "domain":
                item["type"] = "ipv4" if address.version == 4 else "ipv6"
            if not address.is_global:
                item.update(role="metadata" if str(address) == "169.254.169.254" else "non_public",
                            evidence="주소 범위 판정이며 악성 여부 판정이 아닙니다.", actionable=False)
                result.append(item)
                continue
        matches = []
        for doc in documents or []:
            text = " ".join(_plain(doc.get("text")).split())
            for mention in re.finditer(re.escape(value), text, re.I):
                boundary = text.rfind(". ", 0, mention.start())
                start = max(boundary + 2 if boundary >= 0 else 0, mention.start() - 500, 0)
                prefix = text[start:mention.start()]
                candidates = [(m.start(), role) for role, pattern in ROLE_PATTERNS.items()
                              for m in pattern.finditer(prefix)]
                if not candidates:
                    # 역할 설명이 값 뒤에 오는 문장("The domain ..., uasputnik[.]com, was
                    # registered ... and associated with lure URLs")은 앞만 봐서는 못 잡는다.
                    # 같은 문장 안의 뒤쪽만 본다 — 다음 문장은 다른 값의 설명일 수 있다.
                    end = text.find(". ", mention.end())
                    suffix = text[mention.end():end if end >= 0 else mention.end() + 300][:300]
                    candidates = [(0, role) for role, pattern in SUFFIX_ROLE_PATTERNS.items()
                                  if pattern.search(suffix)]
                if candidates:
                    _, role = max(candidates)
                    matches.append({"role": role, "source_url": doc.get("url") or "",
                                    "evidence": text[start:mention.end() + 100][:700]})
        roles = {m["role"] for m in matches}
        # Conflicting roles across reports need review, not a silent upgrade to blocking.
        if len(roles) == 1:
            item.update(matches[0])
        else:
            item.update(role="unknown", evidence=CONFLICT_EVIDENCE if roles else "원문 언급만으로 악성 인프라를 확정할 수 없습니다.")
        item["actionable"] = item["role"] in ATTACK_ROLES
        result.append(item)
    return result


CONFLICT_EVIDENCE = "역할 근거 충돌"


def _sandbox_contacts(block):
    """이 기사의 샘플이 샌드박스에서 실제로 통신한 호스트·IP(첫 관측 파일 해시와 함께)."""
    contacts = {}
    for entry in ((block or {}).get("malware") or {}).get("files") or []:
        behaviour = entry.get("behaviour") or {}
        view = entry.get("interpreted") or {}
        sample = str(entry.get("hash") or "")[:12]
        for host in (view.get("hosts") if view else behaviour.get("dns")) or []:
            contacts.setdefault(str(host).strip().strip(".").lower(), sample)
        for traffic in behaviour.get("ip_traffic") or []:
            contacts.setdefault(str(traffic).partition(":")[0].strip(), sample)
    contacts.pop("", None)
    return contacts


def corroborate(block):
    """원문이 역할을 밝히지 않은(unknown) 네트워크 지표를 독립 관측으로 끌어올린다.

    원문 문장만으로 역할을 못 정한 값은 차단에서 빠진다(assess_iocs). 그런데 실측
    (2026-09-26, Psychedelic Stealer): 원문이 "later-stage sign is traffic to
    193.178.159[.]128:8080"이라고 적고, 같은 기사의 샘플이 VT 샌드박스에서 바로 그
    IP로 통신했는데도 "악성 여부 미확인"으로 남아 차단 후보에 오르지 못했다.

    두 가지 독립 관측만 인정한다 — 원문 문장보다 강한 근거라서다:
      · 기사 샘플의 샌드박스 실제 통신 → 통신처 후보(C2 여부 미확인)
      · urlscan DOM에서 공격 표식 확인 → distribution(유포지 후보)
    원문이 지목하지 않은 값(샌드박스가 들른 정상 서비스 등)은 애초에 assessments에
    없으므로 여기서 올라가지 않는다. 역할 근거가 충돌한 값·정찰 대상·비공인 주소는
    건드리지 않는다 — 악성코드가 정찰 대상으로 통신하는 경우가 그렇다.
    반환: 역할을 바꾼 항목 목록.
    """
    assessed = (block or {}).get("indicator_assessments") or []
    contacts = _sandbox_contacts(block)
    dom_confirmed = {str(seed.get("domain") or seed.get("host") or "").lower()
                     for seed in (block or {}).get("seeds") or [] if seed.get("dom_confirmed")}
    upgraded = []
    for item in assessed:
        kind = str(item.get("type") or "").lower()
        if kind not in NETWORK_KINDS or item.get("role") != "unknown":
            continue
        if item.get("evidence") == CONFLICT_EVIDENCE:
            continue
        value = str(item.get("value") or "")
        host = urlsplit(value).hostname if "://" in value else value.split("/")[0].split(":")[0]
        host = (host or "").lower()
        if host in contacts:
            item.update(role="unknown", actionable=False, corroborated_by="sandbox_contact",
                        evidence="원문이 지목한 통신처이며, 이 기사의 샘플({})이 샌드박스에서 실제로 "
                                 "통신했습니다. C2·페이로드 수신지·정상 서비스 여부는 HTTP 요청·응답 "
                                 "내용과 프로세스 관계로 추가 확인해야 하므로 차단 후보는 아닙니다.".format(
                                     contacts[host]))
            upgraded.append(item)
        elif host in dom_confirmed and not research_entities.shared(host):
            item.update(role="distribution", actionable=True, corroborated_by="urlscan_dom",
                        evidence="원문이 지목한 도메인이며, urlscan 페이지 DOM에서 공격 표식이 "
                                 "확인됐습니다.")
            upgraded.append(item)
    return upgraded


def lookup_iocs(iocs):
    return [i for i in iocs or [] if i.get("role") not in CONTEXT_ROLES]


@analysis_trace.step("참고 보고서 IOC 재추출", kind="extraction", inputs=("text",))
def extract_report_iocs(text, limit=200):
    """Add plain hosts from a read research report; role assessment still decides use."""
    import common_utils

    found = list(common_utils.extract_iocs(text, limit=limit))
    found.extend({"type": "url", "value": url} for url in research_entities.shared_urls(text)
                 if not any(row.get("value") == url for row in found))
    seen = {str(item.get("value") or "").lower() for item in found}
    for kind, pattern in (("url", REPORT_URL_RE), ("domain", REPORT_HOST_RE)):
        for match in pattern.finditer(text or ""):
            value = match.group(0).rstrip(".,;:)]}")
            host = common_utils.host_from_indicator(value)
            if (not host or common_utils.is_benign_ioc("domain", host)
                    or value.lower() in seen):
                continue
            found.append({"type": kind, "value": value})
            seen.add(value.lower())
            if len(found) >= limit:
                return found
    return found


def display_iocs(iocs):
    return [i for i in iocs or [] if str(i.get("type") or "").lower() not in NETWORK_KINDS
            or i.get("actionable") is True]


@analysis_trace.step("판정된 IOC로 조사 대상 제한", kind="validation", inputs=("targets", "assessed"))
def restrict_targets(targets, assessed):
    result = dict(targets or {})
    excluded = {i["value"].lower() for i in assessed if i.get("role") in CONTEXT_ROLES}
    for key in ("domains", "ips", "urls"):
        if key in result:
            result[key] = [v for v in result[key] if _plain(v).lower() not in excluded]
    return result


def article_url(value):
    value = str(value or "").strip()
    for _ in range(3):
        parsed = urlsplit(value)
        if parsed.path != "/api/click":
            break
        inner = parse_qs(parsed.query).get("url")
        if not inner:
            break
        value = inner[0]
    return value


def canonical_url(value):
    parsed = urlsplit(article_url(value))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(),
                       parsed.path.rstrip("/"), parsed.query, ""))


def reference_hosts(urls):
    return {urlsplit(article_url(url)).hostname.lower()
            for url in urls if urlsplit(article_url(url)).hostname}


@analysis_trace.step("참고자료 주소를 IOC에서 제외", kind="validation", inputs=("iocs", "urls"))
def filter_iocs(iocs, urls):
    """Exclude exact source URLs and bare source hosts, not other paths on a host.

    A publication reference is not evidence that its entire host is safe.
    Explicit indicators on another path remain available for investigation.
    """
    references = {canonical_url(url) for url in urls if url}
    hosts = reference_hosts(urls)
    kept, removed = [], []
    for item in iocs or []:
        kind = str(item.get("type") or "").lower()
        value = str(item.get("value") or "").strip()
        source = ((kind == "url" and canonical_url(value) in references)
                  or (kind == "domain" and value.lower().rstrip(".") in hosts))
        (removed if source else kept).append(item)
    return kept, removed


def filter_targets(targets, urls):
    result = dict(targets or {})
    for key, kind in (("urls", "url"), ("domains", "domain")):
        if key in result:
            kept, _ = filter_iocs([{"type": kind, "value": v} for v in result[key]], urls)
            result[key] = [item["value"] for item in kept]
    return result
