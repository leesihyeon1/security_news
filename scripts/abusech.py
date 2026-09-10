# -*- coding: utf-8 -*-
"""URL·해시를 abuse.ch에도 물어본다(URLhaus·ThreatFox).

무엇이 빠져 있었나
    URL은 urlscan에만, 해시는 VirusTotal과 샌드박스 세 곳에만 물어봤다. 그런데
    abuse.ch는 "이 URL이 실제로 악성코드를 뿌리는 것으로 신고됐나", "이 해시가 어느
    패밀리로 등재됐나"를 신고 기반으로 답하는 곳이다. urlscan은 페이지가 어떻게
    생겼는지를 보고, abuse.ch는 커뮤니티가 무엇으로 신고했는지를 본다. 서로 다른
    질문이라 한쪽만 보면 답이 반쪽이다.

무엇을 조회하나
    URLhaus  /v1/url/      URL 하나 — 악성코드 유포로 신고됐나, 지금 살아 있나(online/
                           offline), 어떤 페이로드를 떨궜나(해시가 여기서 나온다).
             /v1/host/     도메인·IP — 이 호스트에서 신고된 URL이 몇 건인가.
             /v1/payload/  해시 — 어느 패밀리로 분류됐나, 어느 URL에서 배포됐나.
    ThreatFox search_ioc   도메인·IP·URL·해시 공통 — IOC 등재 여부와 귀속 패밀리,
                           신고자가 남긴 참고 링크.

    URLhaus의 payloads에서 나온 해시와 ThreatFox의 reference 링크가 다음 단계로
    이어진다 — 해시는 샌드박스 조회로, 링크는 1차 자료 수집으로.

키가 필요하다(실측 2026-09-10)
    예전에는 무키로 됐지만 지금은 abuse.ch 전 서비스가 auth.abuse.ch 통합 키를
    요구한다. 키 없이 부르면 401 Unauthorized, 등록되지 않은 키면 403에
    query_status=unknown_auth_key가 온다. 웹에서 로그인해 검색하면 되는 것은 브라우저
    세션으로 붙기 때문이고, API는 별개다.

    그래서 인증 실패는 "결과 없음"이 아니라 실패로 남긴다. 등재되지 않은 IOC와
    조회하지 못한 IOC를 같은 것으로 적으면 판단이 틀어진다.

urllib이 아니라 requests를 쓰는 이유
    urlhaus-api.abuse.ch는 urllib으로 붙으면 이 장비에서 CERTIFICATE_VERIFY_FAILED가
    난다(같은 abuse.ch인데 mb-api는 된다 — 인증서 체인이 다르다). requests는 certifi
    번들을 쓰기 때문에 붙는다.
"""

import os
import time
import urllib.parse

import requests

USER_AGENT = "boannews-intel/1.0 (threat research)"
REQUEST_TIMEOUT = 25
PAUSE_SECONDS = 1.0
# 목록(태그·패밀리·URL)은 이 정도만 보여준다 — 더 붙여도 판단이 달라지지 않는다.
MAX_ITEMS = 5
# 한 기사에서 종류별로 볼 값의 수. 전부 돌리면 기사 하나에 수십 초가 더 든다.
MAX_PER_KIND = 2

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_PAYLOAD = "https://urlhaus-api.abuse.ch/v1/payload/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

URLHAUS_HOST_PAGE = "https://urlhaus.abuse.ch/browse.php?search={}"
THREATFOX_SEARCH_PAGE = "https://threatfox.abuse.ch/browse.php?search=ioc%3A{}"

AUTH_HINT = ("abuse.ch 인증키가 등록되지 않았습니다(auth.abuse.ch에서 키를 확인/재발급해야 "
             "합니다)")

# 인증이 한 번 거부되면 나머지 호출도 전부 거부된다. 값마다 네 번씩 두드려 같은 실패를
# 쌓지 않는다 — 한 번만 적고 그 회차는 접는다.
_auth_failed = False
# 인증 실패는 이 회차 전체에 한 번만 적는다. 값마다 서비스마다 같은 줄을 남기면
# 조사 과정이 같은 문장으로 도배된다(실측: 값 2개에 네 줄이 같은 말이었다).
_auth_reported = False


def log(message):
    print(message)


def api_key():
    """auth.abuse.ch 통합 키. 서비스별 키 이름 어느 것으로 넣어도 받는다."""
    for name in ("ABUSECH_API_KEY", "ABUSE_CH_API_KEY", "ABUSECH_AUTH_KEY",
                 "MALWAREBAZAAR_API_KEY", "URLHAUS_API_KEY", "THREATFOX_API_KEY"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def available():
    return bool(api_key()) and not _auth_failed


def reset():
    """인증 실패 표시를 지운다 — 키를 새로 넣고 같은 프로세스에서 다시 돌릴 때."""
    global _auth_failed, _auth_reported
    _auth_failed = False
    _auth_reported = False


def _post(url, payload, as_json=False, key=None):
    """(데이터, 오류문). 인증 거부는 오류로 돌려준다 — 결과 없음이 아니다."""
    global _auth_failed
    key = key or api_key()
    if not key:
        return None, "abuse.ch 인증키가 없습니다"
    if _auth_failed:
        return None, AUTH_HINT
    headers = {"User-Agent": USER_AGENT, "Auth-Key": key}
    try:
        if as_json:
            response = requests.post(url, json=payload, headers=headers,
                                     timeout=REQUEST_TIMEOUT)
        else:
            response = requests.post(url, data=payload, headers=headers,
                                     timeout=REQUEST_TIMEOUT)
    except Exception as error:
        return None, str(error)[:120]

    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return None, "HTTP {} (응답을 해석하지 못했습니다)".format(response.status_code)

    status = str(data.get("query_status") or "")
    # 인증 문제는 HTTP 200으로 오는 경우도 있어 본문으로 판단한다.
    if status == "unknown_auth_key" or response.status_code in (401, 403):
        _auth_failed = True
        return None, AUTH_HINT
    if status and status not in ("ok", "no_results"):
        return None, "abuse.ch 응답 {}".format(status[:40])
    return data, ""


def _quote(value):
    """링크에 값을 끼워 넣을 때. URL을 그대로 붙이면 링크가 거기서 잘린다."""
    return urllib.parse.quote(str(value or "").strip(), safe="")


def _items(values, limit=MAX_ITEMS):
    out = []
    for value in values or []:
        value = str(value or "").strip()
        if value and value not in out:
            out.append(value)
        if len(out) >= limit:
            break
    return out


def lookup_url(value):
    """URLhaus에 URL 하나. 신고 여부·생존 여부·떨군 페이로드."""
    data, error = _post(URLHAUS_URL, {"url": value})
    if error:
        return {"found": False, "error": error}
    if (data.get("query_status") or "") != "ok":
        return {"found": False, "error": ""}
    payloads = []
    for item in (data.get("payloads") or [])[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        payloads.append({
            "sha256": (item.get("response_sha256") or "").strip(),
            "file_type": (item.get("file_type") or "").strip(),
            "signature": (item.get("signature") or "").strip(),
        })
    return {
        "found": True,
        "url_status": (data.get("url_status") or "unknown").strip(),
        "threat": (data.get("threat") or "").strip(),
        "tags": _items(data.get("tags")),
        "firstseen": (data.get("date_added") or "")[:10],
        "lastseen": (data.get("last_online") or "")[:10],
        "reference": (data.get("urlhaus_reference") or "").strip(),
        "payloads": payloads,
        "error": "",
    }


def lookup_host(value):
    """URLhaus에 도메인·IP. 이 호스트에서 신고된 URL이 몇 건이고 몇 건이 살아 있나."""
    data, error = _post(URLHAUS_HOST, {"host": value})
    if error:
        return {"found": False, "error": error}
    if (data.get("query_status") or "") != "ok":
        return {"found": False, "error": ""}
    urls = [item for item in (data.get("urls") or []) if isinstance(item, dict)]
    online = sum(1 for item in urls if (item.get("url_status") or "") == "online")
    tags = []
    for item in urls:
        tags.extend(item.get("tags") or [])
    return {
        "found": True,
        "url_count": int(data.get("url_count") or len(urls) or 0),
        "online": online,
        "firstseen": (data.get("firstseen") or "")[:10],
        "tags": _items(tags),
        "threats": _items([item.get("threat") for item in urls], limit=3),
        "reference": (data.get("urlhaus_reference")
                      or URLHAUS_HOST_PAGE.format(_quote(value))).strip(),
        "error": "",
    }


def lookup_payload(hash_value):
    """URLhaus에 해시. 어느 패밀리로 분류됐고 어느 URL에서 배포됐나."""
    field = {32: "md5_hash", 64: "sha256_hash"}.get(len(hash_value.strip()))
    if not field:
        # URLhaus payload 조회는 md5·sha256만 받는다. sha1은 물어볼 방법이 없다.
        return {"found": False, "error": "URLhaus는 md5·sha256만 조회합니다"}
    data, error = _post(URLHAUS_PAYLOAD, {field: hash_value.strip()})
    if error:
        return {"found": False, "error": error}
    if (data.get("query_status") or "") != "ok":
        return {"found": False, "error": ""}
    virustotal = data.get("virustotal") or {}
    urls = [item for item in (data.get("urls") or []) if isinstance(item, dict)]
    return {
        "found": True,
        "signature": (data.get("signature") or "").strip(),
        "file_type": (data.get("file_type") or "").strip(),
        "file_size": data.get("file_size") or 0,
        "firstseen": (data.get("firstseen") or "")[:10],
        "url_count": int(data.get("url_count") or len(urls) or 0),
        "urls": _items([item.get("url") for item in urls], limit=3),
        "vt_percent": (virustotal.get("percent") if isinstance(virustotal, dict)
                       else "") or "",
        "vt_link": (virustotal.get("link") if isinstance(virustotal, dict)
                    else "") or "",
        "reference": (data.get("urlhaus_download") or "").strip(),
        "error": "",
    }


def lookup_threatfox(value):
    """ThreatFox에 IOC 하나. 등재 여부·귀속 패밀리·신고자 참고 링크."""
    data, error = _post(THREATFOX_URL,
                        {"query": "search_ioc", "search_term": value.strip()},
                        as_json=True)
    if error:
        return {"found": False, "error": error}
    rows = data.get("data")
    if not isinstance(rows, list) or not rows:
        return {"found": False, "error": ""}
    items, references, families, tags = [], [], [], []
    for row in rows[:MAX_ITEMS]:
        if not isinstance(row, dict):
            continue
        family = (row.get("malware_printable") or row.get("malware") or "").strip()
        items.append({
            "malware": family,
            "threat_type": (row.get("threat_type") or "").strip(),
            "confidence": row.get("confidence_level") or 0,
            "first_seen": (row.get("first_seen") or "")[:10],
            "reporter": (row.get("reporter") or "").strip(),
        })
        if family:
            families.append(family)
        tags.extend(row.get("tags") or [])
        reference = (row.get("reference") or "").strip()
        if reference.startswith("http"):
            references.append(reference)
    return {
        "found": True,
        "count": len(rows),
        "items": items,
        "families": _items(families, limit=3),
        "tags": _items(tags),
        "references": _items(references, limit=3),
        "page": THREATFOX_SEARCH_PAGE.format(_quote(value)),
        "error": "",
    }


def _note_failure(steps, service, value, error):
    """조회하지 못한 것은 못했다고 적는다. 등재 없음과 같은 줄로 쓰지 않는다.

    인증 실패는 값·서비스와 무관한 한 가지 사실이라 회차당 한 번만 적는다. 그 밖의
    실패는 값마다 다를 수 있으니 그대로 남긴다.
    """
    global _auth_reported
    if error == AUTH_HINT:
        if _auth_reported:
            return
        _auth_reported = True
        steps.append("abuse.ch(URLhaus·ThreatFox) 조회를 건너뜁니다 — {}.".format(error))
        return
    steps.append("{} 조회 실패({}) — {}.".format(service, value, error))


KIND_LABELS = {"url": "URL", "domain": "도메인", "ip": "IP",
               "sha256": "해시", "sha1": "해시", "md5": "해시"}


def _short(kind, value):
    if kind in ("sha256", "sha1", "md5"):
        return value[:16]
    return value if len(value) <= 60 else value[:57] + "..."


def describe(kind, value, pause=True):
    """지표 하나를 abuse.ch에 물어보고 (조사과정, 확인된 사실, 참고링크, 해시)를 낸다.

    kind: url | domain | ip | sha256 | md5 | sha1
    hashes에는 URLhaus가 알려 준 페이로드 해시가 담긴다 — 기사에 해시가 없어도
    URL 하나로 샌드박스 조회까지 이어갈 수 있게 하려는 것이다.

    references에는 원문으로 읽을 값이 있는 것만 담는다(ThreatFox 신고자가 남긴 분석
    글). URLhaus 항목 페이지나 VirusTotal 링크는 조회 기록이라 읽을 본문이 없고,
    그것이 앞자리를 차지하면 1차 자료 수집이 실제 보고서 대신 그 페이지를 읽는다.

    조회가 실제로 일어난 뒤에 조사 과정을 적는다. 먼저 "조회했습니다"를 적고 나서
    실패를 붙이면, 하지 않은 일을 했다고 적은 뒤 취소하는 꼴이 된다.
    """
    kind = (kind or "").lower()
    label = KIND_LABELS.get(kind)
    if not label:
        return {"steps": [], "findings": [], "references": [], "hashes": []}
    steps, findings, references, hashes = [], [], [], []
    short = _short(kind, value)

    if kind == "url":
        result = lookup_url(value)
        if result.get("error"):
            _note_failure(steps, "URLhaus", short, result["error"])
        else:
            steps.append("URL {}을 URLhaus에 조회했습니다 — 악성코드 유포로 신고된 적이 "
                         "있는지, 지금도 살아 있는지 보려는 것입니다.".format(short))
            if result["found"]:
                findings.append(
                    "URL {}은 URLhaus에 악성코드 유포로 신고돼 있습니다({} · 상태 {}{}). "
                    "기사 주장이 아니라 신고 기록으로 확인된 것입니다.".format(
                        short, result["threat"] or "분류 미기재", result["url_status"],
                        " · 최초 " + result["firstseen"] if result["firstseen"] else ""))
                if result["url_status"] == "online":
                    findings.append("· 아직 online이라 지금 차단하지 않으면 계속 "
                                    "유포됩니다.")
                if result["tags"]:
                    findings.append("· URLhaus 태그: {}.".format(", ".join(result["tags"])))
                for payload in result["payloads"]:
                    if not payload["sha256"]:
                        continue
                    hashes.append(payload["sha256"])
                    findings.append(
                        "· 이 URL이 떨군 파일 {}{}{} — 해시가 나왔으니 샌드박스로 "
                        "이어서 볼 수 있습니다.".format(
                            payload["sha256"][:16],
                            " (" + payload["file_type"] + ")"
                            if payload["file_type"] else "",
                            " · " + payload["signature"]
                            if payload["signature"] else ""))
                if result["reference"]:
                    findings.append("· 신고 기록: {}".format(result["reference"]))
            else:
                findings.append(
                    "URL {}은 URLhaus에 신고 기록이 없습니다 — 아직 유포지로 수집되지 "
                    "않았다는 뜻이고, 정상이라는 뜻은 아닙니다.".format(short))

    elif kind in ("domain", "ip"):
        result = lookup_host(value)
        if result.get("error"):
            _note_failure(steps, "URLhaus", short, result["error"])
        else:
            steps.append("{} {}를 URLhaus에 조회했습니다 — 이 호스트에서 유포로 신고된 "
                         "URL이 있는지 보려는 것입니다.".format(label, short))
            if result["found"]:
                findings.append(
                    "{} {}에서 URLhaus에 신고된 URL이 {}건 있습니다({}건은 아직 "
                    "online{}). 한 건짜리 사고가 아니라 유포에 쓰이는 "
                    "호스트입니다.".format(
                        label, short, result["url_count"], result["online"],
                        " · 최초 " + result["firstseen"] if result["firstseen"] else ""))
                if result["tags"]:
                    findings.append("· URLhaus 태그: {}.".format(", ".join(result["tags"])))
                if result["reference"]:
                    findings.append("· 신고 기록: {}".format(result["reference"]))
            else:
                findings.append("{} {}는 URLhaus에 신고된 URL이 없습니다.".format(
                    label, short))

    else:
        result = lookup_payload(value)
        if result.get("error"):
            _note_failure(steps, "URLhaus", short, result["error"])
        else:
            steps.append("해시 {}를 URLhaus 페이로드 목록에 조회했습니다 — 어느 패밀리로 "
                         "분류됐고 어디서 배포됐는지 보려는 것입니다.".format(short))
            if result["found"]:
                findings.append(
                    "해시 {}는 URLhaus에 {}로 등재돼 있습니다{}{}.".format(
                        short, result["signature"] or "패밀리 미기재",
                        " · 파일형식 " + result["file_type"]
                        if result["file_type"] else "",
                        " · 유포 URL " + str(result["url_count"]) + "건"
                        if result["url_count"] else ""))
                if result["vt_percent"]:
                    findings.append("· VirusTotal 탐지율 {}%.".format(result["vt_percent"]))
                for url in result["urls"]:
                    findings.append("· 배포 주소 {}".format(
                        url if len(url) <= 80 else url[:77] + "..."))
                if result["vt_link"]:
                    findings.append("· VirusTotal 항목: {}".format(result["vt_link"]))
            else:
                findings.append("해시 {}는 URLhaus 페이로드 목록에 없습니다.".format(short))

    if pause:
        time.sleep(PAUSE_SECONDS)

    # ThreatFox는 종류를 가리지 않고 같은 질문을 받는다 — 등재됐나, 무엇으로 봤나.
    fox = lookup_threatfox(value)
    if fox.get("error"):
        _note_failure(steps, "ThreatFox", short, fox["error"])
    else:
        steps.append("{} {}를 ThreatFox에도 조회했습니다 — 다른 신고자가 이 지표를 어떤 "
                     "위협으로 등재했는지 보려는 것입니다.".format(label, short))
        if fox["found"]:
            findings.append(
                "ThreatFox에 이 지표가 {}건 등재돼 있습니다{}. 신고 기반이라 귀속에 "
                "근거가 있습니다.".format(
                    fox["count"],
                    " — 귀속: " + ", ".join(fox["families"]) if fox["families"] else ""))
            for item in fox["items"][:2]:
                findings.append("· {} / {} · 신뢰도 {} · 최초 {}".format(
                    item["malware"] or "패밀리 미기재",
                    item["threat_type"] or "유형 미기재",
                    item["confidence"], item["first_seen"] or "?"))
            # ThreatFox의 reference는 신고자가 남긴 분석 글·게시물이라 원문으로
            # 읽을 값이 있다. 그래서 이것만 references로 넘긴다.
            references.extend(fox["references"])
            findings.append("· ThreatFox 항목: {}".format(fox["page"]))
        else:
            findings.append("이 지표는 ThreatFox에 등재돼 있지 않습니다.")

    if pause:
        time.sleep(PAUSE_SECONDS)
    return {"steps": steps, "findings": findings, "references": references,
            "hashes": hashes}
