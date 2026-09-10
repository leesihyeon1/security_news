"""외부 샌드박스·저장소 조회 — Triage, MalwareBazaar, Hybrid Analysis.

왜 필요한가:
    VT 동적분석 하나로는 부실하다. 같은 샘플을 다른 샌드박스가 돌려 놓은 결과에는
    VT에 없는 것이 있다 — Triage는 설정에서 뽑아낸 C2 주소를, MalwareBazaar는
    패밀리 이름과 다른 서비스 리포트 링크를, Hybrid Analysis는 ATT&CK 매핑과
    프로세스 트리를 준다.

    세 서비스 모두 조회에 키가 필요하다(실측: tria.ge 401, MalwareBazaar
    "Unauthorized", Hybrid Analysis 301). 키가 없으면 검색 링크만 만들고, 있으면
    실제로 조회해 "샘플 있음/없음"과 그쪽 판정을 가져온다.

.env 설정:
    TRIAGE_API_KEY           tria.ge 계정 → Account settings → API keys
    MALWAREBAZAAR_API_KEY    auth.abuse.ch 계정의 Auth-Key (MalwareBazaar 공용)
    HYBRID_ANALYSIS_API_KEY  hybrid-analysis.com 계정 → Profile → API key

    키는 .env에만 두고 로그·출력에 남기지 않는다. 이 모듈은 어디에도 키를 찍지 않는다.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "boannews-intel/1.0 (threat research)"
REQUEST_TIMEOUT = 25
PAUSE_SECONDS = 1.0          # 서비스 간 간격 — 세 곳을 연달아 부른다
MAX_ITEMS = 6                # 목록(태그·시그니처·도메인)은 이 정도만 보여준다

TRIAGE_SEARCH_URL = "https://tria.ge/api/v0/search?query={}"
TRIAGE_OVERVIEW_URL = "https://tria.ge/api/v0/samples/{}/overview.json"
TRIAGE_REPORT_URL = "https://tria.ge/{}"
TRIAGE_SEARCH_PAGE = "https://tria.ge/s?q={}"

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
MB_BROWSE_URL = "https://bazaar.abuse.ch/sample/{}/"
MB_SEARCH_PAGE = "https://bazaar.abuse.ch/browse.php?search=sha256%3A{}"

HA_SEARCH_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
# 검증된 조회 경로. 400을 내는 POST 검색 대신 이쪽을 쓴다.
HA_OVERVIEW_URL = "https://www.hybrid-analysis.com/api/v2/overview/{}"
HA_REPORT_URL = "https://www.hybrid-analysis.com/sample/{}"
HA_SEARCH_PAGE = "https://www.hybrid-analysis.com/search?query={}"


def _key(*names):
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def triage_key():
    return _key("TRIAGE_API_KEY", "TRIAGE_KEY")


def malwarebazaar_key():
    return _key("MALWAREBAZAAR_API_KEY", "ABUSECH_API_KEY", "ABUSE_CH_API_KEY")


def hybrid_key():
    return _key("HYBRID_ANALYSIS_API_KEY", "HA_API_KEY")


def _request(url, headers=None, data=None):
    """JSON 요청. 실패는 (None, 사유)로 돌려준다 — 예외로 분석을 막지 않는다."""
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(url, data=body, headers=headers or {})
    # User-Agent를 주지 않으면 urllib이 "Python-urllib/3.x"로 나가고, tria.ge는 그것을
    # 막는다(실측: 같은 키·같은 주소인데 UA만 넣으면 200, 없으면 403이었다).
    if not any(key.lower() == "user-agent" for key in (headers or {})):
        request.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw), ""
    except urllib.error.HTTPError as error:
        # 401/403은 키 문제다 — 키 값 자체는 절대 로그에 남기지 않는다.
        # 다만 본문에 실린 사유는 살린다. abuse.ch는 unknown_auth_key처럼 무엇이
        # 잘못됐는지 알려 주는데, 상태 코드만 남기면 "만료"와 "미등록"이 구별되지 않는다.
        reason = "HTTP {}".format(error.code)
        try:
            detail = json.loads(error.read().decode("utf-8", errors="replace"))
            status = detail.get("query_status") or detail.get("error") or ""
            if status:
                reason = "{} ({})".format(reason, str(status)[:40])
        except Exception:
            pass
        return None, reason
    except Exception as error:
        return None, str(error)[:80]


def _trim(values, limit=MAX_ITEMS, width=90):
    out = []
    for value in values or []:
        text = " ".join(str(value).split())[:width]
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ── Triage ─────────────────────────────────────────────────────────────────────
def lookup_triage(hash_value, api_key=None):
    """Triage 검색 → 리포트 개요. 설정에서 추출한 C2가 있으면 그게 가장 값지다."""
    api_key = api_key if api_key is not None else triage_key()
    result = {"service": "Triage", "found": False, "has_key": bool(api_key),
              "url": TRIAGE_SEARCH_PAGE.format(hash_value), "error": ""}
    if not api_key:
        return result

    headers = {"Authorization": "Bearer {}".format(api_key), "Accept": "application/json"}
    # 검색어는 해시만 넣는다. "sha256:<해시>" 형태로 물으면 인증은 통과하는데 결과가
    # 늘 비어서 "샘플 없음"으로 잘못 읽힌다(실측: EICAR 해시로 확인 — 접두를 붙이면
    # 0건, 해시만 넣으면 리포트가 나온다).
    data, error = _request(TRIAGE_SEARCH_URL.format(
        urllib.parse.quote(hash_value)), headers=headers)
    if data is None:
        result["error"] = error
        return result
    samples = data.get("data") or []
    if not samples:
        return result

    sample = samples[0]
    sample_id = sample.get("id") or ""
    result.update({"found": True, "sample_id": sample_id,
                   "url": TRIAGE_REPORT_URL.format(sample_id) if sample_id else result["url"],
                   "submitted": (sample.get("submitted") or "")[:10],
                   "filename": sample.get("filename") or "",
                   "reports": len(samples)})

    overview, error = _request(TRIAGE_OVERVIEW_URL.format(sample_id), headers=headers)
    if overview is None:
        result["error"] = error
        return result

    analysis = overview.get("analysis") or {}
    result["score"] = analysis.get("score")
    result["family"] = _trim(analysis.get("family"), limit=4, width=40)
    result["tags"] = _trim(analysis.get("tags"), limit=6, width=30)

    signatures, domains, ips, c2 = [], [], [], []
    for target in overview.get("targets") or []:
        for signature in target.get("signatures") or []:
            signatures.append(signature.get("name") or signature.get("desc") or "")
        iocs = target.get("iocs") or {}
        domains.extend(iocs.get("domains") or [])
        ips.extend(iocs.get("ips") or [])
        for value in iocs.get("urls") or []:
            domains.append(value)
    for extracted in overview.get("extracted") or []:
        config = extracted.get("config") or {}
        c2.extend(config.get("c2") or [])
        if config.get("botnet"):
            result.setdefault("botnet", config["botnet"])
    result["signatures"] = _trim(signatures)
    result["domains"] = _trim(domains)
    result["ips"] = _trim(ips)
    result["c2"] = _trim(c2, limit=8, width=120)
    return result


# ── MalwareBazaar ──────────────────────────────────────────────────────────────
def lookup_malwarebazaar(hash_value, api_key=None):
    """MalwareBazaar 조회. 패밀리 이름과 다른 서비스 리포트 링크를 얻는다."""
    api_key = api_key if api_key is not None else malwarebazaar_key()
    result = {"service": "MalwareBazaar", "found": False, "has_key": bool(api_key),
              "url": MB_SEARCH_PAGE.format(hash_value), "error": ""}
    if not api_key:
        return result

    # abuse.ch는 query_status로 실패 이유를 준다. unknown_auth_key는 만료가 아니라
    # "그 키를 모른다"는 뜻이라, auth.abuse.ch에서 새로 받아야 한다.
    data, error = _request(MB_API_URL, headers={"Auth-Key": api_key},
                           data={"query": "get_info", "hash": hash_value})
    if data is None:
        result["error"] = error
        return result
    if (data.get("query_status") or "") != "ok":
        # hash_not_found 는 정상 응답이다 — 샘플이 없다는 뜻.
        if data.get("query_status") not in ("hash_not_found", "no_results"):
            result["error"] = str(data.get("query_status"))
        return result

    entries = data.get("data") or []
    if not entries:
        return result
    entry = entries[0]
    result.update({
        "found": True,
        "url": MB_BROWSE_URL.format(hash_value),
        "filename": entry.get("file_name") or "",
        "file_type": entry.get("file_type") or "",
        "family": _trim([entry.get("signature")], limit=2, width=40),
        "tags": _trim(entry.get("tags"), limit=8, width=30),
        "first_seen": (entry.get("first_seen") or "")[:10],
        "reporter": entry.get("reporter") or "",
        "delivery": entry.get("delivery_method") or "",
        "yara": _trim([r.get("rule_name") for r in entry.get("yara_rules") or []], limit=5, width=50),
    })
    intelligence = entry.get("intelligence") or {}
    result["downloads"] = intelligence.get("downloads")
    result["clamav"] = _trim(intelligence.get("clamav"), limit=3, width=40)

    # vendor_intel — 다른 샌드박스·서비스가 이 샘플을 본 결과와 링크.
    vendors = []
    for vendor, payload in (entry.get("vendor_intel") or {}).items():
        verdict, link = "", ""
        if isinstance(payload, dict):
            verdict = (payload.get("verdict") or payload.get("detection")
                       or payload.get("malware_family") or "")
            link = payload.get("link") or payload.get("analysis_url") or ""
        elif isinstance(payload, list) and payload:
            first = payload[0] if isinstance(payload[0], dict) else {}
            verdict = (first.get("verdict") or first.get("detection")
                       or first.get("malware_family") or "")
            link = first.get("link") or first.get("analysis_url") or ""
        vendors.append({"vendor": vendor, "verdict": str(verdict)[:40], "url": link})
    result["vendors"] = vendors[:8]
    return result


# ── Hybrid Analysis ────────────────────────────────────────────────────────────
def lookup_hybrid(hash_value, api_key=None):
    """Hybrid Analysis 조회. 환경별 판정·위협 점수와 ATT&CK 매핑을 얻는다."""
    api_key = api_key if api_key is not None else hybrid_key()
    result = {"service": "Hybrid Analysis", "found": False, "has_key": bool(api_key),
              "url": HA_SEARCH_PAGE.format(hash_value), "error": ""}
    if not api_key:
        return result

    headers = {"api-key": api_key, "User-Agent": "Falcon Sandbox",
               "Accept": "application/json"}
    # POST /search/hash는 폼도 멀티파트도 본문이 전달되지 않아 늘 400을 낸다
    # (실측: "hash: This value should not be blank"). GET /overview/{sha256}는
    # 같은 정보를 주고 404로 "없음"을 분명히 알려 준다.
    data, error = _request(HA_OVERVIEW_URL.format(urllib.parse.quote(hash_value)),
                           headers=headers)
    if data is None:
        # 404는 오류가 아니라 "이 샘플이 없다"는 결과다.
        result["error"] = "" if error == "HTTP 404" else error
        return result
    reports = (data.get("scanners_v2") and [data]) or [data]
    if not data.get("sha256"):
        return result

    # 위협 점수가 가장 높은 리포트를 대표로 본다(환경마다 결과가 다르다).
    def score_of(report):
        return report.get("threat_score") or 0
    best = max(reports, key=score_of)
    # overview는 환경별 목록 대신 대표 결과 하나를 준다.
    best.setdefault("verdict", best.get("verdict") or "")
    result.update({
        "found": True,
        "url": HA_REPORT_URL.format(hash_value),
        "reports": len(reports),
        "verdict": best.get("verdict") or "",
        "score": best.get("threat_score"),
        "environment": best.get("environment_description") or "",
        "family": _trim([best.get("vx_family")], limit=2, width=40),
        "tags": _trim(best.get("classification_tags"), limit=6, width=30),
        "domains": _trim(best.get("domains")),
        "hosts": _trim(best.get("hosts")),
        "signatures": _trim([s.get("name") for s in best.get("signatures") or []
                             if (s.get("threat_level") or 0) >= 1]),
    })
    techniques = []
    for entry in best.get("mitre_attcks") or []:
        technique_id = entry.get("attck_id") or ""
        if technique_id and technique_id not in techniques:
            techniques.append(technique_id)
    result["techniques"] = techniques[:14]
    result["environments"] = _trim(
        ["{}: {} (점수 {})".format(r.get("environment_description") or "?",
                                r.get("verdict") or "판정 없음",
                                r.get("threat_score") if r.get("threat_score") is not None else "-")
         for r in reports], limit=4, width=70)
    return result


def lookup_all(hash_value, pause=True):
    """세 서비스를 순서대로 조회. 키가 없는 곳은 링크만 담긴 결과가 온다."""
    results = []
    for lookup in (lookup_triage, lookup_malwarebazaar, lookup_hybrid):
        results.append(lookup(hash_value))
        if pause:
            time.sleep(PAUSE_SECONDS)
    return results


def findings(results):
    """조회 결과를 확인내용 문장으로. 키가 없어 못 본 것은 그렇다고 밝힌다."""
    lines = []
    found = [r for r in results if r.get("found")]
    missing_key = [r["service"] for r in results if not r.get("has_key")]
    failed = [(r["service"], r["error"]) for r in results if r.get("error")]

    for result in found:
        service = result["service"]
        bits = []
        if result.get("family"):
            bits.append("패밀리 {}".format(", ".join(result["family"])))
        if result.get("score") is not None:
            bits.append("점수 {}".format(result["score"]))
        if result.get("verdict"):
            bits.append("판정 {}".format(result["verdict"]))
        if result.get("first_seen"):
            bits.append("최초 등록 {}".format(result["first_seen"]))
        if result.get("submitted"):
            bits.append("제출 {}".format(result["submitted"]))
        if result.get("environment"):
            bits.append(result["environment"])
        lines.append("· {}에 샘플이 있습니다{}.".format(
            service, " — {}".format(" / ".join(bits)) if bits else ""))

        if result.get("c2"):
            lines.append("· {}가 설정에서 추출한 C2: {}. 샌드박스가 통신하지 않아도 설정에 박혀 "
                         "있는 주소라 차단·헌팅에 바로 쓸 수 있습니다.".format(
                             service, ", ".join(result["c2"][:5])))
        network = (result.get("domains") or []) + (result.get("hosts") or []) + (result.get("ips") or [])
        if network:
            lines.append("· {}에서 관측된 통신처: {}.".format(service, ", ".join(network[:5])))
        if result.get("signatures"):
            lines.append("· {} 시그니처: {}.".format(service, ", ".join(result["signatures"][:4])))
        if result.get("environments") and len(result["environments"]) > 1:
            lines.append("· {} 환경별 결과: {}.".format(service, " / ".join(result["environments"])))
        if result.get("vendors"):
            named = [v for v in result["vendors"] if v.get("verdict")]
            if named:
                lines.append("· MalwareBazaar가 모아 둔 다른 서비스 판정: {}.".format(
                    ", ".join("{} {}".format(v["vendor"], v["verdict"]) for v in named[:5])))
        if result.get("yara"):
            lines.append("· {} YARA 매칭: {}.".format(service, ", ".join(result["yara"][:4])))

    not_found = [r["service"] for r in results if r.get("has_key") and not r.get("found")
                 and not r.get("error")]
    if not_found:
        lines.append("· {}에는 이 샘플이 없습니다 — 아직 공유되지 않았거나 비공개 제출만 "
                     "있는 경우입니다.".format(", ".join(not_found)))
    if failed:
        lines.append("· 조회 실패: {}. 키가 만료됐거나 요청 한도에 걸린 것일 수 있습니다.".format(
            ", ".join("{}({})".format(name, reason) for name, reason in failed)))
    if missing_key:
        lines.append("· {}는 API 키가 없어 조회하지 않았습니다 — 아래 링크로 직접 확인하면 "
                     "됩니다.".format(", ".join(missing_key)))
    return lines


def link_rows(results):
    """링크 행 — 샘플이 확인된 곳을 앞에 둔다."""
    rows = []
    for result in sorted(results, key=lambda r: (0 if r.get("found") else 1, r["service"])):
        if result.get("found"):
            label = "샘플 확인됨"
        elif not result.get("has_key"):
            label = "키 없음 — 검색만"
        elif result.get("error"):
            label = "조회 실패({})".format(result["error"])
        else:
            label = "샘플 없음"
        rows.append({
            "name": "{} — {}".format(result["service"], label),
            "query": result["url"],
            "url": result["url"],
            "link_label": "{} 열기".format(result["service"]),
            "paid": False,
        })
    return rows


if __name__ == "__main__":
    import argparse
    import sys

    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="외부 샌드박스 조회(Triage/MalwareBazaar/Hybrid Analysis)")
    parser.add_argument("hash", help="SHA-256 해시")
    args = parser.parse_args()

    outcome = lookup_all(args.hash)
    print("키 설정: Triage={} / MalwareBazaar={} / Hybrid Analysis={}".format(
        bool(triage_key()), bool(malwarebazaar_key()), bool(hybrid_key())))
    for line in findings(outcome):
        print(line)
    print()
    for row in link_rows(outcome):
        print("  {:44s} {}".format(row["name"], row["url"]))
