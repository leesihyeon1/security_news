"""취약점 기사의 조사·대응 재료 — KEV·EPSS·NVD.

왜 별도 트랙인가:
    조사 방향은 사건 성격에 따라 갈린다. 유포지(URL 분석), 악성코드(VT 동적 분석)에
    이어 세 번째 축이 취약점이다. 취약점 기사에는 유포지도 파일 해시도 없고 CVE만
    있어서 앞의 두 트랙으로는 아무것도 만들 수 없었다 — 실측: "U.S. CISA adds a
    N-able N-central flaw to its KEV" 같은 기사가 "지표 없음"으로 처리됐다.

    취약점에서 정작 필요한 판단은 "우리가 이걸 지금 패치해야 하나"다. 그 판단은
    CVSS 점수가 아니라 ① 실제 악용 중인지(KEV) ② 악용 확률이 얼마인지(EPSS)
    ③ 우리 환경에 그 제품이 있는지로 정해진다. 이 세 가지를 모아 준다.

무엇을 조회하는가 (모두 키 없이 됨):
    · CISA KEV  — 실제 악용 확인 목록. 등재됐다면 논쟁의 여지가 없다(연방기관 기한도 있다).
    · FIRST EPSS — 30일 내 악용될 확률. KEV에 없을 때 우선순위를 가르는 값이다.
    · NVD       — CVSS 점수·벡터와 영향 제품. 키 없이 30초당 5회 제한이라 조회 수를 묶는다.
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request

from datetime import datetime, timedelta, timezone

import common_utils

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
# 제품 이름으로 CVE를 거꾸로 찾는다. 벤더가 아직 CVE를 배정하지 않은 제로데이
# 기사에서는 이것이 유일한 조사 입력이다(실측: "Adobe Commerce"로 검색하면
# 기사가 다룬 StyleSmuggler 제로데이 CVE-2026-75650이 나온다).
# 기간은 서버에서 걸러야 한다. 클라이언트에서 자르면 API가 돌려준 앞쪽 몇 건이
# 오래된 것일 때 최근 CVE가 통째로 잘린다(실측: Adobe Commerce 검색이 0건이 됐다).
NVD_KEYWORD_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
                   "?keywordSearch={}&resultsPerPage={}"
                   "&pubStartDate={}&pubEndDate={}")
# 제품명 검색은 넓게 잡히므로 최근 것만 본다 — 오래된 CVE까지 끌어오면
# "지금 대응할 것"이 아니라 그 제품의 전체 이력이 된다.
KEYWORD_RESULTS = 8
KEYWORD_RECENT_DAYS = 45
MAX_KEYWORD_PRODUCTS = 3
KEV_CACHE_FILE = common_utils.DATA_DIR / "kev_cache.json"
KEV_CACHE_HOURS = 12

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_CVES = int(os.environ.get("VULN_MAX_CVES", "4"))
NVD_PAUSE_SECONDS = float(os.environ.get("NVD_PAUSE_SECONDS", "6.5"))  # 키 없이 30초당 5회
REQUEST_TIMEOUT = 30


def cves_from_text(text, iocs=None):
    """기사 본문과 IOC에서 CVE를 뽑는다. 등장 순서를 유지한다(먼저 언급된 것이 주제다)."""
    ordered = []
    for source in [str(text or "")] + [str(i.get("value") or "") for i in (iocs or [])]:
        for match in CVE_RE.findall(source):
            value = match.upper()
            if value not in ordered:
                ordered.append(value)
    return ordered


def _request_json(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "boannews-intel/1.0 (vulnerability triage)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def load_kev():
    """KEV 목록을 {CVE: 항목}으로. 12시간 캐시 — 하루에 몇 번 바뀌는 데이터다."""
    try:
        if KEV_CACHE_FILE.exists():
            age_hours = (time.time() - KEV_CACHE_FILE.stat().st_mtime) / 3600
            if age_hours < KEV_CACHE_HOURS:
                return json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass

    for url in KEV_URLS:
        try:
            data = _request_json(url)
        except Exception:
            continue
        entries = {}
        for item in data.get("vulnerabilities") or []:
            cve = (item.get("cveID") or "").upper()
            if not cve:
                continue
            entries[cve] = {
                "vendor": item.get("vendorProject") or "",
                "product": item.get("product") or "",
                "name": item.get("vulnerabilityName") or "",
                "added": item.get("dateAdded") or "",
                "due": item.get("dueDate") or "",
                "action": item.get("requiredAction") or "",
                "ransomware": (item.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
            }
        try:
            KEV_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            KEV_CACHE_FILE.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
        return entries
    return {}


def fetch_nvd(cve):
    """NVD에서 CVSS와 영향 제품을 가져온다. 실패하면 빈 dict."""
    try:
        data = _request_json(NVD_URL.format(cve))
    except Exception:
        return {}
    items = data.get("vulnerabilities") or []
    if not items:
        return {}
    item = (items[0].get("cve") or {})
    metrics = item.get("metrics") or {}
    score, vector, version = None, "", ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data_block = entries[0].get("cvssData") or {}
        score = data_block.get("baseScore")
        vector = data_block.get("vectorString") or ""
        version = data_block.get("version") or key
        break

    # CPE는 취약 버전을 하나씩 나열한다 — 그대로 쓰면 "pan-os 10.2.0, 10.2.1, …"로
    # 목록이 채워져 무슨 제품인지 안 보인다. 제품 단위로 묶고 버전은 범위로 적는다.
    by_product = {}
    for config in item.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) <= 5:
                    continue
                product = "{} {}".format(parts[3], parts[4]).replace("_", " ")
                bucket = by_product.setdefault(product, {"versions": [], "upper": ""})
                if match.get("versionEndExcluding"):
                    bucket["upper"] = match["versionEndExcluding"]
                elif parts[5] not in ("*", "-") and parts[5] not in bucket["versions"]:
                    bucket["versions"].append(parts[5])

    products = []
    for product, info in list(by_product.items())[:8]:
        if info["upper"]:
            products.append("{} < {}".format(product, info["upper"]))
        elif len(info["versions"]) > 3:
            products.append("{} {}~{} 등 {}개 버전".format(
                product, info["versions"][0], info["versions"][-1], len(info["versions"])))
        elif info["versions"]:
            products.append("{} {}".format(product, ", ".join(info["versions"])))
        else:
            products.append(product)
    return {
        "score": score,
        "vector": vector,
        "version": version,
        "published": (item.get("published") or "")[:10],
        "products": products[:8],
        "status": item.get("vulnStatus") or "",
    }


def cves_by_product(products):
    """제품 이름으로 최근 CVE를 찾는다. 실패하거나 없으면 빈 목록.

    반환은 (cve_ids, steps)다 — 무엇을 어떻게 찾았는지 조사 과정에 남겨야 "기사에
    없던 CVE가 왜 여기 있나"를 되짚을 수 있다.
    """
    found, steps = [], []
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=KEYWORD_RECENT_DAYS)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT23:59:59.999")
    for product in (products or [])[:MAX_KEYWORD_PRODUCTS]:
        name = (product.get("name") or "").strip()
        if not name or len(name) < 3:
            continue
        try:
            data = _request_json(NVD_KEYWORD_URL.format(
                urllib.parse.quote(name), KEYWORD_RESULTS,
                urllib.parse.quote(start), urllib.parse.quote(end)))
        except Exception as error:
            steps.append("제품 \"{}\"으로 NVD를 조회하려 했으나 실패했습니다({}).".format(
                name, str(error)[:40]))
            continue
        # 최신순으로 세운 뒤 담는다. NVD가 주는 순서는 공개일과 무관해서, 그대로
        # 앞에서 자르면 정작 기사가 다루는 최신 취약점이 잘려 나간다(실측: Adobe
        # Commerce 8건 중 기사의 제로데이 CVE-2026-75650이 마지막이라 상한에 걸려
        # 빠졌다 — 나머지 4건은 그 기사와 무관한 예전 CVE였다).
        rows = []
        for item in data.get("vulnerabilities") or []:
            cve = (item.get("cve") or {})
            cve_id = cve.get("id")
            if cve_id and cve_id not in found:
                rows.append(((cve.get("published") or ""), cve_id))
        rows.sort(reverse=True)
        hits = [cve_id for _, cve_id in rows]
        found.extend(hits)
        steps.append("기사에 CVE가 없어 제품 이름 \"{}\"으로 NVD를 검색했고, 최근 {}일 "
                     "이내 공개된 {}건을 찾았습니다{}.".format(
                         name, KEYWORD_RECENT_DAYS, len(hits),
                         "(" + ", ".join(hits[:4]) + ")" if hits else ""))
        time.sleep(NVD_PAUSE_SECONDS)   # 키 없이 30초당 5회 제한
    return found, steps


def analyze(cves, text="", with_nvd=True, products=None):
    """CVE 목록으로 취약점 트랙을 만든다. 조사 사실 + 대응 재료.

    CVE가 없으면 제품 이름으로 NVD를 거꾸로 찾는다 — 벤더가 아직 배정하지 않은
    제로데이 기사에서 트랙이 통째로 비는 것을 막는다.
    """
    cves = list(cves or [])[:MAX_CVES]
    lookup_steps = []
    if not cves and products:
        cves, lookup_steps = cves_by_product(products)
        cves = cves[:MAX_CVES]
    if not cves:
        return None

    kev = load_kev()
    epss = common_utils.fetch_epss_scores(cves) or {}
    entries, findings, steps = [], [], []

    steps.extend(lookup_steps)
    steps.append("CVE {}건에 대해 CISA KEV 목록과 FIRST EPSS를 조회했습니다."
                 .format(len(cves)))

    for index, cve in enumerate(cves):
        detail = fetch_nvd(cve) if with_nvd else {}
        if with_nvd:
            steps.append("{} — NVD에서 CVSS·영향 제품을 조회했습니다{}."
                         .format(cve, "(응답 없음)" if not detail else ""))
            if index < len(cves) - 1:
                time.sleep(NVD_PAUSE_SECONDS)   # 키 없이 30초당 5회 제한
        entry = {
            "cve": cve,
            "kev": kev.get(cve) or {},
            "kev_checked": bool(kev),
            "epss_checked": cve in epss,
            "nvd_checked": bool(detail),
            "epss": epss.get(cve),
            "nvd": detail,
            "url": "https://nvd.nist.gov/vuln/detail/{}".format(cve),
        }
        entries.append(entry)
        findings.extend(_findings_for_cve(entry))

    if kev:
        steps.append("KEV 목록 {}건과 대조했습니다.".format(len(kev)))
    else:
        steps.append("KEV 목록을 가져오지 못해 악용 확인 여부는 판단하지 못했습니다.")

    return {"cves": entries, "findings": findings, "steps": steps,
            "generated_at": common_utils.utc_now_iso()}


def _findings_for_cve(entry):
    """CVE 하나에 대한 판단 — 지금 패치해야 하는지까지 말한다."""
    cve = entry["cve"]
    kev = entry["kev"]
    epss = entry["epss"]
    nvd = entry["nvd"]
    lines = []

    head = "{} — ".format(cve)
    if nvd.get("score") is not None:
        head += "CVSS {} ({})".format(nvd["score"], nvd.get("version") or "?")
    else:
        head += "CVSS 점수는 확인되지 않았습니다"
    if nvd.get("published"):
        head += ", 공개 {}".format(nvd["published"])
    lines.append(head + ".")

    if kev:
        due = kev.get("due") or ""
        overdue = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", due) and due < common_utils.utc_now_iso()[:10])
        lines.append("· CISA KEV에 {} 등재 — 실제 악용이 확인된 취약점입니다{}. 조치 기한은 "
                     "{}입니다(미 연방기관 기준이며 조직 적용 기한은 별도 판단합니다)."
                     .format(kev.get("added") or "?",
                             ", 랜섬웨어 캠페인에서 사용됨" if kev.get("ransomware") else "",
                             (due + " (기한 경과)") if overdue else due or "미지정"))
        if kev.get("action"):
            lines.append("· CISA 권고 조치: {}".format(kev["action"][:180]))
    else:
        lines.append("· KEV {} — 미등재·조회 불가는 실제 악용이 없다는 뜻이 아닙니다.".format(
            "미등재(목록 조회됨)" if entry.get("kev_checked") is True else "조회 상태 미확인"))
    if epss is not None:
        lines.append("· EPSS {:.1%}: 향후 30일 악용 확률 추정입니다. 노출·영향·실제 악용 근거와 "
                     "함께 판단하며, 낮은 값만으로 패치를 미루지 않습니다.".format(epss))
    else:
        lines.append("· EPSS 미확인 — 0%로 취급하지 않습니다.")

    if nvd.get("products"):
        lines.append("· 영향 제품: {}. 자산 목록과 대조해 해당 버전이 있는지 확인합니다."
                     .format(", ".join(nvd["products"][:5])))
    if nvd.get("vector"):
        lines.append("· 공격 벡터: {}".format(nvd["vector"]))
    return lines


def response_material(track):
    """취약점 대응 — 패치 우선순위와 노출 자산 확인 쿼리."""
    if not track:
        return None
    from response_builder import _kql_list, LOOKBACK

    entries = track.get("cves") or []
    if not entries:
        return None
    ids = [entry["cve"] for entry in entries]
    kev_ids = [entry["cve"] for entry in entries if entry.get("kev")]
    high_epss = [entry["cve"] for entry in entries
                 if (entry.get("epss") or 0) >= 0.5 and not entry.get("kev")]

    actions = []
    if kev_ids:
        actions.append("KEV 등재 {}건({})은 실제 악용이 확인된 것이다 — 정규 패치 주기를 "
                       "기다리지 말고 예외 처리로 먼저 올린다.".format(len(kev_ids), ", ".join(kev_ids)))
    if high_epss:
        actions.append("EPSS 50% 이상 {}건({})은 노출 자산을 우선 점검하고 벤더의 악용 "
                       "보고·완화책을 함께 확인한다.".format(len(high_epss), ", ".join(high_epss)))
    actions.append("해당 제품·버전과 외부 노출을 확인한다. 검색 0건이어도 TVM 수집 범위·보존 기간을 "
                   "확인하고 CMDB·SBOM·장비 관리 목록으로 대조한 뒤 영향 여부를 판단한다.")

    queries = [{
        "name": "이 CVE에 노출된 단말·소프트웨어",
        "durable": False,
        "note": "Defender 취약점 관리(TVM)가 수집한 소프트웨어 인벤토리에서 직접 찾는다. "
                "TVM을 쓰지 않으면 자산관리(SAM) 도구의 소프트웨어 목록에 같은 조건을 넣는다.",
        "query": "\n".join([
            "let watchedCves = {};".format(_kql_list(ids)),
            "DeviceTvmSoftwareVulnerabilities",
            "| where CveId in~ (watchedCves)",
            "| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId,",
            "          VulnerabilitySeverityLevel, RecommendedSecurityUpdate",
            "| order by CveId asc, DeviceName asc",
        ]),
    }, {
        "name": "노출 현황 요약(패치 계획용)",
        "durable": False,
        "note": "CVE별로 몇 대가 남았는지 센다. 패치 진행률을 이 쿼리로 추적하면 된다.",
        "query": "\n".join([
            "let watchedCves = {};".format(_kql_list(ids)),
            "DeviceTvmSoftwareVulnerabilities",
            "| where CveId in~ (watchedCves)",
            "| summarize Devices = dcount(DeviceName),",
            "            Software = make_set(strcat(SoftwareName, \" \", SoftwareVersion), 5)",
            "          by CveId, VulnerabilitySeverityLevel",
            "| order by Devices desc",
        ]),
    }]

    blocklists = [{
        "label": "패치 대상 — CVE",
        "note": "KEV·EPSS 기준의 검토 순서입니다. 실제 패치 우선순위는 자산 노출·업무 영향·벤더 권고를 반영합니다.",
        "values": ["{}{}{}".format(
            entry["cve"],
            " [KEV]" if entry.get("kev") else "",
            (" EPSS {:.0%}".format(entry["epss"]) if (entry.get("epss") or 0) >= 0.01
             else " EPSS {:.1%}".format(entry["epss"])) if entry.get("epss") is not None else "")
            for entry in sorted(entries,
                                key=lambda e: (0 if e.get("kev") else 1, -(e.get("epss") or 0)))],
    }]
    products = []
    for entry in entries:
        for product in (entry.get("nvd") or {}).get("products") or []:
            if product not in products:
                products.append(product)
    if products:
        blocklists.append({
            "label": "점검 대상 — 영향 제품·버전",
            "note": "NVD 영향 제품 목록은 누락·지연될 수 있습니다. 자산 목록과 벤더 권고를 함께 대조합니다.",
            "values": products[:20],
        })

    return {"blocklists": blocklists, "kql": queries, "actions": actions}
