"""CVE 탭의 취약점 인시던트 — 보유 제품에 실제로 해당하는 CVE만 인시던트로 띄운다.

기준 네 가지를 각각 충족·미확인·불충족으로 판정한다(추정은 포함 쪽으로만 작동).
  1 사용 중인 제품  2 원격 공격 가능(AV:N만)  3 취약 버전·기능 사용  4 외부 노출
  - 어느 기준이든 불충족(확정)  → 만들지 않음(악용 확인 건은 관찰 목록)
  - 기준 1이 추정·미확인        → 후보 목록(14일 뒤 만료)
  - 기준 1 확정 + 나머지 미확인 → '확인 필요' 인시던트
  - 네 기준 모두 충족           → 확정 인시던트
악용 사실이 있어도 기준 2·4를 건너뛰지 않는다(2026-10-21 결정).

자산별 버전·사용 기능·노출 위치·핵심 여부는 git 밖의 state/inventory_v2.json에 둔다
(형식: assets/inventory_v2.example.json). 없으면 기준 3·4는 미확인으로 남는다.
판정 결과는 state/vuln_incidents.json에 쌓여 날짜가 바뀌어도 이어진다.
"""

import argparse
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import common_utils

STATE_PATH = common_utils.STATE_DIR / "vuln_incidents.json"
INVENTORY_V2_PATH = common_utils.STATE_DIR / "inventory_v2.json"
VECTOR_CACHE_PATH = common_utils.STATE_DIR / "cve_vector_cache.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

MAX_VECTOR_LOOKUPS = 15      # 회차당 NVD 조회 상한(키 없이 6.5초 간격)
MAX_POC_LOOKUPS = 10         # 회차당 GitHub 검색 상한(비인증 분당 10회)
CANDIDATE_DAYS = 14
OBSERVE_DAYS = 30
INCIDENT_KEEP_DAYS = 120
DUE_DAYS = {"긴급": 3, "높음": 14, "보통": 30, "낮음": 90}
GRADE_RANK = {"긴급": 0, "높음": 1, "보통": 2, "낮음": 3}
EXPOSURE_LABELS = {"internet": "인터넷", "partner_vpn": "협력사 VPN", "internal_user": "내부 사용자망",
                   "mgmt_segment": "관리망", "isolated": "격리망"}
GATES = (("in_use", "사용 중인 제품"), ("remote", "원격 공격 가능"),
         ("vulnerable", "취약 버전·기능 사용"), ("exposed", "외부 노출"))
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
AV_RE = re.compile(r"\bAV:([NALP])\b")
METRIC_RE = re.compile(r"\b(AC|AT|PR|UI|S|C|I|A|VC|VI|VA):([A-Z])\b")
# 권고에 '이 설정일 때만' 같은 전제가 있으면 기능 사용 여부를 따로 물어야 한다.
FEATURE_HINT_RE = re.compile(
    r"\b(?:when|if|only if|where)\b[^.]{0,80}\b(?:is |are )?(?:enabled|configured|exposed|in use|turned on)\b"
    r"|설정된 경우|활성화된 경우|사용하는 경우", re.I)
VENDOR_SOURCES = {"cisa_kev", "msrc", "cisco_psirt", "fortinet_psirt", "paloalto_psirt", "kisa"}


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def _norm(text):
    return " ".join(re.sub(r"[_:]", " ", str(text or "").lower()).split())


def load_inventory(path=None):
    """인벤토리 v1(이름·별칭) 위에 v2(CPE·버전·기능·노출)를 얹는다."""
    overlay = (_load_json(path or INVENTORY_V2_PATH, {}) or {}).get("products") or {}
    products = []
    for item in common_utils._load_inventory_items(common_utils.INVENTORY_FILE):
        extra = overlay.get(item["name"]) or {}
        exposure = str(extra.get("exposure") or "").strip().lower()
        products.append({
            "name": item["name"], "aliases": item.get("aliases") or [item["name"]],
            "cpe": [str(c).strip().lower() for c in extra.get("cpe") or [] if str(c).strip()],
            "version": str(extra.get("version") or "").strip(),
            "features": [str(f).strip() for f in extra.get("features") or [] if str(f).strip()],
            "exposure": exposure if exposure in EXPOSURE_LABELS else "",
            "core": bool(extra.get("core")),
            "description": str(extra.get("description") or "").strip(),
        })
    return products


def _cpe_phrases(product):
    """'cisco:ios_xe' → ('cisco ios xe', False), 'f5:big-ip*' → ('f5 big-ip', True)."""
    out = []
    for cpe in product["cpe"]:
        prefix = cpe.endswith("*")
        out.append((_norm(cpe.rstrip("*")), prefix, _norm(cpe.rstrip("*").split(":", 1)[-1])))
    return out


def _alias_hit(product, text):
    text = str(text or "").lower()
    return any(re.search(r"(?<![a-z0-9])" + re.escape(alias.lower()) + r"(?![a-z0-9])", text)
               for alias in product["aliases"] if alias)


# ── 버전 비교 ────────────────────────────────────────────────────────────────
def _version_key(value):
    parts = re.findall(r"\d+|[a-z]+", str(value or "").lower())
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts)


def version_in_range(version, affected):
    """affected: '>= 7.2.0, < 7.2.9' 또는 '7.2.8'. 판정 못 하면 None."""
    version = str(version or "").strip()
    affected = str(affected or "").strip()
    if not version or not affected:
        return None
    current = _version_key(version)
    if not current:
        return None
    bounds = re.findall(r"(>=|<=|>|<)\s*([0-9][\w.()\-]*)", affected)
    if not bounds:
        return current == _version_key(affected) if re.match(r"^[0-9]", affected) else None
    for op, raw in bounds:
        other = _version_key(raw)
        ok = {">=": current >= other, ">": current > other,
              "<=": current <= other, "<": current < other}[op]
        if not ok:
            return False
    return True


# ── CVE별 자료 모으기 ─────────────────────────────────────────────────────────
def collect_cves(events):
    """이벤트를 CVE 번호별로 묶는다."""
    groups = {}
    for event in events or []:
        cves = [str(c).upper() for c in event.get("cves") or [] if CVE_RE.match(str(c))]
        for cve in dict.fromkeys(cves):
            # 여러 CVE를 함께 다룬 기사는 본문에 이 CVE가 없으면 출처로만 쓴다.
            blob = " ".join([event.get("title") or "", event.get("summary") or ""]).upper()
            if len(cves) > 1 and cve not in blob and event.get("source") not in ("nvd", "cisa_kev"):
                continue
            groups.setdefault(cve, []).append(event)
    return groups


def _vector_of(cve, events, cache):
    """수집 이벤트에 저장된 벡터를 먼저, 없으면 NVD 조회 캐시를 쓴다."""
    for event in sorted(events, key=lambda e: e.get("source") != "nvd"):
        vector = str(event.get("cvss_vector") or "").strip()
        if vector:
            return vector, "NVD" if event.get("source") == "nvd" else common_utils.source_label(event.get("source"))
    hit = cache.get(cve) or {}
    return (hit.get("vector") or "", "NVD(조회)") if hit.get("vector") else ("", "")


def _metrics(vector):
    return dict(METRIC_RE.findall(vector or ""))


def describe_conditions(vector):
    """CVSS 벡터를 공격 조건 문장으로 푼다."""
    if not vector:
        return ["CVSS 벡터가 아직 없어 공격 조건을 확정하지 못했습니다."]
    av = (AV_RE.search(vector) or [None, ""])[1]
    m = _metrics(vector)
    lines = [{"N": "네트워크로 원격 공격할 수 있습니다.", "A": "같은 네트워크 구간(인접망)에서만 공격할 수 있습니다.",
              "L": "로컬 접근이나 사용자가 파일을 여는 등의 실행이 필요합니다.",
              "P": "장비에 물리적으로 접근해야 합니다."}.get(av, "공격 경로 정보가 없습니다.")]
    lines.append({"N": "인증 없이 공격할 수 있습니다.", "L": "낮은 권한의 계정이 필요합니다.",
                  "H": "관리자 수준 권한이 필요합니다."}.get(m.get("PR"), ""))
    lines.append({"N": "사용자 행동 없이 공격이 성립합니다.", "R": "사용자가 링크를 누르는 등 행동해야 합니다.",
                  "P": "사용자의 수동적 상호작용이 필요합니다.", "A": "사용자의 능동적 상호작용이 필요합니다."}.get(m.get("UI"), ""))
    if m.get("AC") == "H" or m.get("AT") == "P":
        lines.append("특정 설정·조건이 갖춰져야 공격이 성립합니다.")
    impact = [name for key, name in (("C", "기밀성"), ("I", "무결성"), ("A", "가용성"),
                                      ("VC", "기밀성"), ("VI", "무결성"), ("VA", "가용성")) if m.get(key) == "H"]
    if impact:
        lines.append("성공하면 " + "·".join(dict.fromkeys(impact)) + "에 큰 피해가 납니다.")
    return [line for line in lines if line]


# ── 기준 판정 ────────────────────────────────────────────────────────────────
def _gate(state, basis, question=""):
    row = {"state": state, "basis": basis}
    if question:
        row["question"] = question
    return row


def judge_in_use(product, events):
    phrases = _cpe_phrases(product)
    for event in events:
        for package in event.get("affected_packages") or []:
            name = _norm(package.get("product") if isinstance(package, dict) else "")
            for phrase, prefix, _ in phrases:
                if name == phrase or (prefix and name.startswith(phrase)):
                    return _gate("met", "NVD 영향 제품(CPE)이 '{}'와 일치".format(package.get("product")))
    for event in events:
        if event.get("source") not in VENDOR_SOURCES:
            continue
        for name in event.get("affected_products") or []:
            norm = _norm(name)
            for _, _, product_phrase in phrases:
                if product_phrase and re.search(r"(?<![a-z0-9])" + re.escape(product_phrase) + r"(?![a-z0-9])", norm):
                    return _gate("met", "{} 권고의 영향 제품 '{}'".format(
                        common_utils.source_label(event.get("source")), name))
    for event in events:
        for name in list(event.get("affected_products") or []) + [
                (p.get("product") if isinstance(p, dict) else "") for p in event.get("affected_packages") or []]:
            if _alias_hit(product, name):
                return _gate("estimated", "영향 제품 '{}'가 인벤토리 별칭과 일치(제품 단위 확인 필요)".format(name),
                             "'{}' 중 이 제품을 실제로 쓰는지 확인".format(product["name"]))
    for event in events:
        if product["name"] in (event.get("matched_assets") or []):
            gate = _gate("estimated", "설명문에 인벤토리 별칭이 나옴(제품 단위 확인 필요)",
                         "'{}' 중 이 제품을 실제로 쓰는지 확인".format(product["name"]))
            gate["text_only"] = True
            return gate
    return None


def judge_remote(vector):
    av = (AV_RE.search(vector or "") or [None, ""])[1]
    if av == "N":
        return _gate("met", "CVSS 공격 경로 AV:N(네트워크)")
    if av in ("A", "L", "P"):
        label = {"A": "인접망", "L": "로컬", "P": "물리"}[av]
        return _gate("not_met", "CVSS 공격 경로 AV:{}({}) — 원격 공격으로 보지 않음".format(av, label))
    return _gate("unknown", "CVSS 벡터 없음", "NVD·벤더의 공격 경로(AV) 공개 대기")


def judge_vulnerable(product, events, text):
    ranges = []
    phrases = _cpe_phrases(product)
    for event in events:
        for package in event.get("affected_packages") or []:
            if not isinstance(package, dict):
                continue
            name = _norm(package.get("product"))
            if not phrases or any(name == p or (prefix and name.startswith(p)) for p, prefix, _ in phrases):
                if package.get("affected"):
                    ranges.append(package["affected"])
    feature = FEATURE_HINT_RE.search(text or "")
    feature_q = "권고에 설정·기능 조건이 있음 — 해당 기능을 쓰는지 확인" if feature else ""
    if not product["version"]:
        return _gate("unknown", "설치 버전 정보 없음" + (" · 영향 범위 " + ", ".join(ranges[:2]) if ranges else ""),
                     "설치 버전 확인" + (" · " + feature_q if feature_q else ""))
    if not ranges:
        return _gate("unknown", "설치 버전 {} · 영향 범위가 아직 공개되지 않음".format(product["version"]),
                     "벤더 권고의 영향 버전과 대조")
    verdicts = [version_in_range(product["version"], r) for r in ranges]
    if any(v is True for v in verdicts):
        hit = ranges[verdicts.index(True)]
        if feature_q:
            return _gate("unknown", "설치 버전 {}이 영향 범위({})에 듦".format(product["version"], hit), feature_q)
        return _gate("met", "설치 버전 {}이 영향 범위({})에 듦".format(product["version"], hit))
    # 범위 밖이어도 수집된 범위가 잘렸을 수 있어 확정하지 않는다.
    return _gate("unknown", "설치 버전 {}이 수집된 영향 범위 밖({})".format(product["version"], ", ".join(ranges[:2])),
                 "벤더 권고의 수정 버전과 대조해 해당 없음 확인")


def judge_exposed(product):
    exposure = product["exposure"]
    if not exposure:
        return _gate("unknown", "노출 위치 정보 없음", "인터넷에 열린 인터페이스인지 확인")
    label = EXPOSURE_LABELS[exposure]
    if exposure == "internet":
        return _gate("met", "노출 위치: 인터넷")
    if exposure == "isolated":
        return _gate("not_met", "노출 위치: 격리망")
    if product["core"]:
        return _gate("met", "노출 위치: {} · 핵심 자산이라 인시던트로 올림".format(label))
    return _gate("not_met", "노출 위치: {}(외부 노출 아님)".format(label))


def classify(gates):
    states = {key: gates[key]["state"] for key in gates}
    if any(state == "not_met" for state in states.values()):
        return "dropped"
    if states["in_use"] != "met":
        return "candidate"
    if any(state == "unknown" for state in states.values()):
        return "needs_check"
    return "confirmed"


def grade(item, product, gates):
    exploited = item["kev"] or item["vendor_exploited"]
    exposure = product["exposure"] or "internet"   # 모르면 인터넷으로 보고 높게 잡는다
    outside = exposure == "internet"
    m = _metrics(item["vector"])
    automatable = (AV_RE.search(item["vector"] or "") or [None, ""])[1] == "N" and m.get("PR") == "N" and m.get("UI") == "N"
    severe = any(m.get(k) == "H" for k in ("C", "I", "VC", "VI")) or (item.get("cvss") or 0) >= 9
    if exploited and (outside or product["core"]):
        return "긴급"
    if exploited or (outside and automatable and severe) or (outside and (item.get("epss_percentile") or 0) >= 0.95):
        return "높음"
    if exposure == "mgmt_segment":
        return "낮음"
    return "보통"


# ── 외부 조회(테스트에서 바꿔 끼운다) ──────────────────────────────────────────
def fetch_vector(cve):
    import vuln_hunter
    data = vuln_hunter.fetch_nvd(cve) or {}
    return {"vector": data.get("vector") or "", "fetched_at": _iso(_now())}


def fetch_epss(cves):
    out = {}
    ids = sorted(set(cves))
    for start in range(0, len(ids), 100):
        url = "{}?cve={}".format(EPSS_API_URL, ",".join(urllib.parse.quote(c) for c in ids[start:start + 100]))
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "boannews-mail-vuln/1.0"})
            with urllib.request.urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception as error:
            print("[-] EPSS 조회 실패: {}".format(error))
            continue
        for row in data.get("data") or []:
            try:
                out[row["cve"]] = {"score": float(row["epss"]), "percentile": float(row["percentile"]),
                                   "date": row.get("date") or ""}
            except (KeyError, TypeError, ValueError):
                continue
    return out


def fetch_poc(cve):
    return common_utils.check_github_poc(cve)


# ── 요약 행과 분석 ────────────────────────────────────────────────────────────
def summarize(cve, events):
    item = {"cve": cve, "kev": False, "vendor_exploited": False, "cvss": None, "severity": "",
            "published": "", "kev_added": "", "kev_due": "", "vendor_published": "", "ransomware": False,
            "summary": "", "summary_en": "", "title": "", "cwes": [], "references": [], "remediation": "",
            "remediation_url": "", "versions": [], "products": [], "sources": []}
    for event in events:
        source = event.get("source") or ""
        label = common_utils.source_label(source)
        if label and label not in item["sources"]:
            item["sources"].append(label)
        if source == "cisa_kev":
            item["kev"] = True
            item["kev_added"] = item["kev_added"] or str(event.get("published_at") or "")[:10]
            item["kev_due"] = item["kev_due"] or event.get("due_date") or ""
            item["ransomware"] = item["ransomware"] or event.get("ransomware_use") is True
        item["kev"] = item["kev"] or bool(event.get("kev"))
        if source == "msrc" and event.get("exploitation_status") == "active":
            item["vendor_exploited"] = True
        if source == "nvd":
            if isinstance(event.get("score"), (int, float)):
                item["cvss"] = float(event["score"])
            item["severity"] = item["severity"] or str(event.get("severity") or "").upper()
            item["published"] = item["published"] or str(event.get("published_at") or "")[:10]
            item["summary_en"] = item["summary_en"] or event.get("summary") or ""
        elif source in VENDOR_SOURCES and event.get("published_at"):
            date = str(event["published_at"])[:10]
            if not item["vendor_published"] or date < item["vendor_published"]:
                item["vendor_published"] = date
        text = event.get("ai_summary") or ""
        if isinstance(text, str) and text and not item["summary"]:
            item["summary"] = text
        if source in VENDOR_SOURCES and not item["title"]:
            item["title"] = re.sub(r"^\s*CVE-\d{4}-\d{4,7}\s*[-:–]\s*", "", event.get("title") or "")[:120]
        for cwe in event.get("cwes") or []:
            if cwe not in item["cwes"]:
                item["cwes"].append(cwe)
        url = event.get("url") or ""
        if url.startswith("http") and url not in item["references"] and len(item["references"]) < 4:
            item["references"].append(url)
        if event.get("remediation") and not item["remediation"]:
            item["remediation"], item["remediation_url"] = event["remediation"], url
        for package in event.get("affected_packages") or []:
            if isinstance(package, dict) and package.get("product"):
                row = {"product": package["product"], "affected": package.get("affected") or "",
                       "fixed": package.get("fixed") or "", "source": label}
                if row not in item["versions"] and len(item["versions"]) < 8:
                    item["versions"].append(row)
        for name in event.get("affected_products") or []:
            if name and name not in item["products"] and len(item["products"]) < 3:
                item["products"].append(name)
    scores = [float(e["epss"]) for e in events if isinstance(e.get("epss"), (int, float))]
    if scores:
        item["epss"] = max(scores)
    if not item["summary"]:
        item["summary"] = item["summary_en"] or next((e.get("summary") for e in events if e.get("summary")), "")
    item["summary"] = " ".join(str(item["summary"]).split())[:600]
    item["summary_en"] = " ".join(str(item["summary_en"]).split())[:600]
    return item


def analysis(item, product, gates, case):
    exploited = item["kev"] or item["vendor_exploited"]
    poc = case.get("poc") or {}
    if exploited:
        maturity = {"level": "in_the_wild", "label": "실제 악용 확인", "basis": "CISA KEV" if item["kev"] else "MSRC"}
    elif poc.get("count"):
        maturity = {"level": "candidate", "label": "PoC 후보(미검증)", "basis": "GitHub 저장소 {}건".format(poc["count"]),
                    "url": poc.get("latest_url") or ""}
    elif poc:
        maturity = {"level": "none_found", "label": "공개 PoC 찾지 못함", "basis": "GitHub 검색 " + (poc.get("checked_at") or "")[:10]}
    else:
        maturity = {"level": "unchecked", "label": "아직 조회하지 않음", "basis": ""}
    outside = product["exposure"] in ("", "internet")
    return {
        "product": {"name": product["name"], "description": product["description"],
                    "advisory_products": item["products"], "exposure": EXPOSURE_LABELS.get(product["exposure"], "미확인"),
                    "core": product["core"]},
        "evidence": [{"key": key, "label": label, **gates[key]} for key, label in GATES],
        "dates": {"cve_published": item["published"], "vendor_published": item["vendor_published"],
                  "kev_added": item["kev_added"], "kev_due": item["kev_due"],
                  "first_seen": (case.get("first_seen") or "")[:10]},
        "scores": {"cvss": item["cvss"], "severity": item["severity"], "vector": item["vector"],
                   "vector_source": item.get("vector_source") or "", "epss": item.get("epss"),
                   "epss_percentile": item.get("epss_percentile"), "kev": item["kev"],
                   "ransomware": item["ransomware"]},
        "description": {"summary": item["summary"], "original": item["summary_en"] if item["summary_en"] != item["summary"] else "",
                        "cwes": item["cwes"]},
        "conditions": describe_conditions(item["vector"]),
        "remediation": {"versions": item["versions"], "action": item["remediation"],
                        "action_url": item["remediation_url"], "due": case.get("due") or "",
                        "maturity": maturity},
        "compromise_check": ("실제 악용이 확인된 취약점입니다. 패치 전에 벤더 권고의 침해 지표(IoC)와 무결성 점검 도구로 "
                             "이미 침해됐는지 먼저 확인하세요." if exploited and outside else ""),
        "references": item["references"],
    }


# ── 한 회차 실행 ──────────────────────────────────────────────────────────────
def evaluate(events, state=None, inventory=None, now=None, lookups=True):
    """이벤트를 판정해 상태를 갱신하고 공개용 페이로드를 돌려준다."""
    now = now or _now()
    state = state if state is not None else _load_json(STATE_PATH, {})
    state.setdefault("cases", {})
    state.setdefault("seq", {})
    inventory = inventory if inventory is not None else load_inventory()
    vector_cache = _load_json(VECTOR_CACHE_PATH, {}) if lookups else {}
    groups = collect_cves(events)

    evaluations = []
    for cve, cve_events in groups.items():
        matches = [(product, judge_in_use(product, cve_events)) for product in inventory]
        matches = [(p, g) for p, g in matches if g]
        # 설명문에 별칭만 나온 건은 오탐이 대부분이다(실측 30일 후보 591건) — 실제 악용
        # 확인 건만 남긴다. 같은 CVE에서 제품이 확정되면 다른 제품의 추정 매칭은 뺀다.
        exploited = any(e.get("source") == "cisa_kev" or e.get("kev") for e in cve_events)
        matches = [(p, g) for p, g in matches if not g.get("text_only") or exploited]
        if any(g["state"] == "met" for _, g in matches):
            matches = [(p, g) for p, g in matches if g["state"] == "met"]
        if not matches:
            continue
        evaluations.append((cve, cve_events, matches))

    # 벡터가 없는 후보만 NVD에서 받아 온다(회차 상한).
    if lookups:
        def stale(cve):
            hit = vector_cache.get(cve)
            if not hit:
                return True
            fetched = _parse_time(hit.get("fetched_at") or "")
            # NVD 분석이 늦어 빈 값이 온 건은 하루 뒤 다시 묻는다.
            return not hit.get("vector") and (not fetched or now - fetched > timedelta(days=1))
        missing = [(cve, any(g["state"] == "met" for _, g in matches)) for cve, evs, matches in evaluations
                   if not _vector_of(cve, evs, vector_cache)[0] and stale(cve)]
        missing = [cve for cve, _ in sorted(missing, key=lambda row: not row[1])]
        for cve in missing[:MAX_VECTOR_LOOKUPS]:
            try:
                vector_cache[cve] = fetch_vector(cve)
            except Exception as error:
                print("[-] {} 벡터 조회 실패: {}".format(cve, error))
        _save_json(VECTOR_CACHE_PATH, vector_cache)

    rows = []
    for cve, cve_events, matches in evaluations:
        item = summarize(cve, cve_events)
        item["vector"], item["vector_source"] = _vector_of(cve, cve_events, vector_cache)
        text = " ".join([item["summary_en"], item["summary"]])
        for product, in_use in matches:
            gates = {"in_use": in_use, "remote": judge_remote(item["vector"]),
                     "vulnerable": judge_vulnerable(product, cve_events, text), "exposed": judge_exposed(product)}
            rows.append((cve, item, product, gates, classify(gates)))

    if lookups and rows:
        epss = fetch_epss([cve for cve, *_ in rows])
        for cve, item, *_ in rows:
            hit = epss.get(cve)
            if hit:
                item["epss"], item["epss_percentile"] = hit["score"], hit["percentile"]

    stamp = _iso(now)
    poc_budget = MAX_POC_LOOKUPS if lookups else 0
    for cve, item, product, gates, kind in rows:
        key = "{}|{}".format(cve, product["name"])
        case = state["cases"].get(key) or {}
        if kind == "dropped" and not (item["kev"] or item["vendor_exploited"]):
            if case.get("kind") in ("confirmed", "needs_check"):
                case.update(kind="dropped", updated_at=stamp)
            continue
        if kind == "dropped":
            kind = "observe"
        if not case:
            case = {"cve": cve, "product": product["name"], "first_seen": stamp}
        if kind in ("confirmed", "needs_check") and not case.get("id"):
            year = now.strftime("%Y")
            state["seq"][year] = state["seq"].get(year, 0) + 1
            case["id"] = "VC-{}-{:04d}".format(year, state["seq"][year])
            case["opened_at"] = stamp
        level = grade(item, product, gates)
        opened = _parse_time(case.get("opened_at") or stamp) or now
        due = opened + timedelta(days=DUE_DAYS[level])
        if level == "긴급" and item["kev_due"]:
            kev_due = _parse_time(item["kev_due"] + "T23:59:59+00:00")
            if kev_due and kev_due < due:
                due = kev_due
        if kind in ("confirmed", "needs_check") and poc_budget and not (item["kev"] or item["vendor_exploited"]) \
                and not case.get("poc"):
            poc_budget -= 1
            try:
                found = fetch_poc(cve)
                if found is not None:
                    case["poc"] = dict(found, checked_at=stamp)
            except Exception as error:
                print("[-] {} PoC 조회 실패: {}".format(cve, error))
        case.update(kind=kind, grade=level, due=due.strftime("%Y-%m-%d"), updated_at=stamp,
                    title=item["title"] or (item["products"] or [""])[0] or product["name"] + " 취약점",
                    gates={k: gates[k] for k in gates})
        case["analysis"] = analysis(item, product, gates, case)
        state["cases"][key] = case

    return state, public_view(state, now)


def public_view(state, now=None):
    now = now or _now()
    incidents, candidates, observe = [], [], []
    for case in (state.get("cases") or {}).values():
        seen = _parse_time(case.get("updated_at") or case.get("first_seen")) or now
        age = (now - seen).days
        kind = case.get("kind")
        row = {key: case.get(key) for key in ("id", "cve", "product", "title", "grade", "due", "first_seen",
                                               "opened_at", "kind", "gates")}
        row = {k: v for k, v in row.items() if v not in (None, "")}
        if kind in ("confirmed", "needs_check") and age <= INCIDENT_KEEP_DAYS:
            row["analysis"] = case.get("analysis") or {}
            incidents.append(row)
        elif kind == "candidate" and age <= CANDIDATE_DAYS:
            candidates.append(row)
        elif kind == "observe" and age <= OBSERVE_DAYS:
            row["analysis"] = case.get("analysis") or {}
            observe.append(row)
    today = now.strftime("%Y-%m-%d")
    incidents.sort(key=lambda r: (GRADE_RANK.get(r.get("grade"), 9), r.get("due") or "", r.get("id") or ""))
    candidates.sort(key=lambda r: (GRADE_RANK.get(r.get("grade"), 9), r.get("cve") or ""))
    return {
        "generated_at": _iso(now),
        "counts": {"open": len(incidents),
                   "urgent": sum(r.get("grade") == "긴급" for r in incidents),
                   "overdue": sum((r.get("due") or "9999") < today for r in incidents),
                   "needs_check": sum(r.get("kind") == "needs_check" for r in incidents),
                   "candidates": len(candidates), "observe": len(observe)},
        "incidents": incidents, "candidates": candidates[:60], "observe": observe[:30],
    }


# ── ELK 내보내기 ──────────────────────────────────────────────────────────────
# 판정은 여기서 하고, 결과는 JSONL 파일로만 남긴다. security_lab의 Logstash가 이 폴더를
# 읽기 전용으로 마운트해 vuln-cves·vuln-exposure 인덱스에 문서 ID 고정으로 넣는다 —
# 이 프로젝트에 ELK 자격증명을 두지 않고, ELK가 꺼져 있어도 파일이 남아 이어 받는다.
EXPORT_DIR = common_utils.DATA_DIR / "vuln"
CVES_EXPORT = EXPORT_DIR / "vuln_cves.jsonl"
EXPOSURE_EXPORT = EXPORT_DIR / "vuln_exposure.jsonl"
EXPORT_MAX_BYTES = 50 * 1024 * 1024
SEVERITY = {"긴급": ("critical", 99), "높음": ("high", 73), "보통": ("medium", 47), "낮음": ("low", 21)}


def _digest(value):
    import hashlib
    return hashlib.sha1(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _append(path, docs):
    if not docs:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > EXPORT_MAX_BYTES:
        # Logstash가 이미 읽은 옛 줄은 필요 없다. 파일을 새로 시작하면 tail이 처음부터 다시 읽는다.
        path.replace(path.with_suffix(".jsonl.old"))
    with path.open("a", encoding="utf-8") as file:
        for doc in docs:
            file.write(json.dumps(doc, ensure_ascii=False) + "\n")


def cve_doc(item, vector_source=""):
    av = (AV_RE.search(item.get("vector") or "") or [None, ""])[1]
    return {
        "cve": item["cve"], "title": item["title"], "summary": item["summary"], "cvss": item["cvss"],
        "severity": item["severity"], "vector": item.get("vector") or "", "attack_vector": av,
        "vector_source": vector_source, "cwes": item["cwes"], "epss": item.get("epss"),
        "epss_percentile": item.get("epss_percentile"), "kev": item["kev"], "kev_added": item["kev_added"] or None,
        "kev_due": item["kev_due"] or None, "ransomware": item["ransomware"],
        "published": item["published"] or None, "vendor_published": item["vendor_published"] or None,
        "products": item["products"], "sources": item["sources"], "references": item["references"],
    }


def exposure_doc(key, case):
    gates = case.get("gates") or {}
    level, risk = SEVERITY.get(case.get("grade"), ("low", 21))
    return {
        "case_key": key, "case_id": case.get("id") or "", "cve": case.get("cve"), "product": case.get("product"),
        "kind": case.get("kind"), "grade": case.get("grade"), "severity": level, "risk_score": risk,
        "due": case.get("due") or None, "title": case.get("title") or "",
        "first_seen": case.get("first_seen") or None, "opened_at": case.get("opened_at") or None,
        "gate": {name: (gates.get(name) or {}).get("state") or "unknown" for name, _ in GATES},
        "questions": [g.get("question") for g in gates.values() if isinstance(g, dict) and g.get("question")],
        "exploited": bool(((case.get("analysis") or {}).get("scores") or {}).get("kev")),
        "analysis": case.get("analysis") or {},
    }


def export_for_elk(state, events, now=None):
    """바뀐 CVE·판정만 덧붙인다. @timestamp는 내용이 바뀐 시각이라 탐지 규칙이 새 변화만 본다."""
    now = now or _now()
    stamp = _iso(now)
    seen = state.setdefault("exported", {"cves": {}, "exposure": {}})
    vector_cache = _load_json(VECTOR_CACHE_PATH, {})
    cve_docs = []
    for cve, cve_events in collect_cves(events).items():
        item = summarize(cve, cve_events)
        item["vector"], source = _vector_of(cve, cve_events, vector_cache)
        body = cve_doc(item, source)
        digest = _digest(body)
        if seen["cves"].get(cve) != digest:
            seen["cves"][cve] = digest
            cve_docs.append({"@timestamp": stamp, "doc_id": cve, "vuln": body})
    exposure_docs = []
    for key, case in (state.get("cases") or {}).items():
        body = exposure_doc(key, case)
        digest = _digest({k: v for k, v in body.items() if k != "analysis"})
        if seen["exposure"].get(key) != digest:
            seen["exposure"][key] = digest
            exposure_docs.append({"@timestamp": stamp, "doc_id": key.replace("|", "__"), "vuln": body})
    _append(CVES_EXPORT, cve_docs)
    _append(EXPOSURE_EXPORT, exposure_docs)
    return len(cve_docs), len(exposure_docs)


def run(events, lookups=True):
    state, view = evaluate(events, lookups=lookups)
    try:
        exported = export_for_elk(state, events)
        print("[+] ELK 내보내기: CVE {}건, 판정 {}건".format(*exported))
    except OSError as error:
        print("[-] ELK 내보내기 실패(판정은 저장됨): {}".format(error))
    _save_json(STATE_PATH, state)
    return view


def main():
    parser = argparse.ArgumentParser(description="취약점 인시던트 판정(백필·점검용)")
    parser.add_argument("--days", type=int, default=30, help="최근 N일 이벤트로 판정")
    parser.add_argument("--no-lookups", action="store_true", help="NVD·EPSS·GitHub 조회 없이 판정")
    args = parser.parse_args()
    since = _now() - timedelta(days=args.days)
    events = []
    with (common_utils.DATA_DIR / "events.jsonl").open(encoding="utf-8") as file:
        for line in file:
            if '"cves": []' in line:
                continue
            event = json.loads(line)
            moment = _parse_time(event.get("fetched_at") or "")
            if moment and moment >= since:
                events.append(event)
    view = run(events, lookups=not args.no_lookups)
    print(json.dumps(view["counts"], ensure_ascii=False))


if __name__ == "__main__":
    main()
