"""Offline incident triage. Signals prioritize review; they never authorize publication."""

import hashlib
import html
import json
import re
import unicodedata
from datetime import date
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

POLICY_PATH = Path(__file__).resolve().parent.parent / "assets" / "incident_archive_policy.json"
CLASSIFIER_VERSION = 5
# "고객 정보 2만 5천 건 유출"처럼 정보와 유출 사이에 수치가 끼는 제목도 사고 표현으로 본다.
INCIDENT_RE = re.compile(
    r"침해\s*사고|정보\s*(?:유출|탈취|판매)|정보[^.…]{0,12}유출|데이터\s*유출|해킹|디도스|DDoS|랜섬웨어|털렸|뚫렸|뚫려|"
    r"전산망\s*(?:마비|공격)|사이버\s*공격|data\s*breach|ransomware", re.I)
# 사고 보도가 아닌 글: 훈련·행사, 칼럼·기자수첩·연재, 개인 이름을 단 기고 꼭지("[OOO의 …]"), 주간 동향.
EXCLUDE_RE = re.compile(r"모의\s*훈련|모의\s*해킹|웨비나|세미나|채용|제품\s*출시|칼럼|기고|論하다|주의보|"
                        r"기자수첩|연재|소설|미리보기|\d+\s*주차|^\[[^]]*의\s[^]]*\]|공동\s*경보|권고문|동향\s*보고서")
# 업체 사업 소식. "공급망 공격"·"공격 캠페인"은 사고 보도에도 쓰여 제외 대상에서 뺀다.
PROMO_RE = re.compile(r"탐지\s*가능|솔루션\s*(?:출시|선보|공개|구축)|유출\s*전\s*이상|신제품|예방\s*기술|"
                      r"출시|총판|공급(?!망)|계약\s*체결|수상|성료|개최|시연|참가|시장\s*공략|맞손|손잡고|업무\s*협약|MOU|"
                      r"보고서\s*발표|탑재|대회|우승|선정|자격증")
KOREA_EN_RE = re.compile(r"\b(?:South\s+)?Korea(?:n)?\b", re.I)
CONTEXT_RE = re.compile(r"긴급\s*(?:점검)?회의|회의\s*소집|종합\s*분석|연쇄\s*침해|조사\s*속도|처리\s*원칙|"
                        r"유출\s*뒤가|불법유통\s*게시물|통계|실태\s*조사|왜.+반복|조사\s*정책")
FOLLOWUP_RE = re.compile(r"조사\s*결과|수사\s*결과|과징금|제재|소송|배상|보상|후속|추가\s*유출|정정|복구|재발\s*방지|사고\s*이후")
NEW_RE = re.compile(r"또\s*(?:다시|유출|해킹)|재차|새로운\s*(?:침해|해킹|유출)|다시\s*(?:유출|해킹)")
ALLEGED_RE = re.compile(r"주장|의혹|정황|추정|가능성|미확인|확인되지|확인되지\s*않|확인된\s*바\s*없")
DOMESTIC_RE = re.compile(r"국내|대한민국|한국|韓|금융위원회|개인정보위|과기정통부")
FOREIGN_RE = re.compile(r"^(?:\[[^]]+\]\s*)?(?:미국|영국|일본|중국|러시아|독일|프랑스|호주|인도|美|英|日|中|獨)(?:\s|의\s|,)")
# 제목 쉼표 앞이 기관명처럼 보여도 인용문·말줄임표·기간 표현이면 기관이 아니다.
NOT_ORG_RE = re.compile(r"[“”\"'‘’]|\.\.\.|…|상반기|하반기|\d{4}\s*년")
GENERIC_ORG_RE = re.compile(r"\s|·|기관$|사업자|언론사|방송사")
FOLLOWUP_WINDOW_DAYS = 30
CATEGORY_PATTERNS = (
    ("ransomware", r"랜섬웨어|ransomware"),
    ("ddos", r"디도스|DDoS"),
    ("destruction", r"전산망\s*마비|시스템\s*파괴|파일\s*삭제"),
    ("data_breach", r"유출|탈취|data\s*breach"),
)
CATEGORY_LABELS = {"ransomware": "랜섬웨어", "ddos": "서비스 마비", "destruction": "시스템 파괴",
                   "data_breach": "개인정보 유출", "intrusion": "침해사고"}


@lru_cache(maxsize=1)
def policy():
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def clean(value):
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", html.unescape(str(value or "")))).strip()


def normalized(value):
    return re.sub(r"[\W_]+", "", clean(value)).casefold()


@lru_cache(maxsize=1024)
def _normalized_name(name):
    return normalized(name)


def contains_name(text, name, flat=None):
    if re.fullmatch(r"[A-Za-z0-9]+", name):
        return bool(re.search(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])", text, re.I))
    return _normalized_name(name) in (normalized(text) if flat is None else flat)


# 기관명 표는 카탈로그마다 한 번만 만든다 — 기사마다 다시 만들면 전체 이벤트 재검토에 44초가 걸렸다.
@lru_cache(maxsize=8)
def _name_table(catalog_names):
    names = {key: list(values) for key, values in policy()["organizations"].items()}
    for name in catalog_names:
        # "국가기관", "국내 은행·언론사" 같은 설명형 명칭은 기관명이 아니다 — 넣으면 무관한 기사가 붙었다.
        if GENERIC_ORG_RE.search(name):
            continue
        if not any(contains_name(name, alias) for aliases in names.values() for alias in aliases):
            names.setdefault(name, [name])
    return tuple(sorted((key, tuple(aliases)) for key, aliases in names.items()))


@lru_cache(maxsize=256)
def _names(text, catalog_names):
    flat = normalized(text)
    return tuple(key for key, aliases in _name_table(catalog_names)
                 if any(contains_name(text, alias, flat) for alias in aliases))


def names_in(text, catalog):
    catalog_names = tuple(name for record in catalog["incidents"] for name in record.get("organizations", []))
    return list(_names(text, catalog_names))


def parsed_date(value):
    match = re.match(r"(20\d{2})[-./](\d{1,2})[-./](\d{1,2})", str(value or ""))
    if not match:
        return ""
    try:
        return date(*map(int, match.groups())).isoformat()
    except ValueError:
        return ""


def incident_time(title, summary, published):
    # An article's publication date is not the incident date. Only an explicit
    # incident clause can supply a date strong enough for automatic grouping.
    match = re.search(r"(20\d{2})\s*년\s*(\d{1,2})\s*월\s*(\d{1,2})\s*일.{0,30}?"
                      r"(?:발생한|발생|유출된|유출|해킹|침해)", title + " " + summary)
    if match:
        when = parsed_date("{}-{}-{}".format(*match.groups()))
        if when:
            return {"date": when, "year": int(when[:4]), "basis": "explicit"}
    years = re.findall(r"(20\d{2})\s*년.{0,35}?(?:사고|유출|해킹|침해)", title)
    if not years:
        years = re.findall(r"(20\d{2})\s*년.{0,35}?(?:발생한|발생|유출된|침해사고)", summary[:500])
    if len(set(years)) == 1:
        return {"date": "", "year": int(years[0]), "basis": "explicit_year"}
    if published and re.search(r"작년|지난해|재작년|올해", title):
        offset = 2 if "재작년" in title else 1 if re.search(r"작년|지난해", title) else 0
        return {"date": "", "year": int(published[:4]) - offset, "basis": "relative_year"}
    return {"date": "", "year": None, "basis": "unknown"}


def source_type(url):
    host = (urlsplit(url).hostname or "").lower()
    return "official" if host.endswith(".go.kr") or host in {"korea.kr", "www.korea.kr"} else "report"


def significance(title, summary, url):
    text = title + " " + summary
    signals, measurements = [], []
    # 숫자로 시작해야 한다 — "유출, 명의도용"의 쉼표만 잡히면 float("")에서 수집 전체가 멈춘다.
    number_re = re.compile(r"(?<![\d.])(\d[\d,]*(?:\.\d+)?)\s*(억|만|천)?\s*(?:여\s*)?(명|건|계정)")
    for match in number_re.finditer(text):
        context = text[max(0, match.start() - 55):match.end() + 65]
        if not re.search(r"유출|피해|탈취|해킹|노출", context):
            continue
        value = float(match.group(1).replace(",", "")) * {"억": 100000000, "만": 10000, "천": 1000}.get(match.group(2), 1)
        measure = {"value": int(value), "unit": match.group(3), "text": match.group(),
                   "status": "alleged" if ALLEGED_RE.search(context) else "reported", "source_url": url}
        if measure not in measurements:
            measurements.append(measure)
    people = [m["value"] for m in measurements if m["unit"] == "명" and m["status"] == "reported"]
    if people and max(people) >= policy()["selection"]["large_people_threshold"]:
        signals.append({"criterion": "scale", "evidence": "보도된 피해 인원 기준 충족", "source_url": url})
    for key, pattern in (
        ("sensitivity", r"주민등록번호|인증정보|비밀번호|유심정보|금융정보|신용정보|의료정보"),
        ("service", r"서비스\s*(?:중단|마비)|전산망\s*마비|거래\s*중단|시스템\s*파괴"),
        ("systemic", r"공급망|다수\s*기관|전국적|여러\s*(?:금융|기관|회사)|공동\s*대응"),
        ("historical", r"제도\s*개선|법\s*개정|최종\s*조사결과|최종\s*조사\s*결과"),
    ):
        match = re.search(pattern, text)
        if match:
            context = text[max(0, match.start() - 25):match.end() + 45]
            signals.append({"criterion": key, "evidence": context, "source_url": url,
                            "status": "alleged" if ALLEGED_RE.search(context) else "reported"})
    return {"priority": "high" if any(s.get("status") != "alleged" for s in signals) else "review",
            "signals": signals, "measurements": measurements, "people": max(people) if people else None,
            "publication_eligible": False}


def assess(event, catalog):
    title, summary = clean(event.get("title")), clean(event.get("summary"))[:2500]
    text = title + " " + summary
    if not title or EXCLUDE_RE.search(title) or PROMO_RE.search(title):
        return None
    if not INCIDENT_RE.search(text):
        return None
    organizations = names_in(title, catalog)
    if not organizations:
        organizations = names_in(summary[:300], catalog)
    domestic = "confirmed" if organizations or DOMESTIC_RE.search(text) or KOREA_EN_RE.search(text) else "unknown"
    if not organizations and FOREIGN_RE.search(title):
        return None
    # 해외 매체의 영문 기사는 한국이나 알려진 국내 기관이 나올 때만 국내 사고 후보가 된다.
    if not organizations and not re.search(r"[가-힣]", title) and not KOREA_EN_RE.search(text):
        return None
    context = bool(CONTEXT_RE.search(title))
    if not organizations and not context:
        # Keep unfamiliar organizations in review; Korean reporting alone does
        # not establish the victim's country.
        head = re.sub(r"^(?:\[[^]]+\]\s*)+", "", title).split(",", 1)[0].strip()
        if (len(head) <= 30 and "," in title and not INCIDENT_RE.search(head)
                and not NOT_ORG_RE.search(head) and len(head.split()) <= 3):
            organizations = [head]
    category = next((key for key, pattern in CATEGORY_PATTERNS if re.search(pattern, title, re.I)), "intrusion")
    published = parsed_date(event.get("published_at"))
    when = incident_time(title, summary, published)
    matches, possible, reasons = [], [], []
    flat = normalized(text)
    for record in catalog["incidents"]:
        aliases = [a for a in record.get("aliases", []) if _normalized_name(a) in flat]
        record_orgs = names_in(" ".join(record.get("organizations", [])), catalog)
        same_org = bool(set(record_orgs) & set(organizations))
        same_year = when["year"] == int(record["date"][:4])
        date_conflict = when["date"] and record.get("date_basis") == "발생일" and when["date"] != record["date"]
        year_conflict = when["year"] is not None and not same_year
        source_ids = {sid for fact in record["facts"] + record["milestones"] for sid in fact["source_ids"]}
        source_match = any(s["id"] in source_ids and s["url"] == event["url"] for s in catalog["sources"])
        if source_match or (aliases and not year_conflict and not date_conflict and not NEW_RE.search(title)):
            matches.append(record["id"])
            reasons.append("기존 사건명 또는 검토 출처 일치")
        elif same_org:
            # 사고 직후 기사는 연도를 적지 않는 경우가 많다("신한은행 2만5천여 명 정보유출 확인").
            soon_after = bool(published) and 0 <= (date.fromisoformat(published)
                                                   - date.fromisoformat(record["date"])).days <= FOLLOWUP_WINDOW_DAYS
            if NEW_RE.search(title) or date_conflict:
                possible.append(record["id"])
            elif same_year and FOLLOWUP_RE.search(title):
                matches.append(record["id"])
                reasons.append("기관·사고 연도·후속 보도 일치")
            elif soon_after and not year_conflict and (INCIDENT_RE.search(title) or FOLLOWUP_RE.search(title)):
                matches.append(record["id"])
                reasons.append("기관 일치·사고 직후 보도")
            else:
                possible.append(record["id"])
    # 실측(전체 이벤트 5만 5천 건): 요약에만 사고 표현이 있는 글은 제품·행사 소개가 대부분이었고,
    # 피해 기관도 국내 여부도 모르는 글은 해외 위협 분석이었다. 기존 사건의 후속 보도만 예외로 남긴다.
    if not matches and not INCIDENT_RE.search(title):
        return None
    if not matches and not context and not organizations and domestic == "unknown":
        return None
    if context:
        kind = "context"
    elif len(matches) == 1:
        kind = "followup"
    elif len(matches) > 1 or len(organizations) > 1:
        kind = "ambiguous"
    elif domestic == "unknown" or not organizations:
        kind = "needs_context"
    else:
        kind = "new_incident"
    return {"organizations": organizations, "domestic": domestic, "incident_time": when,
            "category": category, "kind": kind, "possible_incident_ids": sorted(set(matches + possible)),
            "linked_incident_id": matches[0] if len(matches) == 1 and kind == "followup" else "",
            "reasons": sorted(set(reasons)) or ["개별 사고 확인 필요" if context else "사고 보도 후보"],
            "source_type": source_type(event["url"]),
            "claim_status": "alleged" if ALLEGED_RE.search(title) else "reported",
            "significance": significance(title, summary, event["url"])}


def fingerprint(item):
    content = {key: item.get(key, "") for key in ("title", "summary", "published_at", "source_updated_at")}
    return hashlib.sha256(json.dumps(content, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def group_key(item):
    if item.get("linked_incident_id"):
        return item["linked_incident_id"]
    when = item.get("incident_time", {})
    orgs = item.get("organizations", [])
    if len(orgs) == 1 and when.get("date"):
        identity = "|".join((orgs[0], when["date"], item["category"]))
    else:
        # No year-only merge: the same company can be breached twice that year.
        identity = item["id"]
    return "candidate-" + hashlib.sha256(identity.encode()).hexdigest()[:16]


def build_drafts(stored, catalog):
    grouped = {}
    for saved in stored.get("candidates", []):
        if saved.get("review_state") == "rejected" and not saved.get("needs_review"):
            continue
        item = saved.get("latest_revision") or saved
        if item.get("kind") == "excluded":
            continue
        key = group_key(item)
        grouped.setdefault(key, []).append((saved, item))
    records = {record["id"]: record for record in catalog["incidents"]}
    groups = []
    for key, pairs in sorted(grouped.items()):
        rows = [item for _, item in pairs]
        record = records.get(key)
        evidence = [{"candidate_id": saved["id"], "url": item["url"], "title": item["title"],
                     "summary": item["summary"], "published_at": item["published_at"],
                     "source_type": item["source_type"], "claim_status": item["claim_status"],
                     "fingerprint": item["content_fingerprint"],
                     "changed_fields": saved.get("changed_fields", []),
                     "review_state": saved.get("review_state", "pending")}
                    for saved, item in pairs]
        measurements = [m for item in rows for m in item["significance"]["measurements"]]
        conflicts = [unit for unit in {m["unit"] for m in measurements}
                     if len({m["value"] for m in measurements if m["unit"] == unit}) > 1]
        organizations = sorted({name for item in rows for name in item["organizations"]})
        missing = ["추가 자료의 사실관계 및 선정 사유 검토"]
        if not record:
            missing += ["공식 자료 또는 피해 기관 발표 확인", "발생일과 공개일 구분"]
        if any(item["domestic"] != "confirmed" for item in rows):
            missing.append("국내 피해 기관 여부 확인")
        if any(item["kind"] in {"context", "ambiguous"} for item in rows):
            missing.append("개별 사고로 분리하고 피해 기관별 출처 연결")
        if conflicts:
            missing.append("동일 단위의 상이한 수치 확인: " + ", ".join(conflicts))
        groups.append({"id": key, "target_incident_id": record["id"] if record else "",
                       "operation": "update" if record else "new",
                       "title": record["title"] if record else rows[0]["title"],
                       "organizations": organizations, "review_state": "draft",
                       "publication_eligible": False, "requires_review": missing,
                       "priority": "high" if any(item["significance"]["priority"] == "high" for item in rows) else "review",
                       "selection_signals": [signal for item in rows for signal in item["significance"]["signals"]],
                       "measurements": measurements, "evidence": evidence,
                       "suggested_related_groups": []})
    # Weak identity matches are suggestions, never a silent cross-incident merge.
    for group in groups:
        group["suggested_related_groups"] = [other["id"] for other in groups
            if other["id"] != group["id"] and set(group["organizations"]) & set(other["organizations"])]
    return {"schema_version": 1, "classifier_version": CLASSIFIER_VERSION,
            "policy": policy()["selection"], "groups": groups}
