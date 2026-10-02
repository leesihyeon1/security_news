"""최근 위협 동향 후보와 분석 근거를 묶는 공격 동향 레이더.

무엇을 푸는가:
    추천기사(pick_trend_reads)는 "알림 문턱을 못 넘었지만 읽을 가치가 있는 기사"를
    뽑는다. 그래서 TerminalFix처럼 새로 등장한 기법·캠페인이 P1/P2로 알림된 경우엔
    애초에 후보군에 들어가지 않는다(실측: 신규 캠페인 구성 기사 60건 중 추천기사와
    겹친 것은 2건, 3%). 완전히 다른 축이라 별도로 뽑아야 한다.

후보 조건: 최근 WINDOW_DAYS 내 new/update 보도 2건, 매체 2곳, PIR 또는 자산 관련성.
수집 최초일·목록 미등재·재보도 수는 신규 캠페인의 증거가 아니다. 저장된 원문 요약과
기술 필드로 유형 및 공격 관측 보도 여부를 분리하며, 불명확한 후보는 자동 분석하지 않는다.

    ④에서 자산 매칭만 쓰면 안 된다. 자산 인벤토리는 네트워크·보안 장비뿐이라
    TerminalFix 같은 엔드포인트 사회공학 기법은 구조적으로 못 잡는다(실측: 진짜
    TerminalFix 기사 4건 모두 자산매칭 0건, 매칭이 걸린 1건은 여러 주제를 섞은
    주간 요약 기사의 오탐). PIR-4가 "ClickFix·InstallFix·피싱 등 엔드포인트 초기
    침투"라 그 축을 정확히 담당한다.

이름이 다른 두 카드를 "서로를 언급하는가"로 합치는 방법은 시도했다가 뺐다. 제목·요약에서
상대 이름을 한 번이라도 부르는 그룹 쌍이 0개였다(실측: 병합 직전 21개 그룹). events.jsonl에
본문이 없어 제목·요약만 볼 수 있고, 캠페인 이름은 "ted backdoor"처럼 여러 낱말이라 기사의
"'ted' 백도어" 표기와 문자열이 안 맞는다. 같은 사건이 두 카드로 갈리는 문제는 남아 있지만
이 신호로는 못 잡는다.

두 가지 함정을 피한다:
    - 개체 필드(threat_actor/malware_family)만 믿으면 소스 수가 과소 집계된다.
      실측: TerminalFix는 제목에 실린 기사가 4건인데 필드가 채워진 건 1건뿐이어서
      "단독 보도"로 탈락했다. 이름은 필드에서 얻고, 코로보레이션은 제목·요약의
      이름 언급으로 센다.
    - 주간 요약·뉴스레터 기사는 한 이벤트에 여러 캠페인을 담고(malware_family=
      'StreamRat, TerminalFix') 무관한 자산까지 끌어온다 — 개체 추출에서 제외한다.
"""

import io
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import common_utils

WINDOW_DAYS = 14
MIN_SOURCES = 2
MIN_NOVELTY_NEW = 2
MAX_CAMPAIGNS = 8            # 대시보드 카드로 노출할 상한
MIN_NAME_CHARS = 4           # 이보다 짧은 이름은 언급 검색에서 오탐이 크다

SPLIT_RE = re.compile(r"\s*(?:,|/|·|;|\band\b|\bor\b)\s*", re.I)
PAREN_RE = re.compile(r"\(([^)]*)\)")
NOISE_SUFFIX_RE = re.compile(r"\b(operators?|group|gang|actors?|apt|team|crew)\b\s*$", re.I)
ALIAS_RE = re.compile(r"\b(aka|a\.k\.a\.?|alias)\b", re.I)
# 여러 캠페인을 한 기사에 몰아넣는 유형
ROUNDUP_RE = re.compile(
    r"weekly recap|week in security|week in review|newsletter|round\s*\d+|"
    r"threatsday|digest|roundup|주간\s*(요약|보안)|이번\s*주",
    re.I,
)
# LLM이 개체 필드를 채우려고 넣는 일반명사 — 캠페인 이름이 아니다
STOPNAMES = {
    "unknown", "n/a", "none", "various", "unattributed", "unspecified",
    "미확인", "불명", "해당 없음", "다수", "미상", "확인되지 않음",
    "chinese state-sponsored", "state-sponsored", "ransomware", "threat actor",
    "attributed", "not attributed", "unidentified", "china", "iran", "russia", "north korea",
}

# 발행처는 원문 후보를 고르는 신호일 뿐, 독립 교차 검증이나 신규성의 증명이 아니다.
RESEARCH_HOSTS = {
    "microsoft.com", "blog.talosintelligence.com", "cloud.google.com",
    "cloudblog.withgoogle.com", "unit42.paloaltonetworks.com", "securelist.com",
    "welivesecurity.com", "asec.ahnlab.com", "threatdown.com", "zimperium.com",
    "cleafy.com", "research.checkpoint.com", "sentinelone.com", "crowdstrike.com",
    "proofpoint.com", "elastic.co", "trendmicro.com", "sysdig.com",
}
UNCONFIRMED_RE = re.compile(
    r"(?:no|not|without|lack of).{0,55}(?:confirm|observ|evidence).{0,65}"
    r"(?:in.the.wild|deploy|attack)|"
    r"(?:실제|실전).{0,35}(?:배포|사용|공격).{0,30}(?:미확인|관측되지|확인되지|확인되지\s*않)", re.I)
OBSERVED_RE = re.compile(
    r"targeted (?:intrusions|operations)|compromised (?:service principals|networks|hosts)|"
    r"(?:observed|detected|identified).{0,90}(?:attack|intrusion|campaign)|"
    r"(?:실제|표적).{0,20}(?:침해|공격)|감염된|침해된", re.I)
BLOCKED_RE = re.compile(r"captcha|verify you are human|access denied|just a moment|캡차", re.I)


def research_source(event):
    try:
        host = (urlsplit(event.get("url") or "").hostname or "").lower()
    except ValueError:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in RESEARCH_HOSTS)


def usable_body(event):
    try:
        size = int(event.get("body_chars") or 0)
    except (ValueError, TypeError):
        return False
    return (size >= 900
            and not BLOCKED_RE.search(event.get("summary") or ""))


def assess_evidence(events, names):
    """저장된 근거의 수준을 표시한다. LLM의 new/active만으로 신규 공격을 확정하지 않는다."""
    primary = [e for e in events if research_source(e) and usable_body(e)]
    name_keys = {n.lower() for n in names}
    typed = [e for e in primary if e.get("malware_family") or e.get("threat_actor")]
    typed = typed or [e for e in events if usable_body(e)]
    malware = any(name_keys.intersection(n.lower() for n in split_entities(e.get("malware_family")))
                  for e in typed)
    actor = any(name_keys.intersection(n.lower() for n in split_entities(e.get("threat_actor")))
                for e in typed)
    kind = "malware" if malware else "actor" if actor else "threat_report"
    labels = {"malware": "악성코드·도구", "actor": "공격 조직 활동", "threat_report": "위협 연구·보도"}
    negative = [e for e in events if UNCONFIRMED_RE.search(_mention_blob(e))]
    observed = [e for e in primary if e.get("exploitation_status") == "active"
                and OBSERVED_RE.search(" ".join([e.get("title") or "", e.get("summary") or ""]))
                and not UNCONFIRMED_RE.search(_mention_blob(e))]
    if negative and observed:
        activity, activity_label = "conflicting", "실전 사용 근거 상충"
    elif negative or (primary and all(e.get("exploitation_status") == "poc" for e in primary)):
        activity, activity_label = "unconfirmed", "실전 사용 미확인"
    elif observed:
        activity, activity_label = "reported", "실제 공격 보고 있음"
    else:
        activity, activity_label = "unknown", "실제 공격 확인 필요"
    evidence_events = (negative + observed) or primary or events[:1]
    evidence = [{"title": e.get("title") or "", "url": e.get("url") or "",
                 "source": common_utils.source_label(e.get("source")),
                 "basis": "수집 요약에 실전 사용 미확인 문구 · 원문 재확인 필요" if e in negative else
                          "연구기관의 공격 관측 보도" if e in observed else "유형·본문 확인 대상",
                 "excerpt": ((e.get("ai_summary") or e.get("summary") or "") if e in negative
                             else (e.get("summary") or ""))[:250]}
                for e in evidence_events[:3]]
    reasons = []
    if not primary:
        reasons.append("본문이 확보된 연구기관 보고서 없음")
    if activity != "reported":
        reasons.append(activity_label)
    if not any(e.get("attack_techniques") or e.get("iocs") or e.get("recommended_actions") for e in primary):
        reasons.append("조사에 사용할 기술 근거 부족")
    return {
        "kind": kind, "kind_label": labels[kind], "activity": activity,
        "activity_label": activity_label, "primary_count": len(primary),
        "novelty_label": "신규 캠페인 여부 미확인", "evidence": evidence,
        "auto_eligible": not reasons, "auto_reason": " · ".join(reasons) or "공격 관측·기술 근거가 있는 연구기관 보고서",
    }


def is_roundup(event):
    return bool(ROUNDUP_RE.search(event.get("title") or ""))


def split_entities(raw):
    """뭉쳐 들어온 개체명을 개별 이름으로 쪼갠다.

    실측 80종이 이런 형태다: "SCATTERED SPIDER, BlackBasta, Royal (BlackSuit)",
    "BlackCat/ALPHV", "Astaroth (Guildma) operators". 괄호 안 별칭도 독립 이름으로 본다.
    """
    if not raw:
        return []
    pieces = []
    for alias in PAREN_RE.findall(raw):
        pieces.extend(SPLIT_RE.split(alias))
    pieces.extend(SPLIT_RE.split(PAREN_RE.sub(" ", raw)))

    names = []
    for piece in pieces:
        name = NOISE_SUFFIX_RE.sub("", ALIAS_RE.sub(" ", piece))
        name = common_utils.clean_text(name).strip(" .-–—'\"")
        if not name or len(name) < MIN_NAME_CHARS or len(name) > 40:
            continue
        if name.lower() in STOPNAMES or not re.search(r"[A-Za-z가-힣]", name):
            continue
        canonical = common_utils.normalize_threat_actor(name)
        if canonical not in names:
            names.append(canonical)
    return names


def _mention_blob(event):
    """이름 언급을 찾을 텍스트. 본문은 events.jsonl에 저장되지 않아 제목·요약만 본다."""
    return " ".join([
        event.get("title") or "",
        event.get("ai_summary") or "",
        event.get("summary") or "",
    ])


def _iter_events(events_file):
    for line in common_utils.iter_lines_reverse(events_file):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not str(event.get("fetched_at") or ""):
            continue
        yield event


KNOWN_NAMES_FILE = common_utils.ASSETS_DIR / "intel" / "known_names.json"
ACTOR_ALIASES_FILE = common_utils.ASSETS_DIR / "intel" / "threat_actor_aliases.json"
_known_cache = None


def known_names():
    """이미 알려진 행위자·랜섬웨어·악성코드 이름 집합(소문자).

    코퍼스가 두 달 남짓이라 "우리가 처음 본 이름"과 "세상에 처음 나온 이름"이 다르다.
    그 차이를 메우는 유일한 근거가 외부 목록이다(MISP Galaxy). 없으면 빈 집합을
    돌려주고 예전처럼 동작한다 — 목록을 못 받았다고 탐지를 멈추지는 않는다.
    """
    global _known_cache
    if _known_cache is not None:
        return _known_cache
    names = set()
    try:
        data = json.loads(KNOWN_NAMES_FILE.read_text(encoding="utf-8"))
        names.update((data.get("names") or {}).keys())
    except (OSError, ValueError):
        pass
    try:
        data = json.loads(ACTOR_ALIASES_FILE.read_text(encoding="utf-8"))
        names.update(key for key in (data.get("aliases") or {}) if len(key) >= MIN_NAME_CHARS)
    except (OSError, ValueError):
        pass
    _known_cache = names
    return names


def unknown_names(names):
    """목록 미등재 이름. 목록 자체가 불완전하므로 신규성 판정에는 사용하지 않는다."""
    known = known_names()
    out = []
    for name in names:
        key = common_utils.clean_text(name).lower()
        # 외부 목록은 정식 명칭을 쓰고 기사는 줄여 쓴다("Lazarus" vs "Lazarus Group").
        # 흔한 꼬리말을 붙여 한 번 더 본다 — 이걸 안 하면 오래된 그룹이 신규로 남는다.
        variants = [key] + [key + suffix for suffix in
                            (" group", " gang", " team", " apt", " crew")]
        if not any(variant in known for variant in variants):
            out.append(name)
    return out


def corpus_start(events_file=None):
    """수집 로그에서 가장 오래된 날짜. "최초 확인"이 무엇을 기준으로 한 말인지 밝히는 데 쓴다.

    이 값이 화면에 없으면 "최초 확인 2026-08-30"이 세계 최초처럼 읽힌다. 실제로는
    우리 수집이 시작된 뒤 처음 본 날이라, 그 전부터 알려진 이름도 신규로 뜬다
    (실측: Rhysida·APT37처럼 오래된 그룹이 신규 캠페인으로 올라왔다).
    """
    path = events_file or common_utils.EVENTS_FILE
    try:
        with io.open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                stamp = (event.get("fetched_at") or "")[:10]
                if stamp:
                    return stamp
    except OSError:
        pass
    return ""


def detect(events_file=None, now=None):
    """최근 위협 동향 후보를 반환. 대시보드 카드로 바로 쓸 수 있는 dict 목록."""
    events_file = events_file or common_utils.EVENTS_FILE
    now = now or datetime.now(timezone.utc)
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    window_start = (now - timedelta(days=WINDOW_DAYS)).isoformat()

    # 최초 등장일을 알아야 하므로 코퍼스 전체를 본다(끝에서부터 읽되 조기 종료는 없다).
    # 재수집된 동일 기사는 보도 수·소스 수·IOC 수를 늘리지 않는다.
    unique = {}
    for event in _iter_events(events_file):
        try:
            fetched = datetime.fromisoformat(event["fetched_at"].replace("Z", "+00:00"))
            fetched = fetched.replace(tzinfo=timezone.utc) if fetched.tzinfo is None else fetched.astimezone(timezone.utc)
        except (ValueError, TypeError):
            continue
        if fetched > now or is_roundup(event):
            continue
        event["fetched_at"] = fetched.isoformat()
        key = event.get("url") or event.get("id")
        if not key:
            continue
        saved = unique.setdefault(key, dict(event, _first_fetched=event["fetched_at"]))
        saved["_first_fetched"] = min(saved["_first_fetched"], event["fetched_at"])
    events = list(unique.values())

    names = {}
    for event in events:
        if str(event.get("fetched_at")) < window_start:
            continue  # 후보 이름은 최근 창에서만 얻는다
        if event.get("category") not in {"공격캠페인", "악성코드", "침해사고", "취약점", "개인정보유출", "공급망공격", "피싱사기"}:
            continue
        for field in ("threat_actor", "malware_family"):
            for name in split_entities(event.get(field)):
                names.setdefault(name.lower(), name)
    if not names:
        return []

    matchers = {
        key: re.compile(r"(?<![0-9A-Za-z])" + re.escape(display) + r"(?![0-9A-Za-z])", re.I)
        for key, display in names.items()
    }

    first_seen = {}
    hits = defaultdict(list)
    for event in events:
        blob = _mention_blob(event)
        fetched = str(event.get("fetched_at"))
        for key, pattern in matchers.items():
            if not pattern.search(blob):
                continue
            first = event.get("_first_fetched") or fetched
            if key not in first_seen or first < first_seen[key]:
                first_seen[key] = first
            if fetched >= window_start:
                hits[key].append(event)

    candidates = {}
    for key, matched in hits.items():
        if first_seen.get(key, "") < window_start and not any(
                e.get("novelty") == "update" and research_source(e) and usable_body(e)
                for e in matched):
            continue
        if sum(1 for e in matched if e.get("novelty") in {"new", "update"}) < MIN_NOVELTY_NEW:
            continue                                            # ②
        if len({e.get("source") or "?" for e in matched}) < MIN_SOURCES:
            continue                                            # ③
        candidates[key] = {"name": names[key], "events": matched, "first": first_seen[key][:10]}

    return _build_rows(_merge_by_story(candidates), events_file=events_file)


def _merge_by_story(candidates):
    """같은 기사에서 나온 개체들을 한 캠페인으로 합친다.

    개체명 단위로 두면 한 사건이 여러 줄로 쪼개진다 — 실측: QTFY/QScan/QTRouter,
    Gambling Goblin/DownPro/AlphaAgent/oRAT/3snake가 각각 같은 보고서에서 나왔다.
    """
    # A-B, B-C의 동시 언급만으로 A-C까지 같은 사건으로 합치지 않는다.
    memberships = {key: {e.get("url") or e.get("id") for e in info["events"]
                        if key in {n.lower() for field in ("threat_actor", "malware_family")
                                   for n in split_entities(e.get(field))}}
                   for key, info in candidates.items()}
    clusters = []
    for key in sorted(candidates):
        for cluster in clusters:
            if all(len(memberships[key] & memberships[other]) >= 2 for other in cluster):
                cluster.append(key)
                break
        else:
            clusters.append([key])
    roots = {key: cluster[0] for cluster in clusters for key in cluster}
    groups = defaultdict(lambda: {"names": [], "events": {}, "first": "9999"})
    for key, info in candidates.items():
        group = groups[roots[key]]
        if info["name"] not in group["names"]:
            group["names"].append(info["name"])
        for event in info["events"]:
            group["events"][event.get("id")] = event
        group["first"] = min(group["first"], info["first"])
    return list(groups.values())


def _build_rows(groups, events_file=None):
    level_rank = {"P1": 0, "P2": 1}
    rows = []
    for group in groups:
        events = list(group["events"].values())
        pirs = sorted({p for e in events for p in (e.get("pirs") or [])})
        assets = common_utils.canonical_assets(
            [a for e in events for a in ((e.get("triage") or {}).get("matched_assets") or [])])
        if not pirs and not assets:
            continue                                            # ④
        levels = sorted({(e.get("triage") or {}).get("level") for e in events} - {None, ""})
        # 요약은 "캠페인 이름이 제목에 있는 기사"에서 가져온다. 아무거나 집으면 그
        # 캠페인을 지나가듯 언급한 기사(주간 위협 보고서 등)의 요약이 실려 엉뚱한
        # 내용이 카드에 나온다 — 실측: Gambling Goblin 카드에 Thomson Reuters
        # 유출 사고 요약이 붙었다.
        name_res = [re.compile(r"(?<![0-9A-Za-z])" + re.escape(n) + r"(?![0-9A-Za-z])", re.I)
                    for n in group["names"]]

        def summary_rank(event):
            title = event.get("title") or ""
            in_title = any(pattern.search(title) for pattern in name_res)
            # 접근 제한된 짧은 재보도보다 본문을 확보한 연구 보고서를 먼저 조사한다.
            return (0 if usable_body(event) else 1,
                    0 if research_source(event) else 1,
                    0 if in_title else 1, 0 if event.get("ai_summary") else 1)

        # 같은 순서로 items도 정렬해 대표 기사가 맨 앞에 오게 한다 — 대시보드 카드가
        # items[0]을 "이 캠페인의 대표 기사"로 보고 심층분석 버튼을 붙인다.
        ordered = sorted(events, key=summary_rank)
        summary = ""
        for event in ordered:
            summary = (event.get("ai_summary") or event.get("summary") or "").strip()
            if summary:
                break
        assessment = assess_evidence(ordered, group["names"])
        rows.append({
            "names": group["names"][:6],
            "assessment": assessment,
            "first_seen": group["first"],
            "level": min(levels, key=lambda l: level_rank.get(l, 2)) if levels else "",
            "sources": sorted({common_utils.source_label(e.get("source")) for e in events}),
            "pirs": pirs,
            "assets": assets,
            "categories": sorted({e.get("category") for e in events if e.get("category")}),
            "techniques": sorted({t for e in events for t in (e.get("attack_techniques") or [])}),
            "ioc_count": len({(i.get("type"), str(i.get("value") or "").strip())
                              for e in events for i in (e.get("iocs") or [])
                              if isinstance(i, dict) and i.get("value")}),
            "novelty_new": sum(1 for e in events if (e.get("novelty") or "") == "new"),
            "summary": summary[:400],
            "items": [
                {
                    "source_label": common_utils.source_label(e.get("source")),
                    "category": e.get("category") or "",
                    "title": e.get("title") or "",
                    "url": common_utils.tracking_url(e.get("id"), e.get("url") or "") or "",
                    "ref": common_utils.event_ref(e.get("id")),
                    "research_source": research_source(e),
                    "body_available": usable_body(e),
                }
                for e in ordered
            ],
        })

    # 기존에 알려진 이름도 새 전개가 있으면 남긴다.
    for row in rows:
        new_names = unknown_names(row["names"])
        row["new_names"] = new_names
        row["assessment"]["name_status"] = "외부 목록 미등재 이름 포함" if new_names else "기존에 알려진 이름의 후속 보도"

    rows.sort(key=lambda r: (level_rank.get(r["level"], 2),
                             not r["assessment"]["auto_eligible"],
                             -len(r["sources"]), -len(r["items"])))
    rows = rows[:MAX_CAMPAIGNS]
    # 화면이 "최초 확인"의 기준을 밝힐 수 있게 코퍼스 시작일을 함께 싣는다.
    started = corpus_start(events_file)
    for row in rows:
        row["corpus_start"] = started
    return rows


def public_row(row):
    """내부 우선순위·자산 정보를 제외한 카드 계약. 생성과 기존 보고서 갱신에 공용한다."""
    from dashboard_text import public_text

    result = {key: row.get(key) for key in (
        "names", "first_seen", "level", "sources", "categories", "techniques", "ioc_count",
        "novelty_new", "corpus_start", "items", "auto_analysis", "analysis_ref") if key in row}
    result["summary"] = public_text(row.get("summary") or "")
    assessment = dict(row.get("assessment") or {})
    assessment["evidence"] = [
        {key: public_text(value) if key in {"title", "excerpt"} else value for key, value in entry.items()}
        for entry in assessment.get("evidence") or []
    ]
    result["assessment"] = assessment
    return result


# 자동 분석은 관측·기술 근거가 있는 후보만 수행한다. 요청 이력과 성공 여부는 별개다.
ANALYSIS_QUEUE_KEY = "analysis:queue"
ANALYSIS_CACHE_PREFIX = "analysis:"
QUEUE_STATE_FILE = common_utils.STATE_DIR / "campaign_analysis_state.json"
# 한 회차에 거는 최대 건수. 워커가 한 건에 2~3분을 쓰므로 한꺼번에 밀어 넣으면
# 그날 대기열이 다른 요청으로 막힌다.
MAX_QUEUED_PER_RUN = 3
MAX_QUEUED_PER_DAY = 3
MAX_QUEUE_DEPTH = 6
MAX_AUTO_ATTEMPTS = 2
RETRY_AFTER_SECONDS = 24 * 60 * 60
STATUS_PREFIX = "analysis:status:"


def mark_analysis_status(client, job, status):
    """수동 요청도 기록해 자동 요청과 중복 실행되지 않도록 한다."""
    if not job.get("ref"):
        return
    try:
        client.set(STATUS_PREFIX + job["ref"], json.dumps({
            "status": status, "updated_at": datetime.now(timezone.utc).isoformat(),
        }), ex=7 * 24 * 60 * 60)
    except Exception:
        pass  # 부가 상태 기록 실패가 분석 결과 저장을 막지는 않는다.


def _json_record(raw):
    try:
        value = json.loads(raw) if raw else {}
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def _age_seconds(stamp, now):
    try:
        parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (now - parsed).total_seconds()
    except (ValueError, TypeError):
        return float("inf")


def _queue_client():
    """Redis 클라이언트. 없으면 None — 큐잉은 부가 기능이라 리포트를 막지 않는다."""
    url = os.environ.get("REDIS_URL", "")
    if not url:
        return None
    try:
        import redis
    except ImportError:
        return None
    try:
        client = redis.from_url(url, decode_responses=True,
                                socket_connect_timeout=10, socket_timeout=15)
        client.ping()
        return client
    except Exception as error:
        print("[-] 심층분석 큐 연결 실패(리포트에는 영향 없음): {}".format(error))
        return None


def campaign_key(row):
    """같은 캠페인인지 가리는 열쇠. 이름 집합이 같으면 같은 것으로 본다."""
    return "|".join(sorted(name.lower() for name in (row.get("names") or [])))


def queue_deep_analysis(rows, now=None):
    """근거가 있는 위협만 제한적으로 조사하고, 실제 처리 결과로 상태를 갱신한다."""
    rows = [row for row in rows or [] if row.get("items")]
    if not rows:
        return 0
    for row in rows:
        row["auto_analysis"] = {"status": "held", "reason": (row.get("assessment") or {}).get("auto_reason") or "분류 근거 확인 필요"}
    client = _queue_client()
    if client is None:
        for row in rows:
            if (row.get("assessment") or {}).get("auto_eligible"):
                row["auto_analysis"]["reason"] = "분석 큐 연결 상태 확인 필요"
        return 0
    # 일간·주간 리포트가 겹쳐도 같은 요청을 동시에 등록하지 않는다.
    if not client.set("campaign:queue-lock", "1", nx=True, ex=120):
        return 0
    try:
        return _queue_rows(client, rows, now or datetime.now(timezone.utc))
    finally:
        client.delete("campaign:queue-lock")


def _queue_rows(client, rows, now):
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now
    state = common_utils.load_json_state(QUEUE_STATE_FILE, lambda: {})
    records = state.get("records") or {}
    today = now.astimezone(timezone(timedelta(hours=9))).date().isoformat()
    daily = state.get("daily") or {}
    used = int(daily.get("count") or 0) if daily.get("date") == today else 0
    pending = [_json_record(raw) for raw in client.lrange(ANALYSIS_QUEUE_KEY, 0, -1)]
    pending_refs = {j.get("ref") for j in pending}
    queued = 0
    for row in rows:
        names = {n.lower() for n in row.get("names") or []}
        refs = {i.get("ref") for i in row["items"] if i.get("ref")}
        key = campaign_key(row)
        # 이름이 추가되거나 대표 기사가 바뀌어도 같은 기사 묶음의 요청 이력을 이어 쓴다.
        matches = [k for k, r in records.items() if refs.intersection(r.get("refs") or [])]
        key = matches[0] if matches else key
        previous = records.get(key) or {}
        candidates = row["items"]
        states = {ref: _json_record(client.get(STATUS_PREFIX + ref)) for ref in refs}
        completed = next((i for i in candidates if
                          (cache := _json_record(client.get(ANALYSIS_CACHE_PREFIX + (i.get("ref") or ""))))
                          and cache.get("analysis") and not cache.get("partial") and not cache.get("collection_failed")
                          and not str(cache.get("analysis")).startswith("[원문 수집 실패]")), None)
        active = next((ref for ref in refs if ref in pending_refs or
                       (states[ref].get("status") == "running" and
                        _age_seconds(states[ref].get("updated_at"), now) < RETRY_AFTER_SECONDS)), None)
        if completed:
            row["analysis_ref"] = completed["ref"]
            outcome = {"status": "completed", "ref": completed["ref"], "reason": "연관 기사 분석 완료"}
        elif active:
            outcome = {"status": "queued" if active in pending_refs else "running", "ref": active, "reason": "기존 분석 요청 처리 중"}
        else:
            item = candidates[0]
            ref = item.get("ref")
            failed = any(s.get("status") == "failed" for s in states.values()) or previous.get("status") in {"queued", "running", "failed"}
            attempts = int(previous.get("attempts") or 0)
            outcome = {"status": "held", "reason": row["auto_analysis"]["reason"]}
            if failed and (attempts >= MAX_AUTO_ATTEMPTS or
                           _age_seconds(previous.get("requested_at"), now) < RETRY_AFTER_SECONDS):
                outcome = {"status": "failed", "reason": "자동 재시도 한도 도달 · 수동 재분석 가능" if attempts >= MAX_AUTO_ATTEMPTS else "실패 후 24시간 재시도 대기"}
            elif not (row.get("assessment") or {}).get("auto_eligible"):
                pass
            elif not ref or not item.get("url") or not item.get("body_available") or not item.get("research_source"):
                outcome["reason"] = "조사 가능한 연구기관 대표 기사 필요"
            elif queued >= MAX_QUEUED_PER_RUN or used >= MAX_QUEUED_PER_DAY or len(pending) >= MAX_QUEUE_DEPTH:
                outcome["reason"] = "일일 자동 분석 한도 또는 대기열 여유 확인 필요"
            else:
                job = {k: item.get(k) or "" for k in ("ref", "title", "url", "source_label", "category")}
                job.update(auto_campaign_key=key, requested_at=now.isoformat())
                client.rpush(ANALYSIS_QUEUE_KEY, json.dumps(job, ensure_ascii=False))
                pending.append(job)
                pending_refs.add(ref)
                previous.update(attempts=attempts + 1, requested_at=now.isoformat())
                outcome = {"status": "queued", "ref": ref, "reason": "근거 확인 후 자동 분석 요청"}
                queued += 1
                used += 1
        row["auto_analysis"] = dict(outcome, checked_at=now.isoformat())
        records[key] = dict(previous, **outcome,
                            names=sorted(names | set(previous.get("names") or [])),
                            refs=sorted(refs | set(previous.get("refs") or [])), checked_at=now.isoformat())
    # 구형 queued 목록은 성공 이력이 아니므로 그대로 차단 목록으로 승계하지 않는다.
    records = dict(sorted(records.items(), key=lambda pair: pair[1].get("checked_at") or "")[-500:])
    common_utils.save_json_state(QUEUE_STATE_FILE, {"version": 2, "records": records, "daily": {"date": today, "count": used}})
    return queued


if __name__ == "__main__":
    import sys

    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    found = detect()
    print("신규 공격 캠페인 {}건 (창 {}일 / 소스 {}곳 이상 / new판정 {}건 이상 / PIR 또는 자산매칭)".format(
        len(found), WINDOW_DAYS, MIN_SOURCES, MIN_NOVELTY_NEW))
    for row in found:
        print()
        print("● {}  [{}]".format(" / ".join(row["names"]), row["level"] or "-"))
        print("   최초 {} | 소스 {}곳 | new판정 {}건 | IOC {}건".format(
            row["first_seen"], len(row["sources"]), row["novelty_new"], row["ioc_count"]))
        if row["pirs"]:
            print("   PIR {}".format(", ".join(row["pirs"])))
        if row["assets"]:
            print("   자산 {}".format(", ".join(row["assets"])))
        print("   {}".format(row["summary"][:120]))
