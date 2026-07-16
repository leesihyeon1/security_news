"""수집된 보안 이벤트(data/events.jsonl)를 집계하고 AI 해석을 붙여
일간/주간 리포트를 메일·슬랙으로 발송하는 스크립트.

사용법:
    python generate_report.py --period daily
    python generate_report.py --period weekly
    python generate_report.py --period weekly --dry-run   # 발송 없이 콘솔 출력만

설계 원칙: 건수/통계는 코드로 정확하게 집계하고, LLM은 해석(총평·핵심 위협·권고)만 담당한다.
LLM 호출이 실패해도 통계 리포트는 발송된다.
"""

import argparse
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta

import common_utils

# Windows 콘솔(cp949)에서 특수문자 출력이 깨지지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

LEGACY_BOANNEWS_EVENTS_FILE = common_utils.DATA_DIR / "boannews_events.jsonl"

SOURCE_LABELS = {
    "nvd": "NVD CVE",
    "cisa_kev": "CISA KEV",
    "kisa": "KISA/KrCERT",
    "asec": "안랩 ASEC",
    "msrc": "Microsoft 패치",
    "github_advisory": "GitHub Advisory",
    "boannews": "보안뉴스",
    "thehackernews": "The Hacker News",
    "bleepingcomputer": "BleepingComputer",
    "sans_isc": "SANS ISC",
    "krebsonsecurity": "Krebs on Security",
    "therecord": "The Record",
    "securityweek": "SecurityWeek",
    "darkreading": "Dark Reading",
    "talos": "Cisco Talos",
    "unit42": "Unit 42",
    "checkpoint_research": "Check Point Research",
    "thedfirreport": "The DFIR Report",
    "securelist": "Securelist",
    "google_security": "Google Security Blog",
}

MAX_ITEMS_PER_SOURCE_IN_PROMPT = 15
MAX_TOP_ITEMS_IN_REPORT = 10
MAX_CVE_CARDS = 5
MAX_ITEMS_PER_CATEGORY = 8
MAX_ITEMS_PER_PIR = 5

# 주요 뉴스 TOP에서 제외할 비뉴스 소스 — API·공지형 항목은 CVSS 점수로 목록을
# 도배하기 쉽고, CVE 카드·소스별 전용 알림이 이미 다루므로 뉴스만 노출한다.
NON_NEWS_SOURCES = {"nvd", "cisa_kev", "msrc", "github_advisory", "kisa"}

# "읽을만한 동향" 큐레이션: 긴급도 점수가 낮아 알림되지 않은 기사 중
# 인사이트 신호(PIR 매칭, 또는 high 관련성의 위협 분석 기사)가 있는 것을 고른다.
MAX_TREND_ITEMS = 5
MAX_TREND_PER_CATEGORY = 2  # 카테고리 쏠림 방지 (슬롯이 남으면 상한 해제)
TREND_CATEGORIES = {"공격캠페인", "침해사고", "개인정보유출", "악성코드", "공급망공격", "기술동향"}


def source_label(source):
    return SOURCE_LABELS.get(source, source or "unknown")


def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def event_score(event):
    score = event.get("score")
    if isinstance(score, (int, float)):
        return float(score)
    return 0.0


def event_level(event):
    return ((event.get("triage") or {}).get("level")) or ""


def normalize_legacy_boannews(raw):
    """구 스키마(data/boannews_events.jsonl)를 통합 스키마로 변환"""
    analysis = raw.get("analysis") or {}
    return {
        "id": raw.get("id", ""),
        "source": "boannews",
        "title": raw.get("title", ""),
        "url": raw.get("url", ""),
        "summary": raw.get("summary", ""),
        "severity": analysis.get("severity") or "",
        "score": None,
        "cves": analysis.get("cves") or [],
        "matched_assets": [],
        "category": analysis.get("category") or "",
        "affected_products": analysis.get("affected_products") or [],
        "epss": None,
        "exploitation_status": "none",
        "kev": False,
        "ransomware_use": None,
        "threat_actor": analysis.get("threat_actor") or "",
        "malware_family": analysis.get("malware_family") or "",
        "attack_techniques": analysis.get("attack_techniques") or [],
        "iocs": analysis.get("iocs") or [],
        "relevance": analysis.get("relevance") or "",
        "references": [],
        "fix_available": None,
        "remediation": "",
        "due_date": "",
        "confidence": analysis.get("confidence") or "",
        "published_at": raw.get("published_at") or "",
        "fetched_at": raw.get("fetched_at") or "",
        "ai_summary": analysis.get("llm_summary"),
        "triage": None,
        "delivery": raw.get("delivery") or {},
    }


def load_events(since):
    """통합 이벤트 로그와 구 보안뉴스 로그를 함께 읽고 (source, url) 기준으로 중복 제거"""
    events = {}

    for path, legacy in ((common_utils.EVENTS_FILE, False), (LEGACY_BOANNEWS_EVENTS_FILE, True)):
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = normalize_legacy_boannews(raw) if legacy else raw
                fetched = parse_iso(event.get("fetched_at"))
                if fetched is None or fetched < since:
                    continue

                key = "{}|{}".format(event.get("source"), event.get("url") or event.get("id"))
                events.setdefault(key, event)

    return list(events.values())


def build_stats(events):
    by_source = Counter(event.get("source") or "unknown" for event in events)
    critical = [event for event in events if event_score(event) >= 9.0]
    kev = [event for event in events if event.get("source") == "cisa_kev"]
    asset_hits = [event for event in events if event.get("matched_assets")]

    cve_counter = Counter()
    for event in events:
        for cve in event.get("cves") or []:
            if cve:
                cve_counter[cve] += 1

    asset_counter = Counter()
    for event in asset_hits:
        for term in event["matched_assets"]:
            asset_counter[term] += 1

    by_category = Counter(
        event.get("category") or "미분류" for event in events
    )
    by_pir = Counter(pid for event in events for pid in event.get("pirs") or [])

    actor_counter = Counter()
    malware_counter = Counter()
    technique_counter = Counter()
    ioc_seen = set()
    iocs = []
    for event in events:
        if event.get("threat_actor"):
            actor_counter[event["threat_actor"]] += 1
        if event.get("malware_family"):
            malware_counter[event["malware_family"]] += 1
        for technique in event.get("attack_techniques") or []:
            technique_counter[technique] += 1
        for ioc in event.get("iocs") or []:
            # 신규 형식은 {"type", "value"} — 구형 문자열도 방어적으로 수용
            if not isinstance(ioc, dict):
                ioc = {"type": "unknown", "value": str(ioc)}
            key = str(ioc.get("value", "")).lower()
            if key and key not in ioc_seen:
                ioc_seen.add(key)
                iocs.append(ioc)

    return {
        "total": len(events),
        "by_source": by_source,
        "by_category": by_category,
        "by_pir": by_pir,
        "critical": critical,
        "kev": kev,
        "ransomware": [event for event in events if event.get("ransomware_use")],
        "asset_hits": asset_hits,
        "p1": [event for event in events if event_level(event) == "P1"],
        "p2": [event for event in events if event_level(event) == "P2"],
        "top_cves": cve_counter.most_common(10),
        "top_assets": asset_counter.most_common(10),
        "top_actors": actor_counter.most_common(10),
        "top_malware": malware_counter.most_common(10),
        "top_techniques": technique_counter.most_common(10),
        "iocs": iocs,
    }


def event_sort_key(event):
    """P1 > P2 > 자산 매칭 > KEV > CVSS 점수 순 우선순위 키"""
    level_rank = {"P1": 0, "P2": 1}.get(event_level(event), 2)
    return (
        level_rank,
        0 if event.get("matched_assets") else 1,
        0 if event.get("source") == "cisa_kev" else 1,
        -event_score(event),
    )


def top_items(events, limit=MAX_TOP_ITEMS_IN_REPORT):
    """P1 > P2 > 자산 매칭 > KEV > CVSS 점수 순으로 우선순위 정렬"""
    return sorted(events, key=event_sort_key)[:limit]


def event_alerted(event):
    delivery = event.get("delivery") or {}
    return bool(delivery.get("email_sent") or delivery.get("slack_sent"))


def importance_score(event):
    return ((event.get("importance") or {}).get("score")) or 0


def pick_trend_reads(events, exclude_ids):
    """알림 문턱을 못 넘었지만 읽을 가치가 있는 동향 기사 큐레이션.

    긴급도(악용·자산) 축과 별개로 '읽을 가치' 축을 보완한다.

    후보: 미알림·미노출 뉴스 중 ①PIR에 답하거나 ②관련성 high인 위협/동향
    기사 ③신뢰도 B(자체 텔레메트리 벤더 리서치) 소스의 관련성 medium 분석.
    이미 다른 소스로 알림된 사건의 재보도와 noise로 라벨된 이벤트는 제외.

    정렬은 인사이트 축 우선 — PIR high 매칭 수 → PIR 매칭 수 → 주제 반복
    여부(이미 알림된 행위자·멀웨어 재탕은 후순위) → LLM 확신도(low 후순위)
    → 관련성 → 신규성(new > update > known) → 콘텐츠 깊이(심층 분석 >
    보고서 > 단신 > 칼럼) → 인텔 풍부도(IOC·ATT&CK 수) → 중요도 점수 →
    최신순. 중요도 점수는 긴급도 축 산물이라 동점 처리자로만
    쓴다(점수 우선으로 두면 "알림 문턱에 가까웠던 기사"가 PIR에 정확히
    답하는 기사를 항상 밀어낸다).

    선택은 그리디 — PIR 커버리지는 기간 내 알림된 기사가 이미 답한 PIR을
    커버된 것으로 시드해서, 추천이 "알림이 못 채운 정보 요구의 빈틈"을
    메우게 한다. 1차로 미커버 high 가중치 PIR, 2차로 미커버 PIR 전체,
    3차는 정렬순 충원. 같은 사건(클러스터)·같은 행위자/멀웨어 주제는
    1건만, 카테고리당 최대 MAX_TREND_PER_CATEGORY건 (슬롯이 남으면
    상한 해제).
    """
    pir_defs = common_utils.load_pirs()
    feedback = common_utils.load_feedback()

    def published_ts(event):
        parsed = parse_iso(event.get("published_at"))
        return parsed.timestamp() if parsed else 0.0

    def event_topics(event):
        return {str(value).lower() for value in (event.get("threat_actor"), event.get("malware_family")) if value}

    alerted_topics, alerted_pirs = set(), set()
    for event in events:
        if event_alerted(event):
            alerted_topics.update(event_topics(event))
            alerted_pirs.update(event.get("pirs") or [])

    # 미판정(구 이벤트, enrichment 실패)은 중간값 — 신규 필드가 없는 이벤트가 불이익을 받지 않게
    depth_rank = {"analysis": 0, "report": 1, "news": 3, "opinion": 4}
    novelty_rank = {"new": 0, "update": 1, "known": 3}

    def insight_sort_key(event):
        weights = [(pir_defs.get(pid) or {}).get("weight") for pid in event.get("pirs") or []]
        intel_richness = min(len(event.get("iocs") or []) + len(event.get("attack_techniques") or []), 10)
        return (
            -sum(1 for weight in weights if weight == "high"),
            -len(weights),
            1 if event_topics(event) & alerted_topics else 0,
            1 if (event.get("confidence") or "") == "low" else 0,  # LLM 스스로 모호하다 한 판정은 후순위
            {"high": 0, "medium": 1}.get(event.get("relevance") or "", 2),
            novelty_rank.get(event.get("novelty") or "", 2),
            depth_rank.get(event.get("content_depth") or "", 2),
            -intel_richness,
            -importance_score(event),
            -published_ts(event),
        )

    candidates = []
    for event in events:
        if event.get("id") in exclude_ids:
            continue
        if (event.get("source") or "") in NON_NEWS_SOURCES:
            continue
        if event_alerted(event):
            continue
        if (event.get("cluster") or {}).get("already_alerted"):
            continue  # 다른 소스로 이미 알림된 사건의 재보도
        if (feedback.get(event.get("id")) or {}).get("label") == "noise":
            continue
        relevance = event.get("relevance") or ""
        reliability = (event.get("importance") or {}).get("reliability") or ""
        has_insight = bool(event.get("pirs")) or (
            (event.get("category") or "") in TREND_CATEGORIES
            and (relevance == "high" or (relevance == "medium" and reliability == "B"))
        )
        if has_insight:
            candidates.append(event)
    candidates.sort(key=insight_sort_key)

    picked, picked_ids, picked_related, picked_topics = [], set(), set(), set()
    category_counts = Counter()
    covered_pirs = set(alerted_pirs)  # 알림이 이미 답한 PIR은 커버된 것으로 시드

    def try_pick(event, require_new_pir, require_high, enforce_cap):
        if len(picked) >= MAX_TREND_ITEMS or event.get("id") in picked_ids:
            return
        related = set((event.get("cluster") or {}).get("related_ids") or [])
        if event.get("id") in picked_related or related & picked_ids:
            return  # 이미 뽑힌 기사와 같은 사건
        topics = event_topics(event)
        category = event.get("category") or "기타"
        if enforce_cap and (category_counts[category] >= MAX_TREND_PER_CATEGORY
                            or topics & picked_topics):
            return  # 카테고리 쏠림 / 같은 행위자·멀웨어 주제 반복 방지 (슬롯 남으면 해제)
        new_pirs = set(event.get("pirs") or []) - covered_pirs
        if require_new_pir and not new_pirs:
            return
        if require_high and not any((pir_defs.get(pid) or {}).get("weight") == "high" for pid in new_pirs):
            return
        picked.append(event)
        picked_ids.add(event.get("id"))
        picked_related.update(related)
        picked_topics.update(topics)
        category_counts[category] += 1
        covered_pirs.update(new_pirs)

    # 1차: 미커버 high 가중치 PIR / 2차: 미커버 PIR 전체 / 3차: 정렬순 충원 /
    # 4차: 슬롯이 남으면 카테고리·주제 상한 해제
    for require_new_pir, require_high, enforce_cap in (
        (True, True, True), (True, False, True), (False, False, True), (False, False, False)
    ):
        for event in candidates:
            try_pick(event, require_new_pir, require_high, enforce_cap)

    return picked


def trend_bits(event):
    """동향 기사 한 줄에 붙일 근거 조각들 (기사 유형, PIR, 관련성, 중요도 점수)"""
    bits = []
    if (event.get("novelty") or "") == "new":
        bits.append("신규")
    depth_label = {"analysis": "심층 분석", "report": "보고서"}.get(event.get("content_depth") or "")
    if depth_label:
        bits.append(depth_label)
    if event.get("pirs"):
        bits.append(", ".join(event["pirs"]))
    if event.get("relevance") == "high":
        bits.append("관련성 high")
    if importance_score(event):
        bits.append("{}점".format(importance_score(event)))
    return bits


def group_by_pir(events):
    """PIR별 이벤트 그룹 [(pir_id, question, 우선순위 정렬된 이벤트들)]. 복수 PIR 매칭 시 중복 등장."""
    pir_defs = common_utils.load_pirs()
    grouped = {}
    for event in events:
        for pid in event.get("pirs") or []:
            if pid in pir_defs:
                grouped.setdefault(pid, []).append(event)
    return [
        (pid, pir_defs[pid]["question"], sorted(grouped[pid], key=event_sort_key))
        for pid in sorted(grouped)
    ]


def unanswered_pirs(pir_groups):
    """정의된 PIR 중 기간 내 매칭 기사가 0건인 것 — 수집 공백(collection gap) 신호"""
    matched = {pid for pid, _, _ in pir_groups}
    pir_defs = common_utils.load_pirs()
    return [(pid, pir_defs[pid]["question"]) for pid in sorted(pir_defs) if pid not in matched]


def group_by_category(events):
    """LLM 분류(category)가 있는 이벤트를 카테고리별로 묶어 (카테고리, 이벤트 목록) 반환.

    뉴스형 소스(보안뉴스·ASEC·RSS 피드) 전용 뷰 — API 소스(NVD 등)는 category가
    비어 있어 제외된다. 카테고리 순서는 ENRICH_CATEGORIES 정의 순, 그룹 내부는
    우선순위 순 정렬.
    """
    grouped = {}
    for event in events:
        category = common_utils.clean_text(event.get("category"))
        if not category:
            continue
        grouped.setdefault(category, []).append(event)

    order = {category: idx for idx, category in enumerate(common_utils.ENRICH_CATEGORIES)}
    return [
        (category, sorted(grouped[category], key=event_sort_key))
        for category in sorted(grouped, key=lambda c: (order.get(c, len(order)), c))
    ]


def _union(group, field):
    """그룹 내 이벤트들의 리스트 필드를 순서 보존하며 합집합"""
    seen = set()
    merged = []
    for event in group:
        for value in event.get(field) or []:
            key = str(value).lower()
            if key not in seen:
                seen.add(key)
                merged.append(value)
    return merged


def build_cve_card(cve, group, sources):
    """같은 CVE를 다루는 여러 소스의 이벤트를 카드 하나로 병합.

    소스마다 가진 정보가 달라(NVD=점수·참조, KEV=악용·기한, 뉴스·ASEC=국내 맥락)
    합치면 취약점 하나의 완성된 그림이 된다.
    """
    level_rank = {"P1": 0, "P2": 1}
    exploitation_rank = {"active": 0, "poc": 1, "none": 2}

    levels = [event_level(event) for event in group if event_level(event) in level_rank]
    epss_values = [event["epss"] for event in group if isinstance(event.get("epss"), (int, float))]

    # 조치 지침은 권위 순: KEV(당국 지침) > 그 외 첫 번째 비어있지 않은 값
    remediation = ""
    for event in sorted(group, key=lambda e: 0 if e.get("source") == "cisa_kev" else 1):
        if event.get("remediation"):
            remediation = event["remediation"]
            break

    # 요약은 한국어 맥락(뉴스·ASEC의 LLM 요약) 우선
    summary = ""
    for event in sorted(group, key=lambda e: 0 if e.get("source") in ("boannews", "asec", "kisa") else 1):
        summary = (event.get("ai_summary") or event.get("summary") or "").strip()
        if summary:
            break

    return {
        "cve": cve,
        "sources": sources,
        "level": min(levels, key=lambda l: level_rank[l]) if levels else "",
        "score": max((event_score(event) for event in group), default=0.0),
        "epss": max(epss_values) if epss_values else None,
        "exploitation": min(
            (event.get("exploitation_status") or "none" for event in group),
            key=lambda s: exploitation_rank.get(s, 2),
        ),
        "kev": any(event.get("kev") for event in group),
        "ransomware": any(event.get("ransomware_use") for event in group),
        "fix_available": any(event.get("fix_available") for event in group) or None,
        "due_date": next((event["due_date"] for event in group if event.get("due_date")), ""),
        "remediation": remediation,
        "summary": summary[:300],
        "products": _union(group, "affected_products"),
        "assets": _union(group, "matched_assets"),
        "actors": [event["threat_actor"] for event in group if event.get("threat_actor")],
        "items": [
            (event.get("source"), event.get("title") or "", event.get("url") or "")
            for event in group
        ],
        "event_ids": {event.get("id") for event in group},
    }


def correlate_by_cve(events):
    """이벤트를 CVE 기준으로 묶어, 복수 소스(≥2)에 동시 등장한 CVE 카드 목록을 반환.

    복수 소스 동시 등장 자체가 가장 강한 중요도 신호다:
    NVD 단독 = 배경 소음, +KEV = 실제 악용, +국내 뉴스·ASEC = 국내에서 문제되는 위협.
    """
    groups = {}
    for event in events:
        for cve in event.get("cves") or []:
            groups.setdefault(cve, []).append(event)

    cards = []
    for cve, group in groups.items():
        sources = sorted({event.get("source") or "unknown" for event in group})
        if len(sources) < 2:
            continue
        cards.append(build_cve_card(cve, group, sources))

    level_rank = {"P1": 0, "P2": 1, "": 2}
    cards.sort(
        key=lambda card: (
            level_rank.get(card["level"], 2),
            -len(card["sources"]),
            0 if card["kev"] else 1,
            0 if card["ransomware"] else 1,
            0 if card["assets"] else 1,
            -(card["epss"] or 0.0),
            -card["score"],
        )
    )
    return cards


def card_severity_bits(card):
    """카드의 심각도 요약 문자열 조각들"""
    bits = []
    if card["level"]:
        bits.append(card["level"])
    if card["score"] > 0:
        bits.append("CVSS {}".format(card["score"]))
    if card["epss"] is not None:
        bits.append("EPSS {:.0%}".format(card["epss"]))
    if card["kev"]:
        bits.append("실제 악용 확인(KEV)")
    elif card["exploitation"] == "active":
        bits.append("악용 정황")
    elif card["exploitation"] == "poc":
        bits.append("PoC 공개")
    if card["ransomware"]:
        bits.append("랜섬웨어 연계")
    if card["assets"]:
        bits.append("자산매칭: {}".format(", ".join(card["assets"])))
    return bits


def event_line(event):
    bits = []
    if event_level(event) in ("P1", "P2"):
        bits.append(event_level(event))
    if event.get("severity"):
        bits.append(str(event["severity"]))
    if event_score(event) > 0:
        bits.append("CVSS {}".format(event["score"]))
    if isinstance(event.get("epss"), (int, float)):
        bits.append("EPSS {:.0%}".format(event["epss"]))
    if event.get("category"):
        bits.append(str(event["category"]))
    if event.get("threat_actor"):
        bits.append("공격그룹: {}".format(event["threat_actor"]))
    if event.get("malware_family"):
        bits.append("악성코드: {}".format(event["malware_family"]))
    if event.get("ransomware_use"):
        bits.append("랜섬웨어 연계")
    if event.get("due_date"):
        bits.append("조치기한 {}".format(event["due_date"]))
    if event.get("fix_available"):
        bits.append("패치 있음")
    if event.get("matched_assets"):
        bits.append("자산매칭: {}".format(", ".join(event["matched_assets"])))
    suffix = " ({})".format("; ".join(bits)) if bits else ""

    # 수집 시점 LLM 요약(ai_summary)이 있으면 원문 요약보다 우선 사용
    summary = (event.get("ai_summary") or event.get("summary") or "").strip()
    if len(summary) > 300:
        summary = summary[:300] + "…"

    line = "- {}{}".format(event.get("title") or event.get("url") or "(제목 없음)", suffix)
    if summary:
        line += " | {}".format(summary)
    if event.get("remediation"):
        line += " | 조치: {}".format(event["remediation"][:100])
    return line


def build_digest(period_label, stats, events, cards):
    """LLM에 전달할 구조화된 요약 텍스트"""
    lines = [
        "기간: {}".format(period_label),
        "총 이벤트: {}건".format(stats["total"]),
        "",
        "[소스별 건수]",
    ]
    for source, count in stats["by_source"].most_common():
        lines.append("- {}: {}건".format(source_label(source), count))

    if len(stats["by_category"]) > 1 or "미분류" not in stats["by_category"]:
        lines.append("")
        lines.append("[카테고리별 건수]")
        for category, count in stats["by_category"].most_common():
            lines.append("- {}: {}건".format(category, count))

    if stats.get("by_pir"):
        lines.append("")
        lines.append("[우선 정보 요구사항(PIR)별 건수]")
        pir_defs = common_utils.load_pirs()
        for pid, count in sorted(stats["by_pir"].items()):
            lines.append("- {} ({}): {}건".format(pid, (pir_defs.get(pid) or {}).get("question", "")[:40], count))

    if stats["top_actors"] or stats["top_malware"]:
        lines.append("")
        lines.append("[언급된 공격 그룹·악성코드]")
        for actor, count in stats["top_actors"]:
            lines.append("- 공격그룹 {}: {}건".format(actor, count))
        for malware, count in stats["top_malware"]:
            lines.append("- 악성코드 {}: {}건".format(malware, count))

    if stats["top_techniques"]:
        lines.append("")
        lines.append("[MITRE ATT&CK 기법]")
        for technique, count in stats["top_techniques"]:
            lines.append("- {}: {}건".format(technique, count))

    lines.append("")
    lines.append("[요약 통계]")
    lines.append("- P1 긴급(악용 중 + 자사 자산): {}건".format(len(stats["p1"])))
    lines.append("- P2 주의: {}건".format(len(stats["p2"])))
    lines.append("- CVSS 9.0 이상(Critical): {}건".format(len(stats["critical"])))
    lines.append("- CISA KEV(실제 악용 확인): {}건".format(len(stats["kev"])))
    lines.append("- 랜섬웨어 캠페인 연계: {}건".format(len(stats["ransomware"])))
    lines.append("- 자사 자산 매칭: {}건".format(len(stats["asset_hits"])))

    if stats["top_assets"]:
        lines.append("")
        lines.append("[자사 자산 매칭 상세]")
        for term, count in stats["top_assets"]:
            lines.append("- {}: {}건".format(term, count))

    if cards:
        lines.append("")
        lines.append("[크로스소스 상관관계 — 복수 소스에 동시 등장한 CVE (신뢰도 높은 핵심 위협)]")
        for card in cards[:MAX_CVE_CARDS]:
            parts = [
                "{} (소스 {}개: {})".format(
                    card["cve"], len(card["sources"]),
                    ", ".join(source_label(s) for s in card["sources"]),
                )
            ]
            parts.extend(card_severity_bits(card))
            if card["products"]:
                parts.append("영향: {}".format(", ".join(card["products"][:5])))
            if card["remediation"]:
                parts.append("조치: {}".format(card["remediation"][:100]))
            if card["due_date"]:
                parts.append("조치기한 {}".format(card["due_date"]))
            lines.append("- " + " | ".join(parts))
            if card["summary"]:
                lines.append("  요약: {}".format(card["summary"][:200]))

    grouped = {}
    for event in events:
        grouped.setdefault(event.get("source") or "unknown", []).append(event)

    for source, group in grouped.items():
        group = sorted(group, key=event_score, reverse=True)
        lines.append("")
        lines.append("[{}]".format(source_label(source)))
        for event in group[:MAX_ITEMS_PER_SOURCE_IN_PROMPT]:
            lines.append(event_line(event))
        if len(group) > MAX_ITEMS_PER_SOURCE_IN_PROMPT:
            lines.append("- ...외 {}건".format(len(group) - MAX_ITEMS_PER_SOURCE_IN_PROMPT))

    return "\n".join(lines)


def ai_narrative(period_label, digest):
    prompt = """당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다.
아래는 {period} 동안 수집된 보안 이벤트 요약이다. 이를 바탕으로 보안담당자용 리포트 본문을 한국어로 작성하라.

출력 형식:
[총평]
- 2~3문장

[핵심 위협 TOP 3]
- 각 항목마다 무엇이 왜 중요한지 1~2문장

[자사 자산 관련]
- 매칭된 항목이 있으면 조치 우선순위를 제시하고, 없으면 "해당 없음"이라고만 작성

[권고 조치]
- 3개 이내

주의: 제공된 데이터에 없는 사실을 만들어내지 마라. 건수와 수치는 데이터에 있는 그대로 사용하라.

데이터:
{digest}
""".format(period=period_label, digest=digest)

    return common_utils.llm_generate(prompt, timeout=300) or ""


def build_text_report(title, period_label, stats, narrative, highlights, cards, categorized, pir_groups,
                      trend_reads):
    lines = [
        title,
        "기간: {}".format(period_label),
        "생성 시각: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
        "",
        "[수집 현황]",
        "- 총 {}건 (P1 {} / P2 {} / Critical {} / KEV {} / 랜섬웨어 {} / 자산매칭 {})".format(
            stats["total"], len(stats["p1"]), len(stats["p2"]),
            len(stats["critical"]), len(stats["kev"]), len(stats["ransomware"]),
            len(stats["asset_hits"])
        ),
    ]
    for source, count in stats["by_source"].most_common():
        lines.append("- {}: {}건".format(source_label(source), count))

    category_counts = [(c, n) for c, n in stats["by_category"].most_common() if c != "미분류"]
    if category_counts:
        lines.append("- 카테고리: {}".format(
            ", ".join("{} {}건".format(category, count) for category, count in category_counts)
        ))

    if narrative:
        lines.append("")
        lines.append("[AI 분석]")
        lines.append(narrative)

    pir_gaps = unanswered_pirs(pir_groups)
    if pir_groups or pir_gaps:
        lines.append("")
        lines.append("[PIR 현황 — 우선 정보 요구사항]")
        for pid, question, group in pir_groups:
            lines.append("")
            lines.append("■ {} — {} ({}건)".format(pid, question, len(group)))
            for event in group[:MAX_ITEMS_PER_PIR]:
                level_prefix = "[{}] ".format(event_level(event)) if event_level(event) in ("P1", "P2") else ""
                lines.append("- {}[{}] {}".format(level_prefix, source_label(event.get("source")), event.get("title")))
                lines.append("  {}".format(event.get("url") or ""))
            if len(group) > MAX_ITEMS_PER_PIR:
                lines.append("- ...외 {}건".format(len(group) - MAX_ITEMS_PER_PIR))
        if pir_gaps:
            lines.append("")
            lines.append("■ 무응답 PIR — 기간 내 매칭 기사 없음 (수집 공백)")
            for pid, question in pir_gaps:
                lines.append("- {} — {}".format(pid, question))

    if cards:
        lines.append("")
        lines.append("[핵심 취약점 TOP {} — 복수 소스 교차 확인]".format(min(len(cards), MAX_CVE_CARDS)))
        for idx, card in enumerate(cards[:MAX_CVE_CARDS], start=1):
            lines.append("{}. {} (소스 {}개: {})".format(
                idx, card["cve"], len(card["sources"]),
                ", ".join(source_label(s) for s in card["sources"]),
            ))
            bits = card_severity_bits(card)
            if bits:
                lines.append("   심각도: {}".format(" / ".join(bits)))
            if card["products"]:
                lines.append("   영향: {}".format(", ".join(card["products"][:5])))
            if card["remediation"]:
                due = " (기한 {})".format(card["due_date"]) if card["due_date"] else ""
                lines.append("   조치: {}{}".format(card["remediation"][:150], due))
            if card["summary"]:
                lines.append("   요약: {}".format(card["summary"][:200]))
            for source, item_title, item_url in card["items"]:
                lines.append("   - [{}] {} {}".format(source_label(source), item_title, item_url))

    lines.append("")
    lines.append("[주요 뉴스 TOP {}]".format(len(highlights)))
    for idx, event in enumerate(highlights, start=1):
        level_prefix = "[{}] ".format(event_level(event)) if event_level(event) in ("P1", "P2") else ""
        lines.append("{}. {}[{}] {}".format(idx, level_prefix, source_label(event.get("source")), event.get("title")))
        lines.append("   {}".format(event.get("url") or ""))

    if trend_reads:
        lines.append("")
        lines.append("[읽을만한 동향 — 알림 외 주목 기사]")
        for event in trend_reads:
            bits = trend_bits(event)
            suffix = " ({})".format(" | ".join(bits)) if bits else ""
            lines.append("- [{}] {}{}".format(source_label(event.get("source")), event.get("title"), suffix))
            lines.append("  {}".format(event.get("url") or ""))

    if categorized:
        lines.append("")
        lines.append("[카테고리별 뉴스]")
        for category, group in categorized:
            lines.append("")
            lines.append("■ {} ({}건)".format(category, len(group)))
            for event in group[:MAX_ITEMS_PER_CATEGORY]:
                level_prefix = "[{}] ".format(event_level(event)) if event_level(event) in ("P1", "P2") else ""
                lines.append("- {}[{}] {}".format(level_prefix, source_label(event.get("source")), event.get("title")))
                lines.append("  {}".format(event.get("url") or ""))
            if len(group) > MAX_ITEMS_PER_CATEGORY:
                lines.append("- ...외 {}건".format(len(group) - MAX_ITEMS_PER_CATEGORY))

    if stats["iocs"]:
        lines.append("")
        lines.append("[부록: 수집된 IOC {}건]".format(len(stats["iocs"])))
        for ioc in stats["iocs"][:30]:
            lines.append("- [{}] {}".format(ioc.get("type", "unknown"), ioc.get("value", "")))
        if len(stats["iocs"]) > 30:
            lines.append("- ...외 {}건".format(len(stats["iocs"]) - 30))

    return "\n".join(lines)


def build_html_report(title, period_label, stats, narrative, highlights, cards, categorized, pir_groups,
                      trend_reads):
    parts = [
        "<html><body>",
        "<h2>{}</h2>".format(html.escape(title)),
        "<p>기간: {} | 생성 시각: {}</p>".format(
            html.escape(period_label), datetime.now().strftime("%Y-%m-%d %H:%M")
        ),
        "<h3>수집 현황</h3>",
        "<p>총 <b>{}</b>건 — <b>P1 {}</b> / P2 {} / Critical {} / KEV {} / 랜섬웨어 {} / 자산매칭 {}</p>".format(
            stats["total"], len(stats["p1"]), len(stats["p2"]),
            len(stats["critical"]), len(stats["kev"]), len(stats["ransomware"]),
            len(stats["asset_hits"])
        ),
        "<ul>",
    ]
    for source, count in stats["by_source"].most_common():
        parts.append("<li>{}: {}건</li>".format(html.escape(source_label(source)), count))
    category_counts = [(c, n) for c, n in stats["by_category"].most_common() if c != "미분류"]
    if category_counts:
        parts.append("<li>카테고리: {}</li>".format(html.escape(
            ", ".join("{} {}건".format(category, count) for category, count in category_counts)
        )))
    parts.append("</ul>")

    if narrative:
        parts.append("<h3>AI 분석</h3>")
        parts.append("<p>{}</p>".format(html.escape(narrative).replace("\n", "<br>")))

    pir_gaps = unanswered_pirs(pir_groups)
    if pir_groups or pir_gaps:
        parts.append("<h3>PIR 현황 — 우선 정보 요구사항</h3>")
        for pid, question, group in pir_groups:
            parts.append("<h4>{} — {} ({}건)</h4>".format(html.escape(pid), html.escape(question), len(group)))
            parts.append("<ul>")
            for event in group[:MAX_ITEMS_PER_PIR]:
                level_prefix = "<b>{}</b> ".format(event_level(event)) if event_level(event) in ("P1", "P2") else ""
                parts.append('<li>{}[{}] <a href="{}">{}</a></li>'.format(
                    level_prefix,
                    html.escape(source_label(event.get("source"))),
                    html.escape(event.get("url") or "#"),
                    html.escape(event.get("title") or "(제목 없음)"),
                ))
            if len(group) > MAX_ITEMS_PER_PIR:
                parts.append("<li>...외 {}건</li>".format(len(group) - MAX_ITEMS_PER_PIR))
            parts.append("</ul>")
        if pir_gaps:
            parts.append("<h4>무응답 PIR — 기간 내 매칭 기사 없음 (수집 공백)</h4>")
            parts.append("<ul>")
            for pid, question in pir_gaps:
                parts.append("<li>{} — {}</li>".format(html.escape(pid), html.escape(question)))
            parts.append("</ul>")

    if cards:
        parts.append("<h3>핵심 취약점 TOP {} — 복수 소스 교차 확인</h3>".format(min(len(cards), MAX_CVE_CARDS)))
        parts.append("<ol>")
        for card in cards[:MAX_CVE_CARDS]:
            card_parts = [
                "<b>{}</b> (소스 {}개: {})".format(
                    html.escape(card["cve"]), len(card["sources"]),
                    html.escape(", ".join(source_label(s) for s in card["sources"])),
                )
            ]
            bits = card_severity_bits(card)
            if bits:
                card_parts.append("심각도: {}".format(html.escape(" / ".join(bits))))
            if card["products"]:
                card_parts.append("영향: {}".format(html.escape(", ".join(card["products"][:5]))))
            if card["remediation"]:
                due = " (기한 {})".format(card["due_date"]) if card["due_date"] else ""
                card_parts.append("조치: {}{}".format(html.escape(card["remediation"][:150]), html.escape(due)))
            if card["summary"]:
                card_parts.append(html.escape(card["summary"][:200]))
            card_parts.append(
                " · ".join(
                    '<a href="{}">{}</a>'.format(html.escape(item_url or "#"), html.escape(source_label(source)))
                    for source, _, item_url in card["items"]
                )
            )
            parts.append("<li>{}</li>".format("<br>".join(card_parts)))
        parts.append("</ol>")

    parts.append("<h3>주요 뉴스 TOP {}</h3>".format(len(highlights)))
    parts.append("<ol>")
    for event in highlights:
        extra = []
        if event_level(event) in ("P1", "P2"):
            extra.append("<b>{}</b>".format(event_level(event)))
        if event.get("severity"):
            extra.append(html.escape(str(event["severity"])))
        if event_score(event) > 0:
            extra.append("CVSS {}".format(event["score"]))
        if event.get("matched_assets"):
            extra.append("자산매칭: {}".format(html.escape(", ".join(event["matched_assets"]))))
        suffix = " ({})".format(" / ".join(extra)) if extra else ""

        parts.append(
            '<li>[{}] <a href="{}">{}</a>{}</li>'.format(
                html.escape(source_label(event.get("source"))),
                html.escape(event.get("url") or "#"),
                html.escape(event.get("title") or "(제목 없음)"),
                suffix,
            )
        )
    parts.append("</ol>")

    if trend_reads:
        parts.append("<h3>읽을만한 동향 — 알림 외 주목 기사</h3>")
        parts.append("<ul>")
        for event in trend_reads:
            bits = trend_bits(event)
            suffix = " ({})".format(html.escape(" | ".join(bits))) if bits else ""
            parts.append('<li>[{}] <a href="{}">{}</a>{}</li>'.format(
                html.escape(source_label(event.get("source"))),
                html.escape(event.get("url") or "#"),
                html.escape(event.get("title") or "(제목 없음)"),
                suffix,
            ))
        parts.append("</ul>")

    if categorized:
        parts.append("<h3>카테고리별 뉴스</h3>")
        for category, group in categorized:
            parts.append("<h4>{} ({}건)</h4>".format(html.escape(category), len(group)))
            parts.append("<ul>")
            for event in group[:MAX_ITEMS_PER_CATEGORY]:
                level_prefix = "<b>{}</b> ".format(event_level(event)) if event_level(event) in ("P1", "P2") else ""
                parts.append('<li>{}[{}] <a href="{}">{}</a></li>'.format(
                    level_prefix,
                    html.escape(source_label(event.get("source"))),
                    html.escape(event.get("url") or "#"),
                    html.escape(event.get("title") or "(제목 없음)"),
                ))
            if len(group) > MAX_ITEMS_PER_CATEGORY:
                parts.append("<li>...외 {}건</li>".format(len(group) - MAX_ITEMS_PER_CATEGORY))
            parts.append("</ul>")

    if stats["iocs"]:
        parts.append("<h3>부록: 수집된 IOC {}건</h3>".format(len(stats["iocs"])))
        parts.append("<ul>")
        for ioc in stats["iocs"][:30]:
            parts.append("<li>[{}] <code>{}</code></li>".format(
                html.escape(ioc.get("type", "unknown")), html.escape(ioc.get("value", ""))
            ))
        if len(stats["iocs"]) > 30:
            parts.append("<li>...외 {}건</li>".format(len(stats["iocs"]) - 30))
        parts.append("</ul>")

    parts.append("</body></html>")
    return "".join(parts)


def build_slack_blocks(title, period_label, stats, narrative, highlights, cards, categorized, pir_groups,
                       trend_reads):
    stat_text = (
        "총 *{}건* 수집 — 🚨 P1 `{}` / ⚠️ P2 `{}` / Critical `{}` / KEV `{}` / 🔒 랜섬웨어 `{}` / 자산매칭 `{}`\n".format(
            stats["total"], len(stats["p1"]), len(stats["p2"]),
            len(stats["critical"]), len(stats["kev"]), len(stats["ransomware"]),
            len(stats["asset_hits"])
        )
        + "\n".join(
            "> {}: {}건".format(source_label(source), count)
            for source, count in stats["by_source"].most_common()
        )
    )

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "📊 " + title, "emoji": True}},
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "🕒 {} | {}".format(period_label, datetime.now().strftime("%Y-%m-%d %H:%M"))}],
        },
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": stat_text}},
    ]

    if narrative:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "🤖 *AI 분석*\n" + narrative}})

    pir_gaps = unanswered_pirs(pir_groups)
    if pir_groups or pir_gaps:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "🎯 *PIR 현황 — 우선 정보 요구사항*"}})
        for pid, question, group in pir_groups:
            pir_lines = []
            for event in group[:3]:
                level = event_level(event)
                marker = "🚨" if level == "P1" else ("⚠️" if level == "P2" else "•")
                pir_lines.append("{} [{}] <{}|{}>".format(
                    marker, source_label(event.get("source")),
                    event.get("url") or "#",
                    (event.get("title") or "(제목 없음)")[:100],
                ))
            if len(group) > 3:
                pir_lines.append("...외 {}건".format(len(group) - 3))
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*{}* — {} ({}건)\n{}".format(
                    pid, question[:60], len(group), "\n".join(pir_lines)
                )},
            })
        if pir_gaps:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "⚪ 무응답 PIR (기간 내 매칭 기사 없음 — 수집 공백): {}".format(
                        ", ".join(pid for pid, _ in pir_gaps)
                    ),
                }],
            })

    if cards:
        card_lines = []
        for idx, card in enumerate(cards[:MAX_CVE_CARDS], start=1):
            marker = "🚨" if card["level"] == "P1" else ("⚠️" if card["level"] == "P2" else "🎯")
            bits = card_severity_bits(card)
            line = "{} {}. *{}* — 소스 {}개 ({})".format(
                marker, idx, card["cve"], len(card["sources"]),
                ", ".join(source_label(s) for s in card["sources"]),
            )
            if bits:
                line += "\n> {}".format(" / ".join(bits))
            if card["remediation"]:
                due = " (기한 {})".format(card["due_date"]) if card["due_date"] else ""
                line += "\n> 조치: {}{}".format(card["remediation"][:120], due)
            card_lines.append(line)
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*핵심 취약점 — 복수 소스 교차 확인*\n" + "\n".join(card_lines)},
        })

    if highlights:
        blocks.append({"type": "divider"})
        highlight_lines = []
        for idx, event in enumerate(highlights, start=1):
            level = event_level(event)
            if level == "P1":
                marker = "🚨"
            elif level == "P2":
                marker = "⚠️"
            elif event.get("source") == "cisa_kev":
                marker = "🔥"
            else:
                marker = "•"
            highlight_lines.append(
                "{} {}. [{}] <{}|{}>".format(
                    marker,
                    idx,
                    source_label(event.get("source")),
                    event.get("url") or "#",
                    (event.get("title") or "(제목 없음)")[:120],
                )
            )
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*주요 뉴스 TOP {}*\n".format(len(highlights)) + "\n".join(highlight_lines)}})

    if trend_reads:
        trend_lines = []
        for event in trend_reads:
            bits = trend_bits(event)
            suffix = " _({})_".format(" · ".join(bits)) if bits else ""
            # 해시는 feedback.py 라벨링용 식별자. 의도적으로 `ref:` 접두사를 뺐다 —
            # 슬랙 폴러가 ref: 패턴을 메시지 단위로 매칭하므로, 리포트 메시지에 단 반응
            # 하나가 트렌드 기사 전체에 동일 라벨로 번지는 오염을 막는다.
            trend_lines.append("• [{}] <{}|{}>{} `{}`".format(
                source_label(event.get("source")),
                event.get("url") or "#",
                (event.get("title") or "(제목 없음)")[:100],
                suffix,
                common_utils.event_ref(event.get("id") or ""),
            ))
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "📖 *읽을만한 동향 — 알림 외 주목 기사*\n" + "\n".join(trend_lines)},
        })
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": "추천이 유용/노이즈였는지 `python scripts\\feedback.py --useful(--noise) <해시>`로 라벨링하면 큐레이션·중요도 학습에 반영됩니다.",
            }],
        })

    if categorized:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "🗂️ *카테고리별 뉴스*"}})
        for category, group in categorized:
            category_lines = []
            for event in group[:MAX_ITEMS_PER_CATEGORY]:
                level = event_level(event)
                marker = "🚨" if level == "P1" else ("⚠️" if level == "P2" else "•")
                category_lines.append(
                    "{} [{}] <{}|{}>".format(
                        marker,
                        source_label(event.get("source")),
                        event.get("url") or "#",
                        (event.get("title") or "(제목 없음)")[:100],
                    )
                )
            if len(group) > MAX_ITEMS_PER_CATEGORY:
                category_lines.append("...외 {}건".format(len(group) - MAX_ITEMS_PER_CATEGORY))
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*{}* ({}건)\n{}".format(category, len(group), "\n".join(category_lines))},
            })

    return blocks


def main():
    parser = argparse.ArgumentParser(description="일간/주간 보안 인텔리전스 리포트 생성")
    parser.add_argument("--period", choices=["daily", "weekly"], default="daily")
    parser.add_argument("--days", type=int, default=None, help="집계 기간 직접 지정(테스트용)")
    parser.add_argument("--dry-run", action="store_true", help="발송하지 않고 콘솔에 출력")
    args = parser.parse_args()

    if args.period == "daily":
        days = args.days or 1
        title = "일간 보안 인텔리전스 리포트"
    else:
        days = args.days or 7
        title = "주간 보안 인텔리전스 리포트"

    now = datetime.utcnow()
    since = now - timedelta(days=days)
    period_label = "{} ~ {} (UTC)".format(since.strftime("%Y-%m-%d %H:%M"), now.strftime("%Y-%m-%d %H:%M"))

    events = load_events(since)
    if not events:
        print("기간 내 수집된 이벤트가 없어 리포트를 생성하지 않습니다.")
        return

    stats = build_stats(events)

    # CVE 크로스소스 상관관계: 복수 소스 등장 CVE는 카드로 병합하고,
    # 카드에 포함된 이벤트는 개별 TOP 목록에서 제외해 중복 표시를 막는다
    cards = correlate_by_cve(events)
    shown_card_event_ids = set()
    for card in cards[:MAX_CVE_CARDS]:
        shown_card_event_ids.update(card["event_ids"])
    highlights = top_items([
        event for event in events
        if event.get("id") not in shown_card_event_ids
        and (event.get("source") or "") not in NON_NEWS_SOURCES
    ])
    categorized = group_by_category(events)
    pir_groups = group_by_pir(events)
    trend_reads = pick_trend_reads(
        events, shown_card_event_ids | {event.get("id") for event in highlights},
    )

    print("[*] 이벤트 {}건 집계 완료 (CVE 상관관계 카드 {}건, 뉴스 카테고리 {}종, PIR {}종). AI 해석 생성 중...".format(
        stats["total"], len(cards), len(categorized), len(pir_groups)
    ))
    digest = build_digest(period_label, stats, events, cards)
    narrative = ai_narrative(period_label, digest)
    if not narrative:
        narrative = "(AI 해석을 생성하지 못해 통계 요약만 제공합니다.)"

    text_body = build_text_report(title, period_label, stats, narrative, highlights, cards, categorized, pir_groups, trend_reads)
    html_body = build_html_report(title, period_label, stats, narrative, highlights, cards, categorized, pir_groups, trend_reads)
    blocks = build_slack_blocks(title, period_label, stats, narrative, highlights, cards, categorized, pir_groups, trend_reads)

    if args.dry_run:
        print("===== DRY RUN: 발송 생략 =====")
        print(text_body)
        return

    subject = "[{}] {} - {}건".format("일간" if args.period == "daily" else "주간", title, stats["total"])
    email_sent = common_utils.send_email_message(subject, text_body, html_body)

    payload = {"text": subject, "blocks": blocks}
    webhook_url = os.environ.get("SLACK_WEBHOOK_REPORT") or common_utils.SLACK_WEBHOOK_URL
    slack_sent = common_utils.send_slack_webhook(payload, webhook_url)

    print("리포트 발송 결과: email={}, slack={}".format(email_sent, slack_sent))


if __name__ == "__main__":
    main()
