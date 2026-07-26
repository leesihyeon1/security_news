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
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta

import common_utils
import publish_web_dashboard

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
    "microsoft_security": "Microsoft Security Blog",
    "mandiant": "Google TI (Mandiant)",
    "crowdstrike": "CrowdStrike",
    "sentinelone": "SentinelOne Labs",
    "welivesecurity": "ESET WeLiveSecurity",
    "sophos": "Sophos News",
    "trendmicro": "Trend Micro Research",
    "rapid7": "Rapid7",
    "elastic_security": "Elastic Security Labs",
    "volexity": "Volexity",
    "jpcert": "JPCERT/CC",
    "cyberscoop": "CyberScoop",
    "infosecurity_magazine": "Infosecurity Magazine",
    "theregister_security": "The Register",
    "helpnetsecurity": "Help Net Security",
    "securityaffairs": "Security Affairs",
    "dailysecu": "데일리시큐",
    "estsecurity_alyac": "알약 블로그",
    "plainbit": "플레인비트",
    "inca_isarc": "잉카 ISARC",
    "s2w": "S2W",
    "nshc_threatrecon": "NSHC ThreatRecon",
    "genians": "지니언스 시큐리티 센터",
    "proofpoint": "Proofpoint",
    "malwarebytes": "Malwarebytes Labs",
    "reddit_netsec": "Reddit r/netsec",
    "reddit_cybersecurity": "Reddit r/cybersecurity",
    "reddit_reverseengineering": "Reddit r/ReverseEngineering",
    "reddit_asknetsec": "Reddit r/AskNetsec",
    "exploit_db": "Exploit-DB",
}

# 웹 대시보드(boannews_vercel)의 국내/해외 탭 분류 — 한국어 매체·국내 벤더 리서치만
# "domestic", 나머지(해외 매체·글로벌 벤더·카탈로그형 소스 포함)는 전부 "overseas".
DOMESTIC_SOURCES = {
    "kisa", "asec", "boannews", "dailysecu", "estsecurity_alyac",
    "plainbit", "inca_isarc", "s2w", "nshc_threatrecon", "genians",
}

def source_region(source):
    return "domestic" if source in DOMESTIC_SOURCES else "overseas"

MAX_ITEMS_PER_SOURCE_IN_PROMPT = 15
MAX_TOP_ITEMS_IN_REPORT = 10
MAX_CVE_CARDS = 5
MAX_ITEMS_PER_PIR = 5

# CVE 카드 필드별 길이 상한 — 소비처마다 예산이 달라 값이 다르다:
# 요약·영향은 전 채널 공통(카드 생성 시 한 번만 자르면 됨), 조치문은 LLM
# 프롬프트(토큰 절약) < Slack(블록 길이 제한) < 이메일/텍스트(가장 여유) 순.
CARD_SUMMARY_CHARS = 200
CARD_PRODUCTS_MAX = 5
CARD_REMEDIATION_CHARS_DIGEST = 100
CARD_REMEDIATION_CHARS_SLACK = 120
CARD_REMEDIATION_CHARS = 150

# 주요 뉴스 TOP에서 제외할 비뉴스 소스 — API·공지형 항목은 CVSS 점수로 목록을
# 도배하기 쉽고, CVE 카드·소스별 전용 알림이 이미 다루므로 뉴스만 노출한다.
NON_NEWS_SOURCES = {"nvd", "cisa_kev", "msrc", "github_advisory", "kisa", "exploit_db"}

# "읽을만한 동향" 큐레이션: 긴급도 점수가 낮아 알림되지 않은 기사 중
# 인사이트 신호(PIR 매칭, 또는 high 관련성의 위협 분석 기사)가 있는 것을 고른다.
MAX_TREND_ITEMS = 5
MAX_TREND_PER_CATEGORY = 2  # 카테고리 쏠림 방지 (슬롯이 남으면 상한 해제)
TREND_CATEGORIES = {"공격캠페인", "침해사고", "개인정보유출", "악성코드", "공급망공격", "기술동향"}

# insight_score()의 축별 가중치 — 튜플 순서(어순위 축이 하나만 달라도 절대 우위) 대신
# 가중합으로 바꾼 이유: 예를 들어 relevance가 high 대 medium 한 끗 차이만으로, 신선도·
# 깊이·인텔풍부도·HN화제성·중요도에서 압도적으로 우세한 기사가 무조건 지는 게 부자연스럽다.
# 값 자체는 실측 튜닝 전 추정치 — 피드백 데이터가 쌓이면 재조정이 필요하다.
INSIGHT_WEIGHTS = {
    "pir_high": 40,       # 고가중치 PIR 매칭 1개당
    "pir_any": 8,         # PIR 매칭 1개당(고가중치 포함 전체 개수)
    "topic_repeat": -15,  # 이미 알림된 행위자·멀웨어 재탕
    "confidence_low": -8,  # LLM 스스로 모호하다고 판정
    "relevance": 25,      # high=1.0 / medium=0.5 / 미판정=0.0
    "novelty": 12,        # new=1.0 / update=0.5 / known=0.0 / 미판정=0.3
    "depth": 10,          # analyst_review rubric(기술적실체+실행가능성+신뢰성, 0~8)/8 — rubric
                          # 없는 이벤트는 하위호환으로 content_depth 근사값(analysis=1.0/.../미판정=0.4) 사용.
                          # IOC·ATT&CK 풍부도는 rubric의 technical_substance 채점 근거에 이미 포함되므로
                          # 별도 intel_richness 축(구 버전에 있었음)은 제거 — 같은 사실의 이중계산 방지.
    "hn_buzz": 6,          # log1p(HN 포인트)
    "importance": 7,      # importance_score / 100 — importance_score 자체가 pir_high/relevance/
                           # confidence_low를 이미 피처로 쓰고 있어 그 3개와 중복 계산됨. 겹치는
                           # 비중을 감안해 절반 수준으로 낮춤(악용상태·심각도·자산매칭·신뢰도 등
                           # 나머지 고유 정보는 이 가중치로 계속 반영).
    "recency": 5,          # 7일 기준 선형 감쇠 (그 이상 오래되면 0)
}



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
    """통합 이벤트 로그와 구 보안뉴스 로그를 함께 읽고 (source, url) 기준으로 중복 제거.

    append-only 로그를 끝에서부터 거슬러 읽다가 since보다 오래된 이벤트를 만나면
    멈춘다 — 로그 전체 크기와 무관하게 이번 집계 기간만큼만 읽는다.
    """
    events = {}

    for path, legacy in ((common_utils.EVENTS_FILE, False), (LEGACY_BOANNEWS_EVENTS_FILE, True)):
        if not path.exists():
            continue
        recent = []
        for line in common_utils.iter_lines_reverse(path):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = normalize_legacy_boannews(raw) if legacy else raw
            fetched = parse_iso(event.get("fetched_at"))
            if fetched is None:
                continue
            if fetched < since:
                break  # 이 지점부터는 전부 더 오래된 이벤트 — 조기 종료
            recent.append(event)

        for event in reversed(recent):  # 시간순으로 되돌려 기존 dedup(첫 등장 우선) 순서 유지
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


def _cluster_representatives(ranked_candidates):
    """related_ids 관계를 Union-Find로 전이적으로 묶어, 같은 사건 클러스터당
    1건(대표)만 남긴다.

    이전엔 "이 기사가 이미 뽑힌 기사와 direct하게 related냐"만 체크했는데,
    A-B, B-C만 related로 기록되고 A-C는 안 기록된 경우(둘 다 B를 통해서만
    연결) 그 사이 관계를 못 잡았다. 여기서는 연결요소(connected components)를
    직접 계산해서 그런 전이적 관계까지 하나의 클러스터로 묶는다.

    ranked_candidates는 이미 insight_score 내림차순으로 정렬된 상태를 가정 —
    클러스터별 대표는 그 안에서 가장 먼저 나오는(=점수가 가장 높은) 이벤트다.
    """
    ids = {event.get("id") for event in ranked_candidates}
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        root_x, root_y = find(x), find(y)
        if root_x != root_y:
            parent[root_x] = root_y

    for event in ranked_candidates:
        for related_id in (event.get("cluster") or {}).get("related_ids") or []:
            if related_id in ids:
                union(event.get("id"), related_id)

    seen_roots = set()
    representatives = []
    for event in ranked_candidates:
        root = find(event.get("id"))
        if root not in seen_roots:
            seen_roots.add(root)
            representatives.append(event)
    return representatives


def pick_trend_reads(events, exclude_ids, max_items=None, include_alerted=False):
    """알림 문턱을 못 넘었지만 읽을 가치가 있는 동향 기사 큐레이션.

    긴급도(악용·자산) 축과 별개로 '읽을 가치' 축을 보완한다.

    후보: 미알림·미노출 뉴스 중 ①PIR에 답하거나 ②관련성 high인 위협/동향
    기사 ③신뢰도 B(자체 텔레메트리 벤더 리서치) 소스의 관련성 medium 분석.
    이미 다른 소스로 알림된 사건의 재보도와 noise로 라벨된 이벤트는 제외.

    include_alerted=True면 이미 알림된 이벤트도 후보에 포함한다 — 일간/주간
    리포트는 별도 섹션(카드·TOP N)이 알림 건을 이미 보여주니 여기선 그걸
    보완해야 의미가 있지만, curator_digest.py처럼 그런 별도 섹션 없이 단독
    발송되는 경우엔 "알림 여부와 무관하게 이 기간 전체에서 읽을 가치가
    있는 것"을 추리는 게 더 맞다.

    정렬은 insight_score()의 가중합 — PIR 매칭·주제 반복·확신도·관련성·
    신규성·분석가 rubric 품질(기술적실체·실행가능성·신뢰성)·HN 화제성·
    중요도 점수·최신성을 각각 연속값으로 환산해 INSIGHT_WEIGHTS로 합산한다. 예전엔
    튜플 순서(앞 축이 조금이라도 다르면 뒤 축은 아예 안 봄)였는데, 이러면
    relevance가 high/medium 한 끗 차이만으로 신선도·깊이·인텔·HN·중요도가
    압도적으로 우세한 기사가 무조건 지는 게 부자연스러워서 가중합으로
    바꿨다. 가중치 값은 실측 튜닝 전 추정치 — 피드백이 쌓이면 재조정 대상.

    중복 제거는 _cluster_representatives()로 정렬 후 한 번에 — 같은 사건
    클러스터당 대표 1건만 후보로 남긴다. 임베딩 코사인 유사도로 유사 기사를
    소프트하게 페널티 주는 MMR 방식을 먼저 시도했었는데, 실측에서 "같은 사건,
    다른 표현"(0.93)보다 "다른 사건, 같은 행위자명 공유"(0.98)가 더 높게 나와
    신뢰할 수 없었다 — 그래서 이미 있던 신뢰할 만한 신호(CVE 겹침·제목 자카드
    기반 related_ids)를 전이적으로 클러스터링하는 방식으로 대체했다.

    선택은 그리디 — PIR 커버리지는 기간 내 알림된 기사가 이미 답한 PIR을
    커버된 것으로 시드해서, 추천이 "알림이 못 채운 정보 요구의 빈틈"을
    메우게 한다. 1차로 미커버 high 가중치 PIR, 2차로 미커버 PIR 전체,
    3차는 정렬순 충원. 카테고리당 최대 MAX_TREND_PER_CATEGORY건 (슬롯이
    남으면 상한 해제).
    """
    max_items = max_items or MAX_TREND_ITEMS
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
    relevance_value = {"high": 1.0, "medium": 0.5}
    novelty_value = {"new": 1.0, "update": 0.5, "known": 0.0}
    depth_value = {"analysis": 1.0, "report": 0.66, "news": 0.33, "opinion": 0.0}
    now_ts = datetime.utcnow().timestamp()

    def analyst_quality_value(event):
        """사람 분석가의 검토를 흉내낸 rubric(기술적 실체+실행가능성+신뢰성, 0~8)을 0~1로 정규화.

        analyst_review가 없는 이벤트(rubric 도입 전 수집분·enrichment 실패)는 예전
        content_depth 카테고리 근사값으로 대체해 하위호환을 유지한다."""
        review = event.get("analyst_review") or {}
        scores = (
            review.get("technical_substance"),
            review.get("actionability"),
            review.get("credibility"),
        )
        if all(isinstance(s, (int, float)) for s in scores):
            return sum(scores) / 8.0
        return depth_value.get(event.get("content_depth") or "", 0.4)
    hn_disabled = [False]  # 첫 실패 시 이번 실행 전체에서 재시도하지 않음 (후보 수백 건 × 실패 지연 방지)

    def hn_points(event):
        """Hacker News 화제성(포인트) — 내부 휴리스틱이 못 잡는 '지금 업계가 주목' 신호 보완.

        결과를 이벤트에 캐시해 trend_bits()가 같은 조회를 반복하지 않게 한다.
        """
        if hn_disabled[0]:
            return 0
        if "_hn_buzz" not in event:
            buzz = common_utils.check_hn_buzz(event.get("url"))
            if buzz is False:  # 조회 자체가 실패 — 이번 실행 전체에서 재시도하지 않음
                hn_disabled[0] = True
                buzz = None
            event["_hn_buzz"] = buzz
        buzz = event["_hn_buzz"]
        return buzz["points"] if buzz else 0

    def insight_score(event):
        """가중합 인사이트 점수(높을수록 우선) — 어느 한 축이 조금 밀려도 나머지 축의
        압도적 우위로 뒤집을 수 있게 튜플 순서 대신 연속값으로 합산한다."""
        weights = [(pir_defs.get(pid) or {}).get("weight") for pid in event.get("pirs") or []]
        recency_days = (now_ts - published_ts(event)) / 86400 if published_ts(event) else 999
        w = INSIGHT_WEIGHTS
        return (
            w["pir_high"] * sum(1 for weight in weights if weight == "high")
            + w["pir_any"] * len(weights)
            + w["topic_repeat"] * (1 if event_topics(event) & alerted_topics else 0)
            + w["confidence_low"] * (1 if (event.get("confidence") or "") == "low" else 0)
            + w["relevance"] * relevance_value.get(event.get("relevance") or "", 0.0)
            + w["novelty"] * novelty_value.get(event.get("novelty") or "", 0.3)
            + w["depth"] * analyst_quality_value(event)
            + w["hn_buzz"] * math.log1p(hn_points(event))
            + w["importance"] * (importance_score(event) / 100.0)
            + w["recency"] * max(0.0, 1.0 - recency_days / 7.0)
        )

    candidates = []
    for event in events:
        if event.get("id") in exclude_ids:
            continue
        if (event.get("source") or "") in NON_NEWS_SOURCES:
            continue
        if not include_alerted and event_alerted(event):
            continue
        if not include_alerted and (event.get("cluster") or {}).get("already_alerted"):
            continue  # 다른 소스로 이미 알림된 사건의 재보도
        if (feedback.get(event.get("id")) or {}).get("label") == "noise":
            continue
        relevance = event.get("relevance") or ""
        reliability = (event.get("importance") or {}).get("reliability") or ""
        has_insight = (
            bool(event.get("pirs"))
            and relevance != "low"
            and (event.get("confidence") or "") != "low"
        ) or (
            (event.get("category") or "") in TREND_CATEGORIES
            and (relevance == "high" or (relevance == "medium" and reliability == "B"))
        )
        if has_insight:
            candidates.append(event)
    candidates.sort(key=insight_score, reverse=True)
    candidates = _cluster_representatives(candidates)  # 같은 사건 클러스터당 대표 1건만

    picked, picked_ids = [], set()
    category_counts = Counter()
    covered_pirs = set(alerted_pirs)  # 알림이 이미 답한 PIR은 커버된 것으로 시드

    def eligible(event, require_new_pir, require_high, enforce_cap):
        if event.get("id") in picked_ids:
            return False
        category = event.get("category") or "기타"
        if enforce_cap and category_counts[category] >= MAX_TREND_PER_CATEGORY:
            return False  # 카테고리 쏠림 방지 (슬롯 남으면 상한 해제)
        new_pirs = set(event.get("pirs") or []) - covered_pirs
        if require_new_pir and not new_pirs:
            return False
        if require_high and not any((pir_defs.get(pid) or {}).get("weight") == "high" for pid in new_pirs):
            return False
        return True

    def commit(event):
        new_pirs = set(event.get("pirs") or []) - covered_pirs
        picked.append(event)
        picked_ids.add(event.get("id"))
        category_counts[event.get("category") or "기타"] += 1
        covered_pirs.update(new_pirs)

    # 1차: 미커버 high 가중치 PIR / 2차: 미커버 PIR 전체 / 3차: 정렬순 충원(카테고리 캡 유지) /
    # 4차: 슬롯이 남으면 카테고리 상한 해제. 클러스터 대표만 남은 후보를 정렬 순서대로
    # 스캔하며 각 차수의 하드 필터를 통과하는 첫 항목을 채운다.
    for require_new_pir, require_high, enforce_cap in (
        (True, True, True), (True, False, True), (False, False, True), (False, False, False)
    ):
        for event in candidates:
            if len(picked) >= max_items:
                break
            if eligible(event, require_new_pir, require_high, enforce_cap):
                commit(event)

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
    hn_buzz = event.get("_hn_buzz")
    if hn_buzz:
        bits.append("HN {}점·댓글 {}".format(hn_buzz["points"], hn_buzz["num_comments"]))
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


def build_cve_card(cve_label, cve_ids, group, sources):
    """같은 CVE(들)를 다루는 여러 소스의 이벤트를 카드 하나로 병합.

    소스마다 가진 정보가 달라(NVD=점수·참조, KEV=악용·기한, 뉴스·ASEC=국내 맥락)
    합치면 취약점 하나의 완성된 그림이 된다. cve_label은 단일 CVE ID이거나,
    같은 사건을 다루는 CVE 여러 개를 합친 " / " 구분 문자열일 수 있다. cve_ids는
    그 개별 CVE ID 리스트 — GitHub PoC 조회 등 CVE 단위 후속 처리에 쓴다.
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
        "cve": cve_label,
        "cve_ids": cve_ids,
        "github_poc": None,  # main()에서 상위 카드만 골라 채운다 (API 호출 비용 제한)
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
        "summary": summary[:CARD_SUMMARY_CHARS],
        "products": _union(group, "affected_products"),
        "assets": _union(group, "matched_assets"),
        "actors": [event["threat_actor"] for event in group if event.get("threat_actor")],
        "items": [
            (event.get("source"), event.get("title") or "", event.get("url") or "", event.get("id"))
            for event in group
        ],
        "event_ids": {event.get("id") for event in group},
    }


def correlate_by_cve(events):
    """이벤트를 CVE 기준으로 묶어, 복수 소스(≥2)에 동시 등장한 CVE 카드 목록을 반환.

    복수 소스 동시 등장 자체가 가장 강한 중요도 신호다:
    NVD 단독 = 배경 소음, +KEV = 실제 악용, +국내 뉴스·ASEC = 국내에서 문제되는 위협.

    완전히 같은 이벤트 집합(동일한 기사들이 여러 CVE를 함께 보도)에 걸린 CVE는
    같은 취약점 체인·공지의 일부이므로 카드 하나로 합쳐 반복 노출을 없앤다.
    """
    groups = {}
    for event in events:
        for cve in event.get("cves") or []:
            groups.setdefault(cve, []).append(event)

    clusters = {}
    for cve, group in groups.items():
        sources = sorted({event.get("source") or "unknown" for event in group})
        if len(sources) < 2:
            continue
        key = frozenset(event.get("id") for event in group)
        cluster = clusters.setdefault(key, {"cves": [], "group": group, "sources": sources})
        cluster["cves"].append(cve)

    cards = []
    for cluster in clusters.values():
        cve_ids = sorted(cluster["cves"])
        cve_label = " / ".join(cve_ids)
        cards.append(build_cve_card(cve_label, cve_ids, cluster["group"], cluster["sources"]))

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


def card_severity_bits(card, include_assets=True):
    """카드의 심각도 요약 문자열 조각들.

    include_assets=False면 자산매칭 문구를 뺀다 — 공개 웹 대시보드(build_dashboard_payload)처럼
    자사가 어떤 제품·자산을 보유하는지 외부에 노출되면 안 되는 곳에서 쓴다.
    """
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
    if include_assets and card["assets"]:
        bits.append("자산매칭: {}".format(", ".join(card["assets"])))
    if (card.get("github_poc") or {}).get("count"):
        bits.append("GitHub PoC 저장소 {}개".format(card["github_poc"]["count"]))
    return bits


MAX_GITHUB_POC_CVES_PER_CARD = 3  # 병합 카드에 CVE가 여러 개면 상위 몇 개까지만 조회 (API 호출 제한)


def enrich_cards_with_github_poc(cards):
    """카드 목록(리포트에 실제 노출되는 상위 N개만 넘길 것)에 GitHub PoC 공개 여부를 붙인다."""
    for card in cards:
        for cve_id in card["cve_ids"][:MAX_GITHUB_POC_CVES_PER_CARD]:
            result = common_utils.check_github_poc(cve_id)
            if result and result["count"] > 0:
                card["github_poc"] = result
                break


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
        lines.append(
            "[크로스소스 상관관계 — 복수 소스에 동시 등장한 CVE (신뢰도 높은 핵심 위협, 우선순위 순으로 이미 정렬됨)]"
        )
        for idx, card in enumerate(cards[:MAX_CVE_CARDS], start=1):
            parts = [
                "{} (소스 {}개: {})".format(
                    card["cve"], len(card["sources"]),
                    ", ".join(source_label(s) for s in card["sources"]),
                )
            ]
            parts.extend(card_severity_bits(card))
            if card["products"]:
                parts.append("영향: {}".format(", ".join(card["products"][:CARD_PRODUCTS_MAX])))
            if card["remediation"]:
                parts.append("조치: {}".format(card["remediation"][:CARD_REMEDIATION_CHARS_DIGEST]))
            if card["due_date"]:
                parts.append("조치기한 {}".format(card["due_date"]))
            lines.append("{}. ".format(idx) + " | ".join(parts))
            if card["summary"]:
                lines.append("  요약: {}".format(card["summary"]))

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


SUMMARY_MAX_CHARS = 200


def _normalize_tail(narrative, end_pos):
    """자른 섹션 뒤에 남은 내용과의 빈 줄 구분을 유지한다 (다음 섹션이 있으면 한 줄 띄우고, 없으면 그대로 끝)."""
    tail = narrative[end_pos:].lstrip("\n")
    return "\n\n" + tail if tail else tail


def _truncate_summary_section(narrative, max_chars=SUMMARY_MAX_CHARS):
    """[총평]이 길게 나오면 문장 단위로 잘라 모바일 가독성을 보장한다 (LLM이 프롬프트 지침을 어길 때의 안전장치)."""
    match = re.search(r"(\[총평\]\s*\n?)(.*?)(?=\n\[|\Z)", narrative, re.S)
    if not match:
        return narrative

    body = match.group(2).strip()
    if len(body) <= max_chars:
        return narrative

    sentences = re.split(r"(?<=[.!?])\s+", body)
    kept, length = [], 0
    for sentence in sentences:
        if kept and length + len(sentence) > max_chars:
            break
        kept.append(sentence)
        length += len(sentence)
    trimmed = " ".join(kept).strip() or (body[:max_chars].strip() + "…")

    return narrative[:match.start(2)] + trimmed + _normalize_tail(narrative, match.end(2))


ITEM_MAX_CHARS = 140


def _truncate_numbered_items(narrative, header, max_chars=ITEM_MAX_CHARS, max_items=None):
    """[핵심 위협 TOP 3]/[자사 자산 관련]/[권고 조치] 같은 번호·불릿 리스트의 항목별 설명이 길면 문장 단위로 자르고,
    max_items가 있으면 LLM이 개수 지침을 어겨도 코드가 항목 수 자체를 강제한다 (안전장치).

    LLM이 가끔 번호/불릿만 쓰고 내용을 안 채운 항목("1.\\n"처럼)을 응답에 섞어 보낸다 —
    그대로 두면 리포트에 빈 줄로 노출되어 미완성처럼 보이므로 통째로 제외한다."""
    match = re.search(r"(\[{}\]\s*\n?)(.*?)(?=\n\[|\Z)".format(re.escape(header)), narrative, re.S)
    if not match:
        return narrative

    # 마커(숫자.·-) 뒤에 공백이 아니라 문자열 끝이 오는 경우("...\n1.")도 분리해야 한다 —
    # 안 그러면 내용 없는 마지막 항목이 바로 앞 항목에 그대로 붙어버린다.
    items = [item.rstrip() for item in re.split(r"(?m)^(?=\d+\.(?:\s|$)|-(?:\s|$))", match.group(2).strip()) if item.strip()]
    if max_items is not None:
        items = items[:max_items]

    trimmed_items = []
    for item in items:
        title_match = re.match(r"(?:\d+\.|-)\s*.*?(?:\*\*\s*:|:)\s*", item)
        title = title_match.group(0) if title_match else ""
        desc = item[len(title):].strip()

        # 콜론 기반 제목을 못 찾으면 desc엔 맨 앞 번호/불릿 마커가 그대로 남아있다 —
        # 그걸 뗀 실제 내용이 있는지로 판단해야 마커만 있는 항목을 걸러낼 수 있다.
        body = desc if title else re.sub(r"^(?:\d+\.|-)\s*", "", desc).strip()
        if not body:
            continue  # 번호/불릿만 있고 실제 내용이 없는 항목 — 빈 줄로 보여주지 않는다

        if len(desc) > max_chars:
            sentences = re.split(r"(?<=[.!?])\s+", desc)
            kept, length = [], 0
            for sentence in sentences:
                if kept and length + len(sentence) > max_chars:
                    break
                kept.append(sentence)
                length += len(sentence)
            desc = " ".join(kept).strip() or (desc[:max_chars].strip() + "…")

        trimmed_items.append((title.rstrip() + " " + desc).strip() if title else desc)

    # 앞쪽 항목이 빠지면 번호가 2.부터 시작해버리므로, 번호 항목(불릿 "-"는 그대로 둠)은 1부터 다시 매긴다.
    numbered_index = 0
    final_items = []
    for entry in trimmed_items:
        marker_match = re.match(r"^\d+\.\s*", entry)
        if marker_match:
            numbered_index += 1
            entry = "{}. {}".format(numbered_index, entry[marker_match.end():])
        final_items.append(entry)

    return narrative[:match.start(2)] + "\n".join(final_items) + _normalize_tail(narrative, match.end(2))


def _strip_narrative_section(narrative, header):
    """narrative에서 [header] 섹션(제목+본문)을 통째로 제거한 사본을 반환한다 — 원본은 안 건드린다.

    공개 웹 대시보드처럼 특정 섹션(예: 자산매칭)을 보여주면 안 되는 출력에서만 쓴다 —
    이메일/슬랙/텍스트 리포트는 이 함수를 거치지 않은 원본 narrative를 그대로 쓴다.
    """
    match = re.search(r"\[{}\]\s*\n?.*?(?=\n\[|\Z)".format(re.escape(header)), narrative, re.S)
    if not match:
        return narrative
    before = narrative[:match.start()].rstrip("\n")
    after = narrative[match.end():].lstrip("\n")
    if before and after:
        return before + "\n\n" + after
    return before or after


def ai_narrative(period_label, digest):
    prompt = """당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다.
아래는 {period} 동안 수집된 보안 이벤트 요약이다. 이를 바탕으로 보안담당자용 리포트 본문을 한국어로 작성하라.

출력 형식:
[총평]
- 가장 중요한 임팩트만 짧게 서술 (분량 제한이 목적이 아니라 핵심만 압축하는 것이 목적)
- CVE ID, PIR별 세부 수치, MITRE 기법 등 개별 데이터 나열 금지 — 이런 디테일은 아래 다른 섹션과 리포트의 통계 섹션에 이미 있으므로 총평에서 반복하지 말 것
- 숫자를 쓰더라도 전체 건수 등 꼭 필요한 것 한두 개만, 나열식으로 늘어놓지 말 것

[핵심 위협 TOP 3]
- 데이터의 [크로스소스 상관관계] 목록은 이미 우선순위 순으로 정렬돼 있다. 그 목록의 1번·2번·3번 항목을 그 순서 그대로 다뤄라 (목록에 없는 CVE·위협을 임의로 추가하거나 순서를 바꾸지 말 것)
- 목록 항목이 3개 미만이면 있는 개수만큼만 쓰고, 목록이 비어 있으면 전체 데이터에서 가장 중요한 것 최대 3건을 골라 써라
- 각 항목마다 무엇이 왜 중요한지 1문장
- EPSS/CVSS 수치, 소스명, 패치 일자 등 세부 데이터 나열 금지 — 이미 [핵심 취약점 TOP N] 카드 섹션에 있으므로 반복하지 말 것. 실무 임팩트(무엇이 뚫리고 왜 위험한지) 중심으로만 쓸 것

[자사 자산 관련]
- 매칭된 항목이 있으면 조치 우선순위를 제시하고, 없으면 "해당 없음"이라고만 작성
- CVE ID, EPSS/CVSS 수치, KEV 등재 여부 등 세부 데이터 나열 금지 — 이미 다른 섹션에 있으므로 반복하지 말 것. 자산별로 뭘 먼저 조치해야 하는지 1문장만

[권고 조치]
- 정확히 3개 이내, 각 항목은 무엇을 해야 하는지 행동 중심으로 1문장
- CVE ID, CVSS 수치, PIR 번호, 공격 그룹명 등 세부 데이터 나열 금지 — 이미 다른 섹션에 있으므로 반복하지 말 것

주의: 제공된 데이터에 없는 사실을 만들어내지 마라. 건수와 수치는 데이터에 있는 그대로 사용하라.

데이터:
{digest}
""".format(period=period_label, digest=digest)

    narrative = common_utils.llm_generate(prompt, timeout=300) or ""
    if not narrative:
        return narrative
    narrative = _truncate_summary_section(narrative)
    narrative = _truncate_numbered_items(narrative, "핵심 위협 TOP 3")
    narrative = _truncate_numbered_items(narrative, "자사 자산 관련")
    narrative = _truncate_numbered_items(narrative, "권고 조치", max_items=3)
    return narrative


def build_text_report(title, period_label, stats, narrative, highlights, cards, pir_groups,
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
                lines.append("  {}".format(common_utils.tracking_url(event.get("id"), event.get("url")) or ""))
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
                lines.append("   영향: {}".format(", ".join(card["products"][:CARD_PRODUCTS_MAX])))
            if card["remediation"]:
                due = " (기한 {})".format(card["due_date"]) if card["due_date"] else ""
                lines.append("   조치: {}{}".format(card["remediation"][:CARD_REMEDIATION_CHARS], due))
            if (card.get("github_poc") or {}).get("count"):
                lines.append("   GitHub PoC: {} ({} 등록)".format(
                    card["github_poc"]["latest_url"], card["github_poc"]["latest_created_at"]
                ))
            if card["summary"]:
                lines.append("   요약: {}".format(card["summary"]))
            for source, item_title, item_url, item_id in card["items"]:
                tracked_url = common_utils.tracking_url(item_id, item_url)
                lines.append("   - [{}] {} {}".format(source_label(source), item_title, tracked_url))

    lines.append("")
    lines.append("[주요 뉴스 TOP {}]".format(len(highlights)))
    for idx, event in enumerate(highlights, start=1):
        level_prefix = "[{}] ".format(event_level(event)) if event_level(event) in ("P1", "P2") else ""
        lines.append("{}. {}[{}] {}".format(idx, level_prefix, source_label(event.get("source")), event.get("title")))
        lines.append("   {}".format(common_utils.tracking_url(event.get("id"), event.get("url")) or ""))

    if trend_reads:
        lines.append("")
        lines.append("[읽을만한 동향 — 알림 외 주목 기사]")
        for event in trend_reads:
            bits = trend_bits(event)
            suffix = " ({})".format(" | ".join(bits)) if bits else ""
            lines.append("- [{}] {}{}".format(source_label(event.get("source")), event.get("title"), suffix))
            lines.append("  {}".format(common_utils.tracking_url(event.get("id"), event.get("url")) or ""))

    if stats["iocs"]:
        lines.append("")
        lines.append("[부록: 수집된 IOC {}건]".format(len(stats["iocs"])))
        for ioc in stats["iocs"][:30]:
            lines.append("- [{}] {}".format(ioc.get("type", "unknown"), ioc.get("value", "")))
        if len(stats["iocs"]) > 30:
            lines.append("- ...외 {}건".format(len(stats["iocs"]) - 30))

    lines.append("")
    lines.append("[소스별 건수]")
    for source, count in stats["by_source"].most_common():
        lines.append("- {}: {}건".format(source_label(source), count))

    return "\n".join(lines)


def build_html_report(title, period_label, stats, narrative, highlights, cards, pir_groups,
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
                    html.escape(common_utils.tracking_url(event.get("id"), event.get("url")) or "#"),
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
                card_parts.append("영향: {}".format(html.escape(", ".join(card["products"][:CARD_PRODUCTS_MAX]))))
            if card["remediation"]:
                due = " (기한 {})".format(card["due_date"]) if card["due_date"] else ""
                card_parts.append("조치: {}{}".format(html.escape(card["remediation"][:CARD_REMEDIATION_CHARS]), html.escape(due)))
            if (card.get("github_poc") or {}).get("count"):
                card_parts.append('GitHub PoC: <a href="{}">{}</a> ({} 등록)'.format(
                    html.escape(card["github_poc"]["latest_url"]),
                    html.escape(card["github_poc"]["latest_url"]),
                    html.escape(card["github_poc"]["latest_created_at"]),
                ))
            if card["summary"]:
                card_parts.append(html.escape(card["summary"]))
            card_parts.append(
                " · ".join(
                    '<a href="{}">{}</a>'.format(
                        html.escape(common_utils.tracking_url(item_id, item_url) or "#"),
                        html.escape(source_label(source)),
                    )
                    for source, _, item_url, item_id in card["items"]
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
                html.escape(common_utils.tracking_url(event.get("id"), event.get("url")) or "#"),
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
                html.escape(common_utils.tracking_url(event.get("id"), event.get("url")) or "#"),
                html.escape(event.get("title") or "(제목 없음)"),
                suffix,
            ))
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

    parts.append("<details><summary>소스별 건수 ({}개 소스)</summary><ul>".format(len(stats["by_source"])))
    for source, count in stats["by_source"].most_common():
        parts.append("<li>{}: {}건</li>".format(html.escape(source_label(source)), count))
    parts.append("</ul></details>")

    parts.append("</body></html>")
    return "".join(parts)


def build_slack_blocks(title, period_label, stats, narrative, highlights, cards, pir_groups,
                       trend_reads):
    stat_text = "총 *{}건* 수집 — 🚨 P1 `{}` / ⚠️ P2 `{}` / Critical `{}` / KEV `{}` / 🔒 랜섬웨어 `{}` / 자산매칭 `{}`".format(
        stats["total"], len(stats["p1"]), len(stats["p2"]),
        len(stats["critical"]), len(stats["kev"]), len(stats["ransomware"]),
        len(stats["asset_hits"])
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
                    common_utils.tracking_url(event.get("id"), event.get("url")) or "#",
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
                line += "\n> 조치: {}{}".format(card["remediation"][:CARD_REMEDIATION_CHARS_SLACK], due)
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
                    common_utils.tracking_url(event.get("id"), event.get("url")) or "#",
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
                common_utils.tracking_url(event.get("id"), event.get("url")) or "#",
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

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": "*소스별 건수* — " + ", ".join(
                "{} {}건".format(source_label(source), count)
                for source, count in stats["by_source"].most_common()
            ),
        }],
    })

    return blocks


def build_dashboard_payload(title, period, period_label, stats, narrative, highlights, cards, trend_reads):
    """boannews_vercel 웹 대시보드용 JSON 페이로드.

    하이라이트·읽을만한 동향은 소스 하나에 붙으니 국내/해외로 나눌 수 있다. CVE 카드는
    여러 소스를 가로지르는 집계라 지역 구분 없이 그대로 담는다(카드 하나에 국내·해외
    소스가 섞여 있을 수 있어 나누는 게 의미 없음).

    PIR(우선 정보 요구사항)과 자산매칭 정보는 의도적으로 담지 않는다 — 조직이 무엇을
    우선순위로 보는지, 어떤 자산·제품을 보유하는지가 공개될 수 있는 이 사이트에 노출되면
    안 되기 때문(내부용인 이메일/슬랙/텍스트 리포트는 그대로 보여줌). 자산매칭은 이름뿐
    아니라 건수(stats.asset_hits)도 뺀다 — "자산매칭 N건"이라는 숫자만으로도 "이 조직이
    자산 인벤토리를 추적한다"는 사실 자체가 드러나므로. PIR 매칭·자산매칭 로직 자체
    (insight_score, classify_urgency 등)는 전혀 바뀌지 않았다 — 여기서 결과를 직렬화하지
    않을 뿐이다. AI 총평(narrative)의 [자사 자산 관련] 섹션도 같은 이유로 여기서만 잘라낸다
    (이메일/슬랙에 넘어가는 narrative 원본은 그대로 유지).
    """
    def serialize_event(event):
        # matched_assets는 의도적으로 뺀다 — 공개 웹 대시보드에 자사 보유 자산/제품명이
        # 노출되면 안 되므로(이메일/슬랙 리포트는 내부용이라 그대로 유지, 여기만 예외).
        return {
            "title": event.get("title") or "(제목 없음)",
            "url": common_utils.tracking_url(event.get("id"), event.get("url") or "") or "",
            "source": event.get("source") or "",
            "source_label": source_label(event.get("source")),
            "level": event_level(event),
            "category": event.get("category") or "",
            "published_at": event.get("published_at") or "",
            "summary": (event.get("ai_summary") or event.get("summary") or "")[:300],
        }

    def split_by_region(events):
        domestic, overseas = [], []
        for event in events:
            bucket = domestic if source_region(event.get("source")) == "domestic" else overseas
            bucket.append(serialize_event(event))
        return domestic, overseas

    def serialize_card(card):
        return {
            "cve": card["cve"],
            "level": card.get("level") or "",
            "sources": [source_label(s) for s in card["sources"]],
            "severity_bits": card_severity_bits(card, include_assets=False),
            "products": card["products"][:CARD_PRODUCTS_MAX],
            "remediation": card["remediation"][:CARD_REMEDIATION_CHARS] if card["remediation"] else "",
            "due_date": card.get("due_date") or "",
            "summary": card["summary"],
            "items": [
                {
                    "source_label": source_label(source),
                    "title": item_title,
                    "url": common_utils.tracking_url(item_id, item_url) or "",
                }
                for source, item_title, item_url, item_id in card["items"]
            ],
        }

    # PIR(우선 정보 요구사항) 구분·문항은 대시보드에서 뺀다 — 조직이 무엇을 우선순위로
    # 보는지(예: 특정 산업 표적 위협) 노출되면 자산매칭과 같은 종류의 정보 유출이라
    # pir_groups 인자는 매칭 로직·리포트 계산에는 여전히 쓰이지만(다른 곳은 그대로),
    # 이 함수의 출력에는 반영하지 않는다.

    highlight_domestic, highlight_overseas = split_by_region(highlights)
    trend_domestic, trend_overseas = split_by_region(trend_reads)

    return {
        "title": title,
        "period": period,
        "period_label": period_label,
        "generated_at": common_utils.utc_now_iso(),
        "narrative": _strip_narrative_section(narrative, "자사 자산 관련") if narrative else "",
        "stats": {
            "total": stats["total"],
            "p1": len(stats["p1"]),
            "p2": len(stats["p2"]),
            "critical": len(stats["critical"]),
            "kev": len(stats["kev"]),
            "ransomware": len(stats["ransomware"]),
            "by_source": dict(stats["by_source"].most_common()),
        },
        "cards": [serialize_card(card) for card in cards[:MAX_CVE_CARDS]],
        "domestic": {"highlights": highlight_domestic, "trend_reads": trend_domestic},
        "overseas": {"highlights": highlight_overseas, "trend_reads": trend_overseas},
    }


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
    enrich_cards_with_github_poc(cards[:MAX_CVE_CARDS])  # 실제 노출되는 카드에만 API 호출
    shown_card_event_ids = set()
    for card in cards[:MAX_CVE_CARDS]:
        shown_card_event_ids.update(card["event_ids"])
    highlights = top_items([
        event for event in events
        if event.get("id") not in shown_card_event_ids
        and (event.get("source") or "") not in NON_NEWS_SOURCES
    ])
    pir_groups = group_by_pir(events)
    highlight_ids = {event.get("id") for event in highlights}
    trend_reads = pick_trend_reads(events, shown_card_event_ids | highlight_ids)

    print("[*] 이벤트 {}건 집계 완료 (CVE 상관관계 카드 {}건, PIR {}종). AI 해석 생성 중...".format(
        stats["total"], len(cards), len(pir_groups)
    ))
    digest = build_digest(period_label, stats, events, cards)
    narrative = ai_narrative(period_label, digest)
    if not narrative:
        narrative = "(AI 해석을 생성하지 못해 통계 요약만 제공합니다.)"

    text_body = build_text_report(title, period_label, stats, narrative, highlights, cards, pir_groups, trend_reads)
    html_body = build_html_report(title, period_label, stats, narrative, highlights, cards, pir_groups, trend_reads)
    blocks = build_slack_blocks(title, period_label, stats, narrative, highlights, cards, pir_groups, trend_reads)

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

    dashboard_payload = build_dashboard_payload(
        title, args.period, period_label, stats, narrative, highlights, cards, trend_reads,
    )
    publish_web_dashboard.publish(dashboard_payload)


if __name__ == "__main__":
    main()
