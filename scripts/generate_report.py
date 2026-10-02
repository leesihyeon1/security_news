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

import campaign_radar
import common_utils
import publish_web_dashboard
from dashboard_text import event_summary, summary_excerpt, public_text, public_evidence, data_status, public_narrative, is_korean_text
from entity_names import count_entities

# Windows 콘솔(cp949)에서 특수문자 출력이 깨지지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

LEGACY_BOANNEWS_EVENTS_FILE = common_utils.DATA_DIR / "boannews_events.jsonl"

# 소스 표시명·비뉴스 소스 제외 목록은 publish_web_dashboard.py(검색 인덱스)도 함께
# 써야 해서 common_utils로 옮겼다 — 이 이름으로 그대로 계속 쓴다.
source_label = common_utils.source_label
NON_NEWS_SOURCES = common_utils.NON_NEWS_SOURCES

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

# 주간 리포트 전용 "전주 대비 급증" 집계 — 표본이 너무 적은 항목의 등락은 노이즈이므로
# 이번 주 건수가 이 값 미만이면 아예 비교 대상에서 제외한다(예: 1건->3건을 "3배 증가"로
# 보여주지 않음).
MIN_WEEKLY_TREND_COUNT = 3
MAX_WEEKLY_TREND_ITEMS = 5

# CVE 카드 필드별 길이 상한 — 소비처마다 예산이 달라 값이 다르다:
# 요약·영향은 전 채널 공통(카드 생성 시 한 번만 자르면 됨), 조치문은 LLM
# 프롬프트(토큰 절약) < Slack(블록 길이 제한) < 이메일/텍스트(가장 여유) 순.
CARD_SUMMARY_CHARS = 200
CARD_PRODUCTS_MAX = 5
CARD_REMEDIATION_CHARS_DIGEST = 100
CARD_REMEDIATION_CHARS_SLACK = 120
CARD_REMEDIATION_CHARS = 150

# "읽을만한 동향" 큐레이션: 긴급도 점수가 낮아 알림되지 않은 기사 중
# 인사이트 신호(PIR 매칭, 또는 high 관련성의 위협 분석 기사)가 있는 것을 고른다.
MAX_TREND_ITEMS = 5
# PIR 매칭 개수를 이만큼까지만 점수에 반영한다(위 pir_any 주석 참고).
PIR_ANY_COUNT_CAP = 2
MAX_TREND_PER_CATEGORY = 2  # 카테고리 쏠림 방지 (슬롯이 남으면 상한 해제)
TREND_CATEGORIES = {"공격캠페인", "침해사고", "개인정보유출", "악성코드", "공급망공격", "기술동향"}
EXPLORE_SLOT_COUNT = 1  # 개인화(feedback_useful·search_interest) 없이 quality_score만으로
                        # 확정하는 탐색 슬롯 수 — 필터버블 방지용 하드 가드(아래 pick_trend_reads 참고)

# insight_score()의 축별 가중치 — 튜플 순서(어순위 축이 하나만 달라도 절대 우위) 대신
# 가중합으로 바꾼 이유: 예를 들어 relevance가 high 대 medium 한 끗 차이만으로, 신선도·
# 깊이·인텔풍부도·HN화제성·중요도에서 압도적으로 우세한 기사가 무조건 지는 게 부자연스럽다.
# 값 자체는 실측 튜닝 전 추정치 — 피드백 데이터가 쌓이면 재조정이 필요하다.
INSIGHT_WEIGHTS = {
    "pir_high": 40,       # 고가중치 PIR에 하나라도 걸리면 한 번만(개수만큼 곱하지 않는다)
    "pir_any": 8,         # PIR 매칭 1개당, 단 PIR_ANY_COUNT_CAP개까지만
                          # 예전엔 둘 다 매칭 개수만큼 그대로 곱했다. 그러면 PIR 3개에
                          # 걸린 기사가 PIR 축에서만 144점을 받는데, 나머지 축(관련성·
                          # 신규성·깊이·중요도·최신성)을 전부 만점 받아도 59점이다.
                          # 실측(2026-09-16 추천기사): "여러 주제를 한 문단씩 훑는" 칼럼이
                          # AI·엔드포인트·공급망 PIR 3개를 맞춰 192점으로 1·2위를 차지하고,
                          # 실제 악용이 확인된 GitLab 최고심각도 취약점(PIR 1개)이 95점으로
                          # 밀렸다. "PIR에 답하는가"는 살리되 "몇 개나 스치는가"로는 이기지
                          # 못하게 개수 의존을 끊는다.
    "topic_repeat": -15,  # 이미 알림된 행위자·멀웨어 재탕
    "confidence_low": -8,  # LLM 스스로 모호하다고 판정
    "relevance": 25,      # high=1.0 / medium=0.5 / 미판정=0.0
    "novelty": 12,        # new=1.0 / update=0.5 / known=0.0 / 미판정=0.3
    "depth": 35,          # analyst_review rubric(기술적실체+실행가능성+신뢰성, 0~8)/8 — rubric
                          # 없는 이벤트는 하위호환으로 content_depth 근사값(analysis=1.0/.../미판정=0.4) 사용.
                          # IOC·ATT&CK 풍부도는 rubric의 technical_substance 채점 근거에 이미 포함되므로
                          # 별도 intel_richness 축(구 버전에 있었음)은 제거 — 같은 사실의 이중계산 방지.
                          # 10점이었는데 35로 올렸다. 10점이면 rubric 만점(8/8)과 0점의 차이가
                          # 10점뿐이라 PIR 하나 차이(48점)의 1/5도 안 됐고, 사람 기준으로
                          # 채점한 "읽을 가치"가 순위에 사실상 반영되지 않았다.
    "actionability_zero": -25,  # rubric의 실행가능성이 명시적으로 0점일 때. 채점자가 "읽어도
                          # 할 일이 없다"고 판정한 글이다. 가중합 안에서 rubric 총점의 일부로만
                          # 반영하면 나머지 두 항목이 상쇄해 버려서(실측: 실행가능성 0인 칼럼이
                          # 기술적실체·신뢰성으로 3/8을 받아 1위) 그 판정을 따로 세운다.
                          # 0점과 미채점을 구별한다 — 채점이 없는 이벤트는 감점하지 않는다.
    "hn_buzz": 6,          # log1p(HN 포인트)
    "importance": 7,      # importance_score / 100 — importance_score 자체가 pir_high/relevance/
                           # confidence_low를 이미 피처로 쓰고 있어 그 3개와 중복 계산됨. 겹치는
                           # 비중을 감안해 절반 수준으로 낮춤(악용상태·심각도·자산매칭·신뢰도 등
                           # 나머지 고유 정보는 이 가중치로 계속 반영).
    "recency": 5,          # 7일 기준 선형 감쇠 (그 이상 오래되면 0)
    "feedback_useful": 15,  # useful 라벨 * feedback_confidence_weight(0.4~1.0) — 이전엔
                            # importance_score(학습 가중치)를 거쳐서만 희석 반영됐는데, 그건
                            # "useful 라벨이 붙은 이 기사 자체"가 아니라 "이 기사의 특징(악용
                            # 상태·자산매칭 등)이 학습에 얼마나 기여했는가"라 간접적이었다.
                            # 여기선 그 기사가 실제로 useful로 라벨된 사실 자체를 직접 가산한다.
                            # 단, 클릭 기반 라벨은 FEEDBACK_USEFUL_MIN_CLICKS 문턱 미만이면
                            # 0으로 취급(아래 feedback_useful_value) — 우연한 클릭 한두 번이
                            # 바로 다음 추천에 영향을 주지 않게.
    "search_interest": 10,  # 최근 SEARCH_INTEREST_WINDOW_DAYS일간 대시보드 History 탭에서
                            # SEARCH_INTEREST_MIN_SEARCHES회 이상 반복 검색된 단어와 매칭되면
                            # 가산 — "요즘 관심사"를 추천에 되먹임. 한 번만 입력된 검색어는
                            # feedback_useful의 클릭 문턱과 같은 이유로 제외한다(우연한 호기심
                            # 방지). 검색 활동은 클릭보다도 능동적인 관심 표현이라 볼 수 있지만,
                            # 아직 사용자 수 대비 검색량이 적어 relevance(25)보다는 낮게 둠.
}

# 클릭 1~2회는 우연히 눌렀을 가능성이 있어 추천기사 가산(feedback_useful)에서는 무시하고,
# 이 문턱 이상 반복 클릭된 것부터만 신호로 인정한다. train_weights.py의 학습 반영 비중은
# 그대로 confidence_weight의 연속값(0.4~0.8)을 쓴다 — 학습은 통계적으로 많은 샘플에 걸쳐
# 완만하게 반영되니 문턱이 필요 없지만, 추천은 개별 기사 하나의 순위를 바로 바꾸는 거라
# 약한 신호 하나로 흔들리면 안 된다.
FEEDBACK_USEFUL_MIN_CLICKS = 3

SEARCH_INTEREST_WINDOW_DAYS = 7  # 이보다 오래된 검색어는 "요즘 관심사"로 보기엔 낡음
SEARCH_INTEREST_MIN_SEARCHES = 2  # 한 번만 입력된 검색어는 우연한 호기심일 수 있어 제외

REPORT_CUTOFF_HOUR_KST = int(os.environ.get("REPORT_CUTOFF_HOUR_KST", "9"))
CVE_LABEL_MAX_SHOWN = 3   # 카드 제목에 늘어놓을 CVE 개수
KST_OFFSET = timedelta(hours=9)
# 수집은 구간 안이지만 발행일이 이보다 더 오래된 기사는 리포트에서 뺀다.
# (아카이브를 통째로 들고 있는 피드가 옛 글을 새 글로 흘려보내는 것을 막는다)
PUBLISHED_GRACE_DAYS = 2



def parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def report_window(days, now_utc=None):
    """마지막으로 완료된 정기 보고 구간을 UTC naive datetime으로 반환한다.

    daily_report.bat을 수동 실행해도 실행 시각 기준 최근 24시간이 아니라, 스케줄 실행과
    같은 KST 기준 마감 시각(기본 09:00)에 닫힌 완성된 구간을 사용한다.
    """
    now_utc = now_utc or datetime.utcnow()
    now_kst = now_utc + KST_OFFSET
    cutoff_kst = now_kst.replace(
        hour=REPORT_CUTOFF_HOUR_KST, minute=0, second=0, microsecond=0
    )
    if now_kst < cutoff_kst:
        cutoff_kst -= timedelta(days=1)

    end_utc = cutoff_kst - KST_OFFSET
    since_utc = end_utc - timedelta(days=days)
    return since_utc, end_utc


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
    return load_events_between(since, None)


def load_events_between(since, until):
    """load_events(since)와 같은 방식이지만 [since, until) 구간만 남긴다.

    주간 리포트의 "전주 대비" 비교처럼 과거의 특정 구간만 필요할 때 쓴다(until=None이면
    load_events(since)와 동일). since보다 오래된 이벤트를 만나면 조기 종료하는 성질은
    그대로 유지된다.

    구간 판정은 수집 시각(fetched_at)으로 한다 — 로그가 수집순으로 쌓여 있어서 그래야
    조기 종료가 성립한다. 다만 그것만 보면 "오늘 수집됐지만 작년에 나온 기사"가 오늘
    리포트에 들어간다. 실측(2026-09-09): Elastic Security Labs 피드가 전체 아카이브를
    계속 들고 있어서, 회차당 몇 건씩 옛 글이 새 글로 수집돼 일간 리포트에 2025-05까지
    섞였다(65건). 그래서 발행일 기준으로 한 번 더 거른다.
    """
    events = {}
    # 발행일이 구간 시작보다 이만큼 이전이면 오늘의 뉴스로 보지 않는다. 0으로 하지
    # 않는 이유는 피드가 늦게 싣거나 수집이 밀리는 경우가 정상적으로 있기 때문이다.
    published_floor = since - timedelta(days=PUBLISHED_GRACE_DAYS)
    dropped = 0

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
            if until is not None and fetched >= until:
                continue  # 구간 상한 이후 이벤트는 건너뛰되, 더 오래된 것을 계속 찾는다
            # 발행일을 못 읽는 항목은 버리지 않는다 — 피드마다 형식이 달라서 판단
            # 근거가 없는 것과 오래된 것을 구별할 수 없다.
            # 취약점·어드바이저리 피드도 거르지 않는다. 거기서 published_at은 "기사가
            # 나온 날"이 아니라 "CVE가 발행된 날"이고, NVD가 며칠 지나 올리는 일이
            # 흔하다(실측: 09-09에 들어온 09-04 발행 CVE 6건). 뉴스와 달리 늦게 들어와도
            # 대응 가치가 그대로여서, 오래됐다는 이유로 빼면 진짜 취약점을 놓친다.
            published = parse_iso(event.get("published_at"))
            if (published is not None and published < published_floor
                    and event.get("source") not in common_utils.NON_NEWS_SOURCES):
                dropped += 1
                continue
            recent.append(event)

        for event in reversed(recent):  # 시간순으로 되돌려 기존 dedup(첫 등장 우선) 순서 유지
            # id를 기준으로 한다 — url이 아니다. KEV·MSRC 같은 구조화 피드는 서로 다른
            # CVE·서로 다른 발행월의 항목이 같은 카탈로그/요약 페이지 url을 공유해서,
            # url로 중복 제거하면 그 구간에 하나만 남는다(실측: cisa_kev 이벤트 82건이
            # url 하나뿐이라 모든 리포트에서 KEV가 최대 1건으로 줄었다. events.jsonl
            # 전체를 보면 msrc도 같은 CVE 페이지 url에 달마다 다른 공지가 830쌍 걸린다).
            # id는 수집 단계에서 "{source}:{고유값}"으로 만들어지므로 그 자체로 이미
            # source 경계를 포함한다 — url보다 세밀하고, RSS 재수집 시 같은 글이면
            # 같은 id를 받으므로 중복 제거 성질은 그대로 유지된다.
            key = event.get("id") or "{}|{}".format(event.get("source"), event.get("url"))
            events.setdefault(key, event)

    if dropped:
        print("[*] 발행일이 {} 이전인 항목 {}건 제외(수집은 구간 안이지만 옛 기사)".format(
            published_floor.strftime("%Y-%m-%d"), dropped))
    return list(events.values())


def _entity_counters(events):
    """threat_actor/malware_family/ATT&CK 기법/자산매칭 이름별 등장 횟수.

    build_stats()와 compute_weekly_trends()(주간 리포트의 전주 대비 비교)가 같은
    집계 로직을 공유하기 위해 분리했다."""
    actor_counter = count_entities(events, "threat_actor")
    malware_counter = count_entities(events, "malware_family")
    technique_counter = Counter()
    asset_counter = Counter()
    for event in events:
        for technique in event.get("attack_techniques") or []:
            technique_counter[technique] += 1
        # 별칭을 그대로 세면 제품 하나가 별칭 수만큼 부풀려진다 — 대표명으로 접어서 센다.
        for term in common_utils.canonical_assets(event.get("matched_assets")):
            asset_counter[term] += 1
    return actor_counter, malware_counter, technique_counter, asset_counter


def is_actionable(event):
    """"우리가 실제로 봐야 하는 건"인지 — 볼륨 지표와 대응 지표를 구분하기 위한 기준.

    NVD는 CVSS>=7.0만 받아도 하루 200건대가 들어온다(실측 2026-09-03: 그날 발행
    353건 중 211건이 기준 통과). CVSS 4.0이 같은 취약점에 v3.1보다 높은 점수를
    주면서 임계값이 선별 기능을 잃었기 때문이다. 그래서 "취약점 295건" 같은
    카테고리 집계는 매일 비슷한 숫자만 찍혀 판단 근거가 못 된다.
    여기서는 자산·악용·KEV처럼 대응 여부를 가르는 신호가 있는 건만 센다.
    """
    if event_level(event) in ("P1", "P2"):
        return True
    if event.get("matched_assets"):
        return True
    if event.get("kev"):
        return True
    return (event.get("exploitation_status") or "none") != "none"


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

    actor_counter, malware_counter, technique_counter, asset_counter = _entity_counters(events)

    by_category = Counter(
        event.get("category") or "미분류" for event in events
    )
    by_pir = Counter(pid for event in events for pid in event.get("pirs") or [])

    ioc_seen = set()
    iocs = []
    for event in events:
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
        "latest_collected_at": max((event.get("fetched_at") or "" for event in events), default=""),
        "by_source": by_source,
        "by_category": by_category,
        "by_pir": by_pir,
        "critical": critical,
        "kev": kev,
        "ransomware": [event for event in events if event.get("ransomware_use")],
        "asset_hits": asset_hits,
        "p1": [event for event in events if event_level(event) == "P1"],
        "p2": [event for event in events if event_level(event) == "P2"],
        "info_by_category": Counter(
            event.get("category") or "미분류"
            for event in events
            if event_level(event) not in ("P1", "P2")
        ),
        "actionable": [event for event in events if is_actionable(event)],
        # 대응 대상을 카테고리별로 센다. 비교 대상 지표와 모수를 맞춰야 나란히 놓고
        # 읽을 수 있으므로 두 벌을 만든다 — by_category(전체)용과 info_by_category
        # (P1/P2 제외, 대시보드 타일이 P1·P2 타일과 중복 계산되지 않게)용.
        "actionable_by_category": Counter(
            event.get("category") or "미분류"
            for event in events
            if is_actionable(event)
        ),
        "actionable_info_by_category": Counter(
            event.get("category") or "미분류"
            for event in events
            if event_level(event) not in ("P1", "P2") and is_actionable(event)
        ),
        "top_cves": cve_counter.most_common(10),
        "top_assets": asset_counter.most_common(10),
        "top_actors": actor_counter.most_common(10),
        "top_malware": malware_counter.most_common(10),
        "top_techniques": technique_counter.most_common(10),
        "iocs": iocs,
    }


def compute_weekly_trends(events, previous_events,
                           min_count=MIN_WEEKLY_TREND_COUNT, max_items=MAX_WEEKLY_TREND_ITEMS):
    """이번 주 vs 전주 위협 행위자/악성코드/ATT&CK 기법/자산매칭 언급 건수를 비교해
    급증(또는 신규 등장)한 항목을 뽑는다 — 주간 리포트 전용.

    표본이 너무 적은 항목은 등락을 봐도 의미가 없으므로(1건->3건을 "3배 증가"라 부르면
    오해만 부름) 이번 주 건수가 min_count 미만인 항목은 아예 비교하지 않는다.
    """
    curr_counters = _entity_counters(events)
    prev_counters = _entity_counters(previous_events)

    def surges(curr_counter, prev_counter):
        result = []
        for name, count in curr_counter.items():
            if count < min_count:
                continue
            previous = prev_counter.get(name, 0)
            delta = count - previous
            if delta <= 0:
                continue
            result.append({"name": name, "count": count, "previous": previous, "delta": delta})
        result.sort(key=lambda item: item["delta"], reverse=True)
        return result[:max_items]

    keys = ("actors", "malware", "techniques", "assets")
    result = {key: surges(curr, prev) for key, curr, prev in zip(keys, curr_counters, prev_counters)}
    result["categories"] = _category_share_surges(events, previous_events, min_count, max_items)
    return result


def _category_share_surges(events, previous_events, min_count, max_items):
    """카테고리별 비중(전체 대비 %) 변화 — raw count가 아니라 비중으로 비교해야 피드
    추가/삭제나 수집량 변동 같은 인프라 변화가 "위협 증가"로 착시되는 걸 막는다.
    미분류(카테고리 없는 이벤트, 예: NVD 등 API 소스)는 분모·분자 모두에서 제외한다."""
    curr_cat = Counter(event.get("category") for event in events if event.get("category"))
    prev_cat = Counter(event.get("category") for event in previous_events if event.get("category"))
    curr_total = sum(curr_cat.values())
    prev_total = sum(prev_cat.values())
    if not curr_total:
        return []

    result = []
    for name, count in curr_cat.items():
        if count < min_count:
            continue
        curr_share = count / curr_total * 100
        prev_count = prev_cat.get(name, 0)
        prev_share = (prev_count / prev_total * 100) if prev_total else 0.0
        delta = curr_share - prev_share
        if delta <= 0:
            continue
        result.append({
            "name": name, "count": count, "share": curr_share,
            "previous_share": prev_share, "delta": delta,
        })
    result.sort(key=lambda item: item["delta"], reverse=True)
    return result[:max_items]


def event_sort_key(event):
    """P1 > P2 > 자산 매칭 > 중요도 점수 순 우선순위 키.

    이전엔 3·4번째 기준이 KEV 소스 여부·CVSS 점수였는데, top_items()의 대상
    범위에서 NON_NEWS_SOURCES(cisa_kev 포함)를 이미 제외하고 뉴스 소스는 score를
    안 채워서 둘 다 죽은 기준이었다(항상 동일값이라 동률을 못 갈랐음). 이미 계산돼
    있는 importance.score(악용 정황·심각도·관련성·PIR 등 종합 0~100점)로 대체해
    같은 등급·자산매칭 안에서도 실질적인 우선순위가 매겨지도록 한다.
    """
    level_rank = {"P1": 0, "P2": 1}.get(event_level(event), 2)
    return (
        level_rank,
        0 if event.get("matched_assets") else 1,
        -importance_score(event),
    )


def top_items(events, limit=MAX_TOP_ITEMS_IN_REPORT):
    """P1 > P2 > 자산 매칭 > 중요도 점수 순으로 우선순위 정렬"""
    return sorted(events, key=event_sort_key)[:limit]


def event_alerted(event):
    delivery = event.get("delivery") or {}
    return bool(delivery.get("email_sent") or delivery.get("slack_sent"))


def importance_score(event):
    return ((event.get("importance") or {}).get("score")) or 0


# 같은 사건을 다룬 다른 매체 기사를 묶는 데 쓰는 어휘.
# 제품명에서 사건을 가르는 이름만 남긴다 — "software"·"enterprise" 같은 수식어와
# "windows"·"chrome" 같은 범용 플랫폼은 서로 무관한 사건이 흔히 공유한다.
# 실측(2026-09-11): "microsoft windows"를 공유한다는 이유로 ShieldCrash 제로데이와
# BlueMoon 익스플로잇킷이, "google chrome"으로 BlueMoon과 LegionLoader ClickFix가
# 한 사건으로 묶였다. 둘 다 다른 사건이다.
GENERIC_PRODUCT_TOKENS = {
    "software", "server", "enterprise", "community", "edition", "gateway", "security",
    "cloud", "service", "services", "system", "systems", "platform", "mobile", "suite",
    "manager", "management", "center", "centre", "studio", "framework", "library",
    "browser", "desktop", "client", "agent", "engine", "portal", "appliance",
}
PLATFORM_PRODUCT_TOKENS = {
    "microsoft", "google", "apple", "anthropic", "openai", "windows", "chrome",
    "chromium", "android", "linux", "macos", "ipados", "safari", "firefox", "edge", "office",
}
MIN_PRODUCT_TOKEN_CHARS = 4
PRODUCT_TOKEN_RE = re.compile(r"[^a-z0-9가-힣]+")


def _product_tokens(product):
    return {token for token in PRODUCT_TOKEN_RE.split(str(product or "").lower())
            if len(token) >= MIN_PRODUCT_TOKEN_CHARS
            and token not in GENERIC_PRODUCT_TOKENS
            and token not in PLATFORM_PRODUCT_TOKENS}


def _same_story(left, right):
    """두 기사가 같은 사건을 다루는가. 맞으면 근거가 된 이름을 돌려준다.

    enrichment가 붙여 준 affected_products를 사건의 열쇠로 쓴다. 제목 자카드로는
    안 잡힌다 — 실측(2026-09-16): "What we know about the Revolut data breach so far"와
    "Revolut gave customer IDs and financial data to a government impostor"는 같은
    사건인데 공유 토큰이 revolut 하나뿐이라 유사도가 문턱을 못 넘고, 추천기사 2위·6위에
    나란히 실렸다.

    세 가지를 모두 요구한다.
      · 같은 제품을 지목했고
      · 분류가 같고(다른 분류면 같은 제품이라도 다른 각도의 사건이다)
      · 다른 매체이며(같은 매체의 연재물은 같은 사건이 아니다 — 안랩 월간
        다크웹 보고서가 "위협 행위자 편"과 "이슈 편"으로 따로 나온다)
      · 그 제품 이름이 양쪽 제목에 모두 나온다.

    마지막 조건이 정밀도를 만든다. 한쪽 제목에만 나와도 된다고 풀면 본문에서 스친
    제품으로 무관한 사건이 묶인다.
    """
    if (left.get("category") or "") != (right.get("category") or ""):
        return ""
    if (left.get("source") or "") == (right.get("source") or ""):
        return ""
    left_title = (left.get("title") or "").lower()
    right_title = (right.get("title") or "").lower()
    left_products = {str(p).strip().lower() for p in (left.get("affected_products") or []) if str(p).strip()}
    right_products = {str(p).strip().lower() for p in (right.get("affected_products") or []) if str(p).strip()}
    for product in left_products & right_products:
        for token in _product_tokens(product):
            if token in left_title and token in right_title:
                return token
    return ""


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

    # related_ids가 비어 있어도 같은 사건인 경우가 있다. 제품·분류·제목이 함께
    # 가리키면 묶는다(_same_story 참고). 후보 수가 수십 건이라 쌍 비교로 충분하다.
    for index, event in enumerate(ranked_candidates):
        for other in ranked_candidates[index + 1:]:
            if find(event.get("id")) == find(other.get("id")):
                continue
            if _same_story(event, other):
                union(event.get("id"), other.get("id"))

    seen_roots = set()
    representatives = []
    for event in ranked_candidates:
        root = find(event.get("id"))
        if root not in seen_roots:
            seen_roots.add(root)
            representatives.append(event)
    return representatives


def _actionability_is_zero(event):
    """분석가 rubric이 실행가능성을 명시적으로 0점으로 채점했는가.

    채점이 없는 이벤트(rubric 도입 전 수집분·enrichment 실패)와 구별한다 — 채점이
    없는 것은 "할 일이 없다"는 판정이 아니라 판정 자체가 없는 것이라, 감점하면
    옛 이벤트가 일괄로 불이익을 받는다.
    """
    value = (event.get("analyst_review") or {}).get("actionability")
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0


def pick_trend_reads(events, exclude_ids, max_items=None, include_alerted=False,
                     rank_by_importance=False):
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

    rank_by_importance=True면 아래 큐레이션(탐색 슬롯·PIR 커버리지·카테고리 캡)을
    건너뛰고 중요도순으로만 돌려준다. 대시보드처럼 상한 없이 전부 보여주는 곳을 위한
    것이다 — 거기서는 큐레이션이 순서만 바꾸는데, 상한이 없으니 어차피 전부 실리고
    화면(app.js)도 중요도순으로 다시 정렬해서 큐레이션 결과가 그대로 사라진다.
    실측(2026-09-16): 시드를 바꿔 순서를 흔들어도 화면 결과가 한 글자도 달라지지
    않았다.

    그리고 상한을 둬 큐레이션 순서를 살려도 대시보드에는 맞지 않았다. 12건으로 잘라
    비교하니 큐레이션 순서는 실제 악용이 확인된 GitLab 최고심각도 취약점(중요도 69)과
    이란 APT(68)를 둘 다 밖으로 떨어뜨렸다 — insight_score는 기사의 질을 보고
    importance_score는 사건의 중대성을 보는데, 전부 보여주는 화면에는 후자가 맞다.

    선택은 그리디 — PIR 커버리지는 기간 내 알림된 기사가 이미 답한 PIR을
    커버된 것으로 시드해서, 추천이 "알림이 못 채운 정보 요구의 빈틈"을
    메우게 한다. 1차로 미커버 high 가중치 PIR, 2차로 미커버 PIR 전체,
    3차는 정렬순 충원. 카테고리당 최대 MAX_TREND_PER_CATEGORY건 (슬롯이
    남으면 상한 해제).
    """
    max_items = max_items or MAX_TREND_ITEMS
    pir_defs = common_utils.load_pirs()
    feedback = common_utils.load_feedback()
    search_queries = common_utils.load_recent_search_terms(
        days=SEARCH_INTEREST_WINDOW_DAYS, min_count=SEARCH_INTEREST_MIN_SEARCHES,
    )

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

    def feedback_useful_value(event):
        """이 기사 자체가 useful로 라벨된 정도(0~1) — noise 제외(위 candidates 필터)와
        별개로, 클릭·슬랙 반응으로 이미 유용하다고 확인된 기사를 추천에서 직접 우대한다.
        클릭 기반 라벨은 FEEDBACK_USEFUL_MIN_CLICKS 미만이면 우연한 클릭일 수 있어 0으로
        취급 — 슬랙/수동 라벨(명시적 판단)은 문턱 없이 그대로 인정한다."""
        record = feedback.get(event.get("id"))
        if not record or record.get("label") != "useful":
            return 0.0
        if record.get("via") == "click" and (record.get("click_count") or 1) < FEEDBACK_USEFUL_MIN_CLICKS:
            return 0.0
        return common_utils.feedback_confidence_weight(record)

    def search_interest_value(event):
        """이 기사가 최근 검색어 중 하나와 매칭되면 1.0, 아니면 0.0 — 검색어의 모든 단어가
        기사 텍스트(제목·요약·카테고리·행위자·멀웨어군)에 있어야 매칭으로 본다(AND, History
        탭 검색과 동일한 방식)."""
        if not search_queries:
            return 0.0
        haystack = " ".join(str(value) for value in (
            event.get("title"), event.get("summary"), event.get("category"),
            event.get("threat_actor"), event.get("malware_family"),
        ) if value).lower()
        if not haystack:
            return 0.0
        return 1.0 if any(all(word in haystack for word in words) for words in search_queries) else 0.0

    def quality_score(event):
        """개인화(feedback_useful·search_interest) 이전의 순수 품질 축 합 — 탐색 슬롯
        (EXPLORE_SLOT_COUNT) 선정에 쓴다. 클릭·검색 이력이 없는 새로운 주제도 이 점수만
        으로 최소 한 자리는 확실히 뽑히게 해, 개인화가 필터버블(이미 관심 보인 주제만
        계속 추천되는 것)로 흐르지 않게 하는 안전장치다."""
        weights = [(pir_defs.get(pid) or {}).get("weight") for pid in event.get("pirs") or []]
        recency_days = (now_ts - published_ts(event)) / 86400 if published_ts(event) else 999
        w = INSIGHT_WEIGHTS
        return (
            w["pir_high"] * (1 if any(weight == "high" for weight in weights) else 0)
            + w["pir_any"] * min(len(weights), PIR_ANY_COUNT_CAP)
            + w["topic_repeat"] * (1 if event_topics(event) & alerted_topics else 0)
            + w["confidence_low"] * (1 if (event.get("confidence") or "") == "low" else 0)
            + w["relevance"] * relevance_value.get(event.get("relevance") or "", 0.0)
            + w["novelty"] * novelty_value.get(event.get("novelty") or "", 0.3)
            + w["depth"] * analyst_quality_value(event)
            + w["actionability_zero"] * (1 if _actionability_is_zero(event) else 0)
            + w["hn_buzz"] * math.log1p(hn_points(event))
            + w["importance"] * (importance_score(event) / 100.0)
            + w["recency"] * max(0.0, 1.0 - recency_days / 7.0)
        )

    def insight_score(event):
        """가중합 인사이트 점수(높을수록 우선) — quality_score에 개인화 축을 더한다.
        어느 한 축이 조금 밀려도 나머지 축의 압도적 우위로 뒤집을 수 있게 튜플 순서
        대신 연속값으로 합산한다."""
        w = INSIGHT_WEIGHTS
        return (
            quality_score(event)
            + w["feedback_useful"] * feedback_useful_value(event)
            + w["search_interest"] * search_interest_value(event)
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
    # 정렬 기준이 클러스터 대표도 정한다 — 같은 사건이면 이 기준으로 가장 앞선 것이 남는다.
    candidates.sort(key=importance_score if rank_by_importance else insight_score,
                    reverse=True)
    candidates = _cluster_representatives(candidates)  # 같은 사건 클러스터당 대표 1건만
    if rank_by_importance:
        return candidates[:max_items]

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

    # 탐색 슬롯: 개인화(클릭·검색 이력) 유무와 무관하게, quality_score만 기준으로
    # EXPLORE_SLOT_COUNT건을 먼저 확정한다 — 필터버블 방지(위 EXPLORE_SLOT_COUNT 주석
    # 참고). 아래 본선발 패스는 이미 채워진 자리를 자연히 건너뛴다(eligible의 picked_ids 체크).
    explore_slots = min(EXPLORE_SLOT_COUNT, max_items)
    for event in sorted(candidates, key=quality_score, reverse=True):
        if len(picked) >= explore_slots:
            break
        if eligible(event, require_new_pir=False, require_high=False, enforce_cap=True):
            commit(event)

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


def build_cve_details(cve_ids, group):
    details = []
    for cve_id in cve_ids:
        related = [event for event in group if cve_id in (event.get("cves") or [])]
        records = []
        seen = set()
        for event in related:
            source_url = event.get("url") or ""
            source_name = source_label(event.get("source"))
            for entry in event.get("affected_packages") or []:
                if not isinstance(entry, dict):
                    continue
                product = str(entry.get("product") or "").strip()
                affected = str(entry.get("affected") or "").strip()
                fixed = str(entry.get("fixed") or "").strip()
                if not product or not (affected or fixed):
                    continue
                key = (product, affected, fixed)
                if key not in seen:
                    seen.add(key)
                    records.append({"product": product, "affected": affected, "fixed": fixed,
                                    "source": source_name, "url": source_url})
            # 기사 한 건이 여러 CVE를 함께 다룬 경우에는 버전을 특정 CVE에 귀속시키지 않는다.
            if len(event.get("cves") or []) == 1:
                products = event.get("affected_products") or []
                product = products[0] if len(products) == 1 else ""
                for affected in event.get("affected_versions") or []:
                    key = (product, affected, "")
                    if key not in seen:
                        seen.add(key)
                        records.append({"product": product, "affected": affected, "fixed": "",
                                        "source": source_name, "url": source_url})

        fix_values = [event.get("fix_available") for event in related]
        fix_status = "confirmed" if any(value is True for value in fix_values) or any(row["fixed"] for row in records) else (
            "unavailable" if any(value is False for value in fix_values) else "unknown")
        actions = [event for event in related if event.get("remediation")]
        actions.sort(key=lambda event: (event.get("source") != "github_advisory",
                                        event.get("source") == "cisa_kev"))
        action = actions[0] if actions else {}
        detail = {
            "id": cve_id,
            "versions": records,
            "fix_status": fix_status,
            "remediation": action.get("remediation") or "",
            "remediation_url": action.get("url") or "",
            "due_date": next((event.get("due_date") for event in related if event.get("due_date")), ""),
            "kev": any(event.get("kev") for event in related),
            "exploitation": "active" if any(event.get("exploitation_status") == "active" for event in related)
                            else "poc" if any(event.get("exploitation_status") == "poc" for event in related)
                            else "none",
            "poc": {"status": "unsearched"},
        }
        details.append(detail)
    return details


# ── 대시보드 CVE 탭: 수집된 CVE 전체 ──────────────────────────────────────────
# CVE 탭은 복수 소스로 교차 확인된 카드만 보여 줘서, 교차되지 않은 날에는 NVD CVE
# 154건을 수집하고도 "해당 없음"만 떴다(실측 2026-09-28). 그 기간에 수집된 CVE를
# 번호마다 한 줄로 따로 싣는다. 카드에 든 CVE는 in_cards로 표시해 목록 맨 앞에 둔다.
MAX_CVE_ITEMS = 2000
CVE_ITEM_SUMMARY_CHARS = 150
CVE_ITEM_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CVE_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "IMPORTANT": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3}
# NVD 설명의 상용구. 리눅스 커널 CVE는 전부 이 문장으로 시작해서, 그대로 자르면 한 줄
# 요약이 수백 건 모두 같아진다.
NVD_BOILERPLATE_RE = re.compile(
    r"^\s*In the Linux kernel, the following vulnerability has been resolved:\s*", re.I)
# CVE 이름으로 쓸 제목을 주는 권고 피드. NVD 제목은 CVE 번호 그대로이고, 뉴스 제목은
# 기사 제목이라 CVE 이름이 아니다.
CVE_TITLE_SOURCES = {"msrc", "cisa_kev", "github_advisory", "cisco_psirt", "fortinet_psirt",
                     "paloalto_psirt", "exploit_db"}


def _cve_item_text(text):
    text = NVD_BOILERPLATE_RE.sub("", " ".join(str(text or "").split()))
    return public_text(summary_excerpt(text, CVE_ITEM_SUMMARY_CHARS))


def build_cve_items(events, cards=None):
    """기간 안에 수집된 CVE를 번호마다 하나씩 — 대시보드 CVE 탭의 "수집된 CVE" 목록.

    공개 페이로드 규칙을 지킨다: 자산 매칭·PIR·트리아지 사유는 넣지 않는다(긴급도
    level은 기존 기사 목록처럼 공개). 링크는 화면이 CVE 번호로 만든다 — 항목마다
    URL을 실으면 주간 파일(1,500건 안팎)이 수백 KB 늘어난다. 같은 이유로 비어 있는
    필드는 싣지 않는다.
    """
    carded = {str(cve).upper() for card in cards or [] for cve in card.get("cve_ids") or []}
    level_rank = {"P1": 0, "P2": 1}
    merged = {}
    for event in events or []:
        cves = [str(cve).upper() for cve in (event.get("cves") or [])
                if CVE_ITEM_ID_RE.fullmatch(str(cve))]
        if not cves:
            continue
        source = event.get("source") or ""
        label = source_label(source)
        text = (event.get("ai_summary") or event.get("summary") or "").strip()
        blob = " ".join([event.get("title") or "", text]).upper()
        for cve in dict.fromkeys(cves):
            item = merged.setdefault(cve, {"cve": cve, "sources": [], "severity": "", "cvss": None,
                                           "kev": False, "epss": None, "level": "", "published": "",
                                           "title": "", "summaries": [], "products": []})
            if label and label not in item["sources"]:
                item["sources"].append(label)
            # 긴급도·EPSS·제품·요약은 이 CVE를 다룬 이벤트에서만 가져온다. 여러 사건을 묶은
            # 기사는 이벤트 단위 값이라, 본문에 이 CVE가 안 나오면 다른 CVE의 값이다 —
            # 실측(2026-09-28): CVE-2026-92005에 같은 기사의 시스코 ISE 제로데이 때문에
            # "긴급 대응"과 Claude Code·OpenAI Codex가 붙었다. 그런 기사는 출처로만 센다.
            if len(cves) > 1 and cve not in blob:
                continue
            if source == "nvd" and isinstance(event.get("score"), (int, float)):
                item["cvss"] = max(item["cvss"] or 0, float(event["score"]))
            severity = str(event.get("severity") or "").upper()
            if severity in CVE_SEVERITY_RANK and (source == "nvd" or not item["severity"]):
                item["severity"] = severity
            item["kev"] = item["kev"] or bool(event.get("kev")) or source == "cisa_kev"
            if isinstance(event.get("epss"), (int, float)):
                item["epss"] = max(item["epss"] or 0, float(event["epss"]))
            level = event_level(event)
            if level in level_rank and (not item["level"] or level_rank[level] < level_rank[item["level"]]):
                item["level"] = level
            published = str(event.get("published_at") or "")[:10]
            if published and (not item["published"] or published < item["published"]):
                item["published"] = published
            if source in CVE_TITLE_SOURCES and not item["title"]:
                title = re.sub(r"^\s*CVE-\d{4}-\d{4,7}\s*[-:–]\s*", "", event.get("title") or "", flags=re.I)
                if title and not CVE_ITEM_ID_RE.fullmatch(title.strip()):
                    item["title"] = title.strip()[:120]
            if text:
                # 요약 본문에 이 CVE가 직접 나오는 것을 먼저, 그다음 언어(한국어 > 권고 피드 >
                # NVD)로 고른다. CVE 하나만 다룬 이벤트의 설명은 그 CVE 설명으로 본다.
                specific = cve in text.upper() or len(cves) == 1
                language = 0 if is_korean_text(text) else (1 if source != "nvd" else 2)
                item["summaries"].append((0 if specific else 1, language, text))
            for product in event.get("affected_products") or []:
                product = str(product or "").strip()
                if product and product not in item["products"] and len(item["products"]) < 3:
                    item["products"].append(product)

    items = []
    for cve, item in merged.items():
        summary = _cve_item_text(min(item["summaries"])[2]) if item["summaries"] else ""
        row = {"cve": cve, "sources": item["sources"], "severity": item["severity"],
               "cvss": item["cvss"], "kev": item["kev"], "epss": item["epss"], "level": item["level"],
               "published": item["published"], "title": item["title"], "summary": summary,
               "products": item["products"], "in_cards": cve in carded}
        items.append({key: value for key, value in row.items() if value not in (None, "", [], False)})
    # 최신이 먼저 오게 한 번 정렬한 뒤(안정 정렬), 중요도 순으로 다시 정렬한다.
    items.sort(key=lambda row: row.get("published") or "", reverse=True)
    items.sort(key=lambda row: (
        0 if row.get("in_cards") else 1,
        0 if row.get("kev") else 1,
        level_rank.get(row.get("level"), 2),
        CVE_SEVERITY_RANK.get(row.get("severity"), 4),
        -(row.get("cvss") or 0),
    ))
    return items[:MAX_CVE_ITEMS]


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

    # 요약은 한국어 맥락(뉴스·ASEC의 LLM 요약) 우선, 그 다음이 다른 뉴스, 기계 피드는
    # 맨 뒤다. 예전에는 한국어 소스만 앞으로 빼고 나머지는 순서가 없었는데, 카드 하나에
    # 여러 CVE가 묶이면서 대표 요약이 엉뚱해졌다(실측: 패치 화요일 101개 CVE를 묶은
    # 카드의 요약이 NVD의 Skype for Business 설명 한 줄이었다 — 그 카드가 무엇에 대한
    # 것인지 알 수 없다). 기계 피드의 설명은 CVE 하나만 서술하므로 묶음을 대표할 수 없다.
    def _summary_rank(event):
        source = event.get("source")
        if source in ("boannews", "asec", "kisa", "dailysecu"):
            return 0
        if source in common_utils.NON_NEWS_SOURCES:
            return 2
        return 1

    summary = ""
    for event in sorted(group, key=_summary_rank):
        summary = (event.get("ai_summary") or event.get("summary") or "").strip()
        if summary and is_korean_text(summary):
            break
        summary = ""

    return {
        "cve": cve_label,
        "cve_ids": cve_ids,
        "cve_details": build_cve_details(cve_ids, group),
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
        "summary": summary_excerpt(summary, CARD_SUMMARY_CHARS),
        "products": _union(group, "affected_products"),
        "assets": common_utils.canonical_assets(_union(group, "matched_assets")),
        "actors": [event["threat_actor"] for event in group if event.get("threat_actor")],
        "items": [
            (event.get("source"), event.get("title") or "", event.get("url") or "", event.get("id"))
            for event in group
        ],
        "event_ids": {event.get("id") for event in group},
        "evidence": [public_evidence(event, source_label(event.get("source"))) for event in group],
    }


# 같은 사건인데 카드가 갈리는 것을 막는 2차 병합 기준. 1차 묶음(이벤트 집합 완전
# 일치)은 너무 엄격하다 — CVE마다 NVD 항목이 따로 있어서, 같은 패치 묶음을 다룬
# CVE들도 집합이 절대 같아지지 않는다(실측 2026-09-10: 9월 패치 화요일이 TOP 3의
# 1·2번을 동시에 차지해, 실질 위협 3건 중 2건이 같은 사건이었다).
#
# 그래서 "어느 기사들이 함께 다뤘는가"로 다시 본다. NVD·KEV 같은 기계 피드는 CVE
# 단위로 항상 갈라지므로 세지 않고, 사람이 쓴 기사만 센다. 두 묶음이 공유하는
# 기사가 둘 이상 겹치고 작은 쪽의 이 비율을 넘으면 같은 사건으로 본다.
STORY_MERGE_OVERLAP = 0.6


def _news_event_ids(group):
    """묶음에서 사람이 쓴 기사의 id만. 기계 피드(NVD·KEV·PSIRT)는 뺀다."""
    return {event.get("id") for event in group
            if event.get("source") not in common_utils.NON_NEWS_SOURCES}


def merge_same_story(clusters):
    """같은 사건을 다룬 CVE 묶음끼리 하나로 합친다.

    CVE가 함께 등장한 기사 하나만으로 합치지 않는다. 여러 제품을 다루는 일일
    동향 기사 한 건이 Citrix·Check Point·F5의 CVE를 하나로 잇는 사례가 있었다.
    동일 기사 집합인 CVE는 correlate_by_cve()에서 이미 한 묶음이 된다.
    """
    items = [dict(cluster,
                  news=_news_event_ids(cluster["group"]))
             for cluster in clusters]

    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)   # 앞선 묶음이 대표가 되게 해 순서를 지킨다

    # 독립된 기사 둘 이상이 공통으로 다뤄야 같은 사건으로 본다.
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if find(i) == find(j):
                continue
            shared = items[i]["news"] & items[j]["news"]
            if len(shared) < 2:
                continue
            smaller = min(len(items[i]["news"]), len(items[j]["news"]))
            if smaller and len(shared) / smaller >= STORY_MERGE_OVERLAP:
                union(i, j)

    merged = {}
    order = []
    for index, item in enumerate(items):
        root = find(index)
        if root not in merged:
            merged[root] = {"cves": list(item["cves"]), "group": list(item["group"]),
                            "sources": list(item["sources"])}
            order.append(root)
            continue
        target = merged[root]
        seen = {event.get("id") for event in target["group"]}
        target["group"].extend(event for event in item["group"]
                               if event.get("id") not in seen)
        target["cves"].extend(c for c in item["cves"] if c not in target["cves"])
        target["sources"] = sorted(set(target["sources"]) | set(item["sources"]))
    return [merged[root] for root in order]


def cve_label(cve_ids, max_shown=CVE_LABEL_MAX_SHOWN):
    """카드 제목에 쓸 CVE 표기. 수백 건이 합쳐질 수 있어 앞의 몇 개만 보인다."""
    ids = sorted(cve_ids)
    if len(ids) <= max_shown:
        return " / ".join(ids)
    return "{} 외 {}건".format(" / ".join(ids[:max_shown]), len(ids) - max_shown)


def correlate_by_entity(events, covered_event_ids):
    """CVE가 없어 CVE 카드로 묶이지 못한 사건을 위협 행위자·악성코드명으로 묶는다.

    공격 캠페인·침해사고·정보유출은 CVE가 없는 경우가 대부분이라(실측: 알림의 55%)
    correlate_by_cve()의 그물에 걸리지 않고 기사 목록에 흩어진 채 남는다. 정작
    "핵심 이슈"라 부를 만한 건 이쪽인데도 카드가 안 만들어진다.

    묶는 기준은 CVE와 동일하게 "복수 소스가 같은 대상을 다뤘는가"다. 다만 키가
    문자열이라 표기 흔들림이 있어 normalize_threat_actor()로 공식 명칭에 맞춘다.
    제목 유사도는 여기서 쓰지 않는다 — 임계값에 따라 무관한 사건이 붙을 위험이 있어,
    정확 일치로 잡히는 것만 먼저 처리한다.

    covered_event_ids: 이미 CVE 카드에 들어간 이벤트. 같은 기사가 카드 두 개에
    중복 노출되지 않도록 제외한다.
    """
    groups = {}
    for event in events:
        if event.get("id") in covered_event_ids:
            continue
        for field, kind in (("threat_actor", "actor"), ("malware_family", "malware")):
            raw = common_utils.clean_text(event.get(field))
            if not raw:
                continue
            name = common_utils.normalize_threat_actor(raw) if field == "threat_actor" else raw
            groups.setdefault((kind, name.lower()), {"label": name, "events": []})["events"].append(event)

    cards = []
    used_event_ids = set()
    # 근거 소스가 많은 묶음부터 확정해, 같은 기사가 행위자·악성코드 양쪽 카드에
    # 중복으로 들어가지 않게 한다.
    ordered = sorted(
        groups.values(),
        key=lambda g: -len({event.get("source") for event in g["events"]}),
    )
    for group in ordered:
        remaining = [event for event in group["events"] if event.get("id") not in used_event_ids]
        sources = sorted({event.get("source") or "unknown" for event in remaining})
        if len(sources) < 2:
            continue
        card = build_cve_card(group["label"], [], remaining, sources)
        used_event_ids |= card["event_ids"]
        cards.append(card)
    return cards


# 제목 토큰 유사도로 묶을 임계값. find_related_events()의 0.5보다 낮은 이유는
# 목적이 달라서다 — 거기는 "같은 사건인지" 판정해 알림을 억제하므로 오병합 비용이
# 크지만, 여기는 카드를 만들 뿐이라 덜 치명적이고 다른 소스여야 한다는 조건이 붙는다.
# 실측(2026-08 주간): 0.30에서 미커버 대응대상 57건이 짝을 찾아 커버율 26%→40%.
TITLE_CLUSTER_THRESHOLD = 0.30


def correlate_by_title(events, covered_event_ids):
    """CVE도 행위자명도 없는 사건을 제목 유사도로 묶는다.

    공급망 공격·인프라 공격(BGP 하이재킹 등)·국내 침해사고는 CVE와 행위자명이 모두
    비어 있는 경우가 많아 앞의 두 단계 그물을 다 빠져나간다. 실제 사례:
      [securityweek]  Malicious Virtualizor Update Served via BGP Hijacking
      [thehackernews] BGP Hijack Delivers Malicious Virtualizor Update That ...
    둘 다 cves=[], threat_actor='', malware_family=''이라 정확 일치로는 못 묶는다.

    같은 소스끼리는 묶지 않는다 — 한 매체의 후속 보도는 교차 확인이 아니고,
    연재물이 제목만 비슷해 묶이는 오병합의 주범이기도 하다.

    카탈로그형 소스(NON_NEWS_SOURCES)는 아예 대상에서 뺀다. 이쪽 제목은 "Remote Code
    Execution", "Denial of Service", "stack buffer overflow" 같은 정형 문구라 내용이
    전혀 달라도 토큰이 크게 겹쳐 오병합이 난다(실측: Azure Cosmos DB RCE와 Entra ID
    OAuth 피싱이 한 카드로 묶였다). 이들은 CVE ID라는 정확한 키가 이미 있어
    correlate_by_cve()가 제대로 묶으므로, 제목으로 또 묶을 이유가 없다.
    """
    candidates = [
        event for event in events
        if event.get("id") not in covered_event_ids
        and (event.get("source") or "") not in common_utils.NON_NEWS_SOURCES
    ]
    token_cache = {id(event): common_utils.title_tokens(event.get("title")) for event in candidates}

    groups = []
    for event in candidates:
        tokens = token_cache[id(event)]
        if not tokens:
            continue
        placed = False
        for group in groups:
            if not group["tokens"] or not tokens:
                continue
            overlap = len(tokens & group["tokens"]) / len(tokens | group["tokens"])
            if overlap >= TITLE_CLUSTER_THRESHOLD:
                group["events"].append(event)
                group["tokens"] |= tokens
                placed = True
                break
        if not placed:
            groups.append({"events": [event], "tokens": set(tokens), "label": event.get("title") or ""})

    cards = []
    for group in groups:
        sources = sorted({event.get("source") or "unknown" for event in group["events"]})
        if len(sources) < 2:
            continue
        # 국내 매체 두 곳이 같은 보도자료를 받아쓰면 제목이 거의 같아 반드시 묶이는데,
        # 제품 출시·행사·부고 같은 건 "복수 소스가 다뤘다"는 사실이 중요도를 뜻하지
        # 않는다(실측: 이 단계 카드의 40%가 그런 묶음이었다). 대응 신호가 있는 기사가
        # 하나도 없으면 카드로 만들지 않는다 — 리포트 집계와 같은 is_actionable 기준.
        if not any(is_actionable(event) for event in group["events"]):
            continue
        cards.append(build_cve_card(group["label"][:80], [], group["events"], sources))
    return cards


def correlate_by_cve(events):
    """이벤트를 CVE 기준으로 묶어, 복수 소스(≥2)에 동시 등장한 CVE 카드 목록을 반환.

    복수 소스 동시 등장 자체가 가장 강한 중요도 신호다:
    NVD 단독 = 배경 소음, +KEV = 실제 악용, +국내 뉴스·ASEC = 국내에서 문제되는 위협.

    예외로 CISA KEV는 단독 등장이어도 카드를 만든다 — "미 연방기관이 실제 악용을
    공식 확인"이라는 신호 자체가 다른 매체의 corroboration보다도 강해서, 그날
    다른 소스가 안 다뤘다는 이유로 TOP 3·총평에서 통째로 안 보이면 안 된다.

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
        if len(sources) < 2 and "cisa_kev" not in sources:
            continue
        key = frozenset(event.get("id") for event in group)
        cluster = clusters.setdefault(key, {"cves": [], "group": group, "sources": sources})
        cluster["cves"].append(cve)

    cards = []
    covered_event_ids = set()
    for cluster in merge_same_story(list(clusters.values())):
        cve_ids = sorted(cluster["cves"])
        card = build_cve_card(cve_label(cve_ids), cve_ids, cluster["group"], cluster["sources"])
        covered_event_ids |= card["event_ids"]
        cards.append(card)

    entity_cards = correlate_by_entity(events, covered_event_ids)
    for card in entity_cards:
        covered_event_ids |= card["event_ids"]
    cards.extend(entity_cards)
    cards.extend(correlate_by_title(events, covered_event_ids))

    # 순서 기준. KEV 등재와 조치 기한을 소스 개수보다 위에 둔다 — 소스 개수는 "언론이
    # 얼마나 다뤘나"이고 KEV·기한은 "언제까지 조치해야 하나"다. 앞의 것을 위에 두면
    # 기한이 걸린 항목이 밀린다(실측 2026-09-10: CISA가 09-12까지 패치를 의무화한
    # Citrix NetScaler 인증 우회가, KEV 단독 등재라 소스가 1개뿐이어서 일반 뉴스보다
    # 아래인 4위였다 — TOP 3에서 빠졌다).
    level_rank = {"P1": 0, "P2": 1, "": 2}
    cards.sort(
        key=lambda card: (
            level_rank.get(card["level"], 2),
            0 if card["kev"] else 1,
            0 if card["due_date"] else 1,
            -len(card["sources"]),
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
        bits.append(common_utils.level_label(card["level"]))
    if card["score"] > 0:
        bits.append("CVSS {}".format(card["score"]))
    if card["epss"] is not None:
        bits.append("EPSS {:.0%}".format(card["epss"]))
    if card["kev"]:
        bits.append("실제 악용 확인(KEV)")
    elif card["exploitation"] == "active":
        bits.append("악용 정황")
    elif card["exploitation"] == "poc":
        bits.append("PoC 관련 신호")
    if card["ransomware"]:
        bits.append("랜섬웨어 연계")
    if include_assets and card["assets"]:
        bits.append("자산매칭: {}".format(", ".join(card["assets"])))
    if (card.get("github_poc") or {}).get("count"):
        bits.append("GitHub 관련 저장소 검색 {}개".format(card["github_poc"]["count"]))
    return bits


MAX_GITHUB_POC_CVES_PER_CARD = 3  # 병합 카드에 CVE가 여러 개면 상위 몇 개까지만 조회 (API 호출 제한)


# 이슈 분석: 카드 하나(같은 사건을 다룬 여러 매체)를 종합한 보고서를 미리 만들어 둔다.
#
# 원래는 대시보드의 서버리스 함수(click-tracker/api/analyze.js)에서 클릭 시 생성했는데,
# 그 함수가 쓰던 모델(openai/gpt-oss-120b)이 폐기(HTTP 410)되면서 남은 대체 모델이
# 전부 Vercel 60초 상한에 걸린다(실측: gpt-oss-20b 36~61초, nemotron 84.9초).
# 여기서는 시간 제한이 없고(timeout=300), 요약을 입력으로 쓰면 프롬프트가 작아
# 실측 25.9초에 끝난다. 즉시성이 필요한 기능이 아니라 미리 만들어 두는 편이 낫다.
ISSUE_ANALYSIS_MAX_CARDS = 10
ISSUE_ANALYSIS_MIN_ITEMS = 3   # 2건짜리는 요약 두 개를 붙인 것과 차이가 없어 제외
ISSUE_ANALYSIS_INPUT_CHARS = 600


def ai_issue_analysis(card, events_by_id):
    """카드의 구성 기사 요약들을 종합해 이슈 단위 보고서를 만든다. 실패 시 빈 문자열.

    본문은 events.jsonl에 저장하지 않으므로(body_chars만 남는다) 기사별 LLM 요약
    (ai_summary)을 입력으로 쓴다 — 이미 본문을 읽고 만든 결과물이라 교차 종합에는
    충분하고, 원문을 다시 긁어오는 네트워크 비용도 없다.
    """
    parts = []
    for source, title, _url, event_id in card["items"]:
        event = events_by_id.get(event_id) or {}
        body = (event.get("ai_summary") or "").strip() or (event.get("summary") or "").strip()
        if not body:
            continue
        parts.append("[{}] {} ({})\n{}".format(
            source_label(source), title, str(event.get("published_at") or "")[:16],
            body[:ISSUE_ANALYSIS_INPUT_CHARS],
        ))
    if len(parts) < 2:
        return ""

    prompt = (
        "당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다.\n"
        "아래는 같은 사건(이슈)을 다룬 서로 다른 매체의 보도 요약이다. 이를 종합해 "
        "이 이슈 하나에 대한 보고서를 한국어로 작성하라.\n\n"
        "출력 형식:\n"
        "[핵심 요약] 이 이슈가 무엇인지 2~3문장\n"
        "[확인된 사실] 복수 매체가 공통으로 전하는 내용만. 각 항목 끝에 근거 매체를 "
        "(출처: A, B) 형태로 적어라. 한 곳만 전한 내용은 여기 쓰지 마라.\n"
        "[매체별 차이] 엇갈리거나 한 곳만 보도한 내용. 수치가 다르면 양쪽을 모두 적고 "
        "어느 매체가 무엇을 말하는지 밝혀라. 차이가 없으면 \"없음\"이라고만 써라.\n"
        "[전개 경과] 보도 시점 순서로 무엇이 밝혀졌는지.\n"
        "[영향 범위 및 위험도] 영향받는 대상과 규모를 요약에 있는 수치로.\n"
        "[권장 조치] 실무자가 바로 실행할 수 있는 것 3~5개.\n\n"
        "추측 금지: 아래 요약에 없는 사실을 만들어내지 마라. 여러 보도를 합치는 것이 "
        "목적이지 없는 내용을 채우는 것이 아니다.\n"
        "문체: 모든 문장을 \"~합니다\"체가 아닌 간결한 서술체로 쓰되 반말은 쓰지 마라.\n\n"
        "이슈명: {}\n\n{}".format(card["cve"], "\n\n".join(parts))
    )
    return common_utils.llm_generate(prompt, timeout=300, nvidia_max_attempts=3) or ""


def enrich_cards_with_issue_analysis(cards, events):
    """상위 카드에만 이슈 분석을 붙인다 — 카드 하나당 LLM 1회라 개수를 제한한다."""
    events_by_id = {event.get("id"): event for event in events}
    done = 0
    for card in cards:
        if done >= ISSUE_ANALYSIS_MAX_CARDS:
            break
        if len(card["items"]) < ISSUE_ANALYSIS_MIN_ITEMS:
            continue
        print("[*] 이슈 분석 생성 중: {} (기사 {}건)".format(card["cve"][:50], len(card["items"])))
        analysis = ai_issue_analysis(card, events_by_id)
        if analysis:
            card["issue_analysis"] = analysis
            done += 1
        else:
            print("[-] 이슈 분석 실패(건너뜀): {}".format(card["cve"][:50]))
    if done:
        print("[+] 이슈 분석 {}건 생성 완료".format(done))


def enrich_cards_with_github_poc(cards):
    """카드 목록(리포트에 실제 노출되는 상위 N개만 넘길 것)에 GitHub PoC 공개 여부를 붙인다."""
    remaining_searches = 10
    for card in cards:
        for cve_id in card["cve_ids"][:MAX_GITHUB_POC_CVES_PER_CARD]:
            if remaining_searches <= 0:
                return
            remaining_searches -= 1
            result = common_utils.check_github_poc(cve_id)
            detail = next((item for item in card.get("cve_details") or [] if item["id"] == cve_id), None)
            if detail is not None:
                detail["poc"] = {
                    "status": "candidate" if result and result["count"] > 0 else "none" if result else "error",
                    "count": result["count"] if result else 0,
                    "url": result["latest_url"] if result else "",
                    "checked_at": common_utils.utc_now_iso(),
                }
            if result and result["count"] > 0:
                if not card.get("github_poc"):
                    card["github_poc"] = result


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
        bits.append("자산매칭: {}".format(", ".join(common_utils.canonical_assets(event["matched_assets"]))))
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
        # 수집 볼륨만 적으면 매일 비슷한 숫자라 판단 근거가 안 된다 — 자산·악용·KEV
        # 신호가 있어 실제로 봐야 하는 건수를 괄호로 함께 적는다.
        lines.append("[카테고리별 건수] (괄호는 자산·악용·KEV 신호가 있는 대응 대상)")
        actionable_by_category = stats.get("actionable_by_category") or Counter()
        for category, count in stats["by_category"].most_common():
            lines.append("- {}: {}건 (대응 대상 {}건)".format(
                category, count, actionable_by_category.get(category, 0)))

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
    lines.append("- 긴급 대응(악용 중 + 자사 자산): {}건".format(len(stats["p1"])))
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
            "[크로스소스 상관관계 — 복수 소스에 동시 등장했거나 CISA KEV(실제 악용 공식 확인)에 등재된 CVE"
            " (신뢰도 높은 핵심 위협, 우선순위 순으로 이미 정렬됨)]"
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

    # [핵심 위협 TOP 3]는 CVE 상관관계 카드에서만 뽑히므로, CVE가 없는 P1 뉴스
    # (캠페인·악성코드·유출 사고 등)는 여러 소스가 다뤘어도 구조적으로 TOP 3에
    # 못 들어간다 — [총평]이 이 사각지대를 보완할 수 있게 별도로 짚어준다.
    covered_ids = set()
    for card in cards:
        covered_ids.update(card.get("event_ids") or set())
    uncovered_p1 = [
        event for event in events
        if event_level(event) == "P1"
        and event.get("id") not in covered_ids
        and (event.get("source") or "") not in common_utils.NON_NEWS_SOURCES
    ]
    if uncovered_p1:
        # 5건으로 자르기 전에 importance_score 내림차순 정렬 — 안 그러면 수집 순서(임의)
        # 대로 잘려서, 그날 6번째 이후로 밀린 진짜 중요한 항목이 통째로 프롬프트에서
        # 빠질 수 있다.
        uncovered_p1 = sorted(uncovered_p1, key=importance_score, reverse=True)
        lines.append("")
        lines.append("[CVE 상관관계 카드에 없는 P1 긴급 항목 — 총평에서 반드시 언급할 것]")
        for event in uncovered_p1[:5]:
            lines.append(event_line(event))

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

# 항목 마커(1. / -)는 줄 맨 앞에 오는 게 원칙이지만, LLM이 들여쓰거나("   1. ")
# 굵게 감싸면("**1. ") 마커가 줄 첫 칸에 없어 분리가 통째로 실패한다. 그러면 항목
# 전부가 한 덩어리가 되고 max_chars 절단에 걸려 2·3번 항목이 사라진다
# (2026-08-31 일간 리포트에서 [핵심 위협 TOP 3]·[권고 조치]가 각 1개만 나간 실제 원인).
# 마커 앞의 공백과 강조 기호를 허용해 분리 자체가 깨지지 않게 한다.
ITEM_SPLIT_RE = re.compile(r"(?m)^[ \t]*(?:\*\*)?(?=\d+\.(?:\s|$)|-(?:\s|$))")
# 항목 첫 줄이 아닌 뒷줄에 또 번호 마커가 있으면 분리에 실패한 것이다
# (첫 줄 마커는 그 항목 자신의 것이므로 앞에 줄바꿈이 있는 경우만 센다)
EMBEDDED_MARKER_RE = re.compile(r"\n[ \t]*(?:\*\*)?\d+\.(?:\s|$)")


RETRY_COVERAGE_HINT = (
    "\n\n[재작성 지시] 방금 만든 답에서 [핵심 위협 TOP 3]에 올린 항목 중 일부가 "
    "[권고 조치]에 빠졌다. 위협으로 올린 것에 조치가 없으면 읽는 사람이 그것을 "
    "놓친다. 위협 항목 수와 조치 항목 수를 같게, 같은 순서로 다시 작성하라."
)


def _clean_narrative(narrative):
    """LLM 응답을 리포트에 실을 형태로 다듬는다(길이 자르기·빈 항목 제거·번호 정리).

    첫 응답과 재시도 응답이 같은 처리를 거쳐야 항목 수를 같은 기준으로 셀 수 있어서
    따로 뺐다.
    """
    narrative = _truncate_summary_section(narrative)
    narrative = _truncate_numbered_items(narrative, "핵심 위협 TOP 3")
    narrative = _truncate_numbered_items(narrative, "자사 자산 관련")
    narrative = _truncate_numbered_items(narrative, "권고 조치", max_items=3)
    narrative = _remove_bare_markers(narrative)
    return _renumber_lists(narrative)


def _uncovered_threat_count(narrative):
    """조치가 붙지 않은 위협 항목 수. 0이면 1:1이 지켜진 것이다."""
    threats = _count_numbered_items(narrative, "핵심 위협 TOP 3")
    actions = _count_numbered_items(narrative, "권고 조치")
    return max(0, threats - actions) if threats else 0


def _count_numbered_items(narrative, header):
    """섹션 안의 번호·불릿 항목 수. 개수 지침이 지켜졌는지 확인하는 데 쓴다."""
    pattern = r"(\[{}\]\s*\n?)(.*?)(?=\n\[|\Z)".format(re.escape(header))
    match = re.search(pattern, narrative, re.S)
    if not match:
        return 0
    return len([line for line in match.group(2).splitlines()
                if re.match(r"\s*(?:\d+\.|[-*])\s*\S", line)])


def _warn_uncovered_threats(narrative):
    """TOP 3에 올린 위협 수보다 권고 조치가 적으면 로그로 알린다.

    프롬프트로 1:1을 강제하지만 LLM이 어길 때가 있다. 자동으로 채워 넣지는 않는다 —
    없는 조치를 코드가 지어내면 더 나쁘다. 대신 실행 로그에 남겨서, 조치가 빠진 채로
    나간 회차를 나중에 찾을 수 있게 한다(2026-09-10에 실제로 그렇게 나갔다).
    """
    threats = _count_numbered_items(narrative, "핵심 위협 TOP 3")
    actions = _count_numbered_items(narrative, "권고 조치")
    if _uncovered_threat_count(narrative):
        print("[-] 총평 점검: 핵심 위협 {}건인데 권고 조치는 {}건 — 조치 없는 위협이 "
              "{}건 있습니다.".format(threats, actions, threats - actions))
    return narrative


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
    items = [item.strip() for item in ITEM_SPLIT_RE.split(match.group(2).strip()) if item.strip()]

    # 분리에 실패해 여러 항목이 한 덩어리로 합쳐지면, 아래 max_chars 절단이 뒤쪽 항목을
    # 통째로 먹어치운다 — 조용히 사라지면 알아챌 방법이 없으므로 로그로 남긴다.
    for item in items:
        if EMBEDDED_MARKER_RE.search(item):
            print("[!] [{}] 항목 분리 실패로 여러 항목이 한 덩어리가 됐습니다 — 뒤쪽 항목이 잘릴 수 있습니다: {}".format(
                header, item[:80].replace("\n", " ")
            ))
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

    # 헤더 정규식의 \s*가 본문 첫 줄의 들여쓰기까지 흡수하기 때문에, 그대로 이어붙이면
    # 첫 항목만 들여쓰인 채 남는다 — 그러면 뒤의 번호 재정렬이 첫 항목을 항목으로 못 세서
    # 번호가 "1. 1. 2."처럼 어긋난다. 줄바꿈 뒤의 들여쓰기만 걷어낸다.
    prefix = narrative[:match.start(2)]
    head, newline, indent = prefix.rpartition("\n")
    if newline and not indent.strip():
        prefix = head + newline

    return prefix + "\n".join(final_items) + _normalize_tail(narrative, match.end(2))


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


KEYWORD_HEADER = "핵심 키워드"
MAX_KEYWORDS = 8


def _extract_keywords(narrative, header=KEYWORD_HEADER, max_items=MAX_KEYWORDS):
    """[핵심 키워드] 섹션 본문을 쉼표/줄바꿈/불릿 구분자 상관없이 파싱해 리스트로 반환한다.
    웹 대시보드 사이드바에서 클릭하면 검색으로 이어지는 태그로 쓴다 — 본문 narrative에는
    안 어울리는 형식이라 여기서 뽑아낸 뒤 _strip_narrative_section()으로 따로 제거한다."""
    match = re.search(r"\[{}\]\s*\n?(.*?)(?=\n\[|\Z)".format(re.escape(header)), narrative, re.S)
    if not match:
        return []
    body = match.group(1).strip()
    if not body:
        return []

    raw_items = re.split(r"[,\n]|(?:^|\n)\s*-\s*", body)
    keywords = []
    seen = set()
    for raw in raw_items:
        term = raw.strip(" -\t.")
        if not term or term.lower() in seen:
            continue
        seen.add(term.lower())
        keywords.append(term)
        if len(keywords) >= max_items:
            break
    return keywords


def _keywords_grounded_in_digest(keywords, digest):
    """LLM이 실제 데이터에 없는 용어를 지어내는 걸 거른다 — attack_techniques를 공식
    카탈로그로 검증하는 것과 같은 목적의 환각 방지 장치. 그 기간 실제 소스 데이터인
    digest에 문자열로(대소문자 무관) 등장하지 않는 키워드는 제외한다."""
    digest_lower = digest.lower()
    return [kw for kw in keywords if kw.lower() in digest_lower]


# "Iranian state-sponsored actors"처럼 국적 형용사 + 일반 명사만으로 구성된 키워드 —
# 프롬프트에 "일반 용어·범주명은 넣지 마라, 구체적 고유명사만"이라고 이미 명시했는데도
# LLM이 종종 어긴다. _keywords_grounded_in_digest는 digest에 그 문구가 실제로 있는지만
# 보므로(환각 방지 목적), 이런 서술적 범주 표현이 digest에 그대로 있으면 통과시켜버린다
# — 그래서 별도로, 키워드를 구성하는 단어 전부가 이 목록(국적·일반 위협 명사)에 속하면
# "구체적 고유명사가 하나도 없다"고 보고 제외한다. 한 단어라도 목록 밖이면(예: SilverFox,
# Lazarus) 살아남는다 — 실제 그룹·악성코드명을 잘못 걸러내지 않기 위한 보수적 기준이다.
_GENERIC_KEYWORD_WORDS = {
    "north", "korean", "korea", "south", "chinese", "china", "russian", "russia",
    "iranian", "iran", "dprk", "state-sponsored", "state", "sponsored", "nation-state",
    "nation", "government-backed", "government", "backed", "advanced", "sophisticated",
    "unnamed", "unidentified", "linked", "affiliated", "backed", "based",
    "actors", "actor", "attackers", "attacker", "hackers", "hacker", "group", "groups",
    "gang", "gangs", "campaign", "campaigns", "operators", "operator", "criminals",
    "criminal", "threat",
}


def _is_generic_keyword(keyword):
    tokens = re.findall(r"[a-z0-9-]+", keyword.lower())
    if not tokens:
        return True
    return all(token in _GENERIC_KEYWORD_WORDS for token in tokens)


def _remove_bare_markers(narrative):
    """번호("1.")나 불릿("-")만 있고 내용이 없는 줄을, 어느 섹션에 있든 통째로 제거하는
    마지막 안전망. _truncate_numbered_items()가 섹션별로 이미 같은 일을 하지만, 그
    파싱이 놓치는 예외적인 경우(섹션 헤더 인식 실패 등)까지 잡아내는 최종 방어선이다 —
    섹션별 로직과 무관하게 "빈 번호/불릿 줄"이 사용자에게 보이는 일 자체를 원천 차단한다.
    """
    lines = narrative.split("\n")
    kept = [line for line in lines if not re.match(r"^\s*(?:\d+\.|-)\s*$", line)]

    result = []
    blank_run = False
    for line in kept:
        is_blank = line.strip() == ""
        if is_blank and blank_run:
            continue
        blank_run = is_blank
        result.append(line)
    return "\n".join(result).strip()


def _renumber_lists(narrative):
    """번호 목록("1. ...")의 연속 구간을 찾아 항상 1부터 순서대로 다시 매기는 최종 방어선.

    _truncate_numbered_items()가 섹션별로 이미 번호를 재정렬하지만, 실제 리포트에서
    간헐적으로 [권고 조치] 등이 "2. / 3. "로 시작해 "1."이 빠진 채 나가는 사례가
    확인됐다 — 원인을 섹션별 파싱 로직 안에서 재현하지 못해서, 어떤 경로로 깨지든
    최종 출력만큼은 항상 올바르게 나가도록 narrative 전체를 대상으로 한 번 더
    강제한다. 불릿("-")은 건드리지 않는다(원래 순서가 없는 목록).
    """
    lines = narrative.split("\n")
    i = 0
    while i < len(lines):
        if not re.match(r"^[ \t]*\d+\.\s", lines[i]):
            i += 1
            continue
        # 번호 줄들의 연속 구간 — 빈 줄이나 "[다음 섹션]" 줄에서 끊긴다. 번호로
        # 시작하지 않는 중간 줄은 앞 항목이 여러 줄에 걸친 것으로 보고 구간에는
        # 포함하되(건너뛰기만) 새 항목으로 세지는 않는다.
        numbered_positions = []
        j = i
        while j < len(lines):
            stripped = lines[j].strip()
            if stripped == "" or re.match(r"^\[.+\]\s*$", stripped):
                break
            if re.match(r"^[ \t]*\d+\.\s", lines[j]):
                numbered_positions.append(j)
            j += 1
        for order, pos in enumerate(numbered_positions, start=1):
            # 들여쓰인 항목도 같은 목록의 일부로 세되, 출력은 들여쓰기 없이 통일한다
            rest = re.sub(r"^[ \t]*\d+\.\s", "", lines[pos], count=1)
            lines[pos] = "{}. {}".format(order, rest)
        i = j
    return "\n".join(lines)


def fallback_keywords(stats, cards, max_items=MAX_KEYWORDS):
    """LLM이 [핵심 키워드] 섹션을 통째로 빼먹거나 빈 채로 내놓을 때의 안전장치 — 이미
    코드로 집계된 위협 행위자·악성코드(stats)·CVE(cards)에서 기계적으로 뽑는다.
    프롬프트에 "절대 생략 금지"를 명시해도 LLM이 가끔 안 지킬 수 있으니, 사이드바가
    아예 안 뜨는 것보다는 이렇게라도 채우는 게 낫다."""
    keywords = []
    seen = set()

    def add(term):
        term = (term or "").strip()
        if not term or term.lower() in seen:
            return
        seen.add(term.lower())
        keywords.append(term)

    for actor, _ in stats.get("top_actors") or []:
        add(actor)
    for malware, _ in stats.get("top_malware") or []:
        add(malware)
    for card in cards:
        add(card.get("cve"))
        if len(keywords) >= max_items:
            break
    return keywords[:max_items]


# 총평 생성 재시도 횟수. 주간은 실패하면 다음 시도가 일주일 뒤라 그 주 리포트가
# "AI 해석을 생성하지 못해..."로 확정된다(실측: 5회 중 1회 실패). 지수 백오프와
# 함께 쓰므로 6회면 마지막 시도까지 누적 대기가 약 5분 — 몇 초~몇 분짜리 장애
# 구간을 넘기기에 충분하고, 주 1회 호출이라 비용 부담도 없다.
NARRATIVE_ATTEMPTS = {"daily": 3, "weekly": 6}


def ai_narrative(period_label, digest, period="daily", public_only=False):
    prompt = """당신은 SOC 보안관제 조직의 위협 인텔리전스 분석가이다.
아래는 {period} 동안 수집된 보안 이벤트 요약이다. 이를 바탕으로 보안담당자용 리포트 본문을 한국어로 작성하라.

문체: 모든 문장은 존댓말 종결어미("~합니다", "~해야 합니다", "~필요가 있습니다",
"~권장합니다")로 끝낼 것 — "~한다", "~하다" 같은 반말체는 쓰지 말 것. 동시에 "~하라",
"~하십시오"처럼 지시·명령하는 어조도 피하고, 동료 분석가가 정보를 전달하듯
"~할 필요가 있습니다", "~하는 것이 좋습니다", "~를 권장합니다" 같은 권고형으로 작성하라.

출력 형식:
[총평]
- 가장 중요한 임팩트만 짧게 서술 (분량 제한이 목적이 아니라 핵심만 압축하는 것이 목적)
- 데이터에 "[CVE 상관관계 카드에 없는 P1 긴급 항목]" 섹션이 있으면 그 존재를 반드시 한 문장으로라도 언급하라 — [핵심 위협 TOP 3]는 CVE가 있는 사건만 다루므로, 그쪽에서 못 다루는 P1 캠페인·악성코드·유출 사고 등을 짚어줄 수 있는 곳은 총평뿐이다
- CVE ID, PIR별 세부 수치, MITRE 기법 등 개별 데이터 나열 금지 — 이런 디테일은 아래 다른 섹션과 리포트의 통계 섹션에 이미 있으므로 총평에서 반복하지 말 것
- 숫자를 쓰더라도 전체 건수 등 꼭 필요한 것 한두 개만, 나열식으로 늘어놓지 말 것

[핵심 위협 TOP 3]
- 데이터의 [크로스소스 상관관계] 목록은 이미 우선순위 순으로 정렬돼 있다. 그 목록의 1번·2번·3번 항목을 그 순서 그대로 다뤄라 (목록에 없는 CVE·위협을 임의로 추가하거나 순서를 바꾸지 말 것)
- 목록 항목이 3개 미만이면 있는 개수만큼만 쓰고, 목록이 비어 있으면 전체 데이터에서 가장 중요한 것 최대 3건을 골라 써라
- 각 항목마다 무엇이 왜 중요한지 1문장
- EPSS/CVSS 수치, 소스명, 패치 일자 등 세부 데이터 나열 금지 — 이미 [핵심 이슈 TOP N] 카드 섹션에 있으므로 반복하지 말 것. 실무 임팩트(무엇이 뚫리고 왜 위험한지) 중심으로만 쓸 것

[자사 자산 관련]
- 매칭된 항목이 있으면 조치 우선순위를 제시하고, 없으면 "해당 없음"이라고만 작성
- CVE ID, EPSS/CVSS 수치, KEV 등재 여부 등 세부 데이터 나열 금지 — 이미 다른 섹션에 있으므로 반복하지 말 것. 자산별로 뭘 먼저 조치해야 하는지 1문장만

[권고 조치]
- [핵심 위협 TOP 3]에 쓴 항목마다 하나씩, 같은 순서로 대응 조치를 써라. TOP 3에 2개만 썼으면 여기도 2개다
  (실제 사고 2026-09-10: 총평에 "제로데이 2건 최우선 대응 필요"라고 써 놓고 권고 조치에는 다른 취약점 1건만 올라가,
   권고만 읽은 사람은 정작 가장 급한 것을 놓쳤다. 위협으로 올린 것에 조치가 없으면 그 위협은 안 쓴 것과 같다)
- 위협 목록에 없지만 반드시 해야 하는 조치가 있으면 그 뒤에 덧붙여도 되지만, 전체는 3개를 넘기지 마라
- 각 항목은 무엇을 해야 하는지 행동 중심으로 1문장
- CVE ID, CVSS 수치, PIR 번호, 공격 그룹명 등 세부 데이터 나열 금지 — 이미 다른 섹션에 있으므로 반복하지 말 것

[핵심 키워드] (다른 섹션과 달리 이 섹션은 절대 생략하면 안 됨 — 반드시 작성할 것)
- 앞쪽의 집계 섹션([언급된 공격 그룹·악성코드], [크로스소스 상관관계] 등)만 보지 말고,
  아래 소스별로 나열된 개별 기사 하나하나의 제목·요약까지 전부 훑어서 골라라 — 집계에는
  안 잡히지만 특정 기사 한 건에만 등장하는 특이한 용어도 놓치지 말 것
- 오늘 데이터에 등장한 것 중 검색해볼 만한 고유명사·구체적 용어 5~8개를 쉼표로 구분해 한 줄로 나열하라
  (예: 위협 행위자명, 멀웨어·랜섬웨어 패밀리명, 제품명, CVE ID, 특이한 공격 기법·도구명)
- "랜섬웨어", "취약점", "피싱" 같은 일반 용어·범주명은 넣지 마라 — 구체적 고유명사만
- 정말 고유명사가 하나도 없는 경우가 아니면 최소 3개 이상은 반드시 채워라 — 이 섹션과
  헤더([핵심 키워드])를 절대 통째로 빼먹지 마라

번호/불릿 항목 작성 규칙 (모든 섹션 공통, 중요):
- 번호나 "-"만 쓰고 그 뒤에 설명 문장을 비워두는 것은 절대 금지한다 (예: "1.\n2." 처럼 내용 없이 끝내지 말 것) — 쓸 항목 수를 줄이는 것은 되지만, 쓰기로 한 항목은 반드시 실질적인 문장으로 채워라
- 항목 형식 예시: "1. 설명 문장." 또는 "1. **키워드**: 설명 문장." — 번호/불릿과 설명 문장은 반드시 같은 줄에 붙여 써라

주의: 제공된 데이터에 없는 사실을 만들어내지 마라. 건수와 수치는 데이터에 있는 그대로 사용하라.

데이터:
{digest}
""".format(period=period_label, digest=digest)

    # 실패 시 "(AI 해석을 생성하지 못해 통계 요약만 제공합니다.)"로 대체할 수단이
    # 없는 단발성 호출이라(하루/주 1번), 재시도를 넉넉히 줘서 일시적 실패로
    # 통째로 못 만드는 상황을 줄인다.
    prompt += "\n본문 설명과 권고는 반드시 한국어로 작성하세요. 영문 원문을 문장 그대로 복사하지 마세요. 제품명, CVE 식별자, 고유명사만 원어 표기를 허용합니다.\n"
    if public_only:
        prompt += "\n이 보고서는 공개용입니다. [자사 자산 관련] 섹션을 작성하지 마세요. 조직의 보유 자산, 내부 시스템, 자산 매칭, PIR을 어떤 섹션에서도 언급하지 마세요.\n"
    narrative = common_utils.llm_generate(
        prompt, timeout=300, nvidia_max_attempts=NARRATIVE_ATTEMPTS.get(period, 3)
    ) or ""
    if not narrative:
        return narrative, []
    narrative = _clean_narrative(narrative)

    # 프롬프트로 "위협마다 조치 하나"를 강제해도 LLM이 어긴다(실측: 두 번 중 한 번).
    # 조치가 빠진 위협은 읽는 사람이 놓치는 것이므로 한 번만 다시 받아 본다. 검사가
    # 걸릴 때만 도는 경로라 평소 비용은 늘지 않는다. 두 번째도 모자라면 더 조르지 않고
    # 둘 중 더 많이 채운 쪽을 쓴다 — 계속 다시 받는다고 나아진다는 근거가 없고,
    # 리포트 발송이 그만큼 늦어진다.
    missing = _uncovered_threat_count(narrative)
    if missing:
        print("[*] 조치 없는 위협 {}건 — 총평을 한 번 다시 받습니다.".format(missing))
        retry = common_utils.llm_generate(
            prompt + RETRY_COVERAGE_HINT, timeout=300,
            nvidia_max_attempts=NARRATIVE_ATTEMPTS.get(period, 3)
        ) or ""
        if retry:
            retry = _clean_narrative(retry)
            if _uncovered_threat_count(retry) < missing:
                narrative = retry
    _warn_uncovered_threats(narrative)
    keywords = _extract_keywords(narrative)
    keywords = _keywords_grounded_in_digest(keywords, digest)
    keywords = [kw for kw in keywords if not _is_generic_keyword(kw)]
    narrative = _strip_narrative_section(narrative, KEYWORD_HEADER)
    return narrative, keywords


def _format_weekly_trend_item(item):
    """단일 항목을 '이름 N건 (전주 M건, +D)' 또는 '이름 N건 (신규)' 텍스트로."""
    if item["previous"] == 0:
        return "{} {}건 (신규)".format(item["name"], item["count"])
    return "{} {}건 (전주 {}건, +{})".format(item["name"], item["count"], item["previous"], item["delta"])


def _format_category_trend_item(item):
    """단일 항목을 '이름 비중 M%→N% (+D%p)' 텍스트로 — 카테고리는 건수가 아니라 비중으로 비교한다."""
    return "{} 비중 {:.0f}%→{:.0f}% (+{:.0f}%p)".format(
        item["name"], item["previous_share"], item["share"], item["delta"]
    )


WEEKLY_TREND_GROUPS = (
    ("actors", "위협 행위자", _format_weekly_trend_item),
    ("malware", "악성코드", _format_weekly_trend_item),
    ("techniques", "ATT&CK 기법", _format_weekly_trend_item),
    ("assets", "자산 매칭", _format_weekly_trend_item),
    ("categories", "기사 분류", _format_category_trend_item),
)


def _weekly_trend_groups(weekly_trends):
    """compute_weekly_trends() 결과에서 항목이 있는 그룹만 (라벨, 항목 리스트, 포맷 함수) 순서로 반환."""
    if not weekly_trends:
        return []
    return [
        (label, weekly_trends[key], formatter)
        for key, label, formatter in WEEKLY_TREND_GROUPS
        if weekly_trends.get(key)
    ]


def build_text_report(title, period_label, stats, narrative, highlights, cards, pir_groups,
                      trend_reads, weekly_trends=None):
    lines = [
        title,
        "기간: {}".format(period_label),
        "생성 시각: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
        "",
        "[수집 현황]",
        "- 총 {}건 (긴급 대응 {} / 주의 {} / Critical {} / KEV {} / 랜섬웨어 {} / 자산매칭 {})".format(
            stats["total"], len(stats["p1"]), len(stats["p2"]),
            len(stats["critical"]), len(stats["kev"]), len(stats["ransomware"]),
            len(stats["asset_hits"])
        ),
    ]
    category_counts = [(c, n) for c, n in stats["by_category"].most_common() if c != "미분류"]
    if category_counts:
        # 수집 볼륨만 적으면 매일 비슷한 숫자라(NVD가 CVSS>=7.0만으로도 하루 200건대)
        # 판단 근거가 안 된다 — 자산·악용·KEV 신호가 있는 대응 대상을 괄호로 병기한다.
        actionable_categories = stats.get("actionable_by_category") or Counter()
        lines.append("- 카테고리(괄호는 대응 대상): {}".format(
            ", ".join(
                "{} {}건({})".format(category, count, actionable_categories.get(category, 0))
                for category, count in category_counts
            )
        ))

    weekly_trend_groups = _weekly_trend_groups(weekly_trends)
    if weekly_trend_groups:
        lines.append("")
        lines.append("[주간 동향 — 전주 대비 급증]")
        for label, items, formatter in weekly_trend_groups:
            lines.append("- {}: {}".format(
                label, " · ".join(formatter(item) for item in items)
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
        lines.append("[핵심 이슈 TOP {} — 복수 소스 교차 확인]".format(min(len(cards), MAX_CVE_CARDS)))
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
                      trend_reads, weekly_trends=None):
    parts = [
        "<html><body>",
        "<h2>{}</h2>".format(html.escape(title)),
        "<p>기간: {} | 생성 시각: {}</p>".format(
            html.escape(period_label), datetime.now().strftime("%Y-%m-%d %H:%M")
        ),
        "<h3>수집 현황</h3>",
        "<p>총 <b>{}</b>건 — <b>긴급 대응 {}</b> / 주의 {} / Critical {} / KEV {} / 랜섬웨어 {} / 자산매칭 {}</p>".format(
            stats["total"], len(stats["p1"]), len(stats["p2"]),
            len(stats["critical"]), len(stats["kev"]), len(stats["ransomware"]),
            len(stats["asset_hits"])
        ),
        "<ul>",
    ]
    category_counts = [(c, n) for c, n in stats["by_category"].most_common() if c != "미분류"]
    if category_counts:
        actionable_categories = stats.get("actionable_by_category") or Counter()
        parts.append("<li>카테고리(괄호는 대응 대상): {}</li>".format(html.escape(
            ", ".join(
                "{} {}건({})".format(category, count, actionable_categories.get(category, 0))
                for category, count in category_counts
            )
        )))
    parts.append("</ul>")

    weekly_trend_groups = _weekly_trend_groups(weekly_trends)
    if weekly_trend_groups:
        parts.append("<h3>주간 동향 — 전주 대비 급증</h3>")
        parts.append("<ul>")
        for label, items, formatter in weekly_trend_groups:
            parts.append("<li>{}: {}</li>".format(
                html.escape(label),
                html.escape(" · ".join(formatter(item) for item in items)),
            ))
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
        parts.append("<h3>핵심 이슈 TOP {} — 복수 소스 교차 확인</h3>".format(min(len(cards), MAX_CVE_CARDS)))
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
            extra.append("자산매칭: {}".format(html.escape(", ".join(common_utils.canonical_assets(event["matched_assets"])))))
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
                       trend_reads, weekly_trends=None):
    stat_text = "총 *{}건* 수집 — 🚨 긴급 대응 `{}` / ⚠️ 주의 `{}` / Critical `{}` / KEV `{}` / 🔒 랜섬웨어 `{}` / 자산매칭 `{}`".format(
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

    weekly_trend_groups = _weekly_trend_groups(weekly_trends)
    if weekly_trend_groups:
        trend_lines = [
            "*{}*: {}".format(label, " · ".join(formatter(item) for item in items))
            for label, items, formatter in weekly_trend_groups
        ]
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "📈 *주간 동향 — 전주 대비 급증*\n" + "\n".join(trend_lines)},
        })

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
            "text": {"type": "mrkdwn", "text": "*핵심 이슈 — 복수 소스 교차 확인*\n" + "\n".join(card_lines)},
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


def dashboard_trend_bits(event):
    """trend_bits()와 같은 "왜 추천됐는지" 근거 조각이지만, PIR 이름은 뺀다 — 공개 대시보드에서
    PIR·자산매칭 정보를 노출하지 않는 build_dashboard_payload()의 원칙과 동일하게 적용."""
    bits = []
    if (event.get("novelty") or "") == "new":
        bits.append("신규")
    depth_label = {"analysis": "심층 분석", "report": "보고서"}.get(event.get("content_depth") or "")
    if depth_label:
        bits.append(depth_label)
    if event.get("relevance") == "high":
        bits.append("관련성 높음")
    if importance_score(event):
        bits.append("우선도 {}점".format(importance_score(event)))
    return bits


def _public_narrative_problem(narrative, issue_count):
    if "한국어 요약을 준비하지 못했습니다" in narrative:
        return "필수 섹션이 비어 있습니다"
    if re.search(r"(?:전체|총)\s*\d+\s*건의?\s*(?:이슈|사고)", narrative):
        return "수집 건수를 고유 이슈 수로 표현했습니다"
    sections = dict(re.findall(r"(?ms)^\[([^\]\n]+)\]\s*\n(.*?)(?=^\[|\Z)", narrative))
    threats = re.findall(r"(?m)^\d+\.\s+(.+)$", sections.get("핵심 위협 TOP 3", ""))
    actions = re.findall(r"(?m)^\d+\.\s+(.+)$", sections.get("권고 조치", ""))
    if issue_count and (len(threats) != issue_count or len(actions) != issue_count):
        return "핵심 위협과 권고 조치가 1:1로 대응하지 않습니다"
    for action in actions:
        if re.search(r"공식\s*(?:보안\s*)?(?:권고|공지|자료).*?(?:확인|참조|검토)", action):
            if not re.search(r"패치|업데이트|차단|격리|비활성화|삭제|점검|탐지|교체|제한", action):
                return "공식 권고 확인만 요구하는 조치가 있습니다"
        if re.search(r"적절한 조치|필요한 조치|보안 대책 수립|모니터링을 강화", action):
            return "구체적인 행동이 없는 조치가 있습니다"
    return ""


def ai_public_narrative(period_label, stats, cards):
    facts = {"period": period_label, "total": stats["total"], "issues": [
        {"issue": card["cve"], "summary": public_text(card.get("summary") or ""),
         "remediation": public_text(card.get("remediation") or ""),
         "products": card.get("products") or []}
        for card in cards[:3]]}
    prompt = """공개 보안 대시보드의 AI 요약을 한국어 존댓말로 작성하세요.
아래 자료에 있는 사실만 사용하고 조직의 보유 자산이나 내부 시스템을 추측하지 마세요.
제품명·CVE·공격자 이름 외에는 영문 문장을 쓰지 마세요. 다음 형식을 정확히 지키세요.
total은 수집된 기사·취약점 레코드 건수이지 서로 다른 사고·이슈 수가 아닙니다. 수치를 언급할 때는 "수집 건수"로만 표현하세요.
[총평]
우선 대응할 노출면과 공통 대응 방향을 한국어 두 문장 이내로 설명합니다. 아래 TOP 3의 세부 내용을 그대로 반복하지 마세요.
[핵심 위협 TOP 3]
자료의 issues를 순서대로 최대 3개 설명합니다. 각 항목은 '1. 한국어 설명' 형식입니다.
여러 취약점 중 일부에만 적용되는 점수·악용 상태·영향을 전체 취약점의 특성처럼 쓰지 마세요. "8건 중 2건"처럼 범위를 명확히 구분하세요.
[권고 조치]
같은 순서로 각 위협의 조치를 번호 목록으로 작성합니다. 각 항목에 노출 경로 차단, 영향 자산 점검, 패치·격리 등 자료의 공격 방식에서 직접 도출되는 구체적 행동을 한 문장으로 씁니다.
remediation이 비어 있어도 summary에 명시된 침투 경로와 지속성·탈취 행위를 바탕으로 최소한의 확인·차단 조치를 제시합니다. 자료에 없는 제품 버전, IOC, 공격 사실은 만들어내지 마세요.
"공식 권고 확인", "모니터링 강화", "적절한 조치"처럼 대상과 행동이 빠진 일반론은 쓰지 마세요.
어떤 섹션도 비우지 마세요. 섹션 제목이나 지시문을 항목 내용으로 복사하지 마세요.
자료:
""" + json.dumps(facts, ensure_ascii=False)
    for attempt in range(2):
        retry_hint = ("\n이전 답은 위협별 구체 조치가 부족했습니다. 각 위협의 summary를 다시 읽고 "
                      "공격 경로와 직접 연결되는 확인·차단 조치를 빠짐없이 작성하세요.\n") if attempt else ""
        result = common_utils.llm_generate(prompt + retry_hint, timeout=180, nvidia_max_attempts=1) or ""
        cleaned = public_narrative(result)
        problem = _public_narrative_problem(cleaned, min(len(cards), 3))
        if not problem:
            return cleaned
    raise RuntimeError("Public Korean AI narrative failed quality checks: " + problem)


def build_dashboard_payload(title, period, period_label, stats, narrative, highlights, cards, trend_reads,
                             keywords=None, weekly_trends=None, campaigns=None, cve_items=None):
    """boannews_vercel 웹 대시보드용 JSON 페이로드.

    이메일/슬랙/텍스트 리포트는 지면이 한정돼 있어 highlights·cards를 상위 N개로
    캡(top_items, MAX_CVE_CARDS)하지만, 대시보드는 그런 제약이 없는 브라우징
    페이지라 그 기간에 해당하는 항목을 전부 받는다(caller인 main()이 highlights는
    캡 없이, cards는 correlate_by_cve() 결과 그대로 넘긴다) — 국내/해외 탭이 국제
    P1 기사가 많은 날에도 항상 그날 국내 기사를 보여줄 수 있다.

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
    def serialize_event(event, include_reason=False):
        # matched_assets는 의도적으로 뺀다 — 공개 웹 대시보드에 자사 보유 자산/제품명이
        # 노출되면 안 되므로(이메일/슬랙 리포트는 내부용이라 그대로 유지, 여기만 예외).
        payload = {
            # 대시보드의 "심층분석" 버튼이 이 값으로 분석 결과를 캐싱·식별한다(클릭
            # 추적용 ref와 같은 해시 함수 — tracking_url 설정 여부와 무관하게 항상 존재).
            "ref": common_utils.event_ref(event.get("id")),
            "title": event.get("title") or "(제목 없음)",
            "url": common_utils.tracking_url(event.get("id"), event.get("url") or "") or "",
            "source": event.get("source") or "",
            "source_label": source_label(event.get("source")),
            "level": event_level(event),
            "category": event.get("category") or "",
            "published_at": event.get("published_at") or "",
            "summary": public_text(event_summary(event, 300)),
            "evidence": [public_evidence(event, source_label(event.get("source")))],
        }
        if include_reason:
            # 추천기사(trend_reads) 전용 — 심층분석을 누르기 전에도 "왜 추천됐는지"와
            # 우선순위 정렬 기준을 보여준다. highlights(국내/해외 전체 목록)는 캡 없이
            # 수백 건이라 여기서 굳이 계산해 페이로드를 불릴 필요가 없어 대상에서 뺀다.
            payload["score"] = importance_score(event)
            payload["reason_bits"] = dashboard_trend_bits(event)
        return payload

    def split_by_region(events, include_reason=False):
        domestic, overseas = [], []
        for event in events:
            bucket = domestic if source_region(event.get("source")) == "domestic" else overseas
            bucket.append(serialize_event(event, include_reason=include_reason))
        return domestic, overseas

    def serialize_card(card):
        details = []
        for detail in card.get("cve_details") or []:
            details.append({
                "id": detail["id"],
                "versions": [{
                    "product": public_text(row.get("product") or ""),
                    "affected": public_text(row.get("affected") or ""),
                    "fixed": public_text(row.get("fixed") or ""),
                    "source": row.get("source") or "",
                    "url": row.get("url") if (row.get("url") or "").startswith(("https://", "http://")) else "",
                } for row in detail["versions"]],
                "fix_status": detail["fix_status"],
                "remediation": public_text(detail["remediation"]),
                "remediation_url": detail["remediation_url"] if detail["remediation_url"].startswith(("https://", "http://")) else "",
                "due_date": detail["due_date"],
                "kev": detail["kev"],
                "exploitation": detail["exploitation"],
                "poc": detail["poc"],
            })
        return {
            "cve": card["cve"],
            "level": card.get("level") or "",
            "sources": [source_label(s) for s in card["sources"]],
            "severity_bits": card_severity_bits(card, include_assets=False),
            "products": card["products"][:CARD_PRODUCTS_MAX],
            "remediation": public_text(card["remediation"]) if card["remediation"] else "",
            "cve_details": details,
            "due_date": card.get("due_date") or "",
            "summary": public_text(card["summary"]),
            "evidence": card.get("evidence") or [],
            "items": [
                {
                    "source_label": source_label(source),
                    "title": item_title,
                    "url": common_utils.tracking_url(item_id, item_url) or "",
                }
                for source, item_title, item_url, item_id in card["items"]
            ],
            # 미리 만들어 둔 이슈 분석 — 대시보드는 클릭 없이 바로 펼쳐 보여준다.
            "issue_analysis": public_text(card.get("issue_analysis") or ""),
        }

    def serialize_campaign(row):
        return campaign_radar.public_row(row)

    # PIR(우선 정보 요구사항) 구분·문항은 대시보드에서 뺀다 — 조직이 무엇을 우선순위로
    # 보는지(예: 특정 산업 표적 위협) 노출되면 자산매칭과 같은 종류의 정보 유출이라
    # pir_groups 인자는 매칭 로직·리포트 계산에는 여전히 쓰이지만(다른 곳은 그대로),
    # 이 함수의 출력에는 반영하지 않는다.

    highlight_domestic, highlight_overseas = split_by_region(highlights)
    trend_domestic, trend_overseas = split_by_region(trend_reads, include_reason=True)

    # 주간 동향(전주 대비 급증)의 "자산 매칭" 그룹은 자사 보유 자산/제품명을 그대로
    # 노출하므로, PIR·자산매칭 정보를 안 담는 것과 같은 원칙으로 공개 대시보드에서 뺀다
    # (위협 행위자·악성코드·ATT&CK 기법·카테고리는 자사 정보가 아니라 그대로 노출해도 됨).
    dashboard_weekly_trends = None
    if weekly_trends:
        dashboard_weekly_trends = {key: value for key, value in weekly_trends.items() if key != "assets"}

    return {
        "title": title,
        "period": period,
        "period_label": period_label,
        "data_status": data_status(period_label, period, stats.get("latest_collected_at") or ""),
        "generated_at": common_utils.utc_now_iso(),
        "narrative": public_narrative(narrative),
        "narrative_basis": "AI 분석 · 출처와 수집 시각은 각 카드 참조",
        "stats": {
            "total": stats["total"],
            "p1": len(stats["p1"]),
            "p2": len(stats["p2"]),
            "info": stats["total"] - len(stats["p1"]) - len(stats["p2"]),
            "info_by_category": dict(
                (c, n) for c, n in stats["info_by_category"].most_common() if c != "미분류"
            ),
            # 메인 화면의 "분류 보기"는 P1/P2를 제외하지 않은 전체 이벤트 모수를 사용한다.
            # info_by_category를 재사용하면 긴급·주의 항목이 분류에서 빠져 합계가 436건과
            # 맞지 않으므로 별도 필드로 공개한다.
            "category_counts": dict((stats.get("by_category") or Counter()).most_common()),
            # 대시보드 상단 타일은 이 값을 우선 쓴다(없는 옛 파일은 info_by_category로 폴백).
            # P1/P2 타일과 중복 계산되지 않도록 info_by_category와 같은 모수를 쓴다.
            "actionable": len(stats.get("actionable") or []),
            "actionable_by_category": dict(stats.get("actionable_by_category") or {}),
            "actionable_info_by_category": dict(
                (c, n) for c, n in (stats.get("actionable_info_by_category") or Counter()).most_common()
                if c != "미분류"
            ),
            "by_source": dict(stats["by_source"].most_common()),
            "top_actors": stats.get("top_actors") or [],
            "top_malware": stats.get("top_malware") or [],
            "top_cves": stats.get("top_cves") or [],
        },
        # 신규 공격 캠페인 — 추천기사 탭 최상단에 별도 카드로 노출한다. 추천기사와는
        # 후보군이 거의 겹치지 않는다(실측 3%): 추천기사는 알림 문턱을 못 넘은 기사를
        # 뽑고, 이쪽은 새로 등장한 캠페인이라 대개 P1/P2로 이미 알림된 건들이다.
        "campaigns": [serialize_campaign(row) for row in (campaigns or [])],
        "cards": [serialize_card(card) for card in cards],
        # CVE 탭 아래쪽 "수집된 CVE" — 카드(복수 소스 교차)에 들지 못한 CVE까지 전부.
        "cve_items": cve_items or [],
        "domestic": {"highlights": highlight_domestic, "trend_reads": trend_domestic},
        "overseas": {"highlights": highlight_overseas, "trend_reads": trend_overseas},
        "keywords": keywords or [],
        "weekly_trends": dashboard_weekly_trends,
    }


def main():
    parser = argparse.ArgumentParser(description="일간/주간 보안 인텔리전스 리포트 생성")
    parser.add_argument("--period", choices=["daily", "weekly"], default="daily")
    parser.add_argument("--days", type=int, default=None, help="집계 기간 직접 지정(테스트용)")
    parser.add_argument("--dry-run", action="store_true", help="발송하지 않고 콘솔에 출력")
    # 데이터가 잘못 실린 것을 고친 뒤 대시보드만 다시 만들어야 할 때가 있다. --dry-run은
    # 발행까지 건너뛰어서 쓸 수 없고, 그렇다고 그냥 돌리면 같은 리포트가 메일·슬랙으로
    # 두 번 나간다.
    parser.add_argument("--no-send", action="store_true",
                        help="메일·슬랙은 보내지 않고 대시보드만 갱신한다")
    args = parser.parse_args()

    if args.period == "daily":
        days = args.days or 1
        title = "일간 보안 인텔리전스 리포트"
    else:
        days = args.days or 7
        title = "주간 보안 인텔리전스 리포트"

    since, now = report_window(days)
    period_label = "{} ~ {} (UTC)".format(since.strftime("%Y-%m-%d %H:%M"), now.strftime("%Y-%m-%d %H:%M"))

    events = load_events_between(since, now)
    if not events:
        print("기간 내 수집된 이벤트가 없어 리포트를 생성하지 않습니다.")
        return

    stats = build_stats(events)

    # 주간 리포트 전용: 전주(같은 길이의 직전 구간)와 비교해 급증한 위협 행위자/
    # 악성코드/ATT&CK 기법/자산매칭을 뽑는다. 일간은 비교 기준(전날 하루)이 표본이
    # 너무 적어 의미가 없으므로 주간에서만 계산한다.
    weekly_trends = None
    if args.period == "weekly":
        previous_events = load_events_between(since - timedelta(days=days), since)
        weekly_trends = compute_weekly_trends(events, previous_events)

    # CVE 크로스소스 상관관계: 복수 소스 등장 CVE는 카드로 병합하고,
    # 카드에 포함된 이벤트는 개별 TOP 목록에서 제외해 중복 표시를 막는다
    cards = correlate_by_cve(events)
    enrich_cards_with_github_poc(cards[:MAX_CVE_CARDS])  # 이메일/슬랙 상위 카드에만 API 호출(비용 절약)
    # 이슈 분석은 주간에만 붙인다 — 일간 카드는 기사가 평균 2.2건(3건 이상이 15%)이라
    # 종합할 이점이 거의 없고, 주간은 평균 2.6건에 3건 이상이 33%다.
    if args.period == "weekly":
        enrich_cards_with_issue_analysis(cards, events)
    shown_card_event_ids = set()
    for card in cards:  # 대시보드는 카드를 전부 보여주므로, 카드로 이미 다루는 이벤트는 전부 제외해야 중복이 없다
        shown_card_event_ids.update(card["event_ids"])
    filtered_events = [
        event for event in events
        if event.get("id") not in shown_card_event_ids
        and (event.get("source") or "") not in NON_NEWS_SOURCES
    ]
    highlights = top_items(filtered_events)
    # 대시보드 국내/해외 탭용 — 이메일과 달리 top-10 캡이 없다. 국제 P1이 많은 날에도
    # 국내 기사가 순위 경쟁에서 밀려 탭이 통째로 비는 일이 없도록 그 기간 전체를 담는다.
    all_highlights = sorted(filtered_events, key=event_sort_key)
    pir_groups = group_by_pir(events)
    highlight_ids = {event.get("id") for event in highlights}
    trend_reads = pick_trend_reads(events, shown_card_event_ids | highlight_ids)
    # 대시보드 추천기사 탭용 — 이메일과 달리 MAX_TREND_ITEMS(5) 캡이 없다. 제외 기준은
    # (대시보드용 전체 하이라이트가 아니라) 이메일과 같은 작은 highlight_ids를 그대로
    # 쓴다 — 대시보드 국내/해외 탭이 이미 그 기간 전체를 보여주는 아카이브가 된 이상,
    # "추천기사"와 일부 겹치는 건 자연스럽다(오히려 all_highlights 기준으로 제외하면
    # 후보 풀이 거의 안 남아 추천기사가 텅 비어버린다).
    # include_alerted=True — curator_digest.py와 동일하게, 이미 알림이 나간(P1/P2 등)
    # 기사도 인사이트 신호가 있으면 추천 후보에 포함한다. 여기서 빼면 "알림 안 된
    # 것들 중에서만" 추천기사가 뽑혀서, 그날 진짜 중요했던 기사가 오히려 대시보드
    # 추천기사 탭에서 배제되는 역설이 생긴다 — 하루치 "진짜 추천할 만한 것"을
    # 보여주는 게 목적이므로 알림 여부와 무관하게 뽑아야 한다.
    all_trend_reads = pick_trend_reads(
        events, shown_card_event_ids | highlight_ids, max_items=len(events),
        include_alerted=True, rank_by_importance=True,
    )

    print("[*] 이벤트 {}건 집계 완료 (CVE 상관관계 카드 {}건, PIR {}종). AI 해석 생성 중...".format(
        stats["total"], len(cards), len(pir_groups)
    ))
    digest = build_digest(period_label, stats, events, cards)
    narrative, keywords = ai_narrative(period_label, digest, period=args.period)
    if not narrative:
        narrative = "(AI 해석을 생성하지 못해 통계 요약만 제공합니다.)"
        # 실패해도 메일·슬랙은 나가므로, 리포트를 열어보기 전에는 알 수 없었다.
        print("[-] AI 해석 생성 실패 — 통계 요약만으로 발송합니다({} 리포트).".format(args.period))
    if not keywords:
        keywords = fallback_keywords(stats, cards)

    text_body = build_text_report(
        title, period_label, stats, narrative, highlights, cards, pir_groups, trend_reads,
        weekly_trends=weekly_trends,
    )
    html_body = build_html_report(
        title, period_label, stats, narrative, highlights, cards, pir_groups, trend_reads,
        weekly_trends=weekly_trends,
    )
    blocks = build_slack_blocks(
        title, period_label, stats, narrative, highlights, cards, pir_groups, trend_reads,
        weekly_trends=weekly_trends,
    )

    if args.dry_run:
        print("===== DRY RUN: 발송 생략 =====")
        print(text_body)
        return

    subject = "[{}] {} - {}건".format("일간" if args.period == "daily" else "주간", title, stats["total"])
    if args.no_send:
        print("[*] --no-send: 메일·슬랙 발송을 건너뛰고 대시보드만 갱신합니다.")
    else:
        email_sent = common_utils.send_email_message(subject, text_body, html_body)

        payload = {"text": subject, "blocks": blocks}
        webhook_url = os.environ.get("SLACK_WEBHOOK_REPORT") or common_utils.SLACK_WEBHOOK_URL
        slack_sent = common_utils.send_slack_webhook(payload, webhook_url)

        print("리포트 발송 결과: email={}, slack={}".format(email_sent, slack_sent))

    # 신규 공격 캠페인 탐지 — 최초 등장일을 알아야 해서 코퍼스 전체를 훑는다.
    # 실패해도 리포트 본체를 막지 않는다(부가 섹션이다).
    try:
        campaigns = campaign_radar.detect()
        if campaigns:
            print("[+] 신규 공격 캠페인 {}건 탐지: {}".format(
                len(campaigns), ", ".join(c["names"][0] for c in campaigns)))
            # 공격 동향에 오른 건 이미 여러 문턱을 통과한 것이라, 사람이 누르기를
            # 기다리지 않고 바로 심층분석을 건다. 같은 캠페인을 두 번 걸지는 않는다.
            campaign_radar.queue_deep_analysis(campaigns)
    except Exception as error:
        print("[-] 신규 공격 캠페인 탐지 실패(리포트에는 영향 없음): {}".format(error))
        campaigns = []

    try:
        dashboard_narrative = ai_public_narrative(period_label, stats, cards)
    except Exception as error:
        # AI 요약이 실패해도 최신 수집 데이터는 발행한다. 공개 페이로드가 빈 요약을
        # 누락 상태로 표시하면 대시보드에서 해당 기간의 요약만 다시 생성할 수 있다.
        print("[-] 공개 AI 요약 생성 실패 — 누락 상태로 대시보드를 발행합니다: {}".format(error))
        dashboard_narrative = ""
    dashboard_payload = build_dashboard_payload(
        title, args.period, period_label, stats, dashboard_narrative, all_highlights, cards, all_trend_reads, keywords,
        weekly_trends=weekly_trends, campaigns=campaigns, cve_items=build_cve_items(events, cards),
    )
    publish_web_dashboard.publish(dashboard_payload)


if __name__ == "__main__":
    main()
