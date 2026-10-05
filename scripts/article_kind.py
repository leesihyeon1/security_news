# -*- coding: utf-8 -*-
"""기사가 "공격 사건"인지 "정보성"인지 가른다 — 조사 경로를 가르는 단일 스위치.

왜 필요한가
    정보성 기사(정책·사업 발표·동향)가 공격형 조사를 통째로 받았다. 실측(2026-09-30,
    "LG U+, IBCT와 … 카테나-X 지원"): 제목의 "공급망" 한 단어로 패키지 레지스트리
    조사가 켜졌고, 회사 이름을 (malware OR APT …)로 감싼 검색이 APT IOC 모음을
    "1차 자료"로 읽었으며, 한글 브랜드명을 명령줄에서 찾는 KQL과 "미달" 판정이 붙었다.
    targets["investigable"]=False가 이미 있었지만 트랙이 하나도 없을 때만 읽혀서
    아무것도 막지 못했다.

왜 한 가지 신호로 가르지 않나
    - investigable=False만 보면 진짜 위협을 끈다. 저장된 79건 중 False 7건에서 4건
      (김수키 KCSCON, Fire Ant, CLOSEDQUORUM, BigCommerce)은 IOC 없이 TTP로 헌팅해야
      하는 실제 위협이었고, 정보성인 "Zero Trust for AI Agents"는 True였다.
    - 분류만 보면 기술동향으로 분류된 위협(DUSTMAKER 프롬프트 인젝션, Check Point
      주간 위협 리포트)을 놓친다.
    그래서 공격 지표(CVE·해시·악성코드·패키지·알려진 위협 그룹)가 하나라도 있으면
    보통 위협으로 둔다. 단, 원문이 여러 전술과 서로 다른 분모의 통계를 비교하고
    구체적 CVE·해시가 없다면 개별 악성코드 이름이 있어도 복수 전술 동향으로 둔다.
    키가 없으면 위협으로 본다 — 기존 레코드·테스트는 모두 예전 경로를 그대로 탄다.

네트워크·LLM을 부르지 않는 순수 함수만 둔다.
"""

import re

THREAT_CATEGORIES = frozenset({"취약점", "악성코드", "침해사고", "개인정보유출", "공격캠페인",
                               "공급망공격", "피싱사기"})
INFO_CATEGORIES = frozenset({"정책규제", "기술동향", "제품행사", "기타"})
INFORMATIONAL = "informational"
THREAT = "threat"
KINDS = (INFORMATIONAL, THREAT)

# 화면(route.label)에 그대로 나가는 우리말 라벨.
SUBTYPE_BY_CATEGORY = {"정책규제": "정책·규제", "제품행사": "제품·사업 발표",
                       "기술동향": "기술·동향", "기타": "일반"}
SUBTYPE_REPORT = "통계·보고서"
SUBTYPE_TACTIC_OVERVIEW = "복수 전술 동향"
SUBTYPE_GENERAL = "일반"

# 이 칸에 값이 있으면 조회할 공격 지표가 있는 기사다. 행위자·제품은 넣지 않는다 —
# 실측(카테나-X): 모델이 협력사·완성차 회사를 행위자 칸에, 발표 대상 플랫폼을 제품
# 칸에 넣었다. 위협 그룹 이름은 원문 대조(threat_substance)가 따로 잡는다.
HARD_TARGET_FIELDS = (("cves", "CVE"), ("hashes", "해시"), ("malware", "악성코드 이름"),
                      ("packages", "패키지"))
HARD_IOC_TYPES = {"cve": "CVE 지표", "md5": "해시 지표", "sha1": "해시 지표",
                  "sha256": "해시 지표"}
# 위협 분류가 붙었는데 정보성으로 선언된 기사는 대개 통계·동향 보고서다(실측: 상반기
# 침해사고 통계가 "침해사고", 클라우드 설정 오류 지수 보고서가 "취약점"으로 분류됐다).
REPORT_RE = re.compile(r"통계|보고서|리포트|설문|조사 결과|실태|현황|지수|백서|"
                       r"\breport\b|\bsurvey\b|statistic|\bindex\b", re.I)
TACTIC_FAMILIES = (
    re.compile(r"\bRMM\b|remote monitoring and management|원격 관리", re.I),
    re.compile(r"mailbox|메일함|inbox rule", re.I),
    re.compile(r"\bAiTM\b|adversary.in.the.middle|중간자", re.I),
    re.compile(r"device.code|디바이스 코드|장치 코드", re.I),
    re.compile(r"ClickFix|클릭픽스", re.I),
    re.compile(r"FakeAgent|가짜 에이전트", re.I),
)
AGGREGATE_RE = re.compile(r"\brank(?:ed|ing)?\b|\btactics?\b|\btrend\b|"
                          r"분석 결과|전술|동향|증가율|분기|통계|보고서|리포트", re.I)
ARTICLE_INDICATOR_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b|\b[a-f0-9]{32}\b|"
                                  r"\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.I)


def is_tactic_overview(title, article):
    """여러 독립 전술의 수치를 비교하는 기사만 단일 사건 경로에서 제외한다."""
    source = "\n".join((title or "", article or ""))
    return (bool(AGGREGATE_RE.search(source))
            and len(re.findall(r"\b\d+(?:\.\d+)?\s*%", source)) >= 2
            and sum(bool(pattern.search(source)) for pattern in TACTIC_FAMILIES) >= 3
            and not ARTICLE_INDICATOR_RE.search(source))


def _values(targets, key):
    value = (targets or {}).get(key)
    if isinstance(value, (list, tuple)):
        return [item for item in value if str(item or "").strip()]
    return [value] if isinstance(value, str) and value.strip() else []


def declared(targets):
    """분석 단계가 [조사 대상]의 기사유형 줄로 선언한 값. 없거나 모르면 ""."""
    value = str((targets or {}).get("article_type_declared") or "").strip().lower()
    return value if value in KINDS else ""


def subtype_for(category):
    """정보성 분류의 화면 라벨. 위협 분류·빈 값이면 ""."""
    return SUBTYPE_BY_CATEGORY.get((category or "").strip(), "")


def _hard_signals(targets, iocs, threat_substance):
    signals = []
    if threat_substance:
        signals.append("CVE·해시·위협 그룹 이름 대조")
    for key, label in HARD_TARGET_FIELDS:
        count = len(_values(targets, key))
        if count:
            signals.append("{} {}건".format(label, count))
    counts = {}
    for item in iocs or []:
        label = HARD_IOC_TYPES.get(str((item or {}).get("type") or "").lower())
        if label:
            counts[label] = counts.get(label, 0) + 1
    signals.extend("{} {}건".format(label, count) for label, count in counts.items())
    return signals


def _informational_subtype(category, targets, text):
    subtype = subtype_for(category)
    if subtype:
        return subtype
    haystack = " ".join([text or "", str((targets or {}).get("reason") or "")])
    return SUBTYPE_REPORT if REPORT_RE.search(haystack) else SUBTYPE_GENERAL


def classify(category, targets, iocs, threat_substance=False, text="", article=""):
    """{"kind", "subtype", "reason", "signals"}.

    text(제목+분석문)는 선택이다 — 위협 분류인데 정보성으로 선언된 기사가 통계·보고서
    인지 가를 때만 쓴다.
    """
    category = (category or "").strip()
    targets = targets if isinstance(targets, dict) else {}
    hard = _hard_signals(targets, iocs, threat_substance)
    said = declared(targets)
    signals = list(hard)
    if category:
        signals.append("분류: {}".format(category))
    if said:
        signals.append("기사유형 선언: {}".format("정보성" if said == INFORMATIONAL else "위협사건"))

    if is_tactic_overview(text, article):
        signals.append("복수 전술과 통계 수치가 기사 원문에 있음")
        return {"kind": INFORMATIONAL, "subtype": SUBTYPE_TACTIC_OVERVIEW,
                "signals": signals,
                "reason": "독립적인 여러 공격 전술을 비교한 동향 기사로, 단일 캠페인의 침해사고로 합치지 않습니다."}

    # 그 외 공격 지표가 있으면 위협이다. 선언·분류보다 먼저 본다.
    if hard:
        return {"kind": THREAT, "subtype": "", "signals": signals,
                "reason": "원문에서 공격 지표({})를 확인해 위협 사건 기사로 판단했습니다.".format(
                    ", ".join(hard))}

    no_indicator = "공격 사건·취약점·악성코드 지표가 없고"
    if said == INFORMATIONAL:
        subtype = _informational_subtype(category, targets, text)
        if category in THREAT_CATEGORIES:
            reason = ("{}, 기사 분류({})는 위협 범주지만 분석 단계가 특정 공격 사건이 아닌 "
                      "정보성 기사({})로 판단했습니다.".format(no_indicator, category, subtype))
        elif category:
            reason = "{}, 기사 분류({})도 정보성 범주이며 분석 단계가 정보성 기사로 판단했습니다.".format(
                no_indicator, category)
        else:
            reason = "{}, 분석 단계가 정보성 기사로 판단했습니다.".format(no_indicator)
        return {"kind": INFORMATIONAL, "subtype": subtype, "reason": reason, "signals": signals}

    if said == THREAT:
        reason = ("원문에서 조회할 공격 지표는 찾지 못했지만 분석 단계가 위협 사건 기사로 "
                  "판단했습니다.")
        return {"kind": THREAT, "subtype": "", "reason": reason, "signals": signals}

    if category in INFO_CATEGORIES:
        return {"kind": INFORMATIONAL, "subtype": _informational_subtype(category, targets, text),
                "signals": signals,
                "reason": "{}, 기사 분류({})가 정보성 범주여서 정보성 기사로 판단했습니다.".format(
                    no_indicator, category)}
    if category:
        reason = "기사 분류({})가 위협 범주여서 위협 사건 기사로 판단했습니다.".format(category)
    else:
        reason = "기사 분류와 기사유형 선언이 없어 기존처럼 위협 사건 기사로 다룹니다."
    return {"kind": THREAT, "subtype": "", "reason": reason, "signals": signals}


def is_informational(targets_or_block):
    """targets dict 또는 조사 블록을 받는다. 키가 없으면 위협(False)."""
    if not isinstance(targets_or_block, dict):
        return False
    if targets_or_block.get("article_kind") == INFORMATIONAL:
        return True
    nested = targets_or_block.get("targets")
    return isinstance(nested, dict) and nested.get("article_kind") == INFORMATIONAL
