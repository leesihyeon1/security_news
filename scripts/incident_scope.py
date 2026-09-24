# -*- coding: utf-8 -*-
"""종합 기사를 사건별로 나눈다 — investigation.build_for_article()의 입력 준비 단계.

왜 필요한가
    analysis_targets.parse()는 "사건구분"이 둘 이상이면 각 값(도메인·해시·행위자
    등)과 목표·확인질문·성공기준·부족한것·주력을 사건 번호로 태깅해 돌려준다
    (incident_map, *_by_incident). 이 모듈은 그 태깅을 읽어 사건마다 독립된
    targets/iocs 묶음으로 쪼갠다 — investigation.build_for_article()이 사건마다
    investigation.build()를 한 번씩 따로 불러, 서로 다른 사건의 IOC·서술이 한 판단
    코퍼스에 섞이는 일(response_synth._corpus()가 사건 구분 없이 전체를 이어붙이는
    문제)을 구조적으로 막는다.

무엇을 하지 않나
    사건이 하나(대다수 기사)면 아무것도 하지 않는다 — 원본 targets/iocs를 그대로
    담은 사건 1개짜리 목록만 돌려준다. investigation.build_for_article()은 이때
    기존 investigation.build()를 그대로 한 번 부르므로, 단일 사건 기사는 오늘과
    똑같은 코드 경로를 탄다.
"""

FIELD_TO_IOC_TYPES = {
    "domains": ("domain",),
    "ips": ("ipv4", "ip"),
    "hashes": ("sha256", "sha1", "md5"),
    "urls": ("url",),
    "cves": ("cve",),
}
IOC_TYPE_TO_FIELD = {ioc_type: field for field, ioc_types in FIELD_TO_IOC_TYPES.items()
                     for ioc_type in ioc_types}

# 인시던트 수가 너무 많으면 사건마다 VT·urlscan·NVD를 따로 도는 비용이 사건 수에
# 비례해 늘어난다. 모델이 과분할하는 경우를 막는 상한.
MAX_INCIDENTS_PER_ARTICLE = 4

TARGET_FIELDS = ("domains", "ips", "hashes", "urls", "cves", "products", "packages",
                 "actors", "malware", "files", "paths", "registry", "commands")


def _label(incidents, index):
    if 1 <= index <= len(incidents):
        return incidents[index - 1]
    return "사건 {}".format(index)


def _incident_numbers_for(incident_map, field, value):
    return (incident_map.get(field) or {}).get(str(value or "").strip().lower()) or [1]


def _split_targets(targets, incidents, incident_map):
    """사건별 targets dict 목록. 태그 없는 값은 사건 1로 폴백한다."""
    count = min(len(incidents), MAX_INCIDENTS_PER_ARTICLE)
    per_incident = [dict() for _ in range(count)]

    for field in TARGET_FIELDS:
        values = targets.get(field) or []
        for value in values:
            for number in _incident_numbers_for(incident_map, field, value):
                if 1 <= number <= count:
                    per_incident[number - 1].setdefault(field, []).append(value)

    objectives = targets.get("objectives_by_incident") or {}
    questions = targets.get("questions_by_incident") or {}
    criteria = targets.get("criteria_by_incident") or {}
    gaps = targets.get("gaps_by_incident") or {}
    primaries = targets.get("primary_by_incident") or {}

    out = []
    for index in range(1, count + 1):
        slot = per_incident[index - 1]
        slot["investigable"] = targets.get("investigable", True)
        if targets.get("reason"):
            slot["reason"] = targets["reason"]
        # 사건별 번호 줄이 있으면 그걸 쓰고, 모델이 빼먹었으면(부분 준수) 기사
        # 전체의 공유 값으로 대체한다 — 조용히 비우는 것보다 낫다.
        slot["objective"] = objectives.get(index) or targets.get("objective") or ""
        slot["questions"] = questions.get(index) or targets.get("questions") or []
        slot["criteria"] = criteria.get(index) or targets.get("criteria") or []
        slot["gaps"] = gaps.get(index) or targets.get("gaps") or []
        primary = primaries.get(index) or targets.get("primary") or ""
        if primary:
            slot["primary"] = primary
        investigable = slot["investigable"]
        slot = {key: value for key, value in slot.items() if value not in (None, [], "")}
        slot["investigable"] = investigable
        out.append(slot)
    return out


def _split_iocs(iocs, incidents, incident_map):
    count = min(len(incidents), MAX_INCIDENTS_PER_ARTICLE)
    per_incident = [[] for _ in range(count)]
    for item in iocs or []:
        field = IOC_TYPE_TO_FIELD.get(str(item.get("type") or "").lower())
        numbers = _incident_numbers_for(incident_map, field, item.get("value")) if field else [1]
        for number in numbers:
            if 1 <= number <= count:
                per_incident[number - 1].append(item)
    return per_incident


def split(targets, iocs):
    """(targets, iocs) -> [{"incident_id","label","targets","iocs"}, ...].

    사건이 하나면(대다수) 원본을 그대로 담은 길이 1 목록 — investigation.
    build_for_article()이 이걸 받으면 기존 build()를 신규 인자 없이 그대로 부른다.
    """
    targets = targets or {}
    incidents = (targets.get("incidents") or [])[:MAX_INCIDENTS_PER_ARTICLE]
    if len(incidents) < 2:
        return [{"incident_id": "1", "label": "", "targets": targets, "iocs": iocs or []}]

    incident_map = targets.get("incident_map") or {}
    target_slices = _split_targets(targets, incidents, incident_map)
    ioc_slices = _split_iocs(iocs, incidents, incident_map)
    return [
        {"incident_id": str(index), "label": _label(incidents, index),
         "targets": target_slices[index - 1], "iocs": ioc_slices[index - 1]}
        for index in range(1, len(incidents) + 1)
    ]
