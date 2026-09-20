# -*- coding: utf-8 -*-
"""무엇을 조회할지 목표를 보고 정한다.

무엇이 빠져 있었나
    조회 대상은 지표의 종류로만 정해졌다 — 해시가 있으면 VirusTotal, 도메인이 있으면
    urlscan. 그래서 목표와 무관한 조회가 돌고, 목표에 필요한데 지표 종류가 안 맞으면
    아예 안 돌았다. 분석가는 "이 건에서 무엇을 확인해야 하는가"를 먼저 정하고 거기
    맞는 도구를 고른다.

무엇을 고를 수 있나
    우리가 가진 조회만 고른다. 없는 도구를 계획에 넣어도 실행할 방법이 없고, 그걸
    허용하면 "Shodan으로 노출을 확인한다" 같은 실행 불가능한 계획이 나온다. 그래서
    카탈로그를 프롬프트에 그대로 주고 그 안에서만 고르게 한다.

    입력이 없는 조회는 골라도 실행하지 않는다. 해시가 한 건도 없는데 VirusTotal을
    고르는 것은 계획이 아니라 희망이다.

실패하면
    규칙 판정(classify)이 정한 트랙을 그대로 쓴다. 계획이 없어도 조회는 돌아야 한다.
"""

import json
import re

import common_utils

# 계획 출력은 짧다 — 길게 쓰라고 하면 이유가 장황해지고 판단에 도움이 안 된다.
MAX_REASON_CHARS = 120

PROMPT = """당신은 SOC 대응 책임자다. 이 건의 대응 목표와 확보된 지표를 보고, 아래 조회
목록 중 무엇을 돌릴지 정하라.

지켜야 할 것:
- 목록에 없는 도구를 만들지 마라. 우리가 실행할 수 있는 것은 목록에 있는 것뿐이다.
- 입력이 "없음"인 조회는 고르지 마라. 돌릴 수 없다.
- 목표 달성에 도움이 안 되는 조회는 skip에 넣고 이유를 적어라. 시간이 드는 작업이라
  전부 돌리는 것이 좋은 것은 아니다.
- run은 먼저 볼 것부터 순서대로 적어라.

[출력 형식 — JSON 하나만. 설명 문장을 앞뒤에 붙이지 마라]
{
  "run": [{"key": "조회 키", "why": "이 목표에 왜 필요한가(한 문장)"}],
  "skip": [{"key": "조회 키", "why": "왜 안 하는가(한 문장)"}]
}
"""


def log(message):
    print(message)


def _availability(route, targets):
    """조회별로 입력이 있는지. 프롬프트에 그대로 넣어 "돌릴 수 없는 것"을 알려 준다."""
    targets = targets or {}
    hashes = route.get("hashes") or []
    domains = route.get("domains") or []
    cves = route.get("cves") or []
    products = route.get("products") or []
    packages = targets.get("packages") or []
    registries = "supply_chain" in (route.get("tracks") or [])
    return {
        "user_action": "도메인 {}건".format(len(domains)) if domains else "없음",
        "malware": "파일 해시 {}건".format(len(hashes)) if hashes else "없음",
        "vulnerability": ("CVE {}건 · 제품 {}건".format(len(cves), len(products))
                          if (cves or products) else "없음"),
        "supply_chain": ("레지스트리 언급 있음{}".format(
            " · 패키지 {}건".format(len(packages)) if packages else "")
            if registries else "없음"),
        # 아래 셋을 빼놓아서 계획에는 늘 "없음"으로 보였고, 모델이 고를 수 없었다.
        # 트랙이 성립했다는 것 자체가 입력이 있다는 뜻이므로 그것으로 판단한다.
        "github": ("저장소 주소 있음" if "github" in (route.get("tracks") or [])
                   else "없음"),
        "extension": ("확장 프로그램 ID 있음" if "extension" in (route.get("tracks") or [])
                      else "없음"),
        "intel": ("도메인·IP·해시 있음" if "intel" in (route.get("tracks") or [])
                  else "없음"),
        "web": ("검색할 이름 있음" if "web" in (route.get("tracks") or []) else "없음"),
    }


def build_prompt(objective, questions, catalog, availability):
    lines = []
    for item in catalog:
        lines.append("- {} ({}): {} 조회. 지금 입력 = {}".format(
            item["key"], item["label"], item.get("consumes") or "",
            availability.get(item["key"], "없음")))
    return (
        PROMPT
        + "\n[대응 목표]\n" + (objective or "(설정되지 않음)")
        + ("\n\n[확인해야 할 질문]\n" + "\n".join("- " + q for q in questions)
           if questions else "")
        + "\n\n[쓸 수 있는 조회]\n" + "\n".join(lines)
        + "\n\nJSON만 출력하라."
    )


def parse(raw):
    if not raw:
        return {}
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def plan(objective, questions, catalog, route, targets=None, timeout=120):
    """돌릴 조회를 정한다.

    반환: {"tracks": [실행할 키], "reasons": {키: 이유}, "skipped": [{key, why}],
           "steps": [조사 과정에 남길 줄]}
    계획을 못 세우면 tracks는 규칙 판정 결과 그대로다.
    """
    fallback = list(route.get("tracks") or [])
    availability = _availability(route, targets)
    runnable = {item["key"] for item in catalog if availability.get(item["key"]) != "없음"}

    raw = common_utils.llm_generate(
        build_prompt(objective, questions, catalog, availability),
        timeout=timeout, json_format=True)
    data = parse(raw)
    if not data:
        return {"tracks": fallback, "reasons": {}, "skipped": [],
                "steps": ["조회 계획을 세우지 못해 지표 종류로 정한 조회를 그대로 돌립니다."]}

    keys = {item["key"] for item in catalog}
    tracks, reasons, dropped = [], {}, []
    for item in data.get("run") or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if key not in keys:
            dropped.append("없는 조회 이름: {}".format(key[:24]))
            continue
        if key not in runnable:
            # 입력이 없는데 고른 것 — 계획이 아니라 희망이다.
            dropped.append("{}는 입력이 없어 돌릴 수 없습니다".format(key))
            continue
        if key not in tracks:
            tracks.append(key)
            reasons[key] = " ".join(str(item.get("why") or "").split())[:MAX_REASON_CHARS]

    skipped = []
    for item in data.get("skip") or []:
        if isinstance(item, dict) and str(item.get("key") or "") in keys:
            skipped.append({"key": item["key"],
                            "why": " ".join(str(item.get("why") or "").split())[:MAX_REASON_CHARS]})

    if not tracks:
        return {"tracks": fallback, "reasons": {}, "skipped": skipped,
                "steps": ["조회 계획이 실행 가능한 조회를 하나도 고르지 않아, 지표 종류로 "
                          "정한 조회를 그대로 돌립니다."]}

    steps = ["대응 목표에 맞춰 조회 {}건을 골랐습니다: {}.".format(
        len(tracks), ", ".join(tracks))]
    for key in tracks:
        if reasons.get(key):
            steps.append("· {}: {}".format(key, reasons[key]))
    for item in skipped:
        # 입력이 없어 애초에 돌릴 수 없는 것은 계획에 적지 않는다 — 판단이 아니라
        # 사실이고, 그런 줄이 계획의 절반을 차지하면 정작 고른 이유가 안 읽힌다.
        if item["key"] not in runnable:
            continue
        steps.append("· 건너뜀 {}: {}".format(item["key"], item["why"]))
    for reason in dropped[:3]:
        steps.append("· 계획에서 제외: {}".format(reason))
    return {"tracks": tracks, "reasons": reasons, "skipped": skipped, "steps": steps}
