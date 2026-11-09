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
import analysis_trace

import common_utils
import browser_research

# 계획 출력은 짧다 — 길게 쓰라고 하면 이유가 장황해지고 판단에 도움이 안 된다.
MAX_REASON_CHARS = 120


def _question_keys(question, tracks, runnable):
    """Map one investigation goal to the evidence-producing lookups it needs."""
    question = str(question or "")
    selected = []
    if browser_research.is_web_question(question) and "user_action" in tracks:
        selected.append("user_action")
    if re.search(r"동적|샌드박스|샘플|C2|통신|지속성|지속화|예약.?작업|RAT|AMSI|ntdll|레지스트리", question, re.I):
        if "malware" in tracks:
            selected.append("malware")
    if re.search(r"CVE|취약점|패치|안전.?버전", question, re.I) and "vulnerability" in tracks:
        selected.append("vulnerability")
    if re.search(r"패키지|npm|공급망|레지스트리", question, re.I) and "supply_chain" in tracks:
        selected.append("supply_chain")
    if not selected:
        selected = [key for key in ("intel", "web") if key in tracks and key in runnable][:1]
    return list(dict.fromkeys(selected))


def _question_reason(question, key):
    labels = {
        "user_action": "개별 URL의 DOM·HTTP·리다이렉트를 확인합니다.",
        "malware": "선정 샘플의 프로세스·지속성·네트워크 행위를 확인합니다.",
        "vulnerability": "공식 취약점·패치 정보를 대조합니다.",
        "supply_chain": "레지스트리·권고 데이터에서 패키지 상태를 대조합니다.",
        "intel": "동일 지표의 독립 인텔리전스 관측을 대조합니다.",
        "web": "원문과 공개 자료에서 확인 가능한 근거를 수집합니다.",
    }
    return labels.get(key, "이 목표에 필요한 외부 관측을 수집합니다.")


def build_task_graph(objective, questions, tracks, runnable, question_lookups=None):
    """Make the investigation ledger explicit: goal, evidence, and next action."""
    planned = {row.get("question"): row.get("lookups") or []
               for row in question_lookups or [] if isinstance(row, dict)}
    tasks = []
    for index, question in enumerate(questions or [], 1):
        allowed = _question_keys(question, tracks, runnable)
        keys = [str(row.get("key")) for row in planned.get(question, [])
                if isinstance(row, dict) and row.get("key") in allowed]
        keys = list(dict.fromkeys(keys or allowed))
        tasks.append({
            "id": "goal-{}".format(index), "goal": str(question),
            "objective": objective or "", "lookup_keys": keys,
            "expected_evidence": "질문에 포함된 주장을 직접 입증하는 관측값",
            "status": "planned", "next_if_missing": "입력 URL·해시를 먼저 확보한 뒤 해당 조회를 재실행",
            "why": ", ".join(_question_reason(question, key) for key in keys) or
                   "현재 실행 가능한 조회가 없어 원문 근거와 미확인 상태를 보존합니다.",
        })
    return tasks


def reconcile_task_graph(tasks, block):
    """Update the ledger from evidence, without treating a successful API call as proof."""
    block = block or {}
    checks = {row.get("question"): row for row in block.get("goal_evidence") or []}
    statuses = {row.get("key"): row.get("status") for row in block.get("lookup_status") or []}
    for task in tasks or []:
        check = checks.get(task.get("goal")) or {}
        task["status"] = check.get("status") or task.get("status") or "planned"
        task["evidence_basis"] = check.get("basis") or "목표별 근거 검증 대기"
        task["missing"] = check.get("missing") or ""
        task["executions"] = [{"key": key, "status": statuses.get(key, "not_recorded")}
                              for key in task.get("lookup_keys") or []]
        if task["status"] != "answered":
            task["next_if_missing"] = task["missing"] or task["next_if_missing"]
    return tasks

PROMPT = """당신은 SOC 대응 책임자다. 이 건의 대응 목표와 확보된 지표를 보고, 아래 조회
목록 중 무엇을 돌릴지 정하라.

지켜야 할 것:
- 목록에 없는 도구를 만들지 마라. 우리가 실행할 수 있는 것은 목록에 있는 것뿐이다.
- 입력이 "없음"인 조회는 고르지 마라. 돌릴 수 없다.
- 목표 달성에 도움이 안 되는 조회는 skip에 넣고 이유를 적어라. 시간이 드는 작업이라
  전부 돌리는 것이 좋은 것은 아니다.
- run은 먼저 볼 것부터 순서대로 적어라.
- 아래 사건 근거에 있는 지표의 역할을 지켜라. 정찰 대상·피해 서비스는 유출지나 C2가 아니다.
- hashes는 동적 분석에서 먼저 비교할 샘플 최대 2개다. 버전별 기능·실행 조건 차이를
  확인할 대표 샘플을 고르되 [확보된 해시]의 값만 사용하라.
- question_lookups는 각 [확인해야 할 질문]에 실제로 고른 run 조회를 연결한다.
  질문 문장을 그대로 쓰고, lookups의 key는 run에 있는 값만 쓴다. 조회로 답할 수 없는
  질문은 빈 배열로 두고 조회를 지어내지 마라. why에는 그 조회로 무엇을 확인할지 적어라.

[출력 형식 — JSON 하나만. 설명 문장을 앞뒤에 붙이지 마라]
{
  "run": [{"key": "조회 키", "why": "이 목표에 왜 필요한가(한 문장)"}],
  "skip": [{"key": "조회 키", "why": "왜 안 하는가(한 문장)"}],
  "question_lookups": [{"question": "확인해야 할 질문 원문", "lookups":
    [{"key": "run의 조회 키", "why": "이 질문에서 확인할 것"}]}],
  "hashes": ["우선 비교할 실제 해시"]
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


def _mandatory_tracks(route, targets, runnable):
    """증거가 있으면 모델이 빼도 반드시 실행할 최소 조회."""
    route = route or {}
    targets = targets or {}
    required = []
    if route.get("hashes") and "malware" in runnable:
        required.append("malware")
    if (route.get("domains") and "user_action" in runnable and
            any(browser_research.QUESTION_RE.search(question) for question in
                (targets.get("questions") or []))):
        required.append("user_action")
    if (route.get("hashes") or route.get("domains") or route.get("ips")) and "intel" in runnable:
        required.append("intel")
    if (targets.get("packages") or "supply_chain" in (route.get("tracks") or [])) and "supply_chain" in runnable:
        required.append("supply_chain")
    return required


def build_prompt(objective, questions, catalog, availability, evidence="", hashes=None):
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
        + "\n\n[사건 근거]\n" + evidence[:11000]
        + "\n\n[확보된 해시]\n" + "\n".join(hashes or [])
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


@analysis_trace.step("목표별 조사 도구·대표 샘플 선정", "plan", inputs=("objective", "questions", "route", "evidence"))
def plan(objective, questions, catalog, route, targets=None, timeout=120, evidence=""):
    """돌릴 조회를 정한다.

    반환: {"tracks": [실행할 키], "reasons": {키: 이유}, "skipped": [{key, why}],
           "steps": [조사 과정에 남길 줄]}
    계획을 못 세우면 tracks는 규칙 판정 결과 그대로다.
    """
    fallback = list(route.get("tracks") or [])
    availability = _availability(route, targets)
    runnable = {item["key"] for item in catalog if availability.get(item["key"]) != "없음"}
    mandatory = _mandatory_tracks(route, targets, runnable)
    fallback = list(dict.fromkeys(fallback + mandatory))

    raw = common_utils.llm_generate(
        build_prompt(objective, questions, catalog, availability, evidence, route.get("hashes")),
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

    added_mandatory = []
    for key in mandatory:
        if key not in tracks:
            tracks.append(key)
            reasons[key] = "확보된 지표가 있어 누락할 수 없는 필수 조회입니다."
            added_mandatory.append(key)

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
    if added_mandatory:
        steps.append("· 증거 보존을 위해 필수 조회를 추가했습니다: "
                     + ", ".join(added_mandatory))
    wanted_questions = {" ".join(str(q).split()): q for q in questions or []}
    question_lookups = []
    for row in data.get("question_lookups") or []:
        if not isinstance(row, dict):
            continue
        question = wanted_questions.get(" ".join(str(row.get("question") or "").split()))
        if not question or any(entry["question"] == question for entry in question_lookups):
            continue
        lookups = []
        for item in row.get("lookups") or []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or "").strip()
            if key in tracks and key not in [entry["key"] for entry in lookups]:
                lookups.append({"key": key,
                                "why": " ".join(str(item.get("why") or "").split())[:MAX_REASON_CHARS]})
        question_lookups.append({"question": question, "lookups": lookups})
    hashes = [v for v in data.get("hashes") or [] if isinstance(v, str) and v in (route.get("hashes") or [])][:2]
    # The model may omit a question or attach a generic browser lookup to a malware
    # goal. Fill the missing mapping deterministically from the goal's evidence type.
    by_question = {row["question"]: row for row in question_lookups}
    for question in questions or []:
        row = by_question.setdefault(question, {"question": question, "lookups": []})
        allowed = _question_keys(question, tracks, runnable)
        current = [item for item in row.get("lookups") or [] if item.get("key") in allowed]
        if not current:
            current = [{"key": key, "why": _question_reason(question, key)} for key in allowed]
        row["lookups"] = current
    question_lookups = list(by_question.values())
    return {"tracks": tracks, "reasons": reasons, "skipped": skipped, "steps": steps,
            "hashes": hashes, "question_lookups": question_lookups,
            "research_plan": build_task_graph(objective, questions, tracks, runnable, question_lookups)}
