# -*- coding: utf-8 -*-
"""Turn the completed article analysis into reviewable investigation decisions."""

import json
import re

import common_utils
import playbook


AXES = {"user_action", "malware", "vulnerability", "supply_chain"}
DISPOSITIONS = {"investigate", "established", "excluded"}
MAX_ISSUES = 12
STEP_RE = re.compile(r"^\s*\d+[.)]\s+(.+)$")
SIGNALS = (
    (re.compile(r"(?<![A-Za-z0-9])clickfix(?![A-Za-z0-9])", re.I), "ClickFix", "user_action",
     "ClickFix 유입 페이지·사용자 실행 명령과 후속 페이로드의 연결 근거는 무엇인가"),
    (re.compile(r"(?<![A-Za-z0-9])BYOVD(?![A-Za-z0-9])|취약\s*드라이버|vulnerable\s+driver", re.I),
     "취약 드라이버 악용", "vulnerability",
     "취약 드라이버 악용의 샘플·실행 조건과 보안 기능 영향은 무엇인가"),
    (re.compile(r"자격\s*증명\s*탈취|credential\s+theft|steal\s+browser\s+credentials", re.I),
     "자격증명 탈취", "malware",
     "자격증명 접근과 외부 전송을 뒷받침하는 샘플 행위는 무엇인가"),
)

PROMPT = """당신은 SOC 조사 책임자다. 이미 완료된 기본 분석을 읽고, 외부 조회 전에
사건별 이슈와 조사 목표를 확정하라. 기사 원문이 확인하지 않은 사실은 전제하지 마라.
침투·사용자 유도·실행·방어 회피·지속화·탈취·유출 중 실제 근거가 있는 단계를
빠짐없이 살펴라. ClickFix가 등장하면 초기 유입 이슈로 반드시 포함하라.
주력 유형은 한 개여도 이슈 유형은 여러 개일 수 있다. 단순히 IOC를 확보하는
질문보다 어떤 조건을 확인하면 탐지·격리·패치·자격증명 보호 결정을 할 수 있는지
묻는다. 이슈마다 조사 필요성을 정하고, 조사할 이슈에는 서로 구분되는 질문을 붙여라.
조회할 입력이 없더라도 이슈를 버리지 말고 필요한 추가 근거를 질문에 적어라.
아래 [기본 분석의 공격 단계]가 있으면 각 단계 ID를 해당 이슈의 step_ids에 붙여라.
한 이슈가 여러 단계를 다뤄도 된다. 단계와 무관한 이슈에는 빈 배열을 쓴다.
기사에서 웹스토어 배포가 확인되지 않았으면 웹스토어 등록을 전제하지 마라.
각 사건의 번호를 지켜 다른 사건의 지표나 행위를 섞지 마라.

JSON만 출력하라:
{"cases":[{"incident":1,"primary":"user_action|malware|vulnerability|supply_chain|없음",
"objective":"대응 결정을 위해 확인할 목표 한 문장",
"criteria":["아래 허용된 산출물 키"],"gaps":["현재 도구로 얻을 수 없는 근거"],
"issues":[{"title":"이슈","type":"user_action|malware|vulnerability|supply_chain|other",
"evidence":"기사 원문 또는 기본 분석에서 그대로 인용한 짧은 근거 구절",
"step_ids":["관련된 공격 단계 ID"],
"disposition":"investigate|established|excluded",
"reason":"조사·확인 완료·제외 판단 이유",
"question":"investigate이면 답해야 할 질문, 아니면 빈 문자열",
"decision":"이 답으로 결정할 대응"}]}]}
허용된 산출물 키:
{vocabulary}
"""


def _text(value, limit=300):
    return " ".join(str(value or "").split())[:limit]


def _source_contains(evidence, source):
    compact = lambda value: re.sub(r"\s+", "", value or "").casefold()
    return len(compact(evidence)) >= 6 and compact(evidence) in compact(source)


def _technical_steps(analysis):
    inside, steps = False, []
    for line in (analysis or "").splitlines():
        stripped = line.strip()
        if stripped == "[기술적 세부사항]":
            inside = True
            continue
        if inside and stripped.startswith("[") and stripped.endswith("]"):
            break
        match = STEP_RE.match(line) if inside else None
        if match and match.group(1).strip():
            steps.append({"id": "s{}".format(len(steps) + 1),
                          "text": _text(match.group(1), 220)})
        if len(steps) >= MAX_ISSUES:
            break
    return steps


def _json(raw):
    if not raw:
        return {}
    match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    raw = match.group(1) if match else raw
    start = raw.find("{")
    if start < 0:
        return {}
    try:
        value, _ = json.JSONDecoder().raw_decode(raw[start:])
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _fallback_case(incident, label, article, analysis, targets, steps, single):
    """Keep a reviewable investigation path when the decision response is unusable."""
    issues = []
    source = article + "\n" + analysis
    if single:
        for pattern, title, kind, question in SIGNALS:
            match = pattern.search(article)
            if not match:
                continue
            start = max(0, match.start() - 65)
            end = min(len(article), match.end() + 65)
            evidence = _text(article[start:end], 160)
            related = [step["id"] for step in steps if pattern.search(step["text"])]
            issues.append({"title": title, "type": kind, "evidence": evidence,
                           "step_ids": related, "disposition": "investigate",
                           "reason": "기사 원문에 언급된 공격 단계의 실행 조건 확인 필요",
                           "question": question, "decision": "영향 범위와 대응 조건 확인"})
    covered = {step_id for issue in issues for step_id in issue["step_ids"]}
    for step in steps:
        if step["id"] in covered:
            continue
        issues.append({"title": "공격 단계 {} 검증".format(step["id"]), "type": "other",
                       "evidence": step["text"], "step_ids": [step["id"]],
                       "disposition": "investigate", "reason": "기본 분석에 기록된 단계 확인 필요",
                       "question": "{}: 어떤 관측으로 실행 여부와 영향 범위를 확인할 수 있는가".format(
                           step["text"][:85]), "decision": "해당 단계의 대응 대상 확인"})
    if not issues:
        excerpt = next((line.strip() for line in analysis.splitlines()
                        if len(line.strip()) >= 12 and not line.strip().startswith("[")), "")
        if not excerpt and single:
            excerpt = next((line.strip() for line in article.splitlines()
                            if len(line.strip()) >= 12), "")
        if excerpt:
            issues.append({"title": "기사 핵심 주장 검증", "type": "other",
                           "evidence": _text(excerpt, 160), "step_ids": [],
                           "disposition": "investigate", "reason": "세부 공격 단계가 구조화되지 않음",
                           "question": "이 주장에 대한 원문·외부 관측 근거와 영향 범위는 무엇인가",
                           "decision": "근거 확인 후 대응 범위 결정"})
    if not issues:
        issues.append({"title": "사건별 근거 확인", "type": "other",
                       "evidence": "사건별 원문 근거를 분리하지 못함", "step_ids": [],
                       "disposition": "investigate", "reason": "사건 소속과 행위 근거 재확인 필요",
                       "question": "{}의 공격 행위와 지표가 원문 어디에 제시되는가".format(label),
                       "decision": "사건별 근거 확인 후 대응 범위 결정"})
    objective = ("{}의 공격 단계와 영향 조건을 확인하고 대응 대상을 가린다".format(label)
                 if not single else "기사의 공격 단계와 영향 조건을 확인하고 대응 대상을 가린다")
    candidate = {"incident": incident, "objective": objective, "issues": issues,
                 "primary": targets.get("primary") if single else "",
                 "criteria": [], "gaps": ["원문·외부 관측 근거와 실제 영향 범위 대조 필요"]}
    case = _case(candidate, incident, article, analysis, steps=steps, check_signals=False)
    if case:
        case["decision_status"] = "review_required"
        case["review_reasons"].append("판단 모델 응답을 검증하지 못해 원문·기본 분석으로 조사 후보를 재구성함")
    return case


def _case(source, incident, article, analysis, steps=(), check_signals=True):
    if not isinstance(source, dict) or str(source.get("incident")) != str(incident):
        return None
    objective = _text(source.get("objective"), 450)
    if not objective or not isinstance(source.get("issues"), list):
        return None
    issues, questions, seen = [], [], set()
    unverified = []
    valid_steps = {step["id"] for step in steps}
    for index, entry in enumerate(source["issues"][:MAX_ISSUES], 1):
        if not isinstance(entry, dict):
            continue
        title = _text(entry.get("title"), 120)
        evidence = _text(entry.get("evidence"), 240)
        disposition = entry.get("disposition")
        question = _text(entry.get("question"), 300)
        if not title or not evidence or disposition not in DISPOSITIONS:
            continue
        if disposition == "investigate" and not question:
            continue
        if title.lower() in seen:
            continue
        seen.add(title.lower())
        issue = {"id": "i{}-{}".format(incident, index), "title": title,
                 "type": entry.get("type") if entry.get("type") in AXES else "other",
                 "evidence": evidence, "disposition": disposition,
                 "reason": _text(entry.get("reason"), 240), "question": question if disposition == "investigate" else "",
                 "decision": _text(entry.get("decision"), 240),
                 "step_ids": [value for value in (entry.get("step_ids") or [])
                              if isinstance(value, str) and value in valid_steps]}
        issue["source_check"] = ("matched" if _source_contains(evidence, article + "\n" + analysis)
                                 else "review_required")
        if issue["source_check"] != "matched":
            unverified.append(issue["id"])
        issues.append(issue)
        if issue["question"] and issue["question"] not in questions:
            questions.append(issue["question"])
    if not issues:
        return None

    missing = []
    covered_steps = {step_id for issue in issues for step_id in issue["step_ids"]}
    missing_steps = [step for step in steps if step["id"] not in covered_steps]
    for step in missing_steps:
        question = "{}: 어떤 관측으로 이 단계를 확인하고 영향 범위를 가릴 수 있는가".format(
            step["text"][:85])
        issues.append({"id": "i{}-{}".format(incident, len(issues) + 1),
                       "title": "공격 단계 {} 검증".format(step["id"]), "type": "other",
                       "evidence": step["text"], "disposition": "investigate",
                       "reason": "기본 분석 단계가 이슈별 판단에서 누락됨",
                       "question": question, "decision": "해당 단계의 영향 범위와 대응 조건 확인",
                       "source_check": "matched", "step_ids": [step["id"]]})
        questions.append(question)
    # A visible source technique cannot disappear merely because the model omitted it.
    for pattern, label, kind, question in SIGNALS if check_signals else ():
        if not pattern.search(article):
            continue
        if any(pattern.search(" ".join((i["title"], i["evidence"], i["question"])))
               for i in issues):
            continue
        missing.append(label)
        issues.append({"id": "i{}-{}".format(incident, len(issues) + 1),
                       "title": label, "type": kind, "evidence": "기사 원문에 {} 언급".format(label),
                       "disposition": "investigate", "reason": "판단 생성에서 누락되어 추가 검증 필요",
                       "question": question, "decision": "해당 공격 단계의 영향 범위와 대응 조건 확인",
                       "source_check": "keyword_verified", "step_ids": []})
        questions.append(question)
    for issue in issues:
        if issue["disposition"] == "investigate" and issue["question"] not in questions:
            questions.append(issue["question"])
    if missing or missing_steps:
        objective = objective.rstrip(".。 ") + "; 추가 조사: " + ", ".join(
            missing + [step["text"][:50] for step in missing_steps]) + "의 실행·영향 조건 확인."
    primary = source.get("primary")
    criteria = [key for key in (source.get("criteria") if isinstance(source.get("criteria"), list) else [])
                if isinstance(key, str) and key in playbook.ARTIFACTS]
    gaps = [_text(value, 180) for value in
            (source.get("gaps") if isinstance(source.get("gaps"), list) else []) if _text(value)]
    review_reasons = []
    if any(issue["disposition"] == "investigate" for issue in issues) and not criteria and not gaps:
        review_reasons.append("달성 기준과 조사 한계가 모두 비어 있음")
    return {"objective": objective, "primary": primary if primary in AXES else "",
            "questions": questions, "criteria": list(dict.fromkeys(criteria)),
            "gaps": gaps, "issues": issues,
            "decision_status": "review_required" if missing or missing_steps or unverified or review_reasons else "confirmed",
            "missing_issues": missing, "missing_steps": [step["id"] for step in missing_steps],
            "unverified_issues": unverified, "review_reasons": review_reasons}


def _incident_steps(title, analysis, targets):
    targets = targets or {}
    incidents = targets.get("incidents") or [title]
    steps = _technical_steps(analysis)
    case_steps = [[] for _ in incidents]
    unscoped_steps = []
    for step in steps:
        matches = [index for index, label in enumerate(incidents)
                   if label and label.casefold() in step["text"].casefold()]
        if len(incidents) == 1:
            case_steps[0].append(step)
        elif len(matches) == 1:
            case_steps[matches[0]].append(step)
        else:
            unscoped_steps.append(step["id"])
    return incidents, steps, case_steps, unscoped_steps


def fallback(title, article, analysis, targets):
    incidents, _, case_steps, unscoped_steps = _incident_steps(title, analysis, targets)
    cases = [_fallback_case(index, label, article, analysis, targets or {},
                            case_steps[index - 1], len(incidents) == 1)
             for index, label in enumerate(incidents, 1)]
    for case in cases:
        if unscoped_steps:
            case["review_reasons"].append(
                "사건 소속이 불분명한 공격 단계: " + ", ".join(unscoped_steps))
    return cases


def decide(title, article, analysis, targets):
    """Use validated model decisions, then source-grounded review candidates."""
    targets = targets or {}
    incidents, steps, case_steps, unscoped_steps = _incident_steps(title, analysis, targets)
    prompt = (PROMPT.replace("{vocabulary}", playbook.vocabulary_spec())
              + "\n[사건]\n" + "\n".join("{}: {}".format(i, name)
                                                for i, name in enumerate(incidents, 1))
              + "\n[기사 원문]\n" + (article or "")[:12000]
              + "\n[완료된 기본 분석]\n" + (analysis or "")[:9000]
              + "\n[기본 분석의 공격 단계]\n" + json.dumps(steps, ensure_ascii=False)
              + "\n[기존 조사 후보]\n" + json.dumps({k: targets.get(k) for k in
                  ("primary", "objective", "questions", "criteria")}, ensure_ascii=False))
    try:
        raw = common_utils.llm_generate(prompt, timeout=180, json_format=True,
                                        nvidia_max_attempts=2, max_tokens=8192)
    except Exception:
        raw = None
    rows = _json(raw).get("cases")
    if not isinstance(rows, list):
        print("[-] 이슈별 판단 응답의 JSON/cases를 검증하지 못했습니다 (응답 {}자).".format(
            len(raw or "")))
    by_incident = {}
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                index = int(row.get("incident"))
            except (TypeError, ValueError):
                continue
            if 1 <= index <= len(incidents) and index not in by_incident:
                by_incident[index] = row
    cases = []
    for index, label in enumerate(incidents, 1):
        case = _case(by_incident.get(index), index, article, analysis,
                     steps=case_steps[index - 1], check_signals=len(incidents) == 1)
        if case is None:
            print("[-] 사건 {}의 이슈별 판단을 검증하지 못해 원문·기본 분석으로 복구합니다.".format(index))
            case = _fallback_case(index, label, article, analysis, targets,
                                  case_steps[index - 1], len(incidents) == 1)
        if case is None:
            return None
        cases.append(case)
    if unscoped_steps:
        for case in cases:
            case["decision_status"] = "review_required"
            case["review_reasons"].append(
                "사건 소속이 불분명한 공격 단계: " + ", ".join(unscoped_steps))
    return cases


def apply(targets, cases):
    """Overlay the post-analysis decision while preserving extracted indicators."""
    out = dict(targets or {})
    if len(cases) == 1:
        out.update(cases[0])
    else:
        for field, key in (("objective", "objectives_by_incident"),
                           ("questions", "questions_by_incident"),
                           ("criteria", "criteria_by_incident"),
                           ("gaps", "gaps_by_incident"),
                           ("primary", "primary_by_incident"),
                           ("issues", "issues_by_incident"),
                           ("decision_status", "decision_status_by_incident"),
                           ("missing_steps", "missing_steps_by_incident"),
                           ("missing_issues", "missing_issues_by_incident"),
                           ("review_reasons", "review_reasons_by_incident")):
            out[key] = {index: case[field] for index, case in enumerate(cases, 1)}
        out["unverified_issues_by_incident"] = {
            index: case["unverified_issues"] for index, case in enumerate(cases, 1)}
    return out
