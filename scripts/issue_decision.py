# -*- coding: utf-8 -*-
"""Turn the completed article analysis into reviewable investigation decisions."""

import json
import re

import article_kind
import common_utils
import playbook


AXES = {"user_action", "malware", "vulnerability", "supply_chain"}
DISPOSITIONS = {"investigate", "established", "excluded"}
MAX_ISSUES = 12
# 정보성 기사의 학습 질문 상한. briefing은 질문마다 공개 자료를 찾는데 검색 횟수에
# 상한이 있어, 그 이상은 답할 재료가 없는 "미해결"로만 남는다.
MAX_LEARNING_QUESTIONS = 3
# 근거 구절을 말줄임표로 이어 붙인 경우 조각마다 대조한다. 짧은 조각("등", "및")은
# 어디에나 있어 대조 의미가 없다.
MIN_EVIDENCE_FRAGMENT = 8
ELLIPSIS_RE = re.compile(r"\.{3,}|…+")
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
question은 외부 조회(원문·공개 스캔·샌드박스·검색·취약점 DB)로 답할 수 있는 형태로
써라 — 예: "이 Custom GPT 응답이 어느 외부 유인 페이지로 연결되는가", "최종 페이로드의
C2 통신 대상은 무엇인가". 프록시·방화벽·EDR·메모리 포렌식 등 사내 로그에서 흔적을
찾는 일은 외부 도구로 답할 수 없으므로 question이 아니라 decision에 적어라.
아래 [기본 분석의 공격 단계]가 있으면 각 단계 ID를 해당 이슈의 step_ids에 붙여라.
한 이슈가 여러 단계를 다뤄도 된다. 단계와 무관한 이슈에는 빈 배열을 쓴다.
기사에서 웹스토어 배포가 확인되지 않았으면 웹스토어 등록을 전제하지 마라.
각 사건의 번호를 지켜 다른 사건의 지표나 행위를 섞지 마라.
제목의 주된 사건 뒤에 관련 사례로 소개된 별도 캠페인은 이 사건의 이슈나
조사 목표에 포함하지 마라.

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

# 정보성 기사(공격 사건이 아닌 기사)용. 위 PROMPT는 공격 단계·탐지·격리를 전제해서,
# 제휴 발표 기사에서도 "망분리 예외·암호화·모니터링 적용 여부를 결정한다"는 목표와
# 보안 인증·탐지 룰 질문이 나왔다(실측 2026-09-30, 카테나-X 건). 여기서는 기사 이해와
# 우리 조직에 주는 의미를 목표로 삼고, 공개 자료로 답할 학습 질문만 받는다.
BRIEF_PROMPT = """당신은 보안 조직의 기술 정보 담당자다. 이미 완료된 기본 분석을 읽고, 이 기사를
어떻게 정리할지 확정하라. 이 기사는 공격 사건이 아닌 정보성 기사다 — IOC·취약점·패키지
조회나 탐지 쿼리를 만들 대상이 아니다. 기사에 나오는 기업·기관·파트너사를 공격자나 조사
대상으로 다루지 말고, 침해·유출·공격 단계를 전제하지 마라. 기사 원문이 확인하지 않은
사실도 전제하지 마라.
objective는 기사 내용과 배경을 이해하고 우리 조직에 주는 의미(도입 검토·규제 대응 검토가
필요한지)를 판단하는 목표 한 문장이다.
이슈는 기사가 다루는 핵심 주제별로 1~4개. disposition은 다음 뜻으로만 쓴다.
  established = 기사 원문으로 이미 확인된 내용(발표 사실, 제도 시행 사실 등)
  excluded = 우리 조직과 무관하거나 정리 범위 밖인 내용
  investigate = 공개 자료(공식 문서·용어 해설)로 확인할 배경 지식
investigate 이슈의 question은 공개 자료로 답할 수 있는 학습 질문 한 문장이다. 개념·구성(그것이
무엇이고 어떻게 이뤄지는가), 요구사항·일정(누구에게 언제부터 무엇이 요구되는가), 보안상
고려점(도입·참여할 때 확인할 보안 요건) 가운데 2~3개만 쓴다. 사내 로그·보안 관제·탐지 룰·
차단 목록·벤더 내부 문서가 있어야 답할 수 있는 질문은 쓰지 마라.
evidence는 기사 원문 또는 기본 분석에서 그대로 옮긴 짧은 구절 하나다. 말줄임표로 여러
구절을 잇지 마라. decision은 그 답으로 판단할 것(도입 검토 필요 여부, 규제 대응 일정 반영
여부 등)이다. primary는 "없음"으로 둔다. criteria는 아래 허용된 산출물 키에서만 고른다.
gaps에는 공개 자료로는 알 수 없는 것을 적고, 없으면 빈 배열로 둔다.

JSON만 출력하라:
{"cases":[{"incident":1,"primary":"없음",
"objective":"기사 내용과 배경을 이해하고 우리 조직에 주는 의미를 판단할 목표 한 문장",
"criteria":["아래 허용된 산출물 키"],"gaps":["공개 자료로 얻을 수 없는 근거"],
"issues":[{"title":"이슈",
"evidence":"기사 원문 또는 기본 분석에서 그대로 인용한 짧은 근거 구절",
"disposition":"established|excluded|investigate",
"reason":"확인 완료·제외·공개 자료 확인 판단 이유",
"question":"investigate이면 공개 자료로 답할 학습 질문, 아니면 빈 문자열",
"decision":"이 답으로 판단할 것"}]}]}
허용된 산출물 키:
{vocabulary}
"""


def _text(value, limit=300):
    return " ".join(str(value or "").split())[:limit]


def _source_contains(evidence, source):
    """근거 구절이 원문에 있는가.

    모델은 긴 문장을 "앞 구절... 뒤 구절"로 줄여 인용한다. 통째로 대조하면 두 구절이
    각각 원문에 있어도 불일치가 된다 — 카테나-X 건의 이슈 3건이 전부 그렇게
    review_required가 됐다(실측 2026-09-30). 말줄임표로 나눠 조각마다 대조한다.
    """
    compact = lambda value: re.sub(r"\s+", "", value or "").casefold()
    haystack = compact(source)
    if not ELLIPSIS_RE.search(evidence or ""):
        return len(compact(evidence)) >= 6 and compact(evidence) in haystack
    fragments = [compact(part) for part in ELLIPSIS_RE.split(evidence)]
    fragments = [part for part in fragments if len(part) >= MIN_EVIDENCE_FRAGMENT]
    return bool(fragments) and all(part in haystack for part in fragments)


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
                          "text": _text(match.group(1), 600)})
        if len(steps) >= MAX_ISSUES:
            break
    return steps


def _stage_title(step):
    """Turn an internal step ID into a short, readable issue title."""
    number = re.sub(r"\D", "", step.get("id") or "") or "?"
    detail = re.sub(r"\*\*|`", "", step.get("text") or "").strip()
    detail = re.sub(r"^.{1,100}캠페인\s*\(\d+\)\s*[:：]\s*", "", detail)
    detail = re.sub(r"\s+", " ", detail).strip(" .:：")
    return "{}단계 · {}".format(number, detail or "행위 근거 확인 필요")


def _stage_question(step):
    return "{}: 실행 여부와 영향 범위를 확인할 원문·샘플·로그 근거는 무엇인가".format(
        _stage_title(step))


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


INFORMATIONAL_OBJECTIVE = "기사 내용과 배경을 정리하고 우리 조직에 주는 의미를 판단한다"
# 기본 분석은 "[핵심 요약] 본문…"처럼 섹션 머리를 본문 줄 앞에 붙여 쓴다. 머리를 떼지
# 않으면 "["로 시작하는 줄을 건너뛰는 규칙에 걸려 인용할 줄이 하나도 남지 않는다.
SECTION_HEAD_RE = re.compile(r"^\[[^\]]+\]\s*")


def _informational_fallback_case(incident, article, analysis):
    """정보성 기사에서 판단 응답을 못 쓸 때의 기본 정리 항목.

    공격형 복구 경로("기사의 공격 단계와 영향 조건을 확인하고 대응 대상을 가린다" +
    investigate 이슈)로 떨어지면 정보성 판정이 여기서 되돌려진다.
    """
    excerpt = ""
    for line in (analysis or "").splitlines() + (article or "").splitlines():
        text = SECTION_HEAD_RE.sub("", line.strip())
        if len(text) >= 12:
            excerpt = text
            break
    candidate = {"incident": incident, "objective": INFORMATIONAL_OBJECTIVE, "primary": "",
                 "criteria": ["background_brief", "reading_list"], "gaps": [],
                 "issues": [{"title": "기사 핵심 내용 정리",
                             "evidence": _text(excerpt, 160) or "기사 원문",
                             "disposition": "established",
                             "reason": "공격 사건이 아닌 정보성 기사로, 기사 원문이 전하는 내용을 정리함",
                             "question": "",
                             "decision": "배경 자료와 함께 우리 조직 해당 여부 판단"}]}
    case = _case(candidate, incident, article, analysis, check_signals=False, informational=True)
    if case:
        case["decision_status"] = "review_required"
        case["review_reasons"].append("판단 모델 응답을 검증하지 못해 기사 핵심 내용 정리로 대체함")
    return case


def _fallback_case(incident, label, article, analysis, targets, steps, single):
    """Keep a reviewable investigation path when the decision response is unusable."""
    if article_kind.is_informational(targets):
        return _informational_fallback_case(incident, article, analysis)
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
        issues.append({"title": _stage_title(step), "type": "other",
                       "evidence": step["text"], "step_ids": [step["id"]],
                       "disposition": "investigate", "reason": "기본 분석에 기록된 단계 확인 필요",
                       "question": _stage_question(step),
                       "decision": "해당 단계의 대응 대상 확인"})
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


def _case(source, incident, article, analysis, steps=(), check_signals=True, informational=False):
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
        matched_step = next((step for step in steps if step["id"] in (entry.get("step_ids") or [])
                             and entry.get("title") == _stage_title(step)), None)
        title = _text(entry.get("title"), 700 if matched_step else 120)
        evidence = _text(entry.get("evidence"), 600 if matched_step else 240)
        disposition = entry.get("disposition")
        question = _text(entry.get("question"), 800 if matched_step else 300)
        if not title or not evidence or disposition not in DISPOSITIONS:
            continue
        if disposition == "investigate" and not question:
            continue
        if title.lower() in seen:
            continue
        seen.add(title.lower())
        # 정보성 기사의 이슈는 공격 단계가 아니다. "other"로 채우면 화면이 "기타 공격 단계"
        # 배지를 붙이고, 조사 축 값이면 "공급망 기반" 같은 공격 유형 배지가 붙는다.
        if informational:
            kind = ""
        else:
            kind = entry.get("type") if entry.get("type") in AXES else "other"
        issue = {"id": "i{}-{}".format(incident, index), "title": title,
                 "type": kind,
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
        question = _stage_question(step)
        issues.append({"id": "i{}-{}".format(incident, len(issues) + 1),
                       "title": _stage_title(step), "type": "other",
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
            missing + (["기본 분석에서 누락된 공격 단계 {}건".format(len(missing_steps))]
                       if missing_steps else [])) + "의 실행·영향 조건 확인."
    primary = "" if informational else source.get("primary")
    # 정보성 기사에 헌팅 쿼리·차단 목록 같은 기준이 선언되면 낼 수 없어 "미달"로만 남는다.
    allowed = playbook.INFORMATIONAL_ARTIFACTS if informational else playbook.ARTIFACTS
    criteria = [key for key in (source.get("criteria") if isinstance(source.get("criteria"), list) else [])
                if isinstance(key, str) and key in allowed]
    gaps = [_text(value, 180) for value in
            (source.get("gaps") if isinstance(source.get("gaps"), list) else []) if _text(value)]
    if informational:
        questions = questions[:MAX_LEARNING_QUESTIONS]
    review_reasons = []
    # 정보성 기사는 기준·한계가 비어도 된다 — 공개 자료로 확인할 학습 질문뿐이라, 이
    # 규칙이 모델을 탐지 산출물 기준으로 밀어붙이던 압력이 여기서는 근거가 없다.
    if (not informational and any(issue["disposition"] == "investigate" for issue in issues)
            and not criteria and not gaps):
        review_reasons.append("달성 기준과 조사 한계가 모두 비어 있음")
    return {"objective": objective, "primary": primary if primary in AXES else "",
            "questions": questions, "criteria": list(dict.fromkeys(criteria)),
            "gaps": gaps, "issues": issues,
            "decision_status": "review_required" if missing or missing_steps or unverified or review_reasons else "confirmed",
            "missing_issues": missing, "missing_steps": [step["id"] for step in missing_steps],
            "unverified_issues": unverified, "review_reasons": review_reasons}


def _incident_steps(title, analysis, targets):
    targets = targets or {}
    if article_kind.is_informational(targets):
        # 정보성 기사는 사건으로 나누지 않고(briefing이 한 블록으로 정리한다) 공격 단계도
        # 없다. 단계를 뽑으면 "공격 단계 s1 검증" 이슈가 다시 붙는다.
        return [title], [], [[]], []
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
    incidents, steps, case_steps, unscoped_steps = _incident_steps(title, analysis, targets)
    cases = [_fallback_case(index, label, article, analysis, targets or {},
                            case_steps[index - 1], len(incidents) == 1)
             for index, label in enumerate(incidents, 1)]
    for case in cases:
        if unscoped_steps:
            case["review_reasons"].append(
                "사건 소속이 불분명한 분석 단계: " + ", ".join(
                    _stage_title(step) for step in steps if step["id"] in unscoped_steps))
    return cases


def _brief_prompt(title, article, analysis, targets):
    """정보성 기사의 판단 프롬프트. 기사 유형 판정 사유와 주제를 함께 넘긴다 — 판정을
    모르는 모델은 제휴 발표에서도 공격 표면을 찾는다."""
    kind_line = " — ".join(part for part in (
        str(targets.get("article_subtype") or "").strip(),
        str(targets.get("article_kind_reason") or "").strip()) if part)
    topics = [str(t).strip() for t in targets.get("topics") or [] if str(t).strip()]
    return (BRIEF_PROMPT.replace("{vocabulary}", playbook.vocabulary_spec("informational"))
            + "\n[사건]\n1: " + (title or "")
            + "\n[기사 유형]\n정보성 기사" + (" — " + kind_line if kind_line else "")
            + ("\n[배경 자료를 찾을 주제]\n" + ", ".join(topics) if topics else "")
            + "\n[기사 원문]\n" + (article or "")[:12000]
            + "\n[완료된 기본 분석]\n" + (analysis or "")[:9000])


def decide(title, article, analysis, targets):
    """Use validated model decisions, then source-grounded review candidates."""
    targets = targets or {}
    informational = article_kind.is_informational(targets)
    incidents, steps, case_steps, unscoped_steps = _incident_steps(title, analysis, targets)
    if informational:
        prompt = _brief_prompt(title, article, analysis, targets)
    else:
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
        # 정보성 기사에서는 ClickFix 같은 신호어가 동향으로 언급돼도 공격 이슈를 덧붙이지 않는다.
        case = _case(by_incident.get(index), index, article, analysis,
                     steps=case_steps[index - 1],
                     check_signals=len(incidents) == 1 and not informational,
                     informational=informational)
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
                "사건 소속이 불분명한 분석 단계: " + ", ".join(
                    _stage_title(step) for step in steps if step["id"] in unscoped_steps))
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
