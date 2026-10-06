# -*- coding: utf-8 -*-
"""내놓기 전에 산출물을 판단과 대조한다 — 자기 검토 단계.

무엇이 빠져 있었나
    파이프라인은 단계가 잘 나뉘어 있다. 조회를 돌리고, 그 결과로 판단을 받고, 재료로
    차단 목록·쿼리·명령을 만든다. 그런데 **판단과 산출물이 서로를 보지 않는다.**
    차단 목록은 지표 목록에서 기계적으로 나오고, 판단은 그 뒤에 따로 쓰인다.

    실측(2026-09-20, Brevo 공급망 공격 기사): 종합 판단은 cdn.brevo.com을 두고
    "정상 Brevo CDN 도메인이 공격 중 악성 로더 추가 경로로 악용됨"이라고 정확히
    적었다. 같은 기록의 차단 목록에는 그 도메인이 sendibt1.com과 나란히
    "차단 후보 — 도메인"에 들어 있었다. 그대로 넣으면 공격자 인프라가 아니라
    우리 쪽 메일·폼이 죽는다. 게다가 그 공격은 엣지 Worker가 원인이라 이미
    벤더가 걷어낸 뒤였다.

    판단은 맞았는데 산출물이 틀렸다. 둘을 맞대 보는 단계가 없었을 뿐이다.

무엇을 하나
    판단이 쓴 문장과 차단 후보 목록을 같이 주고, "이 중 네 판단대로면 막으면 안 되는
    것이 있나"를 묻는다. 지목된 값은 지우지 않고 **차단 금지 칸으로 옮긴다** — 값을
    없애면 왜 뺐는지가 사라지고, 사람이 다시 판단할 기회도 사라진다.

무엇을 하지 않나
    값을 새로 만들지 않는다. 옮기기만 한다. 모델이 목록에 없던 것을 지목하면 버린다 —
    검토 단계가 재료를 늘리기 시작하면 검토가 아니라 또 한 번의 생성이 된다.
"""

import json
import re
import analysis_trace

import common_utils
import response_synth

# 한 개의 잘못된 차단 후보도 실제 운영에 영향을 준다.
MIN_VALUES = 1
# 한 번에 물어볼 값의 수. 길어지면 모델이 목록을 되풀이하기 시작한다.
MAX_VALUES = 60
BLOCK_LABEL = "차단 후보"
SPARED_LABEL = "차단 금지 — 정상 인프라(공격에 악용됨)"
SPARED_NOTE = ("공격자가 만든 것이 아니라 원래 쓰이던 서비스인데 이번 공격에 경유지로 "
               "쓰인 곳이다. 막으면 공격이 아니라 그 서비스를 쓰는 우리 업무가 멈춘다. "
               "차단 대신 이 호스트로 나가는 트래픽에서 문제의 스크립트·경로만 "
               "걸러 내거나, 벤더가 조치를 끝냈는지 확인한다.")

PROMPT = """당신은 SOC 대응 책임자다. 방금 나온 판단과, 그 판단을 근거로 만든 차단 후보
목록이 아래에 있다. 목록을 그대로 방화벽·프록시에 넣기 전에 마지막으로 검토하라.

찾는 것은 하나다 — **네 판단대로라면 막으면 안 되는 값**.

막으면 안 되는 것의 예:
- 공격자가 만든 것이 아니라 원래 우리(또는 다수)가 쓰던 서비스인데 이번에 경유지로 쓰인 것
- 벤더의 정상 CDN·API·메일 발송 도메인처럼, 막으면 공격이 아니라 그 서비스가 멈추는 것
- 공격이 이미 끝났거나 벤더가 걷어냈다고 판단에 적혀 있어, 막는 것이 무의미한 것

지켜야 할 것:
- 아래 목록에 실제로 있는 값만 지목하라. 목록에 없는 값을 쓰면 버려진다.
- 근거는 위 판단에 적힌 말로 대라. "일반적으로 정상 서비스다" 같은 짐작은 근거가 아니다.
- 애매하면 지목하지 마라. 이 단계는 확실한 것만 걷어내는 자리다.
- 막아야 할 것이 분명하면 빈 배열로 두라. 억지로 찾아내지 마라.

[출력 형식 — JSON 하나만. 설명 문장을 앞뒤에 붙이지 마라]
{"spare": [{"value": "목록에 있는 값 그대로", "why": "판단의 어느 대목 때문인가(한 문장)"}]}
"""


def log(message):
    print(message)


def _verdict_text(synthesis):
    """판단에서 근거로 쓸 만한 문장만 모은다."""
    synthesis = synthesis or {}
    parts = [str(synthesis.get("headline") or "")]
    for key in ("confirmed", "unconfirmed", "contradictions"):
        parts.extend(str(line) for line in (synthesis.get(key) or []))
    exposure = synthesis.get("exposure") or {}
    if isinstance(exposure, dict):
        parts.extend(str(exposure.get(key) or "") for key in ("who", "basis"))
    return "\n".join(line for line in parts if line.strip())


def observed_malicious(investigation):
    """샌드박스가 실제로 통신한 곳과, 위협 피드가 악성으로 등재한 값.

    판단이 틀리면 검토도 같이 틀린다. 실측(DPRK ted backdoor 건): 판단이 C2 도메인 셋을
    두고 "9년 된 정상 Microsoft Store 페이지"라고 적었는데, 근거는 urlscan 스캔 1~2건과
    그 페이지 제목이 "Microsoft Store"라는 것뿐이었다. 스캐너에게 미끼 페이지를 보여
    주는 것은 C2가 늘 하는 일이지 정상이라는 증거가 아니다. 같은 기록의 동적 분석에는
    "C2: img.monderhouse.space … 이 캠페인의 통신으로 봅니다, 포트 443"이 적혀 있었다.

    그래서 검토가 판단만 보고 지우지 못하게 한다. 샌드박스가 실제로 그 호스트와
    통신했거나 피드가 악성으로 등재한 값은 무슨 근거를 대도 차단 후보에 남긴다 —
    관측은 추론보다 세다.
    """
    protected = set()
    malware = (investigation or {}).get("malware") or {}
    for entry in malware.get("files") or []:
        behaviour = entry.get("behaviour") or {}
        for key in ("dns", "ip_traffic", "http", "memory_domains"):
            for item in behaviour.get(key) or []:
                protected.add(json.dumps(item, ensure_ascii=False).lower()
                              if isinstance(item, (dict, list)) else str(item).lower())
    findings = list(malware.get("findings") or [])
    findings += ((investigation or {}).get("intel") or {}).get("findings") or []
    return protected, [str(line) for line in findings]


def _is_protected(value, protected, findings):
    low = value.lower()
    if any(low in blob for blob in protected):
        return True
    # 확인내용에 "C2: <값>"이나 "<값> … 악성으로 등재" 형태로 적힌 것.
    for line in findings:
        if low not in line.lower():
            continue
        if any(word in line for word in ("C2", "등재", "악성", "유포")):
            return True
    return False


def _block_groups(response):
    return [group for group in (response or {}).get("blocklists") or []
            if str(group.get("label") or "").startswith(BLOCK_LABEL)]


@analysis_trace.step("대응 산출물 재검토", "outputs", "validation", inputs=("synthesis", "response"))
def review(synthesis, response, investigation=None, timeout=180):
    """차단 후보 중 막으면 안 되는 값을 가려낸다. [{value, why}] 형식, 없으면 []."""
    verdict = _verdict_text(synthesis)
    groups = _block_groups(response)
    candidates = []
    for group in groups:
        for value in group.get("values") or []:
            value = str(value).strip()
            if value and value not in candidates:
                candidates.append(value)
    if not verdict or len(candidates) < MIN_VALUES:
        return []
    candidates = candidates[:MAX_VALUES]

    prompt = (PROMPT
              + "\n[판단]\n" + verdict[:4000]
              + "\n\n[차단 후보 목록]\n"
              + "\n".join("- " + value for value in candidates)
              + "\n\nJSON만 출력하라.")
    try:
        # 판단 호출과 같은 이유로 상한을 올린다 — 추론 모델이 기본 8192 토큰에서
        # 잘리면 검토가 조용히 통째로 건너뛰어졌다(실측 2026-09-26).
        raw = common_utils.llm_generate(prompt, timeout=max(timeout, response_synth.SYNTH_TIMEOUT),
                                        json_format=True, max_tokens=response_synth.SYNTH_MAX_TOKENS)
    except Exception as error:
        log("    [-] 산출물 검토를 건너뜁니다(조사에는 영향 없음): {}".format(str(error)[:70]))
        return []
    # 잘린 응답도 완결된 항목까지는 쓴다. 살아남은 spare도 아래에서 하나씩 후보 목록·
    # 보호 목록과 대조하므로, 일부만 읽혀도 "덜 풀어 준다" 쪽으로만 틀린다.
    data = response_synth.parse(raw)
    if not data:
        log("    [-] 산출물 검토 응답을 JSON으로 읽지 못해 검토 없이 넘어갑니다.")
        return []

    # 목록에 없는 값은 버린다. 검토 단계가 재료를 늘리면 그건 검토가 아니다.
    protected, findings = observed_malicious(investigation)
    lowered = {value.lower(): value for value in candidates}
    spared, seen = [], set()
    for item in (data.get("spare") or [])[:MAX_VALUES]:
        if not isinstance(item, dict):
            continue
        value = " ".join(str(item.get("value") or "").split())
        key = value.lower()
        if key not in lowered or key in seen:
            continue
        seen.add(key)
        if _is_protected(value, protected, findings):
            log("    [*] 차단 후보에 그대로 둡니다 — 조사에서 실제 악성 통신·등재가 "
                "관측된 값입니다: {}".format(value[:60]))
            continue
        spared.append({"value": lowered[key],
                       "why": " ".join(str(item.get("why") or "").split())[:200]})
    return spared


def apply(response, spared):
    """지목된 값을 차단 후보에서 차단 금지 칸으로 옮긴다. 옮긴 값 목록을 돌려준다."""
    if not spared or not response:
        return []
    keep = {item["value"].lower() for item in spared}
    moved = []
    for group in _block_groups(response):
        remaining = []
        for value in group.get("values") or []:
            if str(value).strip().lower() in keep:
                moved.append(str(value).strip())
            else:
                remaining.append(value)
        group["values"] = remaining
    if not moved:
        return []
    # 자유 형식 쿼리에서 값을 문자열 치환하면 조건이 바뀔 수 있어 재검토로 보낸다.
    affected = [{"value": value} for value in moved]
    response["kql"] = [query for query in response.get("kql") or []
                       if not _mentions_spared(json.dumps(query, ensure_ascii=False), affected)]
    response["actions"] = [action for action in response.get("actions") or []
                           if not _stale_action(action, affected)]
    response["commands"] = [command for command in response.get("commands") or []
                            if not _mentions_spared(json.dumps(command, ensure_ascii=False), affected)]
    # 값이 하나도 안 남은 칸은 지운다 — 제목만 남은 빈 목록이 화면에 보인다.
    response["blocklists"] = [group for group in response.get("blocklists") or []
                              if group.get("values")]
    why = {item["value"].lower(): item["why"] for item in spared}
    response["blocklists"].append({
        "label": SPARED_LABEL,
        "note": SPARED_NOTE,
        "values": moved,
        "reasons": [{"value": value, "why": why.get(value.lower(), "")} for value in moved],
    })
    return moved


def _mentions_spared(text, spared):
    return any(str(item["value"]).lower() in str(text).lower() for item in spared)


def _stale_action(text, spared):
    if _mentions_spared(text, spared):
        return True
    # Count-based instructions no longer describe the reviewed list.
    return bool(re.search(r"(?:도메인|IP|해시)\s*\d+\s*(?:건|개)", str(text))
                and "차단" in str(text))


def reconcile_plan(verdict, spared):
    if verdict and spared:
        kept = [(index, step) for index, step in enumerate(verdict.get("plan") or [], 1)
                if not _stale_action(json.dumps(step, ensure_ascii=False), spared)]
        positions = {old: new for new, (old, _) in enumerate(kept, 1)}
        verdict["plan"] = [step for _, step in kept]
        for row in verdict.get("question_status") or []:
            old = row.get("plan_index")
            if old in positions:
                row["plan_index"] = positions[old]
            else:
                row.pop("plan_index", None)


def steps(spared):
    """조사 과정에 남길 줄."""
    if not spared:
        return []
    lines = ["내놓기 전에 차단 후보를 판단과 대조했습니다 — 막으면 안 되는 값 {}건을 "
             "차단 금지로 옮겼습니다.".format(len(spared))]
    for item in spared:
        lines.append("· {} — {}".format(item["value"], item["why"]))
    return lines
