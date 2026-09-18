# -*- coding: utf-8 -*-
"""조회 결과를 읽고 판단해 대응 방안을 낸다 — 심층 분석의 마지막 단계.

무엇이 빠져 있었나
    파이프라인은 기사를 분석하고(LLM), 지표를 뽑고, 외부를 조회했다. 그런데 조회
    결과를 읽고 판단하는 주체가 없었다. LLM은 조회가 시작되기 전에 이미 일을 마쳤고,
    조회 뒤에 남은 것은 규칙 조립뿐이었다.

    그 결과가 숫자로 드러난다(실측 13건): 대응 조치 43개가 서로 다른 틀 13개에서
    찍혀 나왔고, 그중 12개는 기사와 무관한 같은 문장이었다. 확인된 사실도 조회 결과를
    문장으로 옮긴 것이지 해석한 것이 아니었다.

    조사는 자동화됐지만 분석은 없었다. 이 모듈이 그 자리를 맡는다.

무엇을 판단하나
    목표(기사를 읽고 세운 것)를 조회 결과에 비추어 본다.
      - 확인된 것 / 확인 못한 것 / 기사와 어긋나는 것
      - 그래서 무엇을 어떤 순서로 해야 하는가
      - 무엇이 아직 불확실한가
    "조회 결과가 없었다"도 판단 재료다 — 유포지가 안 잡히면 이미 내려갔다는 뜻일 수
    있고, 그건 "안전하다"와 다르다.

지어내기를 막는 방법
    pattern_synth와 같은 규율을 쓴다. 판단문에 나오는 구체값(도메인·IP·해시·CVE·
    패키지)이 조회 재료에 실제로 있는지 대조하고, 없는 값이 섞이면 그 항목을 버린다.
    오늘 그 검증으로 지어낸 CVE와 해시를 실제로 잡아냈다.
"""

import json
import re

import common_utils

# 조회 재료를 프롬프트에 넣을 때의 상한. 전부 넣으면 프롬프트가 수만 자가 되고,
# 정작 판단에 쓰이는 것은 앞쪽 요약이다.
MAX_FINDINGS = 40
MAX_VALUES_PER_LIST = 30
MAX_MATERIAL_CHARS = 9000
# 판단 항목 상한 — 늘어놓으면 카드가 다시 번잡해진다.
MAX_PLAN_STEPS = 5
MAX_LIST_ITEMS = 5
# 후속 조회 상한. 한 바퀴만 돌리므로 이 안에서 답이 나올 것만 고르게 한다.
MAX_FOLLOWUPS = 4

BS = chr(92)

# 지어내면 위험한 값의 모양. pattern_synth와 같은 기준이다 — 이런 종류가 조회 재료에
# 없이 나오면 그 문장은 근거가 없다.
RISKY_RE = re.compile(
    "(?:[a-z0-9][a-z0-9" + BS + "-]{1,60}" + BS + ".[a-z]{2,18}"      # 도메인
    "|" + BS + "d{1,3}(?:" + BS + "." + BS + "d{1,3}){3}"              # IP
    "|[a-f0-9]{32,64}"                                                 # 해시
    "|CVE-" + BS + "d{4}-" + BS + "d{4,7})", re.I)
# 판단문에 흔히 섞이지만 지표가 아닌 것들 — 제품·도구 이름이라 대조 대상이 아니다.
RISKY_SKIP = {
    "defender.microsoft.com", "virustotal.com", "urlscan.io", "osv.dev",
    "github.com", "nvd.nist.gov", "cisa.gov", "npmjs.com", "pypi.org",
}

PROMPT_HEAD = """당신은 SOC 대응 책임자다. 아래는 (1) 기사 분석, (2) 이 건의 대응 목표,
(3) 그 목표를 확인하려고 외부에서 실제로 조회한 결과다. 조회 결과를 읽고 판단하라.

지켜야 할 것:
- 조회 재료에 없는 도메인·IP·해시·CVE·패키지를 쓰지 마라. 쓰면 그 항목은 버려진다.
- 기사 요약을 되풀이하지 마라. 조회로 무엇이 달라졌는지만 쓴다.
- "결과가 없었다"도 판단 재료다. 유포지가 안 잡히면 이미 내려갔다는 뜻일 수 있고,
  그것은 "안전하다"와 다르다. 없는 것을 없다고 쓰고, 그 뜻을 밝혀라.
- 우리 조직에 해당하지 않으면 해당하지 않는다고 쓰라. 억지로 조치를 만들지 마라.
- exposure는 "미확인"으로 끝내지 마라. 사내 로그에 접근할 수 없는 것은 사실이지만,
  피해 규모·악용 대상·탈취 대상은 이미 재료에 있다. 그것으로 "우리 쪽에서 무엇이
  위험한가"까지 밀고 가되, 측정이 아니라 추론임을 밝히고 무엇을 보면 확정되는지 적어라.
  해당 사항이 정말 없으면 who에 "해당 없음"과 그 이유를 쓴다.
- 이미 해 놓은 일을 조치로 쓰지 마라. 아래 [기사가 인용한 1차 자료 원문]은 우리가 이미
  받아서 읽은 것이고, 조회 결과도 이미 돌린 것이다. "원문을 입수하라", "IOC를 수집하라"
  처럼 이미 손에 있는 것을 구해 오라는 조치는 실행할 일이 없다 — 그 자료로 무엇을 할
  것인지를 써라.
- plan의 done은 비워 두지 마라. "차단했다"가 아니라 "무엇을 확인하면 끝난 것인가"를
  쓴다. 쿼리 결과가 0건이면 끝인지, 0건이어도 다른 것을 더 봐야 하는지가 갈린다 —
  그 구분이 없으면 실행하는 사람이 판단을 대신 해야 한다.
- timeline은 이 사건이 어떻게 흘러왔는지를 읽는 곳이다. "언제 시작해서, 언제
  드러나서, 지금 어디까지 왔나"가 보여야 한다 — 공격 활동 기간, 침해·탈취가 일어난
  시점, 1차 자료·연구 보고서가 공개된 날, 인프라가 등록되거나 마지막으로 관측된 날처럼
  사건의 사건을 먼저 쓴다.
  CVE 공개일이나 샌드박스 최초 등록일은 우리가 조회하다 알게 된 날짜지 이 사건의
  사건이 아니다. 그것만 늘어놓으면 시간축이 조회 기록이 된다 — 사건 쪽 날짜를 다 쓰고
  자리가 남을 때만 넣어라.
  재료에 실제로 적힌 날짜만 쓴다. 없으면 빈 배열로 두고, 날짜를 지어내지 마라.

[출력 형식 — JSON 하나만. 설명 문장을 앞뒤에 붙이지 마라]
{
  "verdict": "목표 달성 여부: 확인됨 | 부분 확인 | 미확인",
  "headline": "지금 상황을 한 문장으로(조회 결과 기준)",
  "confirmed": ["조회로 확인된 사실. 무엇을 근거로 확인됐는지까지"],
  "unconfirmed": ["확인하지 못한 것과 그 이유"],
  "contradictions": ["기사 주장과 조회 결과가 어긋나는 점. 없으면 빈 배열"],
  "plan": [
    {"action": "무엇을 한다", "why": "왜 지금 이 순서인가", "when": "즉시|오늘|이번 주|기한 날짜",
     "done": "무엇을 보면 이 조치가 끝난 것인가. 조회 결과가 0건인 것이 끝인지 아닌지까지 밝혀라"}
  ],
  "open_questions": ["대응을 마치려면 추가로 확인해야 할 것"],
  "exposure": {
    "who": "우리 환경에서 무엇이 어떻게 위험한가. 사내 로그가 없어도 조회 결과와 기사의 사실로 추론하라 — 그 확장을 쓰는 사람이 있다면 무엇이 털리는지, 그 제품을 쓴다면 어디까지 열리는지",
    "basis": "그렇게 본 근거. 조회 결과나 기사의 어느 사실인지 밝혀라",
    "confirm": "이 추정을 사실로 바꾸려면 무엇을 보면 되는가(우리가 볼 수 있는 것으로)"
  },
  "timeline": [
    {"when": "날짜 또는 기간", "what": "그때 무슨 일이 있었나", "source": "어디서 나온 날짜인가"}
  ],
  "followups": [
    {"type": "domain|ip|hash|cve|package", "value": "조회할 값", "question": "무엇을 확인하려는가"}
  ]
}

followups에 대해:
- 위 질문 중 우리가 가진 도구(urlscan·VirusTotal·NVD·KEV·OSV·레지스트리)로 답할 수
  있는 것만 넣어라. 사내 자산·네트워크 로그로만 답할 수 있는 것은 넣지 마라 — 우리는
  그쪽에 접근할 수 없다.
- value는 조회 재료에 이미 나온 값이어야 한다. 새로 지어낸 값은 버려진다.
- 답이 이미 조회 재료에 있으면 넣지 마라. 같은 것을 두 번 조회하게 된다.
- 없으면 빈 배열로 두라.
"""


def log(message):
    print(message)


def _material(investigation, targets):
    """LLM에 넘길 조회 재료. 원자료 그대로가 아니라 판단에 쓰이는 부분만 추린다."""
    lines = []
    route = investigation.get("route") or {}
    if route.get("label"):
        lines.append("[조사 방향] {} — {}".format(route["label"], route.get("explain") or ""))

    def add_findings(label, values):
        if not values:
            return
        lines.append("[{}]".format(label))
        lines.extend("- " + str(v) for v in values[:MAX_FINDINGS])

    add_findings("URL 분석 결과", investigation.get("findings"))
    add_findings("VirusTotal 동적분석", (investigation.get("malware") or {}).get("findings"))
    add_findings("취약점 조회(KEV·EPSS·NVD)", (investigation.get("vulnerability") or {}).get("findings"))
    add_findings("패키지 레지스트리 조회", (investigation.get("supply_chain") or {}).get("findings"))

    vuln = investigation.get("vulnerability") or {}
    if vuln.get("cves"):
        lines.append("[조회된 CVE]")
        for entry in vuln["cves"][:MAX_FINDINGS]:
            lines.append("- {} | KEV {} | EPSS {} | 기한 {}".format(
                entry.get("cve"), "등재" if (entry.get("kev") or {}).get("added") else "미등재",
                entry.get("epss"), (entry.get("kev") or {}).get("due") or "-"))

    response = investigation.get("response") or {}
    for block in response.get("blocklists") or []:
        values = block.get("values") or []
        lines.append("[{} — {}건]".format(block.get("label") or "차단 후보", len(values)))
        lines.extend("- " + str(v) for v in values[:MAX_VALUES_PER_LIST])
    if response.get("kql"):
        lines.append("[준비된 헌팅 쿼리] " + ", ".join(
            q.get("name") or "" for q in response["kql"]))
    if response.get("commands"):
        lines.append("[준비된 단말 명령] " + ", ".join(
            c.get("name") or "" for c in response["commands"]))

    assets = targets.get("assets") if isinstance(targets, dict) else None
    if assets:
        lines.append("[자산 매칭] " + ", ".join(assets))

    text = "\n".join(lines)
    return text[:MAX_MATERIAL_CHARS]


def build_prompt(title, analysis, targets, investigation, primary="", extra="",
                 history=""):
    objective = (targets or {}).get("objective") or ""
    questions = (targets or {}).get("questions") or []
    return (
        PROMPT_HEAD
        # 우리 환경. 이걸 안 주면 "우리 쪽에서 무엇이 위험한가"를 재료 없이 묻는 셈이다.
        + ("\n" + common_utils.environment_brief() + "\n"
           if common_utils.environment_brief() else "")
        + "\n[기사 제목]\n" + (title or "")
        + "\n\n[기사 분석]\n" + (analysis or "")[:4000]
        + "\n\n[이 건의 대응 목표]\n" + (objective or "(설정되지 않음 — 조회 결과로 직접 판단하라)")
        + ("\n\n[확인해야 할 질문]\n" + "\n".join("- " + q for q in questions) if questions else "")
        + "\n\n[외부 조회 결과]\n" + _material(investigation, targets or {})
        # 기사가 인용한 1차 자료. 2차 보도가 생략하거나 잘못 옮긴 내용을 여기서 바로잡는다.
        + ("\n\n[기사가 인용한 1차 자료 원문]\n" + primary if primary else "")
        # 후속 조회로 새로 얻은 것. 1차 판단에서 못 답한 질문의 답이 여기 있다.
        + ("\n\n[후속 조회 결과]\n" + extra if extra else "")
        # 전에 우리가 분석한 같은 계열. 같은 수법이 반복되는지는 기록에서만 보인다.
        + ("\n\n" + history if history else "")
        + "\n\nJSON만 출력하라."
    )


def parse(raw):
    """응답에서 JSON 객체를 꺼낸다. 앞뒤에 설명이 붙어 있어도 살려 낸다."""
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


# 무해화 표기 → 실제 값. analysis_targets와 같은 규칙이다.
DEFANG_SUBS = (("[.]", "."), ("[:]", ":"), ("[/]", "/"), ("(.)", "."),
               ("(dot)", "."), ("[dot]", "."), ("hxxps", "https"), ("hxxp", "http"))


def _corpus(investigation, analysis, primary="", extra=""):
    """근거 대조용 텍스트 — 조회 재료·기사 분석·1차 자료·후속 조회를 합친 것.

    1차 자료를 빼놓았다가 크게 틀렸다. 실측(2026-09-16, 악성 확장 프로그램 건):
    socket.dev와 DomainTools 원문을 읽어 프롬프트에 넣어 놓고, 판단이 거기서 인용한
    manusai.sbs·forti-vpn.com·api.sprocketwhirl 같은 값을 "기사에 없다"며 폐기했다.
    대응 계획 4건이 그렇게 잘려 나갔다 — 1차 자료를 읽는 기능이 읽을수록 손해를 내는
    상태였다. 모델에게 근거로 준 글은 검증에서도 근거로 쳐야 한다.
    """
    blob = " ".join([
        json.dumps(investigation, ensure_ascii=False),
        analysis or "", primary or "", extra or "",
    ]).lower()
    # 1차 자료는 IOC를 무해화해 쓴다. 모델은 정상 형태로 복원해 답하므로, 코퍼스를
    # 그대로 두면 그 값이 "지어낸 것"으로 판정된다 — 실측(2026-09-17): DomainTools
    # 원문에 sprocketwhirl[.]top·manusai[.]sbs로 적혀 있었고, 판단이 쓴
    # sprocketwhirl.top·manusai.sbs가 폐기돼 대응 계획 4건이 잘려 나갔다.
    for fanged, plain in DEFANG_SUBS:
        blob = blob.replace(fanged, plain)
    return blob


def _invented(text, corpus):
    """문장에 조회 재료에 없는 지표가 섞였는지. 섞였으면 그 값들을 돌려준다."""
    bad = []
    for match in RISKY_RE.findall(str(text or "")):
        value = match.lower().strip(".")
        if value in RISKY_SKIP or len(value) < 5:
            continue
        if value not in corpus:
            bad.append(match)
    return bad


def _clean_list(values, corpus, dropped):
    out = []
    for value in values or []:
        text = " ".join(str(value).split())
        if not text:
            continue
        bad = _invented(text, corpus)
        if bad:
            dropped.append("근거 없는 값({}) — {}".format(", ".join(bad[:2]), text[:50]))
            continue
        out.append(text)
        if len(out) >= MAX_LIST_ITEMS:
            break
    return out


def followups(data, corpus):
    """LLM이 요청한 후속 조회 중 실행할 만한 것만. 지어낸 값은 버린다.

    조회 재료에 없던 값을 조회하겠다는 것은 없는 지표를 쫓는 것이다 — 그걸 돌리면
    시간만 쓰고 "결과 없음"이 나오는데, 그 결과가 다시 판단 재료로 들어간다.
    """
    allowed = {"domain", "ip", "hash", "cve", "package"}
    out, seen = [], set()
    for item in (data or {}).get("followups") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").strip().lower()
        value = " ".join(str(item.get("value") or "").split())
        key = (kind, value.lower())
        if kind not in allowed or not value or key in seen:
            continue
        if value.lower() not in corpus:
            continue
        seen.add(key)
        out.append({"type": kind, "value": value,
                    "question": " ".join(str(item.get("question") or "").split())[:120]})
        if len(out) >= MAX_FOLLOWUPS:
            break
    return out


# 날짜처럼 생긴 것. timeline 항목이 근거 있는 날짜를 담았는지 보는 데만 쓴다.
DATE_RE = re.compile(r"\d{4}[-./년]\s*\d{1,2}|\d{1,2}[-./월]\s*\d{1,2}|\d{4}")
MAX_TIMELINE = 8
# 우리가 조회하다 알게 된 날짜 — NVD 공개일, 샌드박스 최초 등록일. 사건의 사건이
# 아니라 조회의 부산물이라, 자리가 모자라면 이쪽부터 버린다.
#
# 실측(Anthropic 위협 보고서 기사): 시간축 6줄이 CVE 공개일 4개와 VT 최초 등록일
# 2개로 다 찼다. 같은 조사에서 나온 Anthropic 보고서 관측 기간, Zscaler 공개일,
# 피싱 도메인 등록일은 모델이 뒤에 적었다가 앞에서 자르는 바람에 통째로 빠졌다.
REGISTRY_EVENT_RE = re.compile(
    r"공개일|공개\s*\(|최초\s*등록|최초\s*등장|등재|first\s*seen|published|"
    r"NVD|VirusTotal\s*최초|CVE-\d",
    re.I)
# 정렬용 날짜. 기간("2025-12 ~ 2026-08")이면 시작일을 쓴다.
WHEN_KEY_RE = re.compile(r"(\d{4})(?:[-./년]\s*(\d{1,2}))?(?:[-./월]\s*(\d{1,2}))?")


def _when_key(when):
    match = WHEN_KEY_RE.search(when or "")
    if not match:
        return (9999, 99, 99)
    return (int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0))


def _exposure(value, corpus, dropped):
    """우리 쪽 영향 범위 추정. 근거가 재료 밖이면 버린다."""
    if not isinstance(value, dict):
        return {}
    who = " ".join(str(value.get("who") or "").split())
    if not who:
        return {}
    basis = " ".join(str(value.get("basis") or "").split())
    bad = _invented(who + " " + basis, corpus)
    if bad:
        dropped.append("근거 없는 값({}) — 영향 범위 추정".format(", ".join(bad[:2])))
        return {}
    return {"who": who[:400], "basis": basis[:400],
            "confirm": " ".join(str(value.get("confirm") or "").split())[:300]}


def _timeline(values, corpus, dropped):
    """시간축. 날짜가 없는 항목과 재료에 없는 값이 섞인 항목은 버린다.

    자르기 전에 다 검사한다. 앞에서부터 자르면 모델이 뒤에 적은 사건 날짜가
    검사도 받기 전에 사라진다. 자리가 모자라면 조회 부산물부터 버리고, 남은 것은
    날짜순으로 되돌린다 — 순서가 없는 시간축은 시간축이 아니다.
    """
    out = []
    for item in (values or []):
        if not isinstance(item, dict):
            continue
        when = " ".join(str(item.get("when") or "").split())
        what = " ".join(str(item.get("what") or "").split())
        if not (when and what) or not DATE_RE.search(when):
            continue
        if _invented(when + " " + what, corpus):
            dropped.append("근거 없는 값 — 시간축 \"{}\"".format(what[:40]))
            continue
        out.append({"when": when[:40], "what": what[:200],
                    "source": " ".join(str(item.get("source") or "").split())[:80]})
    if len(out) > MAX_TIMELINE:
        out.sort(key=lambda row: bool(REGISTRY_EVENT_RE.search(
            row["what"] + " " + row["source"])))
        out = out[:MAX_TIMELINE]
    out.sort(key=lambda row: _when_key(row["when"]))
    return out


def synthesize(title, analysis, targets, investigation, timeout=240,
               primary="", extra="", history=""):
    """조회 결과를 읽고 판단한다. 쓸 만한 결과가 없으면 None.

    반환: {"verdict","headline","confirmed","unconfirmed","contradictions",
           "plan":[{action,why,when}],"open_questions","steps"}
    """
    investigation = investigation or {}
    material = _material(investigation, targets or {})
    if not material.strip():
        return None      # 조회한 것이 없으면 판단할 재료도 없다

    raw = common_utils.llm_generate(
        build_prompt(title, analysis, targets, investigation, primary, extra, history),
        timeout=timeout)
    data = parse(raw)
    if not data:
        # 한 번은 더 받아 본다 — JSON이 아닌 답이 오는 경우가 있다(실측: 패턴 합성에서
        # 같은 입력에 6개/0개가 갈렸다).
        raw = common_utils.llm_generate(
            build_prompt(title, analysis, targets, investigation, primary, extra, history)
            + "\n\n반드시 JSON만 출력하라.",
            timeout=timeout)
        data = parse(raw)
    if not data:
        return None

    corpus = _corpus(investigation, analysis, primary=primary, extra=extra)
    dropped = []
    plan = []
    for item in (data.get("plan") or [])[:MAX_PLAN_STEPS]:
        if not isinstance(item, dict):
            continue
        action = " ".join(str(item.get("action") or "").split())
        if not action:
            continue
        bad = _invented(action + " " + str(item.get("why") or ""), corpus)
        if bad:
            dropped.append("근거 없는 값({}) — {}".format(", ".join(bad[:2]), action[:50]))
            continue
        plan.append({
            "action": action,
            "why": " ".join(str(item.get("why") or "").split()),
            "when": " ".join(str(item.get("when") or "").split()),
            "done": " ".join(str(item.get("done") or "").split())[:200],
        })

    headline = " ".join(str(data.get("headline") or "").split())
    if _invented(headline, corpus):
        headline = ""

    result = {
        "verdict": " ".join(str(data.get("verdict") or "").split())[:20],
        "headline": headline,
        "confirmed": _clean_list(data.get("confirmed"), corpus, dropped),
        "unconfirmed": _clean_list(data.get("unconfirmed"), corpus, dropped),
        "contradictions": _clean_list(data.get("contradictions"), corpus, dropped),
        "plan": plan,
        "open_questions": _clean_list(data.get("open_questions"), corpus, dropped),
        "exposure": _exposure(data.get("exposure"), corpus, dropped),
        "timeline": _timeline(data.get("timeline"), corpus, dropped),
        "objective": (targets or {}).get("objective") or "",
        "followups": followups(data, corpus),
    }
    if not (result["plan"] or result["confirmed"] or result["headline"]):
        return None

    steps = ["조회 결과를 종합해 대응 방안을 정리했습니다(판단 {} · 조치 {}단계)."
             .format(result["verdict"] or "-", len(plan))]
    for reason in dropped[:4]:
        steps.append("· 폐기: " + reason)
    result["steps"] = steps
    return result
