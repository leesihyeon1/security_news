"""Operational checks shared by investigation, synthesis, and offline evaluation."""

import re

import article_kind
import lure_hunter
import pattern_synth
import playbook


VERSION = "analyst-workflow-v1"
PLAN_FIELDS = {
    "owner": "담당 역할", "trigger": "실행 조건", "check": "확인할 로그·방법",
    "preserve": "보존할 증거", "alternative": "수행 불가 시 대안", "done": "완료 기준",
}
# 정보성 기사의 할 일은 검토·학습 과제다. 보존할 증거·수행 불가 시 대안은 사고 대응의
# 칸이라 비어 있는 것이 정상이고, 그것을 "실행 전 보완"으로 찍으면 결함처럼 보인다.
INFORMATIONAL_PLAN_FIELDS = ("owner", "trigger", "check", "done")
# 정보성 과제에서 해당이 없는 칸에 채우는 값. 화면의 이유 줄에는 붙이지 않는다.
NOT_APPLICABLE = "해당 없음"
ZERO_CLOSE_RE = re.compile(r"0\s*건.{0,75}(?:이면|시|경우).{0,60}(?:종료|종결|안전|감염\s*없)", re.I)
QUALIFIED_NEGATIVE_RE = re.compile(r"보존\s*기간|수집\s*범위|로그\s*누락|센서|수집\s*상태|커버리지")
# DNS 싱크홀·차단은 이름 단위다. 저장소 경로에는 걸 수 없고 공용 플랫폼 도메인에 걸면
# 업무 서비스가 통째로 끊긴다(실측 2026-10-12, PoeLLM 건: "github.com/ejejejdfbbebe
# DNS 싱크홀 적용", "GitHub 리포지터리 도메인 싱크홀").
DNS_BLOCK_RE = re.compile(r"(?:DNS|RPZ)\s*(?:싱크홀|sinkhole|차단|블록|block)|싱크홀|sinkhole", re.I)
CLAUSE_END_RE = re.compile(r"[.;](?=\s|$)|,\s|\s(?:및|후|또는)\s|\n")
HOST_PATH_RE = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(/[\w\-./%~]*\w)?", re.I)
PATH_WORD_RE = re.compile(r"URL|경로|리포지[터토]리|저장소|repo(?:sitory)?\b|계정", re.I)
PLATFORM_RE = re.compile(
    r"GitHub|GitLab|Bitbucket|Google\s*Drive|구글\s*드라이브|Dropbox|드롭박스|OneDrive|원드라이브|"
    r"SharePoint|Discord|디스코드|Telegram|텔레그램|Pastebin|Notion|노션|Slack|슬랙|npm\b|PyPI", re.I)
# 공용 도메인 바로 아래의 공용 호스트(raw.githubusercontent.com 등). 그보다 깊은
# 테넌트 호스트(evil.s3.amazonaws.com)는 DNS로 그것만 막을 수 있으니 제외한다.
SHARED_LABELS = {"www", "raw", "api", "gist", "objects", "codeload", "drive", "docs",
                 "storage", "s3", "cdn", "media", "dl", "files"}
PLACEHOLDER_RE = re.compile(r"\b[A-Z][A-Za-z]{1,7}(?:-\d{2,4})?-(?:[xX]{3,}|\?{3,})(?![\w?])|"
                            r"\bKB\d*[xX]{3,}\b")


def _shared_host(host):
    host = host.lower().strip(".")
    head, _, rest = host.partition(".")
    return host in lure_hunter.PUBLIC_SERVICE_APEXES or (
        head in SHARED_LABELS and rest in lure_hunter.PUBLIC_SERVICE_APEXES)


def technical_gaps(step):
    """Deterministic checks for actions that cannot work as written."""
    paths, platforms, placeholders = [], [], []
    for key in ("action", "check", "alternative", "done"):
        text = " ".join(str(step.get(key) or "").split())
        for token in PLACEHOLDER_RE.findall(text):
            if token not in placeholders:
                placeholders.append(token)
        for match in DNS_BLOCK_RE.finditer(text):
            starts = [m.end() for m in CLAUSE_END_RE.finditer(text, 0, match.start())]
            end = CLAUSE_END_RE.search(text, match.end())
            clause = text[starts[-1] if starts else 0:end.start() if end else len(text)]
            shared = [(m.group(0), m.group(2)) for m in HOST_PATH_RE.finditer(clause)
                      if _shared_host(m.group(1))]
            # attacker.github.io처럼 호스트 안에 든 이름은 그 호스트 판정을 따른다.
            names = PLATFORM_RE.findall(HOST_PATH_RE.sub(" ", clause))
            if not shared and not names:
                continue
            target = shared[0][0] if shared else names[0]
            pathy = any(path for _, path in shared) or PATH_WORD_RE.search(clause)
            bucket = paths if pathy else platforms
            if target not in bucket:
                bucket.append(target)
    gaps = []
    if paths:
        gaps.append("DNS 싱크홀로 경로 차단 불가({}) — DNS는 도메인 단위라 공용 플랫폼의 저장소·URL 하나만 "
                    "막을 수 없음. 프록시·SWG URL 필터(TLS 검사)로 그 경로만 막고 접속 기록을 헌팅".format(
                        ", ".join(paths[:3])))
    if platforms:
        gaps.append("공용 플랫폼 DNS 차단 금지({}) — 도메인 전체가 업무 서비스라 개별 URL만 프록시에서 "
                    "막고 플랫폼에 악성 자원 신고".format(", ".join(platforms[:3])))
    if placeholders:
        gaps.append("자리표시 번호({}) — 실제 권고·패치 번호를 확인해 채움".format(", ".join(placeholders[:3])))
    return gaps


def plan_gaps(step, informational=False):
    required = INFORMATIONAL_PLAN_FIELDS if informational else PLAN_FIELDS
    gaps = [PLAN_FIELDS[key] for key in required if not str(step.get(key) or "").strip()]
    done = str(step.get("done") or "")
    if ZERO_CLOSE_RE.search(done) and not QUALIFIED_NEGATIVE_RE.search(done):
        gaps.append("0건 결과의 수집 범위·보존 기간 검증")
    return gaps + technical_gaps(step)


def display_plan(step):
    """Use the existing plan card's fields without changing the UI order."""
    row = dict(step, source="판단")
    details = [str(step.get("why") or "")]
    for key in ("owner", "trigger", "check", "preserve", "alternative"):
        if step.get(key) and str(step[key]).strip() != NOT_APPLICABLE:
            details.append("{}: {}".format(PLAN_FIELDS[key], step[key]))
    row["why"] = " | ".join(part for part in details if part)
    gaps = step.get("review_gaps") or plan_gaps(step)
    row["review_gaps"] = gaps
    row["readiness"] = "review_required" if gaps else "specified"
    if gaps:
        row["why"] += " | 실행 전 보완: " + ", ".join(gaps)
    row["done"] = step.get("done") or "완료 기준 미정: 담당자가 범위·검증 방법을 정한 뒤 실행합니다."
    return row


def prepare_queries(response):
    """Check generated as well as template KQL. Never claim tenant execution."""
    if not response:
        return
    kept, rejected = [], []
    for original in response.get("kql") or []:
        candidate = dict(original)
        # validate_kql normalizes time filters; preserve the operational window.
        probe = dict(candidate)
        ok, reason, _ = pattern_synth.validate_kql(probe)
        if not ok:
            rejected.append({"name": candidate.get("name") or "쿼리", "reason": reason})
            continue
        query = str(candidate.get("query") or "")
        tables = sorted(t for t in pattern_synth.KQL_TABLES
                        if re.search(r"\b" + re.escape(t) + r"\b", query))
        candidate["validation"] = {"syntax": "basic_checks_passed", "execution": "not_run",
                                   "required_tables": tables}
        note = str(candidate.get("note") or "")
        marker = "사내 실행 미검증."
        if marker not in note:
            note += " " + marker + " 필요한 테이블: " + ", ".join(tables) + ". "
            note += "양성 결과는 원본 이벤트·프로세스를 대조하고, 0건은 수집 범위·보존 기간·센서 상태를 확인합니다. "
            note += ("TVM 미사용 시 CMDB·SBOM과 벤더 영향 버전을 대조합니다."
                     if any("Tvm" in t for t in tables) else
                     "해당 테이블이 없으면 EDR·SIEM 원본 로그에서 같은 필드와 기간을 대조합니다.")
        candidate["note"] = note.strip()
        kept.append(candidate)
    response["kql"] = kept
    if rejected:
        response["query_review"] = rejected


def assessment(block, informational=None):
    """Measure observable completeness, not factual truth or incident severity."""
    if informational is None:
        informational = article_kind.is_informational(block)
    synthesis = block.get("synthesis") or {}
    plans = synthesis.get("plan") or []
    queries = (block.get("response") or {}).get("kql") or []
    status = block.get("lookup_status") or []
    issues = []
    if not synthesis:
        issues.append("종합 판단 없음")
    # 정보성 기사는 할 일이 없을 수 있다 — 판단 프롬프트가 "관련 없으면 빈 배열"을
    # 허용한다. 그것을 결함으로 세면 억지 과제를 만들게 된다.
    if not plans and not informational:
        issues.append("대응 계획 없음")
    incomplete = sum(bool(plan_gaps(step, informational)) for step in plans)
    if incomplete:
        issues.append("실행 조건·대안·완료 기준 등 보완 필요: {}개 조치".format(incomplete))
    unsafe_closure = sum(bool(ZERO_CLOSE_RE.search(str(p.get("done") or ""))) and
                         not QUALIFIED_NEGATIVE_RE.search(str(p.get("done") or "")) for p in plans)
    if unsafe_closure:
        issues.append("0건만으로 종결하는 기준: {}개".format(unsafe_closure))
    # unavailable은 "응답 없음·조회할 입력 없음"이지 실패가 아니다(investigation의
    # lookup_status detail도 미탐지와 구분한다고 적는다). 그것까지 세다가 카테나-X 건에서
    # 조회 대상이 없던 취약점·공급망 트랙이 "실패·부분 조회: 2개"로 찍혔다.
    failures = [item for item in status if item.get("status") in ("failed", "partial")]
    if failures:
        issues.append("실패·부분 조회: {}개".format(len(failures)))
    if not status:
        issues.append("구조화된 조회 상태 미기록")
    return {"version": VERSION, "basis": "산출물 완결성 점검이며 사실 검증·침해 확정 점수가 아닙니다.",
            "article_kind": article_kind.INFORMATIONAL if informational else article_kind.THREAT,
            "plan_count": len(plans), "incomplete_plans": incomplete,
            "unqualified_zero_closures": unsafe_closure, "query_count": len(queries),
            "internally_executed_queries": sum((q.get("validation") or {}).get("execution") == "executed" for q in queries),
            "issues": issues, "internal_telemetry": "not_connected"}


def finalize(block, targets):
    informational = article_kind.is_informational(block) or article_kind.is_informational(targets or {})
    prepare_queries(block.get("response"))
    cover = playbook.coverage(block, (targets or {}).get("criteria"))
    if cover:
        block["coverage"] = cover
    else:
        # 기준을 비운 뒤 다시 돌려도 옛 "미달" 칩이 남던 문제 — 대조할 선언이 없으면
        # 이전 대조 결과도 근거가 없다.
        block.pop("coverage", None)
    block["quality"] = assessment(block, informational)
    # Replace the provisional count after follow-ups and blocklist review.
    steps = [s for s in block.get("steps") or [] if s.get("track") != "최종 점검"]
    steps = [s for s in steps if not (s.get("track") == "산출물 점검" and
             (str(s.get("text") or "").startswith("목표를 세울 때") or
              str(s.get("text") or "").startswith("· 미달:")))]
    steps.extend({"track": "최종 점검", "text": line} for line in playbook.coverage_steps(cover))
    if informational:
        closing = "공격 사건 기사가 아니어서 사내 로그 조회·차단·격리와 탐지 쿼리는 만들지 않았습니다."
    else:
        closing = "사내 로그 조회·차단·격리는 수행하지 않았습니다."
        # 쿼리가 하나도 없는데 "쿼리는 …조사 후보입니다"를 붙이면 없는 산출물을 설명하게
        # 된다. pattern_synth의 MDE KQL 패턴도 같은 로컬 점검만 거친 후보라 함께 센다.
        if block["quality"]["query_count"] or any(
                isinstance(p, dict) and p.get("platform") == "mde_kql"
                for p in block.get("patterns") or []):
            closing += " 쿼리는 로컬 형식 점검만 거친 조사 후보입니다."
    steps.append({"track": "최종 점검", "text": closing})
    steps.extend({"track": "최종 점검", "text": line} for line in block["quality"]["issues"])
    block["steps"] = steps
