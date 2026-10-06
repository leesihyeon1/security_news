"""Check whether a stated investigation goal has the kind of evidence it needs."""

import re
import analysis_trace
import browser_research


WEB_RE = re.compile(r"clickfix|유포지|가짜.{0,5}(?:캡차|인증)|클립보드|붙여넣|웹.{0,4}패턴", re.I)
PATTERN_RE = re.compile(r"패턴|공통|다른.{0,5}유포지|탐지\s*룰|urlscan", re.I)
MALWARE_RE = re.compile(r"동적\s*분석|샌드박스|샘플.{0,12}(?:행위|통신)|c2|지속성|지속화|예약.?작업|AMSI|ntdll|\bRAT\b|레지스트리", re.I)
PATCH_RE = re.compile(r"(?:패치|수정|안전).{0,8}버전|버전.{0,8}(?:패치|수정|안전)", re.I)


def _browser_facts(block, question=""):
    results = ((block or {}).get("browser_research") or {}).get("results") or []
    results = [row for row in results if not row.get("questions") or question in row["questions"]]
    live = next((row.get("evidence") or {} for row in results
                 if row.get("source") == "isolated_browser" and row.get("status") == "observed"), {})
    archived = [row.get("evidence") or {} for row in results
                if row.get("source") == "archived_scan" and row.get("status") == "observed"]
    commands = live.get("clipboard") or []
    http_after = [row for row in live.get("responses") or []
                  if row.get("phase") == "after" and row.get("status") == 200]
    confirmed = ((live.get("after") or {}).get("dom_status") == "confirmed"
                 and any(row.get("executable") and row.get("destinations") for row in commands))
    return {"live": live, "archived": archived, "confirmed": confirmed,
            "http_after": http_after}


def _web_review(question, block):
    """Return an evidence ceiling, not an assertion that the article's claim is true."""
    question = str(question or "")
    block = block or {}
    if browser_research.is_web_question(question):
        facts = _browser_facts(block, question)
        shared = (block.get("shared_web_fingerprints") or [])
        is_pattern = bool(PATTERN_RE.search(question))
        ids = [row.get("evidence_id") for row in facts["archived"]]
        if facts["live"].get("evidence_id"):
            ids.append(facts["live"]["evidence_id"])
        ids = [item for item in ids if item]
        # 같은 플랫폼의 다른 콘텐츠(platform_baseline)도 비교군으로 인정한다 — 정상 확정은
        # 아니지만 플랫폼 공통 요청을 캠페인 특징에서 걸러내는 데는 충분하다.
        controls = [c for c in block.get("negative_controls") or []
                    if c.get("label") in ("benign_confirmed", "platform_baseline")]
        linked = [seed for seed in block.get("seeds") or []
                  if seed.get("linked_from") and seed.get("in_urlscan")]
        if facts["confirmed"] and facts["http_after"] and (not is_pattern or (shared and controls)):
            return {"ceiling": "answered", "basis": "클릭 후 DOM·복사 명령·HTTP 관측",
                    "missing": "", "evidence_ids": ids}
        missing = []
        if not facts["confirmed"]:
            missing.append("명령 복사와 화면 안내가 연결된 현재 DOM")
        if not facts["http_after"]:
            missing.append("클릭 후 HTTP 응답")
        if is_pattern and not shared:
            missing.append("서로 다른 유포지에서 반복된 구조")
        if is_pattern and not controls:
            missing.append("정상 비교군의 오탐 검증")
        if re.search(r"공유|custom\s*gpt|chatgpt|채팅|연결|리다이렉트", question, re.I) and not linked:
            missing.append("개별 콘텐츠 응답에서 외부 유인 페이지로 이어지는 링크·전환")
        has_observation = bool(facts["live"] or facts["archived"])
        return {"ceiling": "partial" if has_observation else "open",
                "basis": "저장 스캔 또는 제한된 브라우저 관측" if has_observation else "관측 없음",
                "missing": ", ".join(missing), "evidence_ids": ids}
    return None


def _malware_review(question, block):
    if MALWARE_RE.search(question):
        files = ((block.get("malware") or {}).get("files") or [])
        wanted = re.findall(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", question, re.I)
        if wanted:
            files = [row for row in files if str(row.get("hash") or "").lower() in {v.lower() for v in wanted}]
        required = []
        if re.search(r"c2|통신|네트워크", question, re.I):
            required.append(("샘플의 네트워크 목적지·요청", ("dns", "ip_traffic", "http", "http_details")))
        if re.search(r"지속성|지속화|예약.?작업|레지스트리", question):
            required.append(("지속성 관련 레지스트리·예약 작업 행위", ("registry", "commands")))
        if re.search(r"프로세스|실행|동적|샌드박스", question):
            required.append(("샘플 프로세스·실행 행위", ("processes", "commands")))
        if not required:
            required.append(("질문에 해당하는 샘플 행위", ("processes", "commands", "http", "registry")))
        observed, missing = [], set()
        for row in files:
            behaviour = row.get("behaviour") or {}
            row_missing = [label for label, keys in required if not any(behaviour.get(key) for key in keys)]
            if not row_missing:
                observed.append(row)
            missing.update(row_missing)
        # These capabilities need a specific analyst interpretation, not just a nonempty report.
        specific = re.search(r"AMSI|ntdll|우회|운영자|프로토콜|오디오|캠페인|C2.{0,8}확정", question, re.I)
        if specific:
            missing.add("특정 기능·귀속을 입증할 행위와 원문 대조")
        if observed and not specific:
            return {"ceiling": "answered", "basis": "외부 샌드박스 행위 관측(VirusTotal 보고 · 자체 실행 아님)",
                    "missing": "", "evidence_ids": [str(row.get("hash") or "") for row in observed[:2]]}
        return {"ceiling": "partial" if files else "open", "basis": "외부 샌드박스 보고 일부(자체 실행 아님)" if files else "샘플 미확보 — 원문 서술만 있음",
                "missing": ", ".join(sorted(missing)) or "실제 샘플의 프로세스·네트워크 행위", "evidence_ids": []}
    return None


def review(question, block):
    question, block = str(question or ""), block or {}
    if browser_research.INTERNAL_QUESTION_RE.search(question):
        # 사내 로그 질문은 외부 조회를 더 돌려도 풀리지 않는다 — 재조사 대상에서 빼고
        # "사내 확인 필요"로 남긴다.
        return {"ceiling": "open", "basis": "사내 로그 확인 필요(외부 조회 범위 밖)",
                "missing": "", "internal": True, "evidence_ids": []}
    checks = [check for check in (_web_review(question, block), _malware_review(question, block)) if check]
    if checks:
        rank = {"open": 0, "partial": 1, "answered": 2}
        return {"ceiling": min(checks, key=lambda check: rank[check["ceiling"]])["ceiling"],
                "basis": "; ".join(check["basis"] for check in checks),
                "missing": "; ".join(check["missing"] for check in checks if check["missing"]),
                "evidence_ids": list(dict.fromkeys(v for check in checks for v in check["evidence_ids"]))}
    if PATCH_RE.search(question):
        entries = (block.get("vulnerability") or {}).get("cves") or []
        fixed = [row for row in entries if row.get("fixed_versions")]
        return {"ceiling": "answered" if fixed else "partial" if entries else "open",
                "basis": "수정 버전 명시" if fixed else "취약점 조회" if entries else "조회 없음",
                "missing": "" if fixed else "벤더 공지의 수정된 안전 버전",
                "evidence_ids": [row.get("cve") for row in fixed if row.get("cve")]}
    return None


@analysis_trace.step("목표별 답변과 실제 관측 근거 대조", "verify", "validation", inputs=("verdict",))
def reconcile(verdict, block):
    """Downgrade unsupported 'answered' claims; keep the model's grounded answer text."""
    checks = []
    for row in (verdict or {}).get("question_status") or []:
        check = review(row.get("question"), block)
        if check is None:
            continue
        rank = {"open": 0, "partial": 1, "answered": 2}
        if rank.get(row.get("status"), 0) > rank[check["ceiling"]]:
            row["status"] = check["ceiling"]
        row["missing"] = check["missing"]
        row["evidence_basis"] = check["basis"]
        checks.append({"question": row.get("question"), "status": row.get("status") or "open",
                       **check})
    if checks:
        block["goal_evidence"] = checks
    return checks
