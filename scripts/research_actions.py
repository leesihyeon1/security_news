# -*- coding: utf-8 -*-
"""목표별로 모자란 증거를 보고 다음 조사를 고르고 실행한다.

왜 따로 두나
    조사 원장(research_plan)과 목표별 증거 검증(goal_evidence)은 "무엇이 모자란가"를
    적기만 했다. 후속 라운드는 여전히 판단이 요청한 지표와 질문 키워드 검색만 돌아서,
    "개별 GPT에서 외부 유인 페이지로 이어지는지"가 모자라다고 적어 놓고도 그 링크를
    따라가 보지 않았다(실측 2026-10-02, ChatGPT Custom GPTs ClickFix 건). 여기서는
    모자란 증거의 종류마다 정해진 조사 행동을 고르고, 같은 입력으로 같은 행동을 두 번
    하지 않도록 시도 이력을 남긴다.

무엇을 하지 않나
    샘플을 직접 실행하지 않는다(격리 분석 환경 범위 밖). 조회 성공을 목표 해결로
    보지 않는다 — 실행 결과는 goal_evidence.reconcile이 다시 판정한다.
"""

import os
import re
import analysis_trace
import urllib.parse

import research_entities

MAX_ACTIONS_PER_ROUND = 4
MAX_LINKS_TO_FOLLOW = 2
MAX_BASELINE_HOSTS = 2
BASELINES_PER_HOST = 2
MAX_EXTRA_HASHES = 2
HASH_TYPES = ("sha256", "sha1", "md5")

# goal_evidence가 남기는 "남은 확인" 문구 → 그 증거를 얻는 행동.
ACTION_RULES = (
    (re.compile(r"외부 유인 페이지|링크·전환|서로 다른 유포지"), "follow_links"),
    (re.compile(r"정상 비교군"), "platform_baseline"),
    (re.compile(r"현재 DOM|클릭 후 HTTP"), "exact_scan"),
    (re.compile(r"네트워크 목적지|프로세스·실행|지속성 관련|샘플 미확보|질문에 해당하는 샘플 행위|"
                r"실제 샘플의"), "more_samples"),
)
ACTION_LABELS = {
    "follow_links": "공유 콘텐츠의 외부 링크 추적",
    "platform_baseline": "같은 플랫폼 정상 비교군 수집",
    "exact_scan": "개별 URL 공개 스캔 확인",
    "more_samples": "추가 샘플 행위 조회",
}


def _attempt_key(action, value):
    return "{}|{}".format(action, str(value or "").lower())


def plan_actions(block, attempted=()):
    """모자란 증거에서 이번 라운드에 할 행동 목록을 만든다.

    반환: [{"task_id","goal","action","reason"}] — 입력값은 실행 시점에 고른다(그때까지
    새 시드·해시가 생길 수 있어서).
    """
    block = block or {}
    tasks = {task.get("goal"): task for task in block.get("research_plan") or []}
    chosen, seen = [], set()
    for check in block.get("goal_evidence") or []:
        if check.get("status") == "answered":
            continue
        missing = str(check.get("missing") or "")
        task = tasks.get(check.get("question")) or {}
        for pattern, action in ACTION_RULES:
            if not pattern.search(missing) or action in seen:
                continue
            seen.add(action)
            chosen.append({"task_id": task.get("id") or "", "goal": check.get("question") or "",
                           "action": action, "reason": missing})
    # 공유 플랫폼 콘텐츠가 유포 출발점이면, 검증 질문이 어떻게 쓰였든 다음 단계 연결과
    # 플랫폼 공통 특징 제거는 기본으로 확인한다(실측 2026-10-02: 질문 5개가 모두 사내 로그
    # 질문이라 Custom GPT → Google Sites 연결을 아무도 확인하지 않았다).
    if any(research_entities.shared(seed.get("domain")) for seed in block.get("seeds") or []):
        web_task = next((t for t in block.get("research_plan") or []
                         if re.search(r"유포|연결|유인|clickfix|gpt|페이지", str(t.get("goal") or ""), re.I)
                         and not re.search(r"로그에서|엔드포인트에서|포렌식", str(t.get("goal") or ""))), {})
        for action, reason in (("follow_links", "공유 콘텐츠에서 다음 단계 페이지로 이어지는 연결 확인"),
                               ("platform_baseline", "공유 플랫폼 공통 특징을 캠페인 특징에서 제외")):
            if action not in seen:
                seen.add(action)
                chosen.append({"task_id": web_task.get("id") or "", "goal": web_task.get("goal") or "",
                               "action": action, "reason": reason})
    return chosen[:MAX_ACTIONS_PER_ROUND]


def _external_links(seeds):
    """공유 플랫폼 콘텐츠에서 밖으로 나가는 링크. 같은 플랫폼 내비게이션은 뺀다."""
    out = []
    for seed in seeds or []:
        host = str(seed.get("domain") or "").lower()
        if not research_entities.shared(host):
            continue
        for link in seed.get("outgoing_links") or []:
            url = research_entities.web_url(link)
            if not url:
                continue
            link_host = (urllib.parse.urlsplit(url).hostname or "").lower()
            # 같은 플랫폼의 메뉴·로그인 링크는 유인 경로가 아니다. 다른 공유 플랫폼
            # (sites.google.com 등)은 개별 콘텐츠 URL일 때만 따라간다.
            if link_host == host or link_host.endswith("." + host):
                continue
            if research_entities.shared(link_host) and not research_entities.content_url(url):
                continue
            out.append({"url": url, "from": seed.get("target_url") or host})
    return out


def _text_links(block, evidence_text):
    """원문·1차 자료에 적힌 공유 플랫폼 콘텐츠 URL(sites.google.com/view/... 등).

    저장 스캔에는 로그인 뒤 대화 응답이 남지 않아 GPT 페이지 DOM에서 외부 링크가 0건인
    경우가 많다(실측 2026-10-02). 그때는 연구 원문이 밝힌 다음 단계 URL을 따라간다.
    """
    seeds = {research_entities.web_url(seed.get("target_url")) for seed in block.get("seeds") or []
             if seed.get("target_url")}
    seed_hosts = {str(seed.get("domain") or "").lower() for seed in block.get("seeds") or []}
    # 경로가 한 단계뿐인 주소(chatgpt.com/create, /pricing 등)는 서비스 안내 페이지다. 개별
    # 콘텐츠는 /g/<id>, /view/<id>처럼 두 단계 이상이다.
    rows = [{"url": url, "from": "원문 서술"} for url in research_entities.shared_urls(evidence_text)
            if url not in seeds
            and len([part for part in urllib.parse.urlsplit(url).path.split("/") if part]) >= 2]
    # 시드와 다른 플랫폼(GPT → Google Sites)이 다음 단계다. 같은 플랫폼의 다른 주소
    # (chatgpt.com/create 같은 안내 링크)는 뒤로 미룬다.
    return sorted(rows, key=lambda row: (urllib.parse.urlsplit(row["url"]).hostname or "") in seed_hosts)


def follow_links(block, api_key, attempted, lure_hunter, evidence_text=""):
    candidates = _external_links(block.get("seeds")) or _text_links(block, evidence_text)
    links = [row for row in candidates
             if _attempt_key("follow_links", row["url"]) not in attempted][:MAX_LINKS_TO_FOLLOW]
    if not links:
        return [], "따라갈 외부 링크가 없습니다(공유 콘텐츠 DOM·원문 모두에서 다음 단계 URL 미관측)."
    for row in links:
        attempted.add(_attempt_key("follow_links", row["url"]))
    track = lure_hunter.investigation_for_iocs(
        [{"type": "url", "value": row["url"]} for row in links], api_key=api_key,
        max_seeds=len(links))
    new_seeds = []
    known = {str(seed.get("target_url") or seed.get("domain") or "").lower()
             for seed in block.get("seeds") or []}
    origin = {row["url"]: row["from"] for row in links}
    for seed in (track or {}).get("seeds") or []:
        key = str(seed.get("target_url") or seed.get("domain") or "").lower()
        if key in known:
            continue
        seed["linked_from"] = origin.get(seed.get("target_url") or "", "")
        new_seeds.append(seed)
    if new_seeds:
        block["seeds"] = list(block.get("seeds") or []) + new_seeds
    lines = []
    for seed in new_seeds:
        lines.append("{} → {}: 공개 스캔 {}, DOM {}".format(
            seed.get("linked_from") or "공유 콘텐츠", seed.get("target_url") or seed.get("domain"),
            "있음" if seed.get("in_urlscan") else "없음(미확인 — 정상으로 보지 않음)",
            "ClickFix 표식 확인" if seed.get("dom_confirmed") else "표식 미확인"))
    return lines, "외부 링크 {}건을 개별 URL로 확인했습니다.".format(len(links))


# urlscan에는 의심 페이지가 많이 올라온다. 비교군에 피싱 페이지가 섞이면 진짜 캠페인
# 특징까지 "플랫폼 공통"으로 지워진다(실측 2026-10-02: sites.google.com 비교군 1위가
# sign--in--scotia 광고 유입 페이지였다).
SUSPICIOUS_BASELINE_RE = re.compile(
    r"sign|log-?in|verif|captcha|antibot|secure|account|wallet|bank|update|recover|gad_|gclid|utm_", re.I)


def _suspicious_baseline(row, url):
    verdicts = row.get("verdicts") or {}
    overall = verdicts.get("overall") or verdicts.get("urlscan") or {}
    if verdicts.get("malicious") or overall.get("malicious") or (overall.get("score") or 0) > 0:
        return True
    return bool(SUSPICIOUS_BASELINE_RE.search(url or ""))


def platform_baseline(block, api_key, attempted, lure_hunter):
    """같은 공유 플랫폼의 다른 공개 스캔을 비교군으로 모은다.

    이 비교군은 "정상이 확인된" 페이지가 아니라 "같은 플랫폼의 다른 콘텐츠"다. 플랫폼
    공통 요청(예: chatgpt.com의 flush?lightweight_authenticated=)을 캠페인 특징에서
    걸러내는 용도로만 쓴다.
    """
    # 워커는 키를 넘기지 않고 각 헌터가 환경변수에서 읽는다 — 여기서도 같은 자리를 본다.
    api_key = api_key or os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return [], "URLSCAN_API_KEY가 없어 비교군을 수집하지 못했습니다."
    seeds = block.get("seeds") or []
    hosts = list(dict.fromkeys(str(seed.get("domain") or "").lower() for seed in seeds
                               if research_entities.shared(seed.get("domain"))))
    hosts = [h for h in hosts if _attempt_key("platform_baseline", h) not in attempted]
    hosts = hosts[:MAX_BASELINE_HOSTS]
    if not hosts:
        return [], "비교군이 필요한 공유 플랫폼 시드가 없습니다."
    seed_urls = {research_entities.web_url(seed.get("target_url")) for seed in seeds
                 if seed.get("target_url")}
    controls = list(block.get("negative_controls") or [])
    for host in hosts:
        attempted.add(_attempt_key("platform_baseline", host))
        results, _total = lure_hunter.urlscan_search('page.domain:"{}"'.format(host),
                                                     size=10, api_key=api_key)
        picked = 0
        for row in results or []:
            url = ((row.get("page") or {}).get("url") or (row.get("task") or {}).get("url") or "")
            if (not row.get("_id") or research_entities.web_url(url) in seed_urls
                    or row["_id"] in {c.get("uuid") for c in controls}
                    or research_entities.web_url(url) in {research_entities.web_url(c.get("url"))
                                                          for c in controls}
                    or _suspicious_baseline(row, url)):
                continue
            facts = lure_hunter.resource_facts(row["_id"], host, api_key)
            if not facts or not facts.get("http"):
                continue
            controls.append({"label": "platform_baseline", "host": host, "url": url,
                             "uuid": row["_id"], "http": facts["http"]})
            picked += 1
            if picked >= BASELINES_PER_HOST:
                break
    block["negative_controls"] = controls
    count = sum(1 for c in controls if c.get("host") in hosts)
    lines = ["{} 비교군 {}건: 같은 플랫폼의 다른 콘텐츠 스캔(정상 확정 아님) — 공통 요청은 캠페인 "
             "특징에서 뺍니다.".format(host, sum(1 for c in controls if c.get("host") == host))
             for host in hosts]
    return lines, "공유 플랫폼 {}곳의 비교군 {}건을 수집했습니다.".format(len(hosts), count)


def exact_scan(block, api_key, attempted, lure_hunter):
    """DOM·HTTP가 모자란 개별 URL의 공개 스캔 이력을 다시 찾는다."""
    targets = []
    for seed in block.get("seeds") or []:
        url = seed.get("target_url") or ""
        if url and not seed.get("in_urlscan") and _attempt_key("exact_scan", url) not in attempted:
            targets.append(url)
    if not targets:
        return [], "다시 확인할 미관측 개별 URL이 없습니다."
    lines = []
    for url in targets[:MAX_LINKS_TO_FOLLOW]:
        attempted.add(_attempt_key("exact_scan", url))
        facts = lure_hunter.seed_facts(url, api_key=api_key)
        if facts and facts.get("uuid"):
            lines.append("{} — 공개 스캔 {}건 확인(최근 {}).".format(
                url, facts.get("scan_count") or 1, facts.get("scanned_at") or "-"))
        else:
            lines.append("{} — 개별 URL 공개 스캔 없음. 삭제·로그인·비공개 가능성이 있어 미확인으로 "
                         "둡니다.".format(url))
    return lines, "개별 URL {}건의 공개 스캔을 다시 확인했습니다.".format(len(lines))


def more_samples(block, iocs, attempted, run_hash):
    """아직 행위를 보지 않은 해시를 역할 순서대로 추가 조회한다."""
    analysed = {str(f.get("hash") or "").lower() for f in (block.get("malware") or {}).get("files") or []}
    hashes = [str(item.get("value") or "").lower() for item in iocs or []
              if str(item.get("type") or "").lower() in HASH_TYPES]
    hashes = [h for h in dict.fromkeys(hashes)
              if h not in analysed and _attempt_key("more_samples", h) not in attempted]
    ordered = research_entities.sample_order(hashes, evidence="", limit=MAX_EXTRA_HASHES)
    if not ordered:
        return [], "행위를 아직 보지 않은 추가 샘플이 없습니다."
    for value in ordered:
        attempted.add(_attempt_key("more_samples", value))
    lines = run_hash(ordered)
    return lines, "추가 샘플 {}건의 외부 샌드박스 행위를 조회했습니다(자체 실행 아님).".format(len(ordered))


@analysis_trace.step("미확인 목표 재조사: 링크·샘플·비교 조회", "followup", inputs=("iocs", "attempted", "evidence_text"))
def execute(block, iocs, api_key, run_hash, attempted=None, lure_hunter=None, evidence_text=""):
    """plan_actions의 행동을 실행한다. (증거 줄, 단계 줄)을 돌려준다.

    run_hash: 해시 목록을 받아 외부 샌드박스 결과 줄을 돌려주는 함수(investigation의
    _run_followups를 감싼 것). lure_hunter는 테스트에서 바꿔 끼울 수 있게 받는다.
    """
    if lure_hunter is None:
        import lure_hunter as module
        lure_hunter = module
    attempted = attempted if attempted is not None else set(block.get("research_attempt_keys") or [])
    actions = plan_actions(block, attempted)
    lines, steps = [], []
    log_rows = block.setdefault("research_attempts", [])
    for item in actions:
        action = item["action"]
        try:
            if action == "follow_links":
                found, note = follow_links(block, api_key, attempted, lure_hunter, evidence_text)
            elif action == "platform_baseline":
                found, note = platform_baseline(block, api_key, attempted, lure_hunter)
            elif action == "exact_scan":
                found, note = exact_scan(block, api_key, attempted, lure_hunter)
            else:
                found, note = more_samples(block, iocs, attempted, run_hash)
            status = "observed" if found else "no_input"
        except Exception as error:
            found, note, status = [], "실행 실패: {}".format(type(error).__name__), "failed"
        log_rows.append({"task_id": item["task_id"], "goal": item["goal"], "action": action,
                         "label": ACTION_LABELS[action], "reason": item["reason"],
                         "status": status, "result": note, "observations": found[:6]})
        steps.append("{} — {} ({})".format(ACTION_LABELS[action], note, item["task_id"] or "목표"))
        lines.extend(found)
    block["research_attempt_keys"] = sorted(attempted)
    for task in block.get("research_plan") or []:
        task["attempts"] = [row for row in log_rows if row.get("task_id") == task.get("id")]
    return lines, steps


# --- 검색식 등급 ---------------------------------------------------------------
TIER_LABELS = {"lookup": "조회용", "discovery": "확장 후보", "validated": "검증된 탐지식"}


def _query_values(query):
    return {value.lower() for value in re.findall(r'"([^"]+)"', str(query or ""))}


def assign_tiers(block):
    """검색식을 조회용·확장 후보·검증된 탐지식으로 나눈다.

    - 조회용: 이미 알려진 정확한 URL·파일·해시·도메인을 찾는다(새 유포지를 찾지 않는다).
    - 검증된 탐지식: DOM 확인된 서로 다른 유포지 2곳 이상에서 반복되고, 같은 플랫폼
      비교군에는 없는 요청 구조(shared_web_fingerprints)를 쓴 검색식.
    - 나머지는 확장 후보 — 결과가 나와도 탐지 근거가 아니다.
    """
    block = block or {}
    known = set()
    for seed in block.get("seeds") or []:
        for value in (seed.get("domain"), seed.get("target_url")):
            if value:
                known.add(str(value).lower())
    for item in block.get("indicator_assessments") or []:
        if item.get("value"):
            known.add(str(item["value"]).lower())
    controls = [c for c in block.get("negative_controls") or []
                if c.get("label") in ("benign_confirmed", "platform_baseline")]
    validated = set()
    if controls:
        for fact in block.get("shared_web_fingerprints") or []:
            path = str(fact.get("path") or "")
            if path:
                validated.add(path.rsplit("/", 1)[-1].lower() + "?" if fact.get("query_keys") else path.lower())

    def tier(query):
        values = _query_values(query)
        if any(name and any(name in value for value in values) for name in validated):
            return "validated"
        if values and values <= known:
            return "lookup"
        return "discovery"

    counts = {}
    for seed in block.get("seeds") or []:
        for row in seed.get("queries") or []:
            row["tier"] = tier(row.get("query"))
            row["tier_label"] = TIER_LABELS[row["tier"]]
            if row["tier"] == "validated":
                row["validation"] = "validated"
            elif row.get("validation") == "validated":
                row["validation"] = "unverified"
            counts[row["tier"]] = counts.get(row["tier"], 0) + 1
    for pattern in block.get("patterns") or []:
        if pattern.get("platform") != "urlscan":
            continue
        pattern["tier"] = tier(pattern.get("query"))
        pattern["tier_label"] = TIER_LABELS[pattern["tier"]]
        if pattern["tier"] != "validated" and pattern.get("validation_status") == "validated":
            pattern["validation_status"] = "candidate"
        counts[pattern["tier"]] = counts.get(pattern["tier"], 0) + 1
    return counts
