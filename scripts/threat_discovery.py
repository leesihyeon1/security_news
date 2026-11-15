"""AI Discovery: find emerging threats in the collected articles and vet them before showing.

Each candidate goes through the same five steps, and the result records every step:

  1. 탐색  (code)  every statistical detector runs; nothing is sampled
  2. 가설  (LLM)   what is happening, as claims that each cite evidence articles
  3. 검토  (LLM)   a separate skeptical pass tries to refute each claim
  4. 확정  (LLM)   a verdict and response guidance written from the surviving claims only
  5. 검증  (code)  hard rules the model cannot override (sources, cited evidence, unknown CVEs)

Only public article fields are sent to the model. Triage levels, importance scores,
matched assets and PIRs are never read.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import threat_dashboard as td

RELATIVE_OUTPUT = "dashboard/data/threat-discovery.json"
CACHE_NAME = "threat_discovery_cache.json"
WINDOW_DAYS = 7
BASELINE_WEEKS = 4
TREND_WEEKS = 6
MIN_ARTICLES = 3
MIN_SOURCES = 2
SPIKE_RATIO = 2.5
MAX_CANDIDATES = 12
MAX_EVIDENCE = 10
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
DIMENSIONS = (("actors", "위협 그룹"), ("malware", "악성코드"), ("products", "제품"))
VERDICTS = ("confirmed", "watch", "rejected")
EVENT_TYPES = ("취약점 악용", "공격 캠페인", "악성코드 유포", "침해·유출 사고", "공급망 공격", "기타")


# ── 1. 탐색 ───────────────────────────────────────────────────────────────────
def detect(threats, end):
    """All spike and exploited-CVE signals of the last week, before any merging."""
    since = end - timedelta(days=WINDOW_DAYS - 1)
    base_from = since - timedelta(days=7 * BASELINE_WEEKS)
    recent = [a for a in threats if a["day"] >= since]
    signals = []
    for field, label in DIMENSIONS:
        display, current, baseline = {}, {}, Counter()
        for article in threats:
            for name in article[field]:
                key = name.casefold()
                if article["day"] >= since:
                    display.setdefault(key, name)
                    current.setdefault(key, []).append(article)
                elif article["day"] >= base_from:
                    baseline[key] += 1
        for key, rows in current.items():
            usual = baseline[key] / BASELINE_WEEKS
            if (len(rows) >= MIN_ARTICLES and len({a["source"] for a in rows}) >= MIN_SOURCES
                    and len(rows) >= SPIKE_RATIO * max(usual, 0.5)):
                signals.append({"kind": "spike", "field": field, "label": label, "name": display[key],
                                "current": len(rows), "usual": round(usual, 1), "articles": rows})
    by_cve = {}
    for article in recent:
        if article["status"] == "active" or article["kev"]:
            for cve in article["cves"]:
                by_cve.setdefault(cve, []).append(article)
    for cve, rows in by_cve.items():
        if len(rows) >= MIN_ARTICLES and len({a["source"] for a in rows}) >= MIN_SOURCES:
            signals.append({"kind": "exploited", "field": "cves", "label": "악용 취약점", "name": cve,
                            "current": len(rows), "usual": None, "articles": rows})
    return signals


def merge_signals(signals):
    """Signals that mostly share the same articles are one story (e.g. an actor and its malware)."""
    groups = []
    for signal in sorted(signals, key=lambda s: len(s["articles"]), reverse=True):
        urls = {a["url"] for a in signal["articles"]}
        home = next((g for g in groups if len(urls & g["urls"]) >= 0.6 * min(len(urls), len(g["urls"]))), None)
        if home is None:
            home = {"urls": set(), "signals": [], "articles": {}}
            groups.append(home)
        home["urls"] |= urls
        home["signals"].append(signal)
        home["articles"].update({a["url"]: a for a in signal["articles"]})
    return groups


def facts_of(group, threats, end):
    """Deterministic facts of a candidate, counted from its articles (never from the model)."""
    articles = sorted(group["articles"].values(), key=lambda a: (a["day"], a["collected"]), reverse=True)
    share = max(2, round(len(articles) * 0.3))

    def common(field, limit):
        counts = Counter(value for a in articles for value in a[field])
        return [value for value, n in counts.most_common(limit) if n >= min(share, len(articles))]

    lead = max(group["signals"], key=lambda s: (s["kind"] == "exploited", s["current"]))
    weeks = []
    for back in range(TREND_WEEKS - 1, -1, -1):
        hi = end - timedelta(days=7 * back)
        lo = hi - timedelta(days=6)
        key = lead["name"].casefold()
        weeks.append(sum(1 for a in threats if lo <= a["day"] <= hi and (
            lead["name"] in a["cves"] if lead["field"] == "cves" else key in {v.casefold() for v in a[lead["field"]]})))
    return {
        "signals": [{"type": s["label"], "name": s["name"], "current": s["current"], "usual": s["usual"]}
                    for s in group["signals"]],
        "lead": lead["name"], "trend": weeks, "articles": len(articles),
        "sources": sorted({a["source"] for a in articles}),
        "first_seen": min(a["day"] for a in articles).isoformat(),
        "last_seen": max(a["day"] for a in articles).isoformat(),
        "active_reports": sum(a["status"] == "active" for a in articles), "kev": any(a["kev"] for a in articles),
        "actors": common("actors", 4), "malware": common("malware", 4), "products": common("products", 6),
        "cves": common("cves", 6), "techniques": common("techniques", 6), "evidence": articles,
    }


def candidates(threats, end):
    groups = merge_signals(detect(threats, end))
    rows = [facts_of(group, threats, end) for group in groups]
    rows.sort(key=lambda f: (f["kev"], f["active_reports"], len(f["sources"]), f["articles"]), reverse=True)
    return rows[:MAX_CANDIDATES], len(groups)


# ── 2~4. 가설 · 검토 · 확정 ────────────────────────────────────────────────────
def evidence_block(articles):
    return "\n".join("[A{}] {} · {} · {}\n    {}".format(
        index, a["source"], a["day"].isoformat(), a["title"], a["summary"][:420] or "(요약 없음)")
        for index, a in enumerate(articles, 1))


def facts_block(facts):
    signals = "; ".join("{} '{}' 최근 7일 {}건{}".format(
        s["type"], s["name"], s["current"], "" if s["usual"] is None else "(평소 주간 {}건)".format(s["usual"]))
        for s in facts["signals"])
    return ("탐지 신호: {}\n보도 매체 {}곳, 기사 {}건, 첫 보도 {}, 실제 악용 보도 {}건, KEV {}\n"
            "기사에서 집계한 값 — 그룹: {} / 악성코드: {} / 제품: {} / CVE: {}").format(
        signals, len(facts["sources"]), facts["articles"], facts["first_seen"], facts["active_reports"],
        "등재" if facts["kev"] else "미등재", ", ".join(facts["actors"]) or "-", ", ".join(facts["malware"]) or "-",
        ", ".join(facts["products"]) or "-", ", ".join(facts["cves"]) or "-")


RULES = ("규칙: 아래 근거 기사에 적힌 내용만 사용한다. 기사에 없는 사실, CVE 번호, 제품 버전, 수치를 만들지 않는다. "
         "한국어로 쓴다(고유명사·CVE는 원문 표기). JSON 객체 하나만 출력한다.")


def hypothesis_prompt(facts, block):
    return """당신은 위협 인텔리전스 분석가다. 통계 탐지기가 아래 신호를 잡았다. 무슨 일이 일어나고 있는지 가설을 세워라.
{rules}

{facts}

근거 기사:
{block}

출력 형식:
{{"hypothesis": "무슨 일이 벌어지고 있는지 2문장", "event_type": "{types} 중 하나",
  "claims": [{{"text": "검증 가능한 주장 한 문장", "refs": ["A1"]}}],
  "noise_risk": "low|medium|high", "noise_reason": "홍보·회고·무관한 기사 묶음일 가능성과 이유"}}
claims는 3~6개. 각 주장은 반드시 그것을 뒷받침하는 기사 번호를 refs에 적는다.""".format(
        rules=RULES, facts=facts_block(facts), block=block, types=" | ".join(EVENT_TYPES))


def review_prompt(facts, block, hypothesis):
    claims = "\n".join("{}. {} (근거 {})".format(i, c["text"], ", ".join(c["refs"])) for i, c in enumerate(hypothesis["claims"]))
    return """당신은 다른 분석가의 결론을 반박하는 검토자다. 아래 가설과 주장을 근거 기사와 대조해 틀리거나 과장된 부분을 찾아라.
의심스러우면 지지하지 않는 쪽으로 판정한다.
{rules}

가설: {hypothesis}
주장:
{claims}

{facts}

근거 기사:
{block}

출력 형식:
{{"claims": [{{"index": 0, "supported": "yes|partial|no", "reason": "판정 이유 한 문장"}}],
  "single_event": true, "new_or_escalating": true,
  "problems": ["가설의 약점(없으면 빈 배열)"], "recommendation": "confirm|watch|reject"}}
single_event: 기사들이 하나의 사건·캠페인을 다루는가. new_or_escalating: 새로 나타났거나 최근 확대된 위협인가(단순 회고·제품 홍보·정기 패치 소개면 false).
recommendation: 실제 진행 중인 위협이고 근거가 충분하면 confirm, 근거가 약하거나 진행 여부가 불분명하면 watch, 위협 사건이 아니면 reject.""".format(
        rules=RULES, hypothesis=hypothesis["hypothesis"], claims=claims, facts=facts_block(facts), block=block)


def verdict_prompt(facts, block, supported, review):
    return """당신은 보안 대응 담당자에게 전달할 최종 판단을 쓰는 분석가다. 검토를 통과한 주장만 사용해 결론을 확정하라.
{rules}

검토를 통과한 주장:
{claims}
검토자 의견: 권고 {recommendation} / 약점: {problems}

{facts}

근거 기사:
{block}

출력 형식:
{{"verdict": "confirmed|watch|rejected", "confidence": "high|medium|low",
  "title": "위협을 한 줄로(40자 이내)", "summary": "무엇이 일어났는지 2~3문장",
  "why_now": "왜 지금 주목해야 하는지 1문장", "who_is_affected": "어떤 제품·환경을 쓰는 조직이 해당되는지 1문장",
  "actions": ["지금 할 조치(패치·차단·설정). 기사에 근거가 있는 것만, 최대 4개"],
  "detection": ["확인·탐지할 지점(로그, 계정, 프로세스 등). 기사에 근거가 있는 것만, 최대 3개"],
  "reason": "이 판정을 내린 이유 1문장"}}
기사에 조치나 탐지 근거가 없으면 해당 배열을 비운다.""".format(
        rules=RULES, claims="\n".join("- " + c for c in supported) or "- (없음)",
        recommendation=review.get("recommendation", "watch"), problems="; ".join(review.get("problems") or []) or "없음",
        facts=facts_block(facts), block=block)


def parse_json(text):
    if not text:
        return None
    match = re.search(r"\{.*\}", text, re.S)
    try:
        value = json.loads(match.group(0) if match else text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def clean(value, limit=400):
    return td.public_text(re.sub(r"\s+", " ", str(value or "")).strip())[:limit]


def investigate(facts, generate):
    """Run the three model steps for one candidate. Returns the staged record, or None if the model failed."""
    evidence = facts["evidence"][:MAX_EVIDENCE]
    block = evidence_block(evidence)
    valid_refs = {"A{}".format(i) for i in range(1, len(evidence) + 1)}

    hypothesis = parse_json(generate(hypothesis_prompt(facts, block)))
    if not hypothesis or not isinstance(hypothesis.get("claims"), list):
        return None
    claims = []
    for item in hypothesis["claims"][:6]:
        refs = [r for r in (item.get("refs") or []) if r in valid_refs] if isinstance(item, dict) else []
        if isinstance(item, dict) and item.get("text") and refs:   # a claim without evidence is not a claim
            claims.append({"text": clean(item["text"], 240), "refs": refs})
    if not claims:
        return None
    hypothesis = {"hypothesis": clean(hypothesis.get("hypothesis")), "claims": claims,
                  "event_type": hypothesis.get("event_type") if hypothesis.get("event_type") in EVENT_TYPES else "기타",
                  "noise_risk": hypothesis.get("noise_risk") if hypothesis.get("noise_risk") in ("low", "medium", "high") else "medium",
                  "noise_reason": clean(hypothesis.get("noise_reason"), 200)}

    review = parse_json(generate(review_prompt(facts, block, hypothesis)))
    if not review or not isinstance(review.get("claims"), list):
        return None
    judged = {}
    for item in review["claims"]:
        if isinstance(item, dict) and isinstance(item.get("index"), int):
            judged[item["index"]] = (item.get("supported") if item.get("supported") in ("yes", "partial", "no") else "no",
                                     clean(item.get("reason"), 200))
    for index, claim in enumerate(claims):
        claim["supported"], claim["review"] = judged.get(index, ("no", "검토자가 판정하지 않음"))
    review = {"single_event": bool(review.get("single_event")), "new_or_escalating": bool(review.get("new_or_escalating")),
              "problems": [clean(p, 200) for p in (review.get("problems") or [])[:4] if p],
              "recommendation": review.get("recommendation") if review.get("recommendation") in ("confirm", "watch", "reject") else "watch"}

    supported = [c["text"] for c in claims if c["supported"] == "yes"]
    final = parse_json(generate(verdict_prompt(facts, block, supported, review)))
    if not final:
        return None
    return {"hypothesis": hypothesis, "review": review, "final": final, "evidence": evidence}


# ── 5. 검증 ───────────────────────────────────────────────────────────────────
def settle(facts, record):
    """Apply the rules the model cannot override and build the published finding."""
    final, review, claims = record["final"], record["review"], record["hypothesis"]["claims"]
    verdict = final.get("verdict") if final.get("verdict") in VERDICTS else "watch"
    confidence = final.get("confidence") if final.get("confidence") in ("high", "medium", "low") else "low"
    checks = []

    def rule(name, passed, note):
        checks.append({"name": name, "passed": bool(passed), "note": note})
        return passed

    yes = sum(c["supported"] == "yes" for c in claims)
    known = {c.upper() for a in record["evidence"] for c in a["cves"]} | {
        c.upper() for a in record["evidence"] for c in CVE_RE.findall(a["title"] + " " + a["summary"])}
    fields = {key: clean(final.get(key)) for key in ("summary", "why_now", "who_is_affected", "reason")}
    lists = {key: [clean(v, 220) for v in (final.get(key) or [])[:limit] if v] for key, limit in (("actions", 4), ("detection", 3))}
    unknown = sorted({c.upper() for text in list(fields.values()) + lists["actions"] + lists["detection"]
                      for c in CVE_RE.findall(text)} - known)

    if not rule("검토자 권고", review["recommendation"] != "reject", "검토자 권고: " + review["recommendation"]):
        verdict = "rejected"
    if not rule("하나의 사건", review["single_event"], "기사들이 하나의 사건을 다룸" if review["single_event"] else "서로 다른 사건이 섞임"):
        verdict = "rejected" if verdict == "rejected" else "watch"
    if not rule("신규·확대 여부", review["new_or_escalating"], "새로 나타났거나 확대 중" if review["new_or_escalating"] else "회고·홍보·정기 공지로 판단"):
        verdict = "rejected"
    if not rule("주장 근거", yes >= max(2, len(claims) / 2), "주장 {}개 중 {}개가 기사로 확인됨".format(len(claims), yes)) and verdict == "confirmed":
        verdict = "watch"
    if not rule("복수 매체", len(facts["sources"]) >= 3, "보도 매체 {}곳".format(len(facts["sources"]))) and verdict == "confirmed":
        verdict = "watch"
    if not rule("근거 밖 CVE 없음", not unknown, "근거 기사에 없는 CVE: " + ", ".join(unknown) if unknown else "본문의 CVE가 모두 근거 기사에 있음"):
        # Text naming a CVE the evidence never mentions is dropped, not published.
        lists = {key: [v for v in rows if not any(c.upper() in unknown for c in CVE_RE.findall(v))] for key, rows in lists.items()}
        fields = {key: ("" if any(c.upper() in unknown for c in CVE_RE.findall(v)) else v) for key, v in fields.items()}
        verdict = "watch" if verdict == "confirmed" else verdict
    if verdict == "confirmed" and review["recommendation"] != "confirm":
        verdict = "watch"
    if verdict != "confirmed" and confidence == "high":
        confidence = "medium"

    refs = sorted({r for c in claims for r in c["refs"]}, key=lambda r: int(r[1:]))
    return {
        "verdict": verdict, "confidence": confidence, "event_type": record["hypothesis"]["event_type"],
        "title": clean(final.get("title"), 80) or facts["lead"], **fields, **lists,
        "stages": {
            "hypothesis": {"text": record["hypothesis"]["hypothesis"], "noise_risk": record["hypothesis"]["noise_risk"],
                           "noise_reason": record["hypothesis"]["noise_reason"]},
            "claims": claims, "review": {"problems": review["problems"], "recommendation": review["recommendation"]},
            "checks": checks},
        "cited": refs,
    }


def public_facts(facts, evidence):
    techniques = [{"id": t, "label": td.TECHNIQUES.get(t, "")} for t in facts["techniques"]]
    return {"signals": facts["signals"], "trend": facts["trend"], "articles": facts["articles"],
            "sources": len(facts["sources"]), "first_seen": facts["first_seen"], "last_seen": facts["last_seen"],
            "active_reports": facts["active_reports"], "kev": facts["kev"], "actors": facts["actors"],
            "malware": facts["malware"], "products": facts["products"], "cves": facts["cves"], "techniques": techniques,
            "evidence": [{"ref": "A{}".format(i), "title": a["title"], "url": a["url"], "source": a["source"],
                          "date": a["day"].isoformat()} for i, a in enumerate(evidence, 1)]}


def signature(facts, model):
    urls = sorted(a["url"] for a in facts["evidence"][:MAX_EVIDENCE])
    return hashlib.sha256(("\n".join(urls) + "|" + str(model) + "|v1").encode()).hexdigest()[:20]


def discover(events, generate, now=None, cache=None, model=""):
    """Full run. `generate(prompt) -> text` is the model call; pass None to publish statistics only."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    end = now.astimezone(td.KST).date()
    articles, _, _ = td.scan(events, now)
    start = end - timedelta(days=7 * (TREND_WEEKS + BASELINE_WEEKS))
    threats = [a for a in articles.values() if start <= a["day"] <= end and a["category"] in td.THREAT_CATEGORIES]
    rows, detected = candidates(threats, end)
    cache = cache if cache is not None else {}
    findings, calls = [], 0
    for facts in rows:
        key = signature(facts, model)
        evidence = facts["evidence"][:MAX_EVIDENCE]
        result = cache.get(key)
        if result is None and generate is not None:
            record = investigate(facts, generate)
            calls += 3
            if record:
                result = settle(facts, record)
                cache[key] = result
        if result is None:
            # No model verdict: publish the numbers only and say so.
            result = {"verdict": "unreviewed", "confidence": "low", "event_type": "기타", "title": facts["lead"],
                      "summary": "", "why_now": "", "who_is_affected": "", "reason": "AI 검토를 수행하지 못해 통계 신호만 표시합니다.",
                      "actions": [], "detection": [], "stages": None, "cited": []}
        findings.append({"id": key, **result, **public_facts(facts, evidence)})
    order = {"confirmed": 0, "watch": 1, "unreviewed": 2, "rejected": 3}
    findings.sort(key=lambda f: (order[f["verdict"]], -f["active_reports"], -f["sources"]))
    counts = Counter(f["verdict"] for f in findings)
    return {
        "schema_version": 1, "generated_at": now.isoformat(timespec="seconds"), "model": model,
        "window": {"from": (end - timedelta(days=WINDOW_DAYS - 1)).isoformat(), "to": end.isoformat()},
        "funnel": {"articles": sum(1 for a in threats if a["day"] >= end - timedelta(days=WINDOW_DAYS - 1)),
                   "signals": detected, "investigated": len(findings), "confirmed": counts["confirmed"],
                   "watch": counts["watch"], "rejected": counts["rejected"], "unreviewed": counts["unreviewed"]},
        "findings": findings, "llm_calls": calls,
    }


# ── 실행 ─────────────────────────────────────────────────────────────────────
def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    temp.replace(path)


def run(output=None, push=False, use_model=True):
    import common_utils
    import intelligence_dashboard

    cache_path = common_utils.STATE_DIR / CACHE_NAME
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    generate = (lambda prompt: common_utils.llm_generate(prompt, timeout=180, json_format=True, max_tokens=12000)) if use_model else None
    events = intelligence_dashboard.read_events(common_utils.PROJECT_ROOT / "data" / "events.jsonl")
    # The model runs before the repository lock is taken: it can take minutes.
    result = discover(events, generate, cache=cache, model=common_utils.NVIDIA_MODEL if use_model else "")
    live = {f["id"] for f in result["findings"]}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({k: v for k, v in cache.items() if k in live}, ensure_ascii=False), encoding="utf-8")
    funnel = result["funnel"]
    print("[*] AI Discovery: 신호 {} → 조사 {} → 확정 {} / 관찰 {} / 기각 {} / 미검토 {} (모델 호출 {}회)".format(
        funnel["signals"], funnel["investigated"], funnel["confirmed"], funnel["watch"], funnel["rejected"],
        funnel["unreviewed"], result["llm_calls"]))
    del result["llm_calls"]
    if not push:
        write(Path(output), result)
        return result
    import publish_web_dashboard as publisher
    repo = Path(publisher.REPO_PATH) if publisher.REPO_PATH else None
    if not repo or not publisher._validate_publish_repo(repo):
        raise ValueError("WEB_DASHBOARD_REPO_PATH is not a usable dashboard clone")
    with publisher.repo_lock(repo):
        branch = publisher._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).strip()
        publisher._sync_to_remote_head(repo, branch)
        write(repo / RELATIVE_OUTPUT, result)
        publisher._run_git(["add", RELATIVE_OUTPUT], cwd=repo)
        if publisher._has_staged_changes(RELATIVE_OUTPUT, cwd=repo):
            publisher._run_git(["commit", "-m", "Update AI Discovery"], cwd=repo)
            publisher._run_git(["push", "origin", branch], cwd=repo)
            print("[+] AI Discovery 발행")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--push", action="store_true", help="write into the dashboard clone, commit and push")
    parser.add_argument("--output", type=Path, default=Path("threat-discovery-preview.json"))
    parser.add_argument("--no-model", action="store_true", help="statistics only; no model calls")
    args = parser.parse_args()
    run(args.output, push=args.push, use_model=not args.no_model)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("[-] AI Discovery 실패: {}: {}".format(type(error).__name__, error), file=sys.stderr)
        sys.exit(1)
