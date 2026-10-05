"""Select public report evidence and bind each summary to its own sources."""

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dashboard_text import public_text

HEADERS = ("총평", "핵심 위협 TOP 3", "권고 조치")
MISSING_RE = re.compile(
    r"한국어 요약을 준비하지 못했습니다|AI 해석을 생성하지 못해|요약을 생성하지 못했습니다|"
    r"Issues\s*(?:필드|목록)|분석 대상 핵심 위협이 식별되지|세부 위협 정보가 없습니다", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def article_url(value):
    try:
        parts = urlsplit(value or "")
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return ""
        query = dict(parse_qsl(parts.query))
        if parts.path == "/api/click" and query.get("url"):
            return article_url(query["url"])
        return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"),
                          urlencode([(k, v) for k, v in parse_qsl(parts.query)
                                     if not k.startswith("utm_")]), ""))
    except ValueError:
        return ""


def report_articles(payload):
    return [item for region in ("domestic", "overseas")
            for item in (payload.get(region) or {}).get("highlights", [])]


def parse_narrative(text):
    sections = dict(re.findall(r"(?ms)^\[([^\]\n]+)\]\s*\n(.*?)(?=^\[|\Z)", text or ""))
    return {"overview": sections.get("총평", "").strip(),
            "threats": re.findall(r"(?m)^\d+[.)]\s+(.+)$", sections.get(HEADERS[1], "")),
            "actions": re.findall(r"(?m)^\d+[.)]\s+(.+)$", sections.get(HEADERS[2], ""))}


def narrative_problem(text, count=None):
    if not text or MISSING_RE.search(text):
        return "요약이 누락되었거나 분석 후보가 없다는 잘못된 안내입니다"
    parsed = parse_narrative(text)
    if not parsed["overview"] or not parsed["threats"] or not parsed["actions"]:
        return "필수 섹션이 비어 있습니다"
    if len(parsed["threats"]) != len(parsed["actions"]) or (
            count is not None and len(parsed["threats"]) != count):
        return "핵심 위협과 권고 조치가 1:1로 대응하지 않습니다"
    for field in ("threats", "actions"):
        normalized = [re.sub(r"[\W_]+", "", item).casefold() for item in parsed[field]]
        if len(normalized) != len(set(normalized)):
            return "동일한 위협 또는 조치가 반복되었습니다"
    return ""


def _sources(row):
    sources = []
    items = row.get("items") or []
    for value in ([row] if row.get("url") else []) + items + (row.get("evidence") or []):
        if not isinstance(value, dict):
            continue
        url = article_url(value.get("url"))
        if not url or any(item["url"] == url for item in sources):
            continue
        sources.append({"url": url, "title": public_text(value.get("title") or ""),
                        "source_label": value.get("source_label") or "원문",
                        "collected_at": value.get("collected_at") or ""})
    return sources


def select_issues(cards, articles, limit=3):
    candidates = []
    for is_card, rows in ((True, cards or []), (False, articles or [])):
        for row in rows:
            summary = public_text(row.get("summary") or "")
            level = row.get("level") or "INFO"
            if not is_card and level not in ("P1", "P2") and row.get("category") not in (
                    "공격캠페인", "악성코드", "랜섬웨어", "개인정보유출", "취약점"):
                continue
            if not summary:
                continue
            sources = _sources(row)
            title = public_text(row.get("cve") if is_card else row.get("title"))
            cves = sorted(set(CVE_RE.findall(summary.upper())))
            if is_card and not cves:
                cves = sorted(set(CVE_RE.findall(title.upper())))
            key = row.get("ref") or hashlib.sha256((title + summary).encode()).hexdigest()[:12]
            candidate = {"id": key, "title": title, "summary": summary,
                         "action": public_text(row.get("remediation") or row.get("recommended_action") or ""),
                         "level": level, "category": row.get("category") or ("취약점" if cves else "공격 동향"),
                         "products": row.get("products") or [], "cves": cves,
                         "sources": sources, "ref": row.get("ref") or "",
                         "url": article_url(row.get("url")),
                         "published_at": row.get("published_at") or "",
                         "kind": "issue" if is_card else "article"}
            candidates.append(candidate)
    candidates.sort(key=lambda row: (
        {"P1": 3, "P2": 2}.get(row["level"], 1),
        bool(re.search(r"[가-힣]", row["summary"])),
        min(len({s["source_label"] for s in row["sources"]}), 5)), reverse=True)
    unique = []
    for row in candidates:
        urls = {s["url"] for s in row["sources"]}
        if any(row["id"] == old["id"] or row["summary"] == old["summary"] or
               urls.intersection(s["url"] for s in old["sources"]) or
               (0 < len(row["cves"]) <= 3 and 0 < len(old["cves"]) <= 3 and
                set(row["cves"]).intersection(old["cves"])) for old in unique):
            continue
        unique.append(row)
    selected = unique[:limit]
    # A CVE-only cross-source list must not crowd out a high-priority campaign.
    campaign = next((row for row in unique if row["kind"] == "article" and
                     row["level"] == "P1" and not row["cves"]), None)
    if campaign and campaign not in selected and selected:
        selected[-1] = campaign
    return selected


def bind_briefing(payload, issues, narrative):
    problem = narrative_problem(narrative, len(issues))
    ready = bool(issues) and not problem
    parsed = parse_narrative(narrative) if ready else {}
    result = []
    for index, source in enumerate(issues):
        row = dict(source)
        row["action"] = ""
        if ready:
            row["summary"] = parsed["threats"][index]
            row["action"] = parsed["actions"][index]
        result.append(row)
    payload["briefing"] = {"version": 1, "status": "ready" if ready else "needs_summary" if issues else "empty",
                           "overview": parsed.get("overview", ""), "issues": result}
    payload["narrative"] = narrative if ready else ""
    payload["narrative_basis"] = "기간 내 기사·교차 확인 이슈에서 선정 · 이슈별 원문 연결"
    return payload
