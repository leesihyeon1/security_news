"""Offline, public article aggregates for charts and illustrated subject maps."""

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard_text import public_text
from live_news import public_url, utc_timestamp

KST = timezone(timedelta(hours=9))
INFO_CATEGORIES = {"기술동향", "제품행사", "정책규제"}
CATALOG_SOURCES = {"nvd", "cisa_kev", "msrc", "github_advisory", "exploit_db",
                   "cisco_psirt", "fortinet_psirt", "paloalto_psirt"}
AREAS = [
    ("identity", "계정·서비스", "locked", r"\b(?:OAuth|SSO|SaaS|Entra|Okta)\b|계정|인증|자격.?증명"),
    ("endpoint", "단말·브라우저", "laptop", r"\b(?:Windows|Chrome|Edge browser|endpoint|ClickFix|RAT)\b|단말|브라우저|피싱"),
    ("development", "개발·공급망", "toolbox", r"\b(?:GitHub|GitLab|npm|PyPI|supply.chain|developer)\b|공급망|패키지|개발.?도구"),
    ("cloud", "클라우드·서버", "cloud", r"\b(?:cloud|server|Docker|Kubernetes|AWS|Azure)\b|클라우드|서버"),
    ("network", "네트워크·장비", "globe_with_meridians", r"\b(?:VPN|router|firewall|Fortinet|Cisco|Citrix|IoT|DDoS)\b|네트워크|방화벽|공유기"),
    ("data", "데이터·제도", "file_cabinet", r"\b(?:database|privacy|regulation|GDPR|data.breach)\b|개인정보|데이터.?유출|규제|법률"),
]
GROUPS = [
    ("develop", "개발·협업", "toolbox"), ("packages", "패키지·확장", "electric_plug"),
    ("web", "웹 기술", "globe_with_meridians"), ("deploy", "클라우드·배포", "cloud"),
    ("runtime", "서버·데이터", "file_cabinet"), ("ai", "AI·에이전트", "laptop"),
]
# Aliases identify article subjects, not dependencies, installed assets or exposure.
ENTITY_ROWS = [
    ("github", "GitHub", "develop", "development", ["GitHub", "깃허브"]),
    ("gitlab", "GitLab", "develop", "development", ["GitLab", "깃랩"]),
    ("vscode", "VS Code", "develop", "endpoint", ["VS Code", "Visual Studio Code"]),
    ("jenkins", "Jenkins", "develop", "development", ["Jenkins", "젠킨스"]),
    ("npm", "npm", "packages", "development", ["npm"]),
    ("pypi", "PyPI", "packages", "development", ["PyPI"]),
    ("chrome", "Chrome", "packages", "endpoint", ["Chrome", "크롬"]),
    ("firefox", "Firefox", "packages", "endpoint", ["Firefox", "파이어폭스"]),
    ("react", "React", "web", "development", ["React.js", "ReactJS", "React"]),
    ("nextjs", "Next.js", "web", "development", ["Next.js", "NextJS"]),
    ("nodejs", "Node.js", "web", "development", ["Node.js", "NodeJS"]),
    ("javascript", "JavaScript", "web", "development", ["JavaScript", "자바스크립트"]),
    ("nginx", "NGINX", "web", "network", ["NGINX", "엔진엑스"]),
    ("apache", "Apache", "web", "network", ["Apache", "아파치"]),
    ("amazonwebservices", "AWS", "deploy", "cloud", ["AWS", "Amazon Web Services"]),
    ("azure", "Azure", "deploy", "identity", ["Azure", "애저"]),
    ("googlecloud", "Google Cloud", "deploy", "cloud", ["Google Cloud", "GCP", "구글 클라우드"]),
    ("vercel", "Vercel", "deploy", "cloud", ["Vercel", "버셀"]),
    ("cloudflare", "Cloudflare", "deploy", "network", ["Cloudflare", "클라우드플레어"]),
    ("docker", "Docker", "runtime", "cloud", ["Docker", "도커"]),
    ("kubernetes", "Kubernetes", "runtime", "cloud", ["Kubernetes", "K8s", "쿠버네티스"]),
    ("linux", "Linux", "runtime", "cloud", ["Linux", "리눅스"]),
    ("windows11", "Windows", "runtime", "endpoint", ["Windows", "윈도우", "윈도"]),
    ("mongodb", "MongoDB", "runtime", "data", ["MongoDB", "몽고DB"]),
    ("postgresql", "PostgreSQL", "runtime", "data", ["PostgreSQL", "Postgres"]),
    ("python", "Python", "ai", "development", ["Python", "파이썬"]),
    ("tensorflow", "TensorFlow", "ai", "development", ["TensorFlow"]),
    ("pytorch", "PyTorch", "ai", "development", ["PyTorch"]),
    ("mcp", "MCP", "ai", "identity", ["MCP", "Model Context Protocol"]),
]


def entity_catalog():
    return [{"id": key, "label": label, "group": group, "area": area,
             "image": "assets/dashboard-map/" + ("electric_plug.png" if key == "mcp" else key + ".svg")}
            for key, label, group, area, _ in ENTITY_ROWS]


def subject_ids(text):
    result = []
    for key, _, _, _, aliases in ENTITY_ROWS:
        flags = 0 if key == "react" else re.I
        if any(re.search(r"(?<![\w])" + re.escape(alias) + r"(?![A-Za-z0-9_])", text, flags)
               for alias in aliases):
            result.append(key)
    return result


def build(events, now=None, days=180):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    end = now.astimezone(KST).date()
    start = end - timedelta(days=days - 1)
    unique = {}
    for event in events:
        if not isinstance(event, dict) or event.get("source") in CATALOG_SOURCES:
            continue
        url = public_url(event.get("url"))
        title = public_text(str(event.get("title") or "")).strip()
        collected = utc_timestamp(event.get("fetched_at"))
        published = utc_timestamp(event.get("published_at"), event.get("source", ""))
        if published and collected and published > collected:
            if datetime.fromisoformat(published.replace("Z", "+00:00")) > now + timedelta(hours=6):
                published = ""
        stamp = published or collected
        if not url or not title or not stamp:
            continue
        day = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(KST).date()
        if not start <= day <= end:
            continue
        previous = unique.get(url)
        if previous and previous[0] > collected:
            continue
        # Titles and public summaries only; never infer public subjects from private inventories.
        summary = public_text(str(event.get("summary") or ""))
        text = title + " " + summary
        ids = subject_ids(text)
        area_ids = {row[3] for row in ENTITY_ROWS if row[0] in ids}
        area_ids.update(key for key, _, _, pattern in AREAS if re.search(pattern, text, re.I))
        category = public_text(str(event.get("category") or "미분류"))[:60]
        ref = hashlib.sha256(url.encode()).hexdigest()[:16]
        row = {"ref": ref, "title": title[:500], "url": url, "date": day.isoformat(),
               "date_basis": "published" if published else "collected",
               "source": str(event.get("source") or "unknown"), "category": category,
               "entities": ids, "areas": sorted(area_ids)}
        unique[url] = (collected, row)
    articles = sorted((value[1] for value in unique.values()), key=lambda r: (r["date"], r["ref"]), reverse=True)
    daily = {}
    for offset in range(days):
        day = (start + timedelta(days=offset)).isoformat()
        daily[day] = {"date": day, "total": 0, "categories": Counter(), "sources": Counter(),
                      "entities": Counter(), "areas": Counter(), "tech_entities": Counter()}
    details = defaultdict(list)
    for row in articles:
        bucket = daily[row["date"]]
        bucket["total"] += 1
        bucket["categories"][row["category"]] += 1
        bucket["sources"][row["source"]] += 1
        for key in row["entities"]:
            bucket["entities"][key] += 1
            if row["category"] in INFO_CATEGORIES:
                bucket["tech_entities"][key] += 1
            details[key].append(row)
        for key in row["areas"]:
            bucket["areas"][key] += 1
            details["area-" + key].append(row)
    overview = {"schema_version": 1, "generated_at": now.isoformat(), "range": {"from": start.isoformat(), "to": end.isoformat()},
                "available_from": min((a["date"] for a in articles), default=None),
                "latest_collected_at": max((v[0] for v in unique.values()), default=None),
                "basis": "unique_article_url", "total_articles": len(articles),
                "mapped_articles": sum(bool(a["entities"] or a["areas"]) for a in articles),
                "info_categories": sorted(INFO_CATEGORIES), "daily": list(daily.values()),
                "entities": entity_catalog(),
                "areas": [{"id": key, "label": label, "image": "assets/dashboard-map/" + icon + ".png"} for key, label, icon, _ in AREAS],
                "groups": [{"id": key, "label": label, "image": "assets/dashboard-map/" + icon + ".png"} for key, label, icon in GROUPS]}
    return overview, details


def read_events(path):
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                # A truncated input is a failed refresh, not a valid empty dashboard.
                yield json.loads(line)


def publish(data_dir, events_path=None, now=None):
    events_path = events_path or Path(__file__).resolve().parents[1] / "data" / "events.jsonl"
    overview, details = build(read_events(events_path), now=now)
    data_dir = Path(data_dir)
    folder = data_dir / "intelligence"
    folder.mkdir(parents=True, exist_ok=True)
    # Stable names: the folder is committed on every publish, so content-hashed names
    # would add a full new set of files (a few MB) to the repository each day.
    written = set()
    for key in [e["id"] for e in overview["entities"]] + ["area-" + a["id"] for a in overview["areas"]]:
        content = json.dumps(details[key], ensure_ascii=False, separators=(",", ":"))
        filename = key + ".json"
        (folder / filename).write_text(content, encoding="utf-8")
        written.add(filename)
        overview.setdefault("detail_files", {})[key] = "data/intelligence/" + filename
    for stale in folder.glob("*.json"):
        if stale.name not in written:
            stale.unlink()
    target = data_dir / "intelligence-overview.json"
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(overview, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    temp.replace(target)
    return overview


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--events", type=Path)
    args = parser.parse_args()
    result = publish(args.output, args.events)
    print("Dashboard articles:", result["total_articles"], "mapped:", result["mapped_articles"])
