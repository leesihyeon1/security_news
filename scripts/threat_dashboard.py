"""Public threat and vulnerability aggregates for the dashboard's overview.

Answers three questions from the collected events: what needs attention now,
how threats and CVEs are moving, and whether collection itself is healthy.

Only public signals are used (article fields, KEV, CVSS, exploitation status).
Triage levels, importance scores, matched assets and PIRs are never read here:
they encode internal asset and priority context.
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard_text import public_text
from live_news import public_url, utc_timestamp

KST = timezone(timedelta(hours=9))
CATALOG_SOURCES = {"nvd", "cisa_kev", "msrc", "github_advisory", "exploit_db",
                   "cisco_psirt", "fortinet_psirt", "paloalto_psirt"}
THREAT_CATEGORIES = ["취약점", "공격캠페인", "악성코드", "침해사고", "개인정보유출", "공급망공격", "피싱사기"]
SEVERITIES = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_WORDS = {"critical": "critical", "high": "high", "important": "high",
                  "medium": "medium", "moderate": "medium", "low": "low"}
EXPLOIT_RANK = {"none": 0, "poc": 1, "active": 2}
NOT_A_NAME = {"info", "byod", "unknown", "none", "n/a", "na", "-", "불명", "미상", "미확인", "알 수 없음", "unattributed",
              "unknown threat actor", "unknown actor", "multiple", "various"}
TOP_NAMES = 60
SPOTLIGHT_NAMES = 30
SPOTLIGHT_ARTICLES = 6
PRIORITY_DAYS = 7
PRIORITY_ITEMS = 8

TECHNIQUES = {
    "T1190": "공개 서비스 취약점 악용", "T1068": "권한 상승 취약점 악용", "T1027": "난독화", "T1078": "정상 계정 악용",
    "T1566": "피싱", "T1562": "보안 기능 무력화", "T1041": "C2 채널로 유출", "T1059": "명령·스크립트 실행",
    "T1505": "서버 구성요소 악용(웹셸)", "T1195": "공급망 침해", "T1486": "데이터 암호화(랜섬)", "T1203": "클라이언트 취약점 실행",
    "T1204": "사용자 실행 유도", "T1133": "외부 원격 서비스", "T1110": "무차별 대입", "T1071": "응용 계층 프로토콜 C2",
    "T1105": "도구 반입", "T1082": "시스템 정보 수집", "T1485": "데이터 파괴", "T1003": "자격 증명 덤프",
    "T1021": "원격 서비스 이동", "T1055": "프로세스 인젝션", "T1547": "부팅·로그온 자동 실행", "T1053": "예약 작업",
    "T1210": "원격 서비스 취약점 악용", "T1552": "보호되지 않은 자격 증명", "T1555": "저장된 비밀번호 탈취",
    "T1539": "세션 쿠키 탈취", "T1567": "웹 서비스로 유출", "T1098": "계정 조작", "T1136": "계정 생성",
    "T1574": "실행 흐름 가로채기", "T1036": "위장", "T1140": "난독화 해제", "T1583": "인프라 확보", "T1588": "도구 확보",
    "T1589": "피해자 신원 정보 수집", "T1598": "정보 수집용 피싱", "T1656": "사칭", "T1657": "금전 탈취",
    "T1528": "앱 접근 토큰 탈취", "T1199": "신뢰 관계 악용", "T1189": "드라이브 바이 감염", "T1490": "복구 방해",
    "T1498": "네트워크 서비스 거부", "T1499": "엔드포인트 서비스 거부", "T1005": "로컬 데이터 수집", "T1560": "수집 데이터 압축",
    "T1218": "시스템 바이너리 우회 실행", "T1219": "원격 접속 도구", "T1572": "프로토콜 터널링", "T1090": "프록시",
    "T1056": "입력 가로채기", "T1557": "중간자 공격", "T1621": "MFA 요청 남발", "T1611": "컨테이너 탈출",
    "T1606": "웹 자격 증명 위조", "T1212": "자격 증명 접근 취약점 악용", "T1211": "방어 우회 취약점 악용",
}
CWES = {
    "CWE-416": "해제 후 사용", "CWE-122": "힙 버퍼 오버플로", "CWE-79": "크로스 사이트 스크립팅", "CWE-787": "범위 밖 쓰기",
    "CWE-862": "권한 검사 누락", "CWE-89": "SQL 인젝션", "CWE-22": "경로 탐색", "CWE-78": "OS 명령 주입",
    "CWE-863": "잘못된 권한 검사", "CWE-502": "신뢰할 수 없는 역직렬화", "CWE-20": "입력 검증 미흡", "CWE-125": "범위 밖 읽기",
    "CWE-200": "정보 노출", "CWE-284": "접근 통제 미흡", "CWE-287": "인증 미흡", "CWE-306": "인증 누락",
    "CWE-352": "사이트 간 요청 위조", "CWE-400": "자원 고갈", "CWE-434": "위험한 파일 업로드", "CWE-476": "NULL 포인터 역참조",
    "CWE-77": "명령 주입", "CWE-94": "코드 주입", "CWE-918": "서버 측 요청 위조", "CWE-119": "메모리 버퍼 오류",
    "CWE-190": "정수 오버플로", "CWE-269": "권한 관리 미흡", "CWE-362": "경쟁 조건", "CWE-121": "스택 버퍼 오버플로",
    "CWE-798": "하드코딩된 자격 증명", "CWE-601": "오픈 리다이렉트", "CWE-732": "잘못된 권한 할당", "CWE-59": "링크 추적",
    "CWE-843": "타입 혼동", "CWE-285": "부적절한 인가", "CWE-427": "검색 경로 통제 미흡", "CWE-770": "제한 없는 자원 할당",
}


def names(value):
    """Split "A, B (aka C)" into clean names; drop placeholders the classifier leaves behind."""
    result, seen = [], set()
    values = value if isinstance(value, list) else re.split(r"[,;]", str(value or ""))
    for part in values:
        name = re.sub(r"\s+", " ", re.sub(r"\([^)]*\)?", "", str(part))).strip(" .\"'")
        key = name.casefold()
        if 2 <= len(name) <= 40 and key not in NOT_A_NAME and key not in seen:
            seen.add(key)
            result.append(name)
    return result


def severity_of(event):
    word = SEVERITY_WORDS.get(str(event.get("severity") or "").strip().lower())
    if word:
        return word
    score = event.get("score")
    if isinstance(score, (int, float)) and 0 < score <= 10:
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return "unknown"


def _day(event, now):
    collected = utc_timestamp(event.get("fetched_at"))
    published = utc_timestamp(event.get("published_at"), event.get("source", ""))
    if published and datetime.fromisoformat(published.replace("Z", "+00:00")) > now + timedelta(hours=6):
        published = ""
    stamp = published or collected
    if not stamp:
        return None, collected
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(KST).date(), collected


def _top(counter, limit=TOP_NAMES):
    return {key for key, _ in counter.most_common(limit)}


def build(events, now=None, days=180):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    end = now.astimezone(KST).date()
    start = end - timedelta(days=days - 1)
    articles, cves, sources = {}, {}, {}
    seen_ids = set()

    for event in events:
        if not isinstance(event, dict):
            continue
        source = str(event.get("source") or "unknown")
        day, collected = _day(event, now)
        if collected:
            info = sources.setdefault(source, {"id": source, "kind": "catalog" if source in CATALOG_SOURCES else "news",
                                               "last": "", "stamps": {}})
            info["last"] = max(info["last"], collected)
            if event.get("id") not in seen_ids:
                seen_ids.add(event.get("id"))
                collected_day = datetime.fromisoformat(collected.replace("Z", "+00:00")).astimezone(KST).date()
                info["stamps"][collected_day] = info["stamps"].get(collected_day, 0) + 1
        if day is None:
            continue
        status = event.get("exploitation_status") if event.get("exploitation_status") in EXPLOIT_RANK else "none"
        if source in CATALOG_SOURCES:
            for cve in event.get("cves") or []:
                cve = str(cve).upper()
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                    continue
                row = cves.setdefault(cve, {"day": day, "severity": "unknown", "kev": False, "status": "none", "cwes": set()})
                row["day"] = min(row["day"], day)
                level = severity_of(event)
                if SEVERITIES.index(level) < SEVERITIES.index(row["severity"]):
                    row["severity"] = level
                row["kev"] = row["kev"] or bool(event.get("kev")) or source == "cisa_kev"
                if EXPLOIT_RANK[status] > EXPLOIT_RANK[row["status"]]:
                    row["status"] = status
                row["cwes"].update(c for c in event.get("cwes") or [] if re.fullmatch(r"CWE-\d+", str(c)))
            continue
        url = public_url(event.get("url"))
        title = public_text(str(event.get("title") or "")).strip()
        if not url or not title:
            continue
        previous = articles.get(url)
        if previous and previous["collected"] > collected:
            continue
        cluster = event.get("cluster") if isinstance(event.get("cluster"), dict) else {}
        articles[url] = {
            "collected": collected, "day": day, "title": title[:300], "url": url, "source": source,
            "category": str(event.get("category") or ""), "status": status, "kev": bool(event.get("kev")),
            "severity": severity_of(event), "actors": names(event.get("threat_actor")),
            "malware": names(event.get("malware_family")),
            "techniques": sorted({str(t).split(".")[0] for t in event.get("attack_techniques") or []
                                  if re.fullmatch(r"T\d{4}(\.\d{3})?", str(t))}),
            "products": names(event.get("affected_products")),
            "cves": [str(c).upper() for c in event.get("cves") or [] if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(c), re.I)],
            "corroborated": len(cluster.get("corroborating_sources") or []),
        }

    in_window = [a for a in articles.values() if start <= a["day"] <= end]
    threats = [a for a in in_window if a["category"] in THREAT_CATEGORIES]
    display, totals = {}, defaultdict(Counter)
    for article in threats:
        for field in ("actors", "malware", "products"):
            for name in article[field]:
                display.setdefault((field, name.casefold()), name)
                totals[field][name.casefold()] += 1
        totals["techniques"].update(article["techniques"])
    window_cves = {cve: row for cve, row in cves.items() if start <= row["day"] <= end}
    for row in window_cves.values():
        totals["cwes"].update(row["cwes"])
    keep = {field: _top(counter) for field, counter in totals.items()}

    daily = {}
    for offset in range(days):
        day = start + timedelta(days=offset)
        daily[day] = {"date": day.isoformat(), "collected": 0, "threat": 0, "active": 0, "categories": Counter(),
                      "actors": Counter(), "malware": Counter(), "techniques": Counter(), "products": Counter(),
                      "cve": Counter(), "cwes": Counter()}
    for article in in_window:
        bucket = daily[article["day"]]
        bucket["collected"] += 1
        if article["category"] not in THREAT_CATEGORIES:
            continue
        bucket["threat"] += 1
        bucket["categories"][article["category"]] += 1
        bucket["active"] += article["status"] == "active"
        for field in ("actors", "malware", "products"):
            for name in article[field]:
                if name.casefold() in keep[field]:
                    bucket[field][display[(field, name.casefold())]] += 1
        for technique in article["techniques"]:
            if technique in keep["techniques"]:
                bucket["techniques"][technique] += 1
    for row in window_cves.values():
        bucket = daily[row["day"]]
        bucket["cve"]["new"] += 1
        bucket["cve"][row["severity"]] += 1
        bucket["cve"]["kev"] += row["kev"]
        if row["status"] != "none":
            bucket["cve"][row["status"]] += 1
        for cwe in row["cwes"]:
            if cwe in keep["cwes"]:
                bucket["cwes"][cwe] += 1

    return {
        "schema_version": 1, "generated_at": now.isoformat(timespec="seconds"),
        "range": {"from": start.isoformat(), "to": end.isoformat()},
        "latest_collected_at": max((a["collected"] for a in articles.values()), default=None),
        "threat_categories": THREAT_CATEGORIES, "daily": list(daily.values()),
        "priority": _priority(threats, end), "spotlight": _spotlight(threats, end),
        "sources": _sources(sources, end),
        "labels": {"techniques": {key: TECHNIQUES[key] for key in keep.get("techniques", ()) if key in TECHNIQUES},
                   "cwes": {key: CWES[key] for key in keep.get("cwes", ()) if key in CWES}},
    }


def _article_row(article):
    return {"title": article["title"], "url": article["url"], "date": article["day"].isoformat(),
            "source": article["source"], "category": article["category"]}


def _priority(threats, end):
    """Recent reports of real-world exploitation, ranked on public signals only."""
    since = end - timedelta(days=PRIORITY_DAYS - 1)
    recent = [a for a in threats if a["day"] >= since and (a["status"] == "active" or a["kev"])]

    def rank(article):
        return (article["kev"] * 3 + (article["status"] == "active") * 2 + (article["severity"] == "critical")
                + min(article["corroborated"], 3), article["day"], article["collected"])

    picked, used_cves, used_titles = [], set(), set()
    for article in sorted(recent, key=rank, reverse=True):
        title_key = re.sub(r"\W+", "", article["title"].casefold())[:60]
        if title_key in used_titles or used_cves.intersection(article["cves"]):
            continue  # another outlet's report of an issue already listed
        used_titles.add(title_key)
        used_cves.update(article["cves"])
        flags = [label for label, on in (("KEV 등재", article["kev"]), ("실제 악용", article["status"] == "active"),
                                         ("심각도 Critical", article["severity"] == "critical")) if on]
        picked.append({**_article_row(article), "flags": flags, "cves": article["cves"][:3],
                       "other_sources": article["corroborated"]})
        if len(picked) == PRIORITY_ITEMS:
            break
    return picked


def _spotlight(threats, end):
    """Recent articles behind the most-reported actors and malware, for drill-down."""
    since = end - timedelta(days=89)
    result = {}
    for field in ("actors", "malware"):
        groups, labels = defaultdict(list), {}
        for article in threats:
            if article["day"] >= since:
                for name in article[field]:
                    labels.setdefault(name.casefold(), name)
                    groups[name.casefold()].append(article)
        top = sorted(groups, key=lambda key: len(groups[key]), reverse=True)[:SPOTLIGHT_NAMES]
        result[field] = {labels[key]: [_article_row(a) for a in sorted(
            groups[key], key=lambda a: (a["day"], a["collected"]), reverse=True)[:SPOTLIGHT_ARTICLES]] for key in top}
    return result


def _sources(sources, end):
    rows = []
    for info in sources.values():
        count = lambda span: sum(n for day, n in info["stamps"].items() if end - timedelta(days=span - 1) <= day <= end)  # noqa: E731
        rows.append({"id": info["id"], "kind": info["kind"], "last_collected_at": info["last"],
                     "count_7d": count(7), "count_30d": count(30)})
    return sorted(rows, key=lambda row: (row["kind"] != "news", -row["count_30d"], row["id"]))


def publish(data_dir, events, now=None):
    overview = build(events, now=now)
    target = Path(data_dir) / "threat-overview.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(overview, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    temp.replace(target)
    return overview
