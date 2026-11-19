"""Breaking vulnerability reports for the top of the latest-news tab.

국내 속보(breaking_news.py)처럼 화면 맨 위에 "지금 대응할 취약점"을 띄운다. 이미 수집한
기사(events.jsonl)만 읽고, 모델·외부 호출이 없다. Redis 키 하나에만 쓴다.

왜 "매체 3곳 이상" 하나로 고르지 않는가 — 실측(2026-11-20, 최근 한 달):
PHP2Shell·Node2Shell·Java4Shell·NGINX2Root·Plex2Shell은 모두 첫 보도 회차에 수집됐지만
KEV에는 하나도 오르지 않았고, 세 번째 매체가 나오기까지 2~16시간이 걸렸다. 그래서 첫
기사 한 건으로도 잡는 신호를 둔다.

  · 이름 붙은 취약점: ○○2Shell·○○4Shell·○○2Root 등 — 원격 실행·인증 우회 맥락이 있을 때
  · 국내 매체의 [긴급]·[속보] 취약점 기사
  · CISA KEV 신규 등재
  · 24시간 안에 매체 3곳 이상 보도

같은 사건은 이름 → CVE 순으로 묶는다(PHP2Shell 기사 126건이 카드 하나가 된다). 사내 자산
일치 여부는 쓰지 않는다 — 공개 화면이라 자산 정보가 드러난다.
"""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

import common_utils
import live_news

REDIS_KEY = "news:cve-breaking"
REDIS_TTL_SECONDS = 3 * 3600
SHOW_HOURS = 48          # 마지막 보도 후 이만큼 띄운다(국내 사고 24시간보다 길다 — 대응 기간이 길다)
MAX_AGE_DAYS = 7         # 첫 보도가 이보다 오래되면 후속 보도가 있어도 내린다
OUTLET_WINDOW_HOURS = 24
MIN_OUTLETS = 3
MAX_ITEMS = 6
MAX_CVES_FOR_LINK = 3    # CVE를 여럿 나열한 요약 기사로 서로 다른 사건이 묶이지 않게

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
NAME_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9.\-]{1,24}?)([24])(Shell|Root|RCE|Pwn)(?![A-Za-z0-9])", re.I)
# 이름 꼴이지만 취약점이 아닌 것 — 해킹 대회, 주간 요약의 말장난.
NAME_STOP = {"pwn2own", "this2shell", "that2shell", "everything2shell", "anything2shell"}
CONTEXT_RE = re.compile(
    r"원격\s*(?:코드|명령)\s*실행|\bRCE\b|remote code|code execution|command execution|인증\s*(?:없이|우회)|"
    r"unauthenticated|pre-?auth|auth(?:entication)?\s*bypass|takeover|장악|권한\s*상승|privilege escalation|"
    r"취약점|vulnerab|flaw|exploit|CVE-\d{4}", re.I)
URGENT_TAG_RE = re.compile(r"\[(긴급|속보)\]")
VULN_RE = re.compile(r"취약점|CVE-\d{4}|원격\s*코드|제로데이|패치|보안\s*업데이트|vulnerab|zero-day|exploit", re.I)
KOREAN_RE = re.compile(r"[가-힣]")
# 매체 수 신호에서 빼는 정기 공지 — KISA "○○ 제품 보안 업데이트 권고"를 국내 매체가 옮겨 실어
# 3곳 이상이 된다(재현: Zyxel·Zoom·Apache). 이름·[긴급]·KEV 신호는 그대로 받는다.
ROUTINE_RE = re.compile(r"(?:보안\s*)?(?:업데이트|패치)\s*권고|security updates? (?:advisory|roundup)|patch tuesday", re.I)
# 매체 수로만 걸린 묶음은 제목에 이 사건이 취약점·악용 소식이라는 표시가 있어야 한다. CVE를
# 배경으로만 언급한 캠페인 분석 글이 같은 CVE로 묶여 3곳이 됐다(재현: Gorbag·KeyDrift).
HEADLINE_RE = re.compile(r"CVE-\d{4}-\d{4,7}|악용|제로데이|원격\s*코드|취약점|exploit|zero-day|0-?day|\bRCE\b|"
                         r"vulnerab|flaw|bug", re.I)
LOW_TRUST_SOURCES = {"reddit_netsec", "reddit_cybersecurity", "reddit_reverseengineering", "reddit_asknetsec"}
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _time(event):
    for key in ("published_at", "fetched_at"):
        stamp = live_news.utc_timestamp(event.get(key), event.get("source") or "")
        if stamp:
            return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    return None


def _text(event):
    return " ".join(str(event.get(key) or "") for key in ("title", "summary"))


def _cves(event):
    values = {str(value).upper() for value in event.get("cves") or [] if CVE_RE.fullmatch(str(value))}
    return values | {value.upper() for value in CVE_RE.findall(_text(event))}


def vuln_names(event):
    """기사가 다루는 이름 붙은 취약점(소문자). 원격 실행·인증 우회 등 취약점 맥락이 있어야 한다.

    제목에 나온 이름을 앞에 둔다 — 묶을 때 그 기사의 주된 사건으로 쓴다. 제품 소개 글
    ("Product showcase: … stops HTTP2Shell")은 취약점 보도가 아니다.
    """
    text = _text(event)
    if not CONTEXT_RE.search(text) or event.get("category") == "제품행사":
        return []
    title = (event.get("title") or "").lower()
    # 요약에만 이름이 스친 기사("AI agents are a 'bane' …" 속 PHP2SHELL)는 그 취약점 보도가
    # 아니다. 이름이 제목에 있거나, 제목 자체가 취약점·악용 소식일 때만 받는다.
    if not NAME_RE.search(title) and not HEADLINE_RE.search(event.get("title") or ""):
        return []
    names = []
    for match in NAME_RE.finditer(text):
        name = "".join(match.groups())
        key = name.lower()
        if key in NAME_STOP or key in names:
            continue
        names.append(key)
    return sorted(names, key=lambda name: name not in title)


def _display_name(key, events):
    """기사에 실제로 쓰인 표기(PHP2Shell)를 고른다."""
    pattern = re.compile(re.escape(key), re.I)
    counts = {}
    for event in events:
        for match in pattern.findall(_text(event)):
            counts[match] = counts.get(match, 0) + 1
    # 소문자로만 쓴 표기(nginx2root)보다 기사 제목의 표기(NGINX2Root)를 쓴다.
    return max(counts, key=lambda value: (value != value.lower(), counts[value])) if counts else key


def _urgent(event):
    return bool(URGENT_TAG_RE.search(event.get("title") or "")) and bool(VULN_RE.search(_text(event)))


def _group_events(news):
    """같은 사건을 묶는다. 한 기사에 함께 나온 이름·CVE는 같은 사건으로 보고 합친다.

    실측(재현): 이름 없는 기사가 CVE로만 묶이면 "NGINX2Root"와 "CVE-2026-123007"이 따로
    카드가 됐다. 이름과 CVE가 함께 나온 기사가 하나라도 있으면 합친다. CVE를 여럿 나열한
    요약 기사(MAX_CVES_FOR_LINK 초과)는 연결 고리로 쓰지 않는다.
    """
    parent = {}

    def find(key):
        while parent.setdefault(key, key) != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a, b):
        parent[find(a)] = find(b)

    keyed = []
    for event in sorted(news, key=lambda e: e["_at"]):
        # 이름이 둘 이상인 기사("PHP2Shell 이어 이번엔 Node2Shell")는 주된 이름 하나로만 묶는다 —
        # 비교 기사 하나로 서로 다른 취약점이 한 카드가 됐다. 이름이 있는 기사의 CVE는 제목에
        # 나온 것만 연결한다(본문의 비교 대상 CVE로 다른 사건이 딸려 오지 않게).
        found = vuln_names(event)
        names = ["name:" + found[0]] if found else []
        cves = _cves(event)
        if found:
            cves = {cve.upper() for cve in CVE_RE.findall(event.get("title") or "")}
        links = names + (["cve:" + cve for cve in sorted(cves)] if len(cves) <= MAX_CVES_FOR_LINK else [])
        if not links:
            continue
        for key in links[1:]:
            union(links[0], key)
        keyed.append((event, links))
    groups = {}
    for event, links in keyed:
        group = groups.setdefault(find(links[0]), {"names": [], "cves": set(), "events": []})
        group["events"].append(event)
        for key in links:
            kind, value = key.split(":", 1)
            if kind == "name" and value not in group["names"]:
                group["names"].append(value)
            elif kind == "cve":
                group["cves"].add(value)
    return list(groups.values())


def _label_cve(group):
    """이름이 없을 때 카드에 쓸 CVE. 제목에 가장 많이 나온 것, 같으면 최신 번호."""
    counts = {}
    for event in group["events"]:
        for cve in CVE_RE.findall(event.get("title") or ""):
            counts[cve.upper()] = counts.get(cve.upper(), 0) + 1
    pool = counts or {cve: 0 for cve in group["cves"]}
    return max(pool, key=lambda cve: (pool[cve], int(cve.split("-")[1]), int(cve.split("-")[2]))) if pool else ""


def _lead(events_in, keys):
    """대표 기사: 제목에 이름·CVE가 있는 기사 → 국내 기사 → 신뢰 소스 → 첫 보도 순."""
    def score(event):
        title = (event.get("title") or "").lower()
        return ((any(key.lower() in title for key in keys if key) and 4 or 0)
                + (KOREAN_RE.search(event.get("title") or "") and 2 or 0)
                + (event.get("source") not in LOW_TRUST_SOURCES and 1 or 0))
    best = max(score(event) for event in events_in)
    return next(event for event in events_in if score(event) == best)


def build(events, now=None):
    """수집된 이벤트로 CVE 속보 묶음을 만든다. 순수 함수 — 과거 데이터 재현에도 쓴다."""
    now = now or _now()
    news, kev = [], {}
    for event in events:
        at = _time(event)
        if at is None or at > now + timedelta(minutes=10) or at < now - timedelta(days=MAX_AGE_DAYS):
            continue
        source = event.get("source") or ""
        if source == "cisa_kev":
            for cve in _cves(event):
                kev.setdefault(cve, dict(event, _at=at))
            continue
        if source in common_utils.NON_NEWS_SOURCES:
            continue
        if not live_news.public_url(event.get("url")) or not event.get("title"):
            continue
        news.append(dict(event, _at=at))

    items = []
    for group in _group_events(news):
        events_in = group["events"]
        first = events_in[0]["_at"]
        last = max(event["_at"] for event in events_in)
        if last < now - timedelta(hours=SHOW_HOURS):
            continue
        outlets = list(dict.fromkeys(event.get("source") for event in events_in))
        early = {event.get("source") for event in events_in if event["_at"] <= first + timedelta(hours=OUTLET_WINDOW_HOURS)}
        recent = {event.get("source") for event in events_in if event["_at"] >= now - timedelta(hours=6)}
        kev_cves = sorted(cve for cve in group["cves"] if cve in kev)
        urgent = any(_urgent(event) for event in events_in)
        signals = []
        if group["names"]:
            signals.append("named")
        if urgent:
            signals.append("urgent")
        if kev_cves:
            signals.append("kev")
        # 매체 수만으로는 KISA의 정기 "○○ 제품 보안 업데이트 권고"가 옮겨 실린 것도 걸린다
        # (재현: Oracle·Zoom·Apache). 치명적이거나 실제 악용 중이라는 판정이 함께 있어야 한다.
        reported = [event for event in events_in if not ROUTINE_RE.search(event.get("title") or "")]
        early = {event.get("source") for event in reported
                 if event["_at"] <= first + timedelta(hours=OUTLET_WINDOW_HOURS)}
        severe = any(event.get("severity") == "critical" or event.get("exploitation_status") == "active"
                     for event in reported)
        headline = any(HEADLINE_RE.search(event.get("title") or "") for event in reported)
        if len(early) >= MIN_OUTLETS and severe and headline:
            signals.append("outlets")
        if not signals:
            continue
        names = [_display_name(name, events_in) for name in group["names"]]
        label = names[0] if names else (kev_cves[0] if kev_cves and not group["names"] and len(kev_cves) == 1
                                         else _label_cve(group))
        lead = _lead(events_in, names + [label] + kev_cves)
        lead_title = (lead.get("title") or "").lower()
        kev_lead = None
        # KEV로만 걸렸는데 그 CVE를 제목에 단 기사가 없으면(배경으로만 언급) KEV 항목을 대표로 쓴다.
        if signals == ["kev"] and not any(cve.lower() in lead_title for cve in kev_cves):
            # 카드 이름과 같은 CVE의 KEV 항목을 쓴다(다른 KEV CVE와 묶였을 때 제목이 어긋났다).
            if label not in kev_cves:
                label = kev_cves[0]
            kev_lead = kev[label]
        cves = sorted(group["cves"], key=lambda cve: (cve != label, -int(cve.split("-")[1]), cve))
        article = {} if kev_lead else (live_news.public_article(lead) or {})
        items.append({
            "ref": hashlib.sha256(("cve:" + str(events_in[0].get("id") or events_in[0].get("url"))).encode()).hexdigest()[:12],
            "title": (kev_lead.get("title") if kev_lead else article.get("title") or str(lead.get("title")))[:300],
            "url": KEV_URL if kev_lead else (article.get("url") or live_news.public_url(lead.get("url"))),
            "source_label": "CISA KEV" if kev_lead else common_utils.source_label(lead.get("source") or ""),
            "image_url": article.get("image_url") or "", "source_image": article.get("source_image") or "",
            "category": "취약점", "group_label": label, "names": names, "cves": cves[:6],
            "kev": bool(kev_cves), "urgent": urgent, "signals": signals,
            "published_at": _iso((kev_lead or lead)["_at"]), "first_at": _iso(first), "last_at": _iso(last),
            "collected_at": _iso(now), "outlets": len(outlets), "outlets_6h": len(recent),
            "outlet_names": [common_utils.source_label(name) for name in outlets[:6]],
            "articles": len(events_in),
        })
    # 새 사건이 위로. 같은 시각이면 신호가 강한 쪽(KEV·이름 붙은 취약점)을 앞에 둔다.
    weight = {"kev": 3, "named": 2, "urgent": 1, "outlets": 1}
    items.sort(key=lambda item: (item["first_at"], sum(weight[s] for s in item["signals"])), reverse=True)
    return {"version": 1, "updated_at": _iso(now), "show_hours": SHOW_HOURS, "items": items[:MAX_ITEMS]}


def load_events(path=None, days=MAX_AGE_DAYS + 1):
    cutoff = _now() - timedelta(days=days)
    events = []
    for line in common_utils.iter_lines_reverse(path or common_utils.EVENTS_FILE):
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        stamp = live_news.utc_timestamp(event.get("fetched_at"))
        if stamp and datetime.fromisoformat(stamp.replace("Z", "+00:00")) < cutoff:
            break
        events.append(event)
    return events


def publish(payload, client=None):
    owned = client is None
    if owned:
        url = os.environ.get("REDIS_URL", "")
        if not url:
            return False
        import redis
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=3, socket_timeout=5,
                                retry_on_timeout=False)
    try:
        client.set(REDIS_KEY, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), ex=REDIS_TTL_SECONDS)
        return True
    finally:
        if owned:
            client.close()


def refresh(client=None, now=None):
    payload = build(load_events(), now=now)
    try:
        published = publish(payload, client=client)
    except Exception as error:
        # 연결 예외 메시지에 자격 증명이 든 Redis 주소가 섞일 수 있다.
        print("[cve-breaking] publish deferred ({})".format(type(error).__name__))
        published = False
    print("[*] 취약점 속보: {}건{}".format(len(payload["items"]), "" if published else " (게시 안 함)"))
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print the payload without publishing")
    args = parser.parse_args()
    if args.dry_run:
        print(json.dumps(build(load_events()), ensure_ascii=False, indent=2))
    else:
        refresh()


if __name__ == "__main__":
    main()
