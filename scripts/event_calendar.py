# -*- coding: utf-8 -*-
"""Build a conservative security-event calendar from collected news articles."""

import json
import re
from datetime import date, datetime, timedelta

import common_utils

EVENT_RE = re.compile(r"웨비나|웹세미나|컨퍼런스|콘퍼런스|세미나|워크숍|포럼|"
                      r"webinar|conference|workshop", re.I)
SECURITY_RE = re.compile(r"보안|사이버|정보보호|해킹|침해|취약점|랜섬웨어|위협|"
                         r"제로트러스트|공급망|CISO|SOC|EDR|XDR|security|cyber|threat", re.I)
DATE_RE = re.compile(r"(?:(?P<year>20\d{2})\s*년\s*)?(?P<month>1[0-2]|0?[1-9])\s*월\s*"
                     r"(?P<day>3[01]|[12]\d|0?[1-9])\s*일")
UPCOMING_RE = re.compile(r"오는|개최한다|개최할|열린다|열릴|진행한다|진행할|예정|"
                         r"참가자\s*모집|참가\s*신청|사전\s*등록|개최한다고", re.I)
PAST_RE = re.compile(r"지난|개최했다|열렸다|진행했다|참석했다|발표했다")
DEADLINE_RE = re.compile(r"등록\s*마감|신청\s*마감|접수\s*마감|마감일")
TIME_RE = re.compile(r"(?:(오전|오후)\s*)?(\d{1,2})\s*시(?:\s*(\d{1,2})\s*분)?")
MAX_EVENTS = 120


def _published_date(event):
    try:
        return date.fromisoformat(str(event.get("published_at") or
                                       event.get("fetched_at") or "")[:10])
    except ValueError:
        return None


def _event_date(match, published):
    year = int(match.group("year")) if match.group("year") else published.year
    month, day = int(match.group("month")), int(match.group("day"))
    if not match.group("year") and month < published.month - 6:
        year += 1
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _time(text):
    match = TIME_RE.search(text)
    if not match:
        return ""
    hour, minute = int(match.group(2)), int(match.group(3) or 0)
    if hour > 23 or minute > 59 or (match.group(1) and hour > 12):
        return ""
    if match.group(1) == "오후" and hour < 12:
        hour += 12
    if match.group(1) == "오전" and hour == 12:
        hour = 0
    return "{:02d}:{:02d}".format(hour, minute)


def extract(event, today=None):
    """Return one future/very recent scheduled event, or None when date is uncertain."""
    today = today or date.today()
    title = str(event.get("title") or "").strip()
    summary = str(event.get("summary") or event.get("ai_summary") or "").strip()
    published = _published_date(event)
    if not published or not EVENT_RE.search(title) or not SECURITY_RE.search(title + " " + summary):
        return None
    # Only the opening text describes the event itself. Later dates often refer to
    # registration deadlines, previous editions or speakers' other appearances.
    source = title + ". " + summary[:480]
    for match in DATE_RE.finditer(source):
        when = _event_date(match, published)
        if not when or when < today - timedelta(days=30) or when > today + timedelta(days=365):
            continue
        if when < published:
            continue
        context = source[max(0, match.start() - 55):match.end() + 100]
        if DEADLINE_RE.search(context):
            continue
        if not UPCOMING_RE.search(context) or PAST_RE.search(context):
            continue
        after = source[match.end():match.end() + 65]
        time = _time(after)
        kind_match = EVENT_RE.search(title)
        kind = kind_match.group(0) if kind_match else "행사"
        online = bool(re.search(r"온라인|라이브\s*웨비나|webinar", source[:260], re.I))
        return {"id": common_utils.event_ref(event.get("id")),
                "date": when.isoformat(), "time": time, "timezone": "Asia/Seoul" if time else "",
                "title": title, "kind": kind, "mode": "온라인" if online else "",
                "source_label": common_utils.source_label(event.get("source") or ""),
                "url": str(event.get("url") or ""), "basis": "기사에 명시된 개최 예정일"}
    return None


def build(events, today=None):
    today = today or date.today()
    dedup = {}
    for event in events:
        item = extract(event, today=today)
        if not item or not item["url"]:
            continue
        key = (item["date"], re.sub(r"\W+", "", item["title"]).casefold())
        dedup.setdefault(key, item)
    items = sorted(dedup.values(), key=lambda item: (item["date"], item["time"], item["title"]))
    return {"generated_at": datetime.utcnow().isoformat() + "Z", "events": items[:MAX_EVENTS]}


def from_collected_events(today=None):
    today = today or date.today()
    cutoff = (today - timedelta(days=40)).isoformat()
    rows = []
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if str(event.get("fetched_at") or "")[:10] < cutoff:
            break
        if event.get("source") not in common_utils.NON_NEWS_SOURCES:
            rows.append(event)
    return build(rows, today=today)
