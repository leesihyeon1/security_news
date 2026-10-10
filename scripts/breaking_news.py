"""Domestic breaking incident reports from Google News search RSS.

보안 전문지 두 곳만 수집하면 일반 언론보다 늦게 안다 — 2026-10-01 신한은행 정보유출은 일반
언론이 10시 17분경 보도했는데 우리 첫 수집은 11시 55분이었다. 구글 뉴스 검색 RSS로 국내
언론 전체에서 사고 보도를 찾고, 같은 사고를 다룬 매체 수를 긴급도로 쓴다.

키·모델 호출이 없다. 제목·링크·매체·시각만 쓰고 본문은 저장하지 않는다. 구글 뉴스 RSS는
비공식 피드라 실패하면 조용히 넘어가고, 마지막 결과는 Redis 만료 시각까지 그대로 둔다.

화면 표시 전용이다. 제목뿐인 속보를 events.jsonl에 쓰면 리포트·통계·트렌드·검색·아카이브
후보 집계가 얕은 기사로 채워진다 — 이 모듈은 Redis 키 하나와 자체 상태 파일만 쓴다.
"""

import argparse
import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import incident_archive
import incident_archive_review as review

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "state" / "breaking_news.json"
FEED_URL = "https://news.google.com/rss/search"
QUERY = "해킹 OR 정보유출 OR 개인정보유출 OR 랜섬웨어 OR 디도스 OR 침해사고 OR 사이버공격 when:1d"
REDIS_KEY = "news:breaking"
REDIS_TTL_SECONDS = 3 * 3600
MIN_INTERVAL_SECONDS = 240
FAILURE_BACKOFF_SECONDS = 900
WINDOW_HOURS = 24
MIN_OUTLETS = 3
MAX_ITEMS = 6
MAX_BYTES = 2_000_000
TAG_RE = re.compile(r"\[(속보|긴급|단독)\]|^(속보|긴급)\s*[:|]")
# 기관명이 없는 업권 단위 보도("금융권 해킹 배후")는 업권으로 묶는다 — 실측에서 24개 매체가
# 다룬 금융권 후속 보도가 기관 미상으로 흩어졌다.
SECTOR_PATTERNS = (
    ("금융권", r"금융권|은행권|금융사|금융기관|금융회사|시중은행|저축은행|카드사"),
    ("통신사", r"통신사|이동통신"),
    ("공공기관", r"공공기관|정부기관|지자체|부처"),
    ("의료기관", r"병원|의료기관"),
    ("교육기관", r"대학교|대학|학교"),
)
OUTAGE_RE = re.compile(r"먹통|접속\s*(?:장애|불가|오류)|서비스\s*(?:장애|중단)|전산\s*장애")
NOT_HACK_RE = re.compile(r"해킹\s*(?:은|이)?\s*아니|해킹\s*아닌")


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch(query=QUERY, timeout=15):
    url = FEED_URL + "?" + urllib.parse.urlencode({"q": query, "hl": "ko", "gl": "KR", "ceid": "KR:ko"})
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 boannews-breaking/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(MAX_BYTES + 1)[:MAX_BYTES]


def parse(xml_bytes):
    """Return [{title, outlet, url, published_at}] from a Google News RSS document."""
    rows, seen = [], set()
    for item in ET.fromstring(xml_bytes).findall("./channel/item"):
        outlet = review.clean(item.findtext("source"))
        title = review.clean(item.findtext("title"))
        if outlet and title.endswith(" - " + outlet):
            title = title[: -len(outlet) - 3].strip()
        url = incident_archive.canonical_url(item.findtext("link"))
        try:
            published = parsedate_to_datetime(item.findtext("pubDate") or "")
        except (TypeError, ValueError):
            continue
        if published is None or published.tzinfo is None or not (title and outlet and url):
            continue
        key = (outlet, review.normalized(title))
        if key in seen:
            continue
        seen.add(key)
        rows.append({"title": title[:300], "outlet": outlet[:80], "url": url, "published_at": _iso(published)})
    return rows


def _group(row, assessment, catalog):
    title = row["title"]
    if assessment["linked_incident_id"]:
        record = next(item for item in catalog["incidents"] if item["id"] == assessment["linked_incident_id"])
        return "record:" + record["id"], record["organizations"][0] if record["organizations"] else record["title"]
    known = review.names_in(title, catalog)
    if len(known) == 1:
        return "org:" + known[0], known[0]
    sector = next((label for label, pattern in SECTOR_PATTERNS if re.search(pattern, title)), "")
    if sector:
        return "sector:" + sector, sector
    if len(known) > 1:
        return "orgs:" + ",".join(known), "·".join(known)
    if assessment["organizations"]:
        name = assessment["organizations"][0]
        return "org:" + name, name
    # 기관도 업권도 없는 속보·긴급 표시 기사는 제목 하나를 묶음으로 둔다(다른 기사와 합치지 않는다).
    if TAG_RE.search(title):
        return "title:" + review.normalized(title)[:40], ""
    return "", ""


def _sector_assessment(title):
    """국내 언론의 업권 단위 보도("은행권 해킹 잇따라")는 피해 기관이 없어도 국내 사고 보도로 본다."""
    if (not any(re.search(pattern, title) for _, pattern in SECTOR_PATTERNS) or not review.INCIDENT_RE.search(title)
            or review.EXCLUDE_RE.search(title) or review.PROMO_RE.search(title) or review.FOREIGN_RE.search(title)):
        return None
    category = next((key for key, pattern in review.CATEGORY_PATTERNS if re.search(pattern, title, re.I)), "intrusion")
    return {"kind": "context", "organizations": [], "domestic": "confirmed", "linked_incident_id": "", "category": category,
            "claim_status": "alleged" if review.ALLEGED_RE.search(title) else "reported"}


def build(rows, catalog, now=None):
    """Cluster domestic incident reports and keep groups covered by several outlets or a 속보 tag."""
    now = now or _now()
    cutoff = now - timedelta(hours=WINDOW_HOURS)
    groups = {}
    for row in rows:
        published = datetime.fromisoformat(row["published_at"].replace("Z", "+00:00"))
        if published < cutoff or published > now + timedelta(minutes=10):
            continue
        assessment = review.assess({"url": row["url"], "title": row["title"], "summary": "",
                                    "published_at": row["published_at"][:10]}, catalog) or _sector_assessment(row["title"])
        if not assessment or (assessment["domestic"] != "confirmed" and not assessment["organizations"]):
            continue
        key, label = _group(row, assessment, catalog)
        if not key:
            continue
        group = groups.setdefault(key, {"label": label, "articles": [], "alleged": 0, "tags": set(), "outage": 0,
                                        "categories": Counter()})
        group["categories"][assessment["category"]] += 1
        group["articles"].append(dict(row, published=published))
        group["alleged"] += assessment["claim_status"] == "alleged"
        group["outage"] += bool(OUTAGE_RE.search(row["title"]) or NOT_HACK_RE.search(row["title"]))
        tag = TAG_RE.search(row["title"])
        # 묶음에는 긴급도(속보·긴급)만 붙인다 — 매체 수십 곳이 다룬 묶음에 기사 하나의 '단독'을 달면 오해를 부른다.
        if tag and (tag.group(1) or tag.group(2)) in ("속보", "긴급"):
            group["tags"].add(tag.group(1) or tag.group(2))
    items = []
    for key, group in groups.items():
        articles = sorted(group["articles"], key=lambda article: article["published"])
        outlets = sorted({article["outlet"] for article in articles})
        recent = {article["outlet"] for article in articles if now - article["published"] <= timedelta(hours=6)}
        if len(outlets) < MIN_OUTLETS and "속보" not in group["tags"] and "긴급" not in group["tags"]:
            continue
        lead = articles[-1]
        first = articles[0]["published"]
        items.append({
            "ref": "breaking-" + hashlib.sha256((key + _iso(first)[:10]).encode()).hexdigest()[:16],
            "title": lead["title"], "url": lead["url"], "source": "google_news",
            "source_label": lead["outlet"],
            "category": "서비스 장애" if group["outage"] * 2 >= len(articles)
            else review.CATEGORY_LABELS[group["categories"].most_common(1)[0][0]],
            "group_label": group["label"], "published_at": _iso(lead["published"]), "first_at": _iso(first),
            "collected_at": _iso(now), "outlets": len(outlets), "outlets_6h": len(recent),
            "outlet_names": outlets[:6], "articles": len(articles), "tags": sorted(group["tags"]),
            "claim_status": "alleged" if group["alleged"] * 2 > len(articles) else "reported",
        })
    items.sort(key=lambda item: (item["outlets_6h"] >= MIN_OUTLETS, item["published_at"]), reverse=True)
    return {"version": 1, "updated_at": _iso(now), "source": "google_news", "window_hours": WINDOW_HOURS,
            "min_outlets": MIN_OUTLETS, "items": items[:MAX_ITEMS]}


def _load_state(path=STATE):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _redis_client():
    import common_utils  # noqa: F401 — 단독 실행에서도 .env의 REDIS_URL을 환경변수로 올린다.
    url = os.environ.get("REDIS_URL", "")
    if not url:
        return None
    import redis
    return redis.from_url(url, decode_responses=True, socket_connect_timeout=3, socket_timeout=5,
                          retry_on_timeout=False)


def publish(payload, client=None):
    owned = client is None
    client = client or _redis_client()
    if client is None:
        return False
    try:
        client.set(REDIS_KEY, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), ex=REDIS_TTL_SECONDS)
        return True
    finally:
        if owned:
            client.close()


def refresh(force=False, state_path=STATE, fetcher=fetch, client=None, now=None):
    """Fetch, cluster and publish at most every few minutes. Never raises."""
    state = _load_state(state_path)
    clock = time.time()
    if not force and clock < state.get("next_at", 0):
        return None
    try:
        payload = build(parse(fetcher()), incident_archive.load_catalog(), now=now)
        published = publish(payload, client)
        state = {"next_at": clock + MIN_INTERVAL_SECONDS, "updated_at": payload["updated_at"],
                 "items": len(payload["items"]), "published": published}
        print("[breaking] 국내 속보 {}건 갱신{}".format(len(payload["items"]), "" if published else "(Redis 미설정)"))
        return payload
    except Exception as error:
        # 연결 예외 문자열에는 자격 증명이 든 Redis 주소가 섞일 수 있어 종류만 남긴다.
        state = dict(state, next_at=clock + FAILURE_BACKOFF_SECONDS, error=type(error).__name__)
        print("[breaking] 국내 속보 갱신 보류({})".format(type(error).__name__))
        return None
    finally:
        try:
            incident_archive.write_json(state_path, state)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="Print clusters without publishing")
    args = parser.parse_args()
    if args.dry_run:
        print(json.dumps(build(parse(fetch()), incident_archive.load_catalog()), ensure_ascii=False, indent=2))
        return
    refresh(force=True)


if __name__ == "__main__":
    main()
