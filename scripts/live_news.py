"""Public, bounded news feed published independently of daily reports."""

import argparse
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from dashboard_text import event_summary, public_text

INDEX_KEY = "news:latest"
ITEM_PREFIX = "news:item:"
MAX_ITEMS = 300
RETENTION_SECONDS = 14 * 86400
KST = timezone(timedelta(hours=9))
LOCAL_DATE_SOURCES = {"boannews", "dailysecu", "dailysecurity", "ahnlab_asec", "asec"}


def public_url(value, base=""):
    try:
        value = str(value or "").strip()
        if not value:
            return ""
        url = urljoin(base, value)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host or parts.username or parts.password:
            return ""
        if host == "localhost" or host.endswith((".local", ".internal")):
            return ""
        try:
            if not ipaddress.ip_address(host).is_global:
                return ""
        except ValueError:
            pass
        return url if len(url) <= 2048 else ""
    except ValueError:
        return ""


def article_image(markup, base=""):
    """Read publisher media only; no additional request or model call."""
    from bs4 import BeautifulSoup

    soup = markup if hasattr(markup, "find_all") else BeautifulSoup(markup or "", "html.parser")
    for attrs in ({"property": "og:image"}, {"name": "twitter:image"}):
        node = soup.find("meta", attrs=attrs)
        if node:
            value = public_url(node.get("content"), base)
            if value:
                return value
    for node in soup.find_all(["img", "thumbnail", "content", "enclosure"]):
        if node.name == "enclosure" and not str(node.get("type", "")).startswith("image/"):
            continue
        if node.name == "content" and node.get("medium") not in (None, "image"):
            continue
        if any(str(node.get(dim, "")) in ("0", "1") for dim in ("width", "height")):
            continue
        value = public_url(node.get("url") or node.get("src") or node.get("data-src"), base)
        if value and not any(token in value.lower() for token in ("feedburner", "/pixel", "/tracking")):
            return value
    return ""


def utc_timestamp(value, source=""):
    try:
        date = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=KST if source in LOCAL_DATE_SOURCES else timezone.utc)
        return date.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return ""


def public_article(event):
    import common_utils

    source = event.get("source") or ""
    url = public_url(event.get("url"))
    title = public_text(str(event.get("title") or "")).strip()
    collected = utc_timestamp(event.get("fetched_at"))
    published = utc_timestamp(event.get("published_at"), source)
    if source in common_utils.NON_NEWS_SOURCES or not url or not title or not (published or collected):
        return None
    # An invalid future publisher timestamp must not pin an article at the top.
    if published and collected and published > utc_timestamp(
            datetime.fromisoformat(collected.replace("Z", "+00:00")) + timedelta(hours=6)):
        published = ""
    return {
        "ref": common_utils.event_ref(event.get("id") or url),
        "title": title[:500],
        "url": url,
        "source": source,
        "source_label": common_utils.source_label(source),
        "category": public_text(str(event.get("category") or "미분류"))[:60],
        "summary": public_text(event_summary(event, 600)),
        "published_at": published,
        "collected_at": collected,
        "image_url": public_url(event.get("image_url")),
    }


def latest_articles(events, limit=MAX_ITEMS):
    seen = set()
    rows = []
    for event in events:
        row = public_article(event)
        if row and row["url"] not in seen:
            seen.add(row["url"])
            rows.append(row)
    return sorted(rows, key=lambda row: (row["published_at"] or row["collected_at"], row["ref"]), reverse=True)[:limit]


def from_events_file(path=None, limit=MAX_ITEMS):
    import common_utils

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=RETENTION_SECONDS)
    events = []
    for line in common_utils.iter_lines_reverse(Path(path) if path else common_utils.EVENTS_FILE):
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        stamp = utc_timestamp(event.get("fetched_at"))
        if stamp and datetime.fromisoformat(stamp.replace("Z", "+00:00")) < cutoff:
            break
        events.append(event)
    rows = latest_articles(events, limit)
    try:
        images = json.loads((common_utils.DATA_DIR / "news_images.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        images = {}
    for row in rows:
        if not row["image_url"]:
            row["image_url"] = public_url(images.get(row["url"]))
    return rows


def backfill_images(rows, limit):
    """Fetch a bounded set of publisher metadata; never executes page scripts."""
    from concurrent.futures import ThreadPoolExecutor
    import common_utils
    import network_safety

    path = common_utils.DATA_DIR / "news_images.json"
    try:
        images = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        images = {}

    def fetch_image(row):
        try:
            with network_safety.safe_get(row["url"], timeout=8, stream=True,
                                        headers={"User-Agent": "Mozilla/5.0"}) as response:
                if response.status_code != 200 or "html" not in response.headers.get("Content-Type", ""):
                    return row["url"], ""
                chunks = []
                size = 0
                for chunk in response.iter_content(16384):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= 1000000:
                        break
                return row["url"], article_image(b"".join(chunks), response.url)
        except Exception:
            return row["url"], ""

    candidates = [row for row in rows if not row["image_url"]][:max(0, min(limit, 60))]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for url, image in pool.map(fetch_image, candidates):
            if image:
                images[url] = image
    allowed = {row["url"] for row in rows}
    images = {url: image for url, image in images.items() if url in allowed}
    path.write_text(json.dumps(images, ensure_ascii=False), encoding="utf-8")
    for row in rows:
        row["image_url"] = row["image_url"] or images.get(row["url"], "")
    return rows


def feed_payload(rows):
    return {
        "version": 1,
        "updated_at": max((row.get("collected_at") or "" for row in rows), default=""),
        "items": rows,
    }


def write_snapshot(path, rows=None):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(feed_payload(from_events_file() if rows is None else rows),
                                 ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def publish_rows(rows, client=None):
    if not rows:
        return 0
    owned = client is None
    if owned:
        url = os.environ.get("REDIS_URL", "")
        if not url or os.environ.get("LIVE_NEWS_ENABLED", "1").strip().lower() in ("0", "false", "no"):
            return 0
        import redis
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=2,
                                socket_timeout=3, retry_on_timeout=False)
    try:
        pipe = client.pipeline(transaction=True)
        for row in rows:
            stamp = row["published_at"] or row["collected_at"]
            score = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            pipe.set(ITEM_PREFIX + row["ref"], json.dumps(row, ensure_ascii=False), ex=RETENTION_SECONDS)
            pipe.zadd(INDEX_KEY, {row["ref"]: score})
        pipe.zremrangebyrank(INDEX_KEY, 0, -MAX_ITEMS - 1)
        pipe.expire(INDEX_KEY, RETENTION_SECONDS)
        pipe.execute()
        return len(rows)
    finally:
        if owned:
            client.close()


def publish_events(events):
    try:
        return publish_rows(latest_articles(reversed(events)))
    except Exception as error:
        # Connection exceptions may contain the credential-bearing Redis URL.
        print("[live-news] publish deferred ({})".format(type(error).__name__))
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", help="Write a static fallback without a Git push")
    parser.add_argument("--publish", action="store_true", help="Seed the existing Redis news feed")
    parser.add_argument("--images", type=int, default=0, help="Backfill at most 60 publisher thumbnails")
    args = parser.parse_args()
    rows = from_events_file()
    if args.images:
        backfill_images(rows, args.images)
    if args.snapshot:
        write_snapshot(args.snapshot, rows)
    if args.publish:
        print("Published {} articles".format(publish_rows(rows)))
    print("Latest feed: {} articles".format(len(rows)))


if __name__ == "__main__":
    main()
