"""Publisher images for news cards that arrive without one (no model calls).

카드 이미지는 다음 순서로 고른다.
1) 기사 원문의 대표 이미지(og:image·twitter:image) — RSS에 사진이 없는 출처도 원문에는 있다.
   실측(2026-10-10): 최신 기사 300건 중 128건이 사진 없이 참고 사진을 썼고, Help Net Security·
   데일리시큐·Infosecurity Magazine 등 몇몇 출처에 몰려 있었다.
2) 그래도 없으면 언론사 홈페이지의 대표 이미지(로고·배너) — source_image로 따로 싣는다.
3) 둘 다 없으면 대시보드가 기사 종류별 참고 사진을 한 줄 안에서 겹치지 않게 고른다.

외부 페이지는 network_safety.safe_get으로만 받는다(리다이렉트마다 사설망 여부를 다시 본다).
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
ARTICLE_IMAGES = ROOT / "data" / "news_images.json"
OUTLET_IMAGES = ROOT / "data" / "outlet_images.json"
OUTLET_TTL_DAYS = 30
PAGE_LIMIT = 1_000_000
ARTICLES_PER_RUN = 12
OUTLETS_PER_RUN = 4
OUTLET_IMAGE_MAX_BYTES = 600_000
BUDGET_SECONDS = 30
_outlet_cache = {"mtime": None, "data": {}}


def meta_image(markup, base):
    """대표 이미지 태그만 읽는다 — 본문 첫 그림은 로고·광고인 경우가 많다."""
    from bs4 import BeautifulSoup
    import live_news

    soup = BeautifulSoup(markup or "", "html.parser")
    for attrs in ({"property": "og:image"}, {"name": "og:image"}, {"name": "twitter:image"},
                  {"property": "twitter:image"}):
        node = soup.find("meta", attrs=attrs)
        value = live_news.public_url(node.get("content"), base) if node else ""
        if value:
            return value
    return ""


def fetch_page(url, timeout=8):
    """Return (final_url, html) for a public HTML page, or ("", "")."""
    import network_safety

    with network_safety.safe_get(url, timeout=timeout, stream=True,
                                 headers={"User-Agent": "Mozilla/5.0 boannews-media/1.0"}) as response:
        if response.status_code != 200 or "html" not in response.headers.get("Content-Type", ""):
            return "", ""
        chunks, size = [], 0
        for chunk in response.iter_content(16384):
            chunks.append(chunk)
            size += len(chunk)
            if size >= PAGE_LIMIT:
                break
        return response.url, b"".join(chunks).decode(response.encoding or "utf-8", "replace")


def page_image(url):
    try:
        final, html = fetch_page(url)
        return meta_image(html, final) if html else ""
    except Exception:
        return ""


def light_image(url):
    """카드마다 불러오므로 큰 로고 파일은 쓰지 않는다 — 실측: 3000px PNG 1.8MB, 1792px PNG 2.2MB."""
    import network_safety

    try:
        with network_safety.safe_get(url, timeout=8, stream=True,
                                     headers={"User-Agent": "Mozilla/5.0 boannews-media/1.0"}) as response:
            if response.status_code != 200 or not response.headers.get("Content-Type", "").startswith("image/"):
                return False
            length = response.headers.get("Content-Length", "")
            if length.isdigit():
                return int(length) <= OUTLET_IMAGE_MAX_BYTES
            size = 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > OUTLET_IMAGE_MAX_BYTES:
                    return False
            return True
    except Exception:
        return False


def outlet_page_image(url):
    image = page_image(url)
    return image if image and light_image(image) else ""


def _host(url):
    return (urlsplit(url or "").hostname or "").lower()


def _read(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write(path, data):
    import incident_archive
    incident_archive.write_json(path, data)


def cached_outlet_image(url, path=None):
    """네트워크 없이 저장된 언론사 대표 이미지만 돌려준다(카드를 만들 때 쓴다)."""
    path = path or OUTLET_IMAGES
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return ""
    if _outlet_cache["mtime"] != (str(path), mtime):
        _outlet_cache.update(mtime=(str(path), mtime), data=_read(path))
    return (_outlet_cache["data"].get(_host(url)) or {}).get("image", "")


def outlet_image(url, path=None, fetcher=outlet_page_image, now=None):
    """언론사 홈페이지 대표 이미지. 도메인마다 30일 동안 저장해 두고 다시 받지 않는다."""
    # 기본 경로는 호출 때 읽는다 — 정의 때 묶으면 테스트가 경로를 바꿔도 실제 파일에 썼다.
    path = path or OUTLET_IMAGES
    host = _host(url)
    if not host:
        return ""
    data = _read(path)
    now = now or datetime.now(timezone.utc)
    saved = data.get(host)
    if saved and saved.get("at", "") >= (now - timedelta(days=OUTLET_TTL_DAYS)).isoformat():
        return saved.get("image", "")
    image = fetcher("{}://{}/".format(urlsplit(url).scheme or "https", host))
    data[host] = {"image": image, "at": now.isoformat()}
    _write(path, data)
    return image


def refresh(rows=None, articles=ARTICLES_PER_RUN, outlets=OUTLETS_PER_RUN, budget=BUDGET_SECONDS,
            fetcher=page_image, outlet_fetcher=outlet_page_image, publish=None, clock=time.monotonic):
    """사진 없는 최신 기사 몇 건씩 원문 대표 이미지를 찾고, 없으면 언론사 이미지를 준비한다.

    찾은 결과는 data/news_images.json(기사)과 data/outlet_images.json(언론사)에 쌓이고,
    바뀐 카드만 실시간 피드(Redis)에 다시 싣는다. 실패해도 예외를 내지 않는다.
    """
    import live_news

    deadline = clock() + budget
    rows = live_news.from_events_file() if rows is None else rows
    images = _read(ARTICLE_IMAGES)
    pending = [row for row in rows if not row["image_url"] and row["url"] not in images][:articles]
    changed = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for row, image in zip(pending, pool.map(fetcher, [row["url"] for row in pending])):
            images[row["url"]] = image  # 빈 값도 남겨 같은 기사를 매번 다시 받지 않는다.
            if image:
                row["image_url"], row["source_image"] = image, ""
                changed.append(row)
    allowed = {row["url"] for row in rows}
    _write(ARTICLE_IMAGES, {url: image for url, image in images.items() if url in allowed})
    hosts = []
    for row in rows:
        if not row["image_url"] and _host(row["url"]) not in hosts:
            hosts.append(_host(row["url"]))
    known = _read(OUTLET_IMAGES)
    for host in [host for host in hosts if host and host not in known][:outlets]:
        if clock() > deadline:
            break
        outlet_image("https://" + host + "/", fetcher=outlet_fetcher)
    for row in rows:
        if not row["image_url"] and not row.get("source_image"):
            row["source_image"] = cached_outlet_image(row["url"], OUTLET_IMAGES)
            if row["source_image"]:
                changed.append(row)
    changed = list({row["ref"]: row for row in changed}.values())
    if changed:
        (publish or live_news.publish_rows)(changed)
    return {"articles_checked": len(pending), "found": sum(1 for row in pending if row["image_url"]),
            "republished": len(changed)}
