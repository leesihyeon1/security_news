import json
from datetime import datetime, timezone

import news_media


def test_meta_image_reads_only_representative_tags():
    page = '<html><head><meta content="https://img.example.com/og.jpg" property="og:image"></head>' \
           '<body><img src="https://img.example.com/logo.png"></body></html>'
    assert news_media.meta_image(page, "https://news.example.com/a") == "https://img.example.com/og.jpg"
    assert news_media.meta_image('<img src="https://img.example.com/logo.png">', "https://news.example.com/a") == ""
    assert news_media.meta_image('<meta property="og:image" content="http://127.0.0.1/x.png">', "https://a.example") == ""


def test_outlet_image_is_cached_per_domain(tmp_path):
    path = tmp_path / "outlets.json"
    calls = []

    def fetch(url):
        calls.append(url)
        return "https://www.ytn.co.kr/og.png"

    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    assert news_media.outlet_image("https://www.ytn.co.kr/_ln/1", path, fetch, now) == "https://www.ytn.co.kr/og.png"
    assert news_media.outlet_image("https://www.ytn.co.kr/_ln/2", path, fetch, now) == "https://www.ytn.co.kr/og.png"
    assert calls == ["https://www.ytn.co.kr/"]
    assert news_media.cached_outlet_image("https://www.ytn.co.kr/_ln/3", path) == "https://www.ytn.co.kr/og.png"
    assert news_media.cached_outlet_image("https://other.example/a", path) == ""


def _row(n, image=""):
    return {"ref": "r{}".format(n), "url": "https://news{}.example/a".format(n % 2), "title": "t", "image_url": image,
            "source_image": "", "published_at": "2026-10-10T00:00:00Z", "collected_at": "2026-10-10T00:00:00Z"}


def test_refresh_backfills_article_images_then_outlet_images(tmp_path, monkeypatch):
    monkeypatch.setattr(news_media, "ARTICLE_IMAGES", tmp_path / "articles.json")
    monkeypatch.setattr(news_media, "OUTLET_IMAGES", tmp_path / "outlets.json")
    rows = [_row(0), _row(1), _row(2, "https://img.example/kept.jpg")]
    rows[1]["url"] = "https://news1.example/b"
    pages = {"https://news0.example/a": "https://img.example/a.jpg", "https://news1.example/b": "",
             "https://news1.example/": "https://news1.example/logo.png"}
    published = []
    fake = lambda url: pages.get(url, "")
    result = news_media.refresh(rows, fetcher=fake, outlet_fetcher=fake, publish=published.extend)
    assert rows[0]["image_url"] == "https://img.example/a.jpg"
    assert rows[1]["image_url"] == "" and rows[1]["source_image"] == "https://news1.example/logo.png"
    assert result == {"articles_checked": 2, "found": 1, "republished": 2}
    assert {row["ref"] for row in published} == {"r0", "r1"}
    # 한 번 확인한 기사는 다시 받지 않는다.
    assert json.loads((tmp_path / "articles.json").read_text(encoding="utf-8"))["https://news1.example/b"] == ""
    again = news_media.refresh(rows, fetcher=lambda url: (_ for _ in ()).throw(AssertionError(url)), publish=published.extend)
    assert again["articles_checked"] == 0


class _Response:
    def __init__(self, headers, chunks=()):
        self.status_code, self.headers, self._chunks = 200, headers, chunks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, size):
        return iter(self._chunks)


def test_heavy_outlet_images_are_skipped(monkeypatch):
    import network_safety

    responses = {
        "https://img.example/small.png": _Response({"Content-Type": "image/png", "Content-Length": "8000"}),
        "https://img.example/huge.png": _Response({"Content-Type": "image/png", "Content-Length": "1849285"}),
        "https://img.example/stream.png": _Response({"Content-Type": "image/png"}, [b"x" * 400_000] * 2),
        "https://img.example/page.html": _Response({"Content-Type": "text/html", "Content-Length": "100"}),
    }
    monkeypatch.setattr(network_safety, "safe_get", lambda url, **kwargs: responses[url])
    assert news_media.light_image("https://img.example/small.png")
    assert not news_media.light_image("https://img.example/huge.png")
    assert not news_media.light_image("https://img.example/stream.png")
    assert not news_media.light_image("https://img.example/page.html")
