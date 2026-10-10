import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import breaking_news as breaking
import incident_archive

NOW = datetime(2026, 10, 1, 3, 0, tzinfo=timezone.utc)  # 12:00 KST


def _rss(rows):
    items = "".join(
        "<item><title>{title} - {outlet}</title><link>https://news.google.com/rss/articles/{n}?oc=5</link>"
        "<pubDate>{date}</pubDate><source url=\"https://example.com\">{outlet}</source></item>".format(
            title=title, outlet=outlet, n=index, date=format_datetime(NOW - timedelta(minutes=minutes)))
        for index, (title, outlet, minutes) in enumerate(rows))
    return ("<?xml version=\"1.0\"?><rss><channel>" + items + "</channel></rss>").encode("utf-8")


def _build(rows):
    return breaking.build(breaking.parse(_rss(rows)), incident_archive.load_catalog(), now=NOW)


def test_parse_strips_outlet_suffix_and_duplicate_titles():
    rows = breaking.parse(_rss([("신한은행 고객정보 유출", "연합뉴스", 30), ("신한은행 고객정보 유출", "연합뉴스", 20)]))
    assert rows == [{"title": "신한은행 고객정보 유출", "outlet": "연합뉴스",
                     "url": "https://news.google.com/rss/articles/0?oc=5",
                     "published_at": (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")}]


# 2026-10-01 신한은행 사례: 오전 10시대 여러 매체가 같은 사고를 보도했다.
def test_same_incident_from_several_outlets_becomes_one_breaking_item():
    payload = _build([
        ("금감원, 신한은행 정보유출 긴급 현장조사", "연합뉴스", 103),
        ("[속보]신한은행 2만5000명 정보유출… 금감원 긴급 현장조사", "문화일보", 90),
        ("신한은행 해킹에 2만5000명 개인정보 유출", "한국일보", 60),
        ("신한은행 고객 정보 2만 5천 건 유출", "MBC 뉴스", 40),
    ])
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert item["group_label"] == "신한은행" and item["outlets"] == 4 and item["articles"] == 4
    assert item["tags"] == ["속보"] and item["category"] == "개인정보 유출"
    assert item["source_label"] == "MBC 뉴스"  # 가장 최근 보도를 대표로 보여 준다
    assert item["first_at"] < item["published_at"]


def test_single_outlet_claim_waits_for_more_coverage_unless_flagged_urgent():
    claim = [("[단독] 다크웹에 OO은행 고객정보 판매 주장", "데일리시큐", 30)]
    assert _build(claim)["items"] == []
    urgent = _build([("[긴급] 국내 대형 종교기관 2곳 사이버 공격 확인… 대규모 개인정보 유출", "데일리시큐", 30)])
    assert len(urgent["items"]) == 1 and urgent["items"][0]["tags"] == ["긴급"]


def test_sector_reports_without_an_institution_are_grouped():
    payload = _build([
        ("경찰, '금융권 해킹' 수사팀 43명으로 확대", "연합뉴스TV", 50),
        ("한국 금융권 노린 해커, 중국 디도스 대행 조직 배후 정황", "연합뉴스", 40),
        ("은행권 해킹 잇따르는데 보안투자는 뒷걸음", "Daily NTN", 20),
    ])
    assert [item["group_label"] for item in payload["items"]] == ["금융권"]


def test_outage_denied_as_hacking_is_labelled_service_outage():
    payload = _build([
        ("쿠팡 또 먹통‥\"해킹은 아니라지만\"", "MBC 뉴스", 90),
        ("\"해킹인가 철렁\"‥쿠팡 새벽 2시간 반 먹통", "MBC 뉴스", 60),
        ("'개인정보유출' 쿠팡, 한밤중 먹통···내부 전산 시스템도 멈춰", "여성경제신문", 40),
        ("\"해킹 아니냐\" 떠들썩...쿠팡이츠 한밤중 '먹통 사태'", "YTN", 10),
    ])
    assert payload["items"][0]["category"] == "서비스 장애"


def test_vendor_foreign_and_old_reports_are_ignored():
    payload = _build([
        ("파이오링크, 금융권 해킹 대책으로 '웹방화벽' 제시", "보안뉴스", 30),
        ("Coca-Cola confirms data breach after ransomware attack", "Reuters", 30),
        ("미 법무부, 중국 테크 기업 연계 도메인 압수… 해킹 인프라 무력화", "글로벌이코노믹", 30),
        ("신한은행 고객정보 유출", "연합뉴스", 60 * 30),
        ("신한은행 고객정보 유출 확인", "뉴시스", 60 * 30),
        ("신한은행 해킹 피해", "뉴스1", 60 * 30),
    ])
    assert payload["items"] == []


def test_refresh_publishes_and_then_waits_between_fetches(tmp_path):
    stored = {}

    class Redis:
        def set(self, key, value, ex):
            stored[key] = (json.loads(value), ex)

    calls = []

    def fetcher():
        calls.append(1)
        return _rss([("신한은행 정보유출", "연합뉴스", 30), ("신한은행 해킹 피해", "뉴스1", 20),
                     ("신한은행 고객정보 유출", "뉴시스", 10)])

    state = tmp_path / "state.json"
    payload = breaking.refresh(state_path=state, fetcher=fetcher, client=Redis(), now=NOW,
                               resolve=lambda url: ("", ""))
    assert payload["items"] and stored[breaking.REDIS_KEY][1] == breaking.REDIS_TTL_SECONDS
    assert breaking.refresh(state_path=state, fetcher=fetcher, client=Redis(), now=NOW) is None
    assert len(calls) == 1


def test_refresh_failure_backs_off_without_raising(tmp_path):
    def broken():
        raise OSError("redis://user:secret@host")

    state = tmp_path / "state.json"
    assert breaking.refresh(state_path=state, fetcher=broken) is None
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["error"] == "OSError" and "secret" not in state.read_text(encoding="utf-8")


def _payload_with_candidates():
    return {"items": [{"title": "최신 기사", "url": "https://news.google.com/rss/articles/a", "source_label": "A",
                       "published_at": "2026-10-01T02:50:00Z", "image_url": "",
                       "candidates": [
                           {"title": "최신 기사", "url": "https://news.google.com/rss/articles/a", "outlet": "A",
                            "published_at": "2026-10-01T02:50:00Z"},
                           {"title": "이전 기사", "url": "https://news.google.com/rss/articles/b", "outlet": "B",
                            "published_at": "2026-10-01T02:40:00Z"}]}]}


def test_attach_media_uses_the_original_article_and_its_image():
    calls = []

    def resolve(url):
        calls.append(url)
        return "https://www.example.co.kr/news/1", "https://img.example.co.kr/1.jpg"

    item = breaking.attach_media(_payload_with_candidates(), {}, resolve)["items"][0]
    assert item["url"] == "https://www.example.co.kr/news/1" and item["image_url"] == "https://img.example.co.kr/1.jpg"
    assert "candidates" not in item and calls == ["https://news.google.com/rss/articles/a"]


def test_attach_media_falls_back_to_the_next_article_with_an_image():
    found = {"https://news.google.com/rss/articles/a": ("https://a.example/1", ""),
             "https://news.google.com/rss/articles/b": ("https://b.example/2", "https://b.example/2.jpg")}
    item = breaking.attach_media(_payload_with_candidates(), {}, found.__getitem__)["items"][0]
    assert (item["title"], item["source_label"], item["url"]) == ("이전 기사", "B", "https://b.example/2")
    assert item["image_url"] == "https://b.example/2.jpg"


def test_attach_media_reuses_cached_lookups_and_respects_the_time_budget():
    cache = {}
    breaking.attach_media(_payload_with_candidates(), cache, lambda url: ("https://a.example/1", "https://a.example/1.jpg"))

    def never(url):
        raise AssertionError("cached lookups must not hit the network again")

    assert breaking.attach_media(_payload_with_candidates(), cache, never)["items"][0]["image_url"] == "https://a.example/1.jpg"
    ticks = iter([0, 100, 100, 100])
    late = breaking.attach_media(_payload_with_candidates(), {}, never, budget=10, clock=lambda: next(ticks))
    assert late["items"][0]["image_url"] == "" and "candidates" not in late["items"][0]


def test_page_image_reads_only_the_representative_image_tags():
    page = '<html><head><meta content="https://img.example.com/og.jpg" property="og:image"></head>' \
           '<body><img src="https://img.example.com/logo.png"></body></html>'
    assert breaking.page_image(page, "https://news.example.com/a") == "https://img.example.com/og.jpg"
    assert breaking.page_image('<img src="https://img.example.com/logo.png">', "https://news.example.com/a") == ""
