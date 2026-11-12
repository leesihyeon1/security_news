from scripts.collect_x_post_urls import extract_posts, normalize_post


def test_normalize_post_requires_matching_author():
    assert normalize_post("https://twitter.com/DarkWebInformer/status/123?ref=home", "DarkWebInformer") == (
        "https://x.com/DarkWebInformer/status/123"
    )
    assert normalize_post("https://x.com/other/status/123", "DarkWebInformer") is None
    assert normalize_post("https://example.com/DarkWebInformer/status/123", "DarkWebInformer") is None


def test_extract_posts_deduplicates_and_orders_by_id():
    links = [
        "https://x.com/troyhunt/status/12",
        "https://x.com/troyhunt/status/10",
        "https://x.com/troyhunt/status/12/photo/1",
        "https://x.com/other/status/99",
        "https://x.com/troyhunt/status/11",
    ]
    assert extract_posts(links, "troyhunt", 2) == [
        "https://x.com/troyhunt/status/12",
        "https://x.com/troyhunt/status/11",
    ]
