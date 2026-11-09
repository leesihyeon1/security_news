from datetime import datetime, timezone

import featured_sources


def article(ref, label, day="2026-10-08"):
    return {"type": "article", "ref": ref, "title": ref, "url": "https://example.com/" + ref,
            "source_label": label, "date": day, "category": "악성코드"}


def test_recent_sources_require_three_articles_and_reuse_feed_images():
    index = [article(str(i), "안랩 ASEC") for i in range(3)] + [
        article("old", "안랩 ASEC", "2026-09-01"),
        article("ms1", "Microsoft Security Blog"), article("ms2", "Microsoft Security Blog"),
        article("other", "일반 뉴스"),
    ]
    latest = {"items": [{"ref": "0", "published_at": "2026-10-08T09:00:00Z",
                         "image_url": "https://example.com/image.jpg"}]}
    result = featured_sources.build(index, latest, {"안랩 ASEC", "Microsoft Security Blog"},
                                    datetime(2026, 10, 10, tzinfo=timezone.utc))
    assert [source["label"] for source in result["sources"]] == ["안랩 ASEC"]
    assert len(result["sources"][0]["items"]) == 3
    assert result["sources"][0]["items"][0]["image_url"] == "https://example.com/image.jpg"


def test_duplicate_and_advisory_rows_do_not_fill_source():
    index = [article("one", "안랩 ASEC"), article("one", "안랩 ASEC"),
             article("two", "안랩 ASEC"), {**article("three", "안랩 ASEC"), "type": "cve"},
             {**article("marketing", "안랩 ASEC"), "category": "제품행사"}]
    result = featured_sources.build(index, {"items": []}, {"안랩 ASEC"},
                                    datetime(2026, 10, 10, tzinfo=timezone.utc))
    assert result["sources"] == []
