import json
from datetime import datetime, timedelta

import kev_feedback_labeler as kfl


def _iso(hours_ago):
    return (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat() + "Z"


def _article_event(event_id, cves, hours_ago, source="asec"):
    return {
        "id": "{}:{}".format(source, event_id),
        "source": source,
        "title": "t{}".format(event_id),
        "cves": cves,
        "fetched_at": _iso(hours_ago),
    }


def _kev_event(cve, hours_ago):
    return {
        "id": "cisa_kev:{}".format(cve),
        "source": "cisa_kev",
        "cves": [cve],
        "fetched_at": _iso(hours_ago),
    }


def test_load_kev_cve_first_seen_picks_earliest_observation(tmp_path):
    events_file = tmp_path / "events.jsonl"
    later_event = _kev_event("CVE-2026-1111", hours_ago=10)
    earlier_event = _kev_event("CVE-2026-1111", hours_ago=20)  # 더 이른 관측
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(later_event) + "\n")
        f.write(json.dumps(earlier_event) + "\n")

    result = kfl.load_kev_cve_first_seen(events_file)
    assert result["CVE-2026-1111"] == earlier_event["fetched_at"]


def test_find_candidates_only_when_kev_seen_after_article(tmp_path):
    events_file = tmp_path / "events.jsonl"
    # article이 50시간 전, KEV 등재가 10시간 전(=article보다 나중) -> 사후 확인 대상
    article_before_kev = _article_event(1, ["CVE-2026-2222"], hours_ago=50)
    # article이 5시간 전, KEV 관측이 10시간 전(=article보다 먼저) -> 사후 확인 아님, 제외
    article_after_kev = _article_event(2, ["CVE-2026-2222"], hours_ago=5)

    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(article_before_kev) + "\n")
        f.write(json.dumps(article_after_kev) + "\n")
        f.write(json.dumps(_kev_event("CVE-2026-2222", hours_ago=10)) + "\n")

    kev_first_seen = kfl.load_kev_cve_first_seen(events_file)
    candidates = kfl.find_auto_useful_candidates(kev_first_seen, {}, events_file)

    ids = [event["id"] for event, _, _ in candidates]
    assert ids == ["asec:1"]


def test_find_candidates_excludes_kev_source_itself(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(_kev_event("CVE-2026-3333", hours_ago=10)) + "\n")

    kev_first_seen = kfl.load_kev_cve_first_seen(events_file)
    candidates = kfl.find_auto_useful_candidates(kev_first_seen, {}, events_file)
    assert candidates == []


def test_find_candidates_skips_already_labeled_events(tmp_path):
    events_file = tmp_path / "events.jsonl"
    article = _article_event(1, ["CVE-2026-4444"], hours_ago=50)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(article) + "\n")
        f.write(json.dumps(_kev_event("CVE-2026-4444", hours_ago=10)) + "\n")

    kev_first_seen = kfl.load_kev_cve_first_seen(events_file)
    existing_labels = {"asec:1": {"label": "noise"}}  # 이미 사람이 판단함
    candidates = kfl.find_auto_useful_candidates(kev_first_seen, existing_labels, events_file)
    assert candidates == []


def test_find_candidates_ignores_cves_never_kev_listed(tmp_path):
    events_file = tmp_path / "events.jsonl"
    article = _article_event(1, ["CVE-2026-5555"], hours_ago=50)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(article) + "\n")

    kev_first_seen = kfl.load_kev_cve_first_seen(events_file)
    candidates = kfl.find_auto_useful_candidates(kev_first_seen, {}, events_file)
    assert candidates == []


def test_main_dry_run_does_not_write_feedback(tmp_path, monkeypatch, capsys):
    events_file = tmp_path / "events.jsonl"
    article = _article_event(1, ["CVE-2026-6666"], hours_ago=50)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(article) + "\n")
        f.write(json.dumps(_kev_event("CVE-2026-6666", hours_ago=10)) + "\n")

    import common_utils
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    written = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: written.extend(records))
    monkeypatch.setattr(kfl.sys, "argv", ["kev_feedback_labeler.py", "--dry-run"])

    kfl.main()
    out = capsys.readouterr().out
    assert "asec:1" in out or "자동 useful 라벨링 대상" in out
    assert written == []
