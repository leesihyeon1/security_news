import json
from datetime import datetime, timedelta

import common_utils
import feedback


def _make_event(event_id, hours_ago):
    return {
        "id": "asec:{}".format(event_id),
        "source": "asec",
        "title": "t{}".format(event_id),
        "fetched_at": (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat() + "Z",
    }


def test_load_recent_events_respects_count_limit_and_order(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    events = [_make_event(i, 100 - i) for i in range(1, 11)]  # id1이 가장 오래됨, id10이 가장 최신
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(feedback, "RECENT_LINES", 5)

    result = feedback.load_recent_events()
    ids = [e["id"] for e in result]
    assert len(ids) == 5
    assert ids[0] == "asec:10"  # 최신순 정렬
    assert "asec:1" not in ids  # 가장 오래된 것은 5건 창 밖


def test_load_recent_events_dedups_by_id_keeping_newest(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    e1 = _make_event(1, 10)
    e1_updated = dict(e1, title="updated")
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(e1, ensure_ascii=False) + "\n")
        f.write(json.dumps(e1_updated, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(feedback, "RECENT_LINES", 10)

    result = feedback.load_recent_events()
    assert len(result) == 1
    assert result[0]["title"] == "updated"
