import json
from datetime import datetime, timedelta

import common_utils
import slack_feedback_poller as sfp


def _make_event(event_id, hours_ago):
    return {
        "id": "asec:{}".format(event_id),
        "source": "asec",
        "title": "t{}".format(event_id),
        "fetched_at": (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat() + "Z",
    }


def test_build_ref_map_respects_count_limit(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    events = [_make_event(i, 100 - i) for i in range(1, 11)]
    with events_file.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(sfp, "RECENT_LINES", 5)

    ref_map = sfp.build_ref_map()
    assert len(ref_map) == 5
    expected_ref = common_utils.event_ref("asec:10")
    assert ref_map[expected_ref] == "asec:10"
    excluded_ref = common_utils.event_ref("asec:1")
    assert excluded_ref not in ref_map


def test_message_verdict_useful_and_noise():
    assert sfp.message_verdict({"reactions": [{"name": "+1"}]}) == "useful"
    assert sfp.message_verdict({"reactions": [{"name": "-1"}]}) == "noise"


def test_message_verdict_recognizes_expanded_reaction_vocabulary():
    for name in ("fire", "pushpin", "star", "100"):
        assert sfp.message_verdict({"reactions": [{"name": name}]}) == "useful"
    for name in ("no_entry", "zzz"):
        assert sfp.message_verdict({"reactions": [{"name": name}]}) == "noise"


def test_message_verdict_ignores_conflicting_or_missing_reactions():
    assert sfp.message_verdict({"reactions": []}) is None
    assert sfp.message_verdict({"reactions": [{"name": "+1"}, {"name": "-1"}]}) is None
    assert sfp.message_verdict({"reactions": [{"name": "fire"}, {"name": "no_entry"}]}) is None
    assert sfp.message_verdict({}) is None


def test_message_verdict_ignores_unmapped_reactions():
    """👀(eyes) 같은 '봤지만 판단 없음' 반응은 useful/noise 어느 쪽도 아니므로 무시된다."""
    assert sfp.message_verdict({"reactions": [{"name": "eyes"}]}) is None
