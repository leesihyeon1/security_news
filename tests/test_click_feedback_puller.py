import json

import click_feedback_puller as cfp
import common_utils


def _make_event(event_id, source="asec"):
    return {"id": "{}:{}".format(source, event_id), "source": source, "title": "t{}".format(event_id)}


class FakeRedis:
    """실제 Redis 리스트 동작(LRANGE/LTRIM)을 흉내내는 가짜 클라이언트."""

    def __init__(self, items=None):
        self._items = list(items or [])
        self.ltrim_calls = []

    def lrange(self, key, start, end):
        if end == -1:
            return self._items[start:]
        return self._items[start:end + 1]

    def ltrim(self, key, start, end):
        self.ltrim_calls.append((start, end))
        if end == -1:
            self._items = self._items[start:]
        else:
            self._items = self._items[start:end + 1]

    def ping(self):
        return True


def test_peek_click_records_parses_json_entries():
    raw = [json.dumps({"ref": "abc123", "url": "http://x", "ts": "2026-01-01T00:00:00Z"})]
    client = FakeRedis(raw)
    records = cfp.peek_click_records(client)
    assert records == [{"ref": "abc123", "url": "http://x", "ts": "2026-01-01T00:00:00Z"}]


def test_peek_click_records_returns_empty_when_client_is_none():
    assert cfp.peek_click_records(None) == []


def test_peek_click_records_skips_malformed_entries():
    raw = ["not json", json.dumps({"ref": "abc123", "url": "http://x"})]
    client = FakeRedis(raw)
    records = cfp.peek_click_records(client)
    assert records == [{"ref": "abc123", "url": "http://x"}]


def test_trim_processed_removes_leading_n_items():
    client = FakeRedis(["a", "b", "c"])
    cfp.trim_processed(client, 2)
    assert client.ltrim_calls == [(2, -1)]
    assert client.lrange("clicks", 0, -1) == ["c"]


def test_trim_processed_noop_when_client_none_or_count_zero():
    client = FakeRedis(["a"])
    cfp.trim_processed(None, 5)  # client 없으면 조용히 무시
    cfp.trim_processed(client, 0)  # count 0이면 무시
    assert client.ltrim_calls == []


def test_main_labels_matched_clicks_and_trims_after_success(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    event = _make_event(1)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    ref = common_utils.event_ref(event["id"])
    click_log = [json.dumps({"ref": ref, "url": "http://x", "ts": "2026-01-01T00:00:00Z"})]
    fake_client = FakeRedis(click_log)
    monkeypatch.setattr(cfp, "_connect", lambda: fake_client)

    written = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: written.extend(records))
    monkeypatch.setattr(cfp.sys, "argv", ["click_feedback_puller.py"])

    cfp.main()

    assert len(written) == 1
    assert written[0]["event_id"] == event["id"]
    assert written[0]["label"] == "useful"
    assert written[0]["via"] == "click"
    assert fake_client.ltrim_calls == [(1, -1)]  # 처리된 1건만큼 리스트에서 제거됨


def test_main_dry_run_skips_write_and_trim(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    event = _make_event(1)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    ref = common_utils.event_ref(event["id"])
    click_log = [json.dumps({"ref": ref, "url": "http://x"})]
    fake_client = FakeRedis(click_log)
    monkeypatch.setattr(cfp, "_connect", lambda: fake_client)

    calls = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: calls.append("write"))
    monkeypatch.setattr(cfp.sys, "argv", ["click_feedback_puller.py", "--dry-run"])

    cfp.main()

    assert "write" not in calls
    assert fake_client.ltrim_calls == []


def test_main_skips_already_labeled_events(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    event = _make_event(1)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {event["id"]: {"label": "noise"}})

    ref = common_utils.event_ref(event["id"])
    click_log = [json.dumps({"ref": ref, "url": "http://x"})]
    fake_client = FakeRedis(click_log)
    monkeypatch.setattr(cfp, "_connect", lambda: fake_client)

    written = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: written.extend(records))
    monkeypatch.setattr(cfp.sys, "argv", ["click_feedback_puller.py"])

    cfp.main()
    assert written == []  # 이미 사람이 noise로 판단한 건 자동라벨이 덮어쓰지 않음
