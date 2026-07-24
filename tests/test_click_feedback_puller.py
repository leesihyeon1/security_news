import json
from unittest import mock

import click_feedback_puller as cfp
import common_utils


def _make_event(event_id, source="asec"):
    return {"id": "{}:{}".format(source, event_id), "source": source, "title": "t{}".format(event_id)}


def _fake_upstash_response(result):
    class Response:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"result": result}
    return Response()


def test_peek_click_records_parses_json_entries(monkeypatch):
    monkeypatch.setattr(cfp, "UPSTASH_REST_URL", "https://fake-upstash")
    monkeypatch.setattr(cfp, "UPSTASH_REST_TOKEN", "token")

    raw = [json.dumps({"ref": "abc123", "url": "http://x", "ts": "2026-01-01T00:00:00Z"})]
    with mock.patch.object(cfp.requests, "post", return_value=_fake_upstash_response(raw)):
        records = cfp.peek_click_records()

    assert records == [{"ref": "abc123", "url": "http://x", "ts": "2026-01-01T00:00:00Z"}]


def test_peek_click_records_returns_empty_when_not_configured(monkeypatch):
    monkeypatch.setattr(cfp, "UPSTASH_REST_URL", "")
    monkeypatch.setattr(cfp, "UPSTASH_REST_TOKEN", "")
    assert cfp.peek_click_records() == []


def test_peek_click_records_skips_malformed_entries(monkeypatch):
    monkeypatch.setattr(cfp, "UPSTASH_REST_URL", "https://fake-upstash")
    monkeypatch.setattr(cfp, "UPSTASH_REST_TOKEN", "token")

    raw = ["not json", json.dumps({"ref": "abc123", "url": "http://x"})]
    with mock.patch.object(cfp.requests, "post", return_value=_fake_upstash_response(raw)):
        records = cfp.peek_click_records()

    assert records == [{"ref": "abc123", "url": "http://x"}]


def test_main_labels_matched_clicks_and_trims_after_success(tmp_path, monkeypatch, capsys):
    events_file = tmp_path / "events.jsonl"
    event = _make_event(1)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    ref = common_utils.event_ref(event["id"])
    click_log = [json.dumps({"ref": ref, "url": "http://x", "ts": "2026-01-01T00:00:00Z"})]

    monkeypatch.setattr(cfp, "UPSTASH_REST_URL", "https://fake-upstash")
    monkeypatch.setattr(cfp, "UPSTASH_REST_TOKEN", "token")

    written = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: written.extend(records))

    trimmed = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        if json[0] == "LRANGE":
            return _fake_upstash_response(click_log)
        if json[0] == "LTRIM":
            trimmed["count"] = json[2]
            return _fake_upstash_response("OK")
        raise AssertionError("unexpected command {}".format(json))

    monkeypatch.setattr(cfp.requests, "post", fake_post)
    monkeypatch.setattr(cfp.sys, "argv", ["click_feedback_puller.py"])

    cfp.main()

    assert len(written) == 1
    assert written[0]["event_id"] == event["id"]
    assert written[0]["label"] == "useful"
    assert written[0]["via"] == "click"
    assert trimmed["count"] == 1  # 처리된 1건만큼 리스트에서 제거 요청됨


def test_main_dry_run_skips_write_and_trim(tmp_path, monkeypatch, capsys):
    events_file = tmp_path / "events.jsonl"
    event = _make_event(1)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {})

    ref = common_utils.event_ref(event["id"])
    click_log = [json.dumps({"ref": ref, "url": "http://x"})]

    monkeypatch.setattr(cfp, "UPSTASH_REST_URL", "https://fake-upstash")
    monkeypatch.setattr(cfp, "UPSTASH_REST_TOKEN", "token")

    calls = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: calls.append("write"))

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json[0])
        return _fake_upstash_response(click_log if json[0] == "LRANGE" else "OK")

    monkeypatch.setattr(cfp.requests, "post", fake_post)
    monkeypatch.setattr(cfp.sys, "argv", ["click_feedback_puller.py", "--dry-run"])

    cfp.main()

    assert "write" not in calls
    assert "LTRIM" not in calls


def test_main_skips_already_labeled_events(tmp_path, monkeypatch):
    events_file = tmp_path / "events.jsonl"
    event = _make_event(1)
    with events_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    monkeypatch.setattr(common_utils, "EVENTS_FILE", events_file)
    monkeypatch.setattr(common_utils, "load_feedback", lambda: {event["id"]: {"label": "noise"}})

    ref = common_utils.event_ref(event["id"])
    click_log = [json.dumps({"ref": ref, "url": "http://x"})]

    monkeypatch.setattr(cfp, "UPSTASH_REST_URL", "https://fake-upstash")
    monkeypatch.setattr(cfp, "UPSTASH_REST_TOKEN", "token")

    written = []
    monkeypatch.setattr(common_utils, "append_feedback", lambda records: written.extend(records))

    def fake_post(url, headers=None, json=None, timeout=None):
        return _fake_upstash_response(click_log if json[0] == "LRANGE" else "OK")

    monkeypatch.setattr(cfp.requests, "post", fake_post)
    monkeypatch.setattr(cfp.sys, "argv", ["click_feedback_puller.py"])

    cfp.main()
    assert written == []  # 이미 사람이 noise로 판단한 건 자동라벨이 덮어쓰지 않음
