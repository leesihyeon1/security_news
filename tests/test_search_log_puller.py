import json

import search_log_puller as slp


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


def test_peek_search_log_parses_json_entries():
    raw = [json.dumps({"query": "fortinet", "result_count": 3, "ts": "2026-01-01T00:00:00Z"})]
    client = FakeRedis(raw)
    records = slp.peek_search_log(client)
    assert records == [{"query": "fortinet", "result_count": 3, "ts": "2026-01-01T00:00:00Z"}]


def test_peek_search_log_returns_empty_when_client_is_none():
    assert slp.peek_search_log(None) == []


def test_peek_search_log_skips_malformed_entries():
    raw = ["not json", json.dumps({"query": "x", "result_count": 0})]
    client = FakeRedis(raw)
    records = slp.peek_search_log(client)
    assert records == [{"query": "x", "result_count": 0}]


def test_trim_processed_removes_leading_n_items():
    client = FakeRedis(["a", "b", "c"])
    slp.trim_processed(client, 2)
    assert client.ltrim_calls == [(2, -1)]
    assert client.lrange("search_log", 0, -1) == ["c"]


def test_trim_processed_noop_when_client_none_or_count_zero():
    client = FakeRedis(["a"])
    slp.trim_processed(None, 5)  # client 없으면 조용히 무시
    slp.trim_processed(client, 0)  # count 0이면 무시
    assert client.ltrim_calls == []


def test_main_appends_records_and_trims_after_success(tmp_path, monkeypatch):
    log_file = tmp_path / "search_log.jsonl"
    monkeypatch.setattr(slp, "SEARCH_LOG_FILE", log_file)

    entries = [
        json.dumps({"query": "fortinet", "result_count": 3, "ts": "2026-01-01T00:00:00Z"}),
        json.dumps({"query": "no such thing", "result_count": 0, "ts": "2026-01-01T00:01:00Z"}),
    ]
    fake_client = FakeRedis(entries)
    monkeypatch.setattr(slp, "_connect", lambda: fake_client)
    monkeypatch.setattr(slp.sys, "argv", ["search_log_puller.py"])

    slp.main()

    assert fake_client.ltrim_calls == [(2, -1)]
    saved = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(saved) == 2
    assert {r["query"] for r in saved} == {"fortinet", "no such thing"}


def test_main_dry_run_skips_write_and_trim(tmp_path, monkeypatch):
    log_file = tmp_path / "search_log.jsonl"
    monkeypatch.setattr(slp, "SEARCH_LOG_FILE", log_file)

    entries = [json.dumps({"query": "fortinet", "result_count": 3})]
    fake_client = FakeRedis(entries)
    monkeypatch.setattr(slp, "_connect", lambda: fake_client)
    monkeypatch.setattr(slp.sys, "argv", ["search_log_puller.py", "--dry-run"])

    slp.main()

    assert fake_client.ltrim_calls == []
    assert not log_file.exists()


def test_main_noop_when_no_records(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "search_log.jsonl"
    monkeypatch.setattr(slp, "SEARCH_LOG_FILE", log_file)

    fake_client = FakeRedis([])
    monkeypatch.setattr(slp, "_connect", lambda: fake_client)
    monkeypatch.setattr(slp.sys, "argv", ["search_log_puller.py"])

    slp.main()

    assert not log_file.exists()
    assert fake_client.ltrim_calls == []
