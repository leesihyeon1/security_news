import json

import worker_progress as wp


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.lists = {}
        self.sorted = {}

    def set(self, key, value, ex=None):
        self.values[key] = value

    def get(self, key):
        return self.values.get(key)

    def delete(self, key):
        self.values.pop(key, None)

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    def lrange(self, key, start, stop):
        return self.lists.get(key, [])[:]

    def lmove(self, source, destination, wherefrom, whereto):
        rows = self.lists.get(source, [])
        if not rows:
            return None
        value = rows.pop(0)
        self.rpush(destination, value)
        return value

    def lrem(self, key, count, value):
        rows = self.lists.get(key, [])
        if value in rows:
            rows.remove(value)
            return 1
        return 0

    def zadd(self, key, values):
        self.sorted.setdefault(key, {}).update(values)

    def zrangebyscore(self, key, low, high, start=0, num=20):
        return [value for value, score in sorted(self.sorted.get(key, {}).items(),
                key=lambda pair: pair[1]) if score <= high][start:start + num]

    def zrem(self, key, value):
        return 1 if self.sorted.get(key, {}).pop(value, None) is not None else 0


def test_checkpoint_is_private_and_changes_with_input():
    client = FakeRedis()
    assert wp.save(client, "ref", "base", "digest-one", "Korean report")
    assert wp.load(client, "ref", "base", "digest-one") == "Korean report"
    assert wp.load(client, "ref", "base", "digest-two") is None
    assert all(not key.startswith("analysis:") for key in client.values)
    wp.clear(client, "ref", "base")
    assert wp.load(client, "ref", "base", "digest-one") is None


def test_claim_and_recover_only_expired_jobs(monkeypatch):
    monkeypatch.setattr(wp.time, "time", lambda: 100.0)
    client = FakeRedis()
    client.rpush("analysis:queue", "one")
    assert wp.claim(client, "analysis:queue") == "one"
    assert client.lists["analysis:queue"] == []
    assert wp.recover_expired(client, "analysis:queue", now=101.0) == 0
    assert wp.recover_expired(client, "analysis:queue", now=100 + wp.LEASE_SECONDS + 1) == 1
    assert client.lists["analysis:queue"] == ["one"]
    assert client.lists[wp.PROCESSING_KEY] == []


def test_retry_waits_and_has_fixed_limit():
    client = FakeRedis()
    job = {"ref": "one", "title": "report"}
    assert wp.defer_retry(client, job, now=100)
    assert wp.promote_retries(client, "analysis:queue", now=159) == 0
    assert wp.promote_retries(client, "analysis:queue", now=160) == 1
    retry = json.loads(client.lists["analysis:queue"][0])
    assert retry["_retry_count"] == 1
    assert wp.defer_retry(client, retry, now=200)
    assert wp.promote_retries(client, "analysis:queue", now=380) == 1
    assert not wp.defer_retry(client, {"_retry_count": 2}, now=400)
