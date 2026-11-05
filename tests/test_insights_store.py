import json

import analysis_worker


class FakeRedis:
    """store_result가 쓰는 목록 명령만 흉내 낸다. 목록 전체를 다시 쓰는 명령은 거부한다."""

    def __init__(self, items=()):
        self.lists = {analysis_worker.INSIGHTS_LIST_KEY: list(items)}
        self.values = {}

    def lrange(self, key, start, end):
        return list(self.lists.get(key, []))

    def set(self, key, value, ex=None):
        self.values[key] = value

    def delete(self, key):
        if key == analysis_worker.INSIGHTS_LIST_KEY:
            raise AssertionError("목록 전체를 지우면 안 된다")
        self.values.pop(key, None)

    def pipeline(self):
        return FakePipe(self)


class FakePipe:
    def __init__(self, redis):
        self.redis, self.ops = redis, []

    def lrem(self, key, count, value):
        self.ops.append(lambda: self.redis.lists[key].remove(value) if value in self.redis.lists[key] else None)

    def rpush(self, key, *values):
        assert len(values) == 1, "한 번에 한 건만 붙인다"
        self.ops.append(lambda: self.redis.lists.setdefault(key, []).extend(values))

    def ltrim(self, key, start, end):
        self.ops.append(lambda: self.redis.lists.__setitem__(key, self.redis.lists[key][start:]))

    def delete(self, key):
        self.ops.append(lambda: self.redis.delete(key))

    def execute(self):
        for op in self.ops:
            op()


def record(ref, **extra):
    return dict({"ref": ref, "title": ref, "analysis": "본문", "links": [], "iocs": [], "category": "",
                 "attack_techniques": [], "glossary": {}, "attack_grouped": [], "investigation": {},
                 "targets": {}}, **extra)


def test_store_replaces_same_ref_and_appends_without_rewriting_list(monkeypatch):
    monkeypatch.setattr(analysis_worker.common_utils, "inventory_product_terms", lambda: [])
    client = FakeRedis([json.dumps({"ref": "a"}), json.dumps({"ref": "b"})])
    analysis_worker.store_result(client, record("a", title="새 결과"))
    refs = [json.loads(item)["ref"] for item in client.lists[analysis_worker.INSIGHTS_LIST_KEY]]
    assert refs == ["b", "a"]


def test_store_keeps_the_newest_records_up_to_the_cap(monkeypatch):
    monkeypatch.setattr(analysis_worker.common_utils, "inventory_product_terms", lambda: [])
    cap = analysis_worker.MAX_INSIGHTS_LIST_SIZE
    client = FakeRedis([json.dumps({"ref": str(i)}) for i in range(cap)])
    analysis_worker.store_result(client, record("new"))
    items = client.lists[analysis_worker.INSIGHTS_LIST_KEY]
    assert len(items) == cap
    assert json.loads(items[-1])["ref"] == "new" and json.loads(items[0])["ref"] == "1"
