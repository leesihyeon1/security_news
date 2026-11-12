import json

import pytest

import collect_x_post_urls as xc


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}
        self.headers = {"x-rate-limit-reset": "1"}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(self.status_code)


class FakeSession:
    """Serves /users/by once, then one page of posts per user id."""

    def __init__(self, timelines, limit_after=None):
        self.timelines = timelines
        self.limit_after = limit_after
        self.calls = []

    def get(self, url, params=None, timeout=None, headers=None):
        self.calls.append((url, dict(params or {})))
        if url.endswith("/users/by"):
            names = params["usernames"].split(",")
            return FakeResponse(200, {"data": [{"id": str(100 + i), "username": n} for i, n in enumerate(names)]})
        if self.limit_after is not None and len(self.calls) > self.limit_after:
            return FakeResponse(429)
        user = url.split("/users/")[1].split("/")[0]
        return FakeResponse(200, {"data": [{"id": t} for t in self.timelines.get(user, [])]})


def test_normalize_post_requires_matching_author():
    assert xc.normalize_post("https://twitter.com/DarkWebInformer/status/123?ref=home", "DarkWebInformer") == (
        "https://x.com/DarkWebInformer/status/123"
    )
    assert xc.normalize_post("https://x.com/other/status/123", "DarkWebInformer") is None
    assert xc.normalize_post("https://example.com/DarkWebInformer/status/123", "DarkWebInformer") is None


def test_refresh_saves_newest_posts_first_and_caches_user_ids(tmp_path):
    out = tmp_path / "x-posts.json"
    session = FakeSession({"100": ["7", "9", "8"], "104": ["50"]})
    added = xc.refresh(out, "token", per_account=2, session=session)
    data = json.loads(out.read_text(encoding="utf-8"))
    urls = [p["url"] for p in data["posts"]]
    assert added == 4
    assert urls == ["https://x.com/SwiftOnSecurity/status/50", "https://x.com/DarkWebInformer/status/9",
                    "https://x.com/DarkWebInformer/status/8"]
    assert data["posts"][0]["group"] == "insight" and data["accounts"]["DarkWebInformer"] == "100"

    second = FakeSession({"100": ["10"]})
    assert xc.refresh(out, "token", per_account=2, session=second) == 1
    assert not any(url.endswith("/users/by") for url, _ in second.calls)  # cached ids, no paid lookup
    dwi = next(params for url, params in second.calls if "/users/100/" in url)
    assert dwi["since_id"] == "9"  # only posts newer than the saved ones are billed
    urls = [p["url"] for p in json.loads(out.read_text(encoding="utf-8"))["posts"]]
    assert urls[:3] == ["https://x.com/SwiftOnSecurity/status/50", "https://x.com/DarkWebInformer/status/10",
                        "https://x.com/DarkWebInformer/status/9"]


def test_rate_limit_stops_calls_and_keeps_previous_posts(tmp_path):
    out = tmp_path / "x-posts.json"
    xc.refresh(out, "token", session=FakeSession({"101": ["5"], "105": ["6"]}))
    limited = FakeSession({}, limit_after=0)
    limited_calls_before = len(limited.calls)
    assert xc.refresh(out, "token", session=limited) == 0
    assert len(limited.calls) - limited_calls_before == 1  # no further requests after a 429
    urls = {p["url"] for p in json.loads(out.read_text(encoding="utf-8"))["posts"]}
    assert urls == {"https://x.com/DailyDarkWeb/status/5", "https://x.com/briankrebs/status/6"}


def test_publish_is_a_no_op_without_a_token(tmp_path, monkeypatch):
    monkeypatch.delenv("X_BEARER_TOKEN", raising=False)
    assert xc.publish(tmp_path) is None
    assert not (tmp_path / "x-posts.json").exists()


def test_rejected_token_is_reported_without_its_value(tmp_path):
    class Rejecting(FakeSession):
        def get(self, url, params=None, timeout=None, headers=None):
            return FakeResponse(401)

    with pytest.raises(RuntimeError) as error:
        xc.refresh(tmp_path / "x.json", "secret-token-value", session=Rejecting({}))
    assert "secret-token-value" not in str(error.value)
