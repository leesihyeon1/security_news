import pytest

import network_safety as ns


def test_rejects_non_http_scheme():
    with pytest.raises(ns.UnsafeUrlError):
        ns.check_public_url("file:///etc/passwd")
    with pytest.raises(ns.UnsafeUrlError):
        ns.check_public_url("javascript:alert(1)")


def test_rejects_url_with_no_host():
    with pytest.raises(ns.UnsafeUrlError):
        ns.check_public_url("https://")


def test_rejects_loopback_and_private_and_link_local_and_cloud_metadata(monkeypatch):
    """실측(2026-09-22): /api/analyze가 인증 없이 url을 받아 그대로 큐에 넣고,
    이 저장소의 워커가 그 url을 사용자 PC에서 그대로 requests.get했다 —
    169.254.169.254(클라우드 메타데이터), 127.0.0.1(로컬 서비스), 192.168.x.x
    (사설망)를 넣으면 워커가 대신 스캔해 주는 SSRF였다."""
    unsafe_hosts = {
        "metadata.internal": ["169.254.169.254"],
        "localhost": ["127.0.0.1"],
        "printer.lan": ["192.168.1.50"],
        "nas.corp": ["10.0.0.5"],
        "loopback6.example": ["::1"],
        "unspecified.example": ["0.0.0.0"],
    }

    def fake_resolve(hostname):
        return set(unsafe_hosts[hostname])

    monkeypatch.setattr(ns, "_resolve_all", fake_resolve)
    for host in unsafe_hosts:
        with pytest.raises(ns.UnsafeUrlError):
            ns.check_public_url("http://{}/".format(host))


def test_accepts_a_public_address(monkeypatch):
    monkeypatch.setattr(ns, "_resolve_all", lambda hostname: {"93.184.216.34"})
    assert ns.check_public_url("https://example.com/article") == "https://example.com/article"


def test_rejects_if_any_resolved_ip_is_private():
    """DNS 라운드로빈으로 공인 IP와 사설 IP가 섞여 오면 어느 쪽으로 실제 연결이
    될지 우리가 통제할 수 없다 — 하나라도 사설이면 전체를 거부한다."""
    import network_safety as ns_module
    orig = ns_module._resolve_all
    ns_module._resolve_all = lambda hostname: {"93.184.216.34", "127.0.0.1"}
    try:
        with pytest.raises(ns.UnsafeUrlError):
            ns.check_public_url("http://mixed.example/")
    finally:
        ns_module._resolve_all = orig


def test_dns_failure_is_treated_as_unsafe(monkeypatch):
    def fail(hostname):
        raise ns.UnsafeUrlError("DNS 조회 실패: boom")

    monkeypatch.setattr(ns, "_resolve_all", fail)
    with pytest.raises(ns.UnsafeUrlError):
        ns.check_public_url("http://nonexistent.invalid/")


def test_safe_get_revalidates_every_redirect_hop(monkeypatch):
    """requests의 기본 allow_redirects=True는 첫 주소만 검사하고 그 뒤로는 무엇이든
    따라간다. safe_get은 매 리다이렉트마다 다시 검사해야 한다 — 겉보기엔 공개
    주소인 url이 301로 사설 주소를 가리키는 우회를 막는다."""
    calls = []

    class FakeResponse:
        def __init__(self, redirect_to=None):
            self._redirect_to = redirect_to
            self.is_redirect = redirect_to is not None
            self.is_permanent_redirect = False
            self.headers = {"Location": redirect_to} if redirect_to else {}

    def fake_get(url, **kwargs):
        calls.append(url)
        if url == "https://public.example/start":
            return FakeResponse(redirect_to="http://169.254.169.254/latest/meta-data/")
        return FakeResponse()

    monkeypatch.setattr(ns.requests, "get", fake_get)
    monkeypatch.setattr(ns, "_resolve_all", lambda hostname: (
        {"93.184.216.34"} if hostname == "public.example" else {"169.254.169.254"}))

    with pytest.raises(ns.UnsafeUrlError):
        ns.safe_get("https://public.example/start")
    assert calls == ["https://public.example/start"]  # 리다이렉트를 실제로 따라가지 않았다


def test_safe_get_follows_a_safe_redirect_chain(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, redirect_to=None):
            self.is_redirect = redirect_to is not None
            self.is_permanent_redirect = False
            self.headers = {"Location": redirect_to} if redirect_to else {}
            self.text = "final" if redirect_to is None else ""

    def fake_get(url, **kwargs):
        calls.append(url)
        if url == "https://public.example/start":
            return FakeResponse(redirect_to="https://public.example/final")
        return FakeResponse()

    monkeypatch.setattr(ns.requests, "get", fake_get)
    monkeypatch.setattr(ns, "_resolve_all", lambda hostname: {"93.184.216.34"})

    result = ns.safe_get("https://public.example/start")
    assert result.text == "final"
    assert calls == ["https://public.example/start", "https://public.example/final"]
