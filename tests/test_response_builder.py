import response_builder
import lure_hunter


def test_collect_returns_provenance_for_lure_domain_and_hash(monkeypatch):
    monkeypatch.setattr(lure_hunter, "classify_ioc_hosts", lambda iocs, text="": {
        "lure": ["evil.example"], "public_service": [], "leak_site": [], "tor": [],
    })
    iocs = [{"type": "domain", "value": "evil.example"},
            {"type": "sha256", "value": "a" * 64}]
    values = response_builder._collect({}, iocs, text="")
    assert values["provenance"]["evil.example"] == {"role": "lure", "bucket": "domains"}
    assert values["provenance"]["a" * 64] == {"role": "hash", "bucket": "hashes"}


def test_collect_provenance_marks_public_service_and_tor(monkeypatch):
    monkeypatch.setattr(lure_hunter, "classify_ioc_hosts", lambda iocs, text="": {
        "lure": [], "public_service": ["cdn.example"], "leak_site": [], "tor": ["abc.onion"],
    })
    values = response_builder._collect({}, [], text="")
    assert values["provenance"]["cdn.example"]["role"] == "public_service"
    assert values["provenance"]["abc.onion"]["role"] == "tor"


def test_collect_provenance_marks_named_ip():
    block = {"intel": {"named_ips": [{"ip": "3.3.3.3", "hostnames": ["svc.amazon.com"]}]}}
    values = response_builder._collect(block, [], text="")
    assert values["provenance"]["3.3.3.3"]["role"] == "named_ip"


def test_build_carries_provenance_through_to_response(monkeypatch):
    monkeypatch.setattr(lure_hunter, "classify_ioc_hosts", lambda iocs, text="": {
        "lure": ["evil.example"], "public_service": [], "leak_site": [], "tor": [],
    })
    iocs = [{"type": "domain", "value": "evil.example"}]
    result = response_builder.build({}, iocs, primary="user_action", text="")
    assert result is not None
    assert result["provenance"]["evil.example"] == {"role": "lure", "bucket": "domains"}
