from datetime import datetime, timezone

import pytest

import vuln_incidents as vi

NOW = datetime(2026, 10, 21, 0, 0, tzinfo=timezone.utc)


def product(**overrides):
    base = {"name": "Fortigate", "aliases": ["Fortigate", "Fortinet", "FortiOS"],
            "cpe": ["fortinet:fortios"], "version": "", "features": [], "exposure": "",
            "core": False, "description": "방화벽 운영체제"}
    base.update(overrides)
    return base


def nvd(cve, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", affected=">= 7.2.0, < 7.2.9", **extra):
    event = {"source": "nvd", "cves": [cve], "title": cve, "summary": "A flaw in FortiOS.", "score": 9.8,
             "severity": "CRITICAL", "cvss_vector": vector, "published_at": "2026-10-10T00:00:00Z",
             "affected_packages": [{"product": "fortinet fortios", "affected": affected, "fixed": ""}],
             "url": "https://nvd.nist.gov/vuln/detail/" + cve}
    event.update(extra)
    return event


def kev(cve, product_name="Fortinet FortiOS"):
    return {"source": "cisa_kev", "cves": [cve], "title": cve + " - FortiOS flaw", "kev": True,
            "affected_products": [product_name], "due_date": "2026-10-22", "remediation": "Apply updates.",
            "published_at": "2026-10-20T00:00:00Z", "url": "https://www.cisa.gov/kev"}


def run(events, inventory, state=None):
    return vi.evaluate(events, state=state if state is not None else {}, inventory=inventory, now=NOW, lookups=False)


@pytest.mark.parametrize("version,affected,expected", [
    ("7.2.8", ">= 7.2.0, < 7.2.9", True), ("7.2.9", ">= 7.2.0, < 7.2.9", False),
    ("7.4.1", "<= 7.4.1", True), ("7.2.8", "7.2.8", True), ("", "< 1", None), ("7.2.8", "all", None),
])
def test_version_range(version, affected, expected):
    assert vi.version_in_range(version, affected) is expected


def test_only_network_attack_vector_counts_as_remote():
    assert vi.judge_remote("CVSS:3.1/AV:N/AC:L")["state"] == "met"
    for av in "ALP":
        assert vi.judge_remote("CVSS:3.1/AV:{}/AC:L".format(av))["state"] == "not_met"
    assert vi.judge_remote("")["state"] == "unknown"


def test_confirmed_incident_needs_all_four_gates():
    _, view = run([nvd("CVE-2026-1001")], [product(version="7.2.8", exposure="internet")])
    row = view["incidents"][0]
    assert row["kind"] == "confirmed" and row["id"] == "VC-2026-0001"
    assert row["grade"] == "높음"  # 인터넷 노출 + 인증 없는 원격 + 치명적 영향
    assert [g["state"] for g in row["analysis"]["evidence"]] == ["met"] * 4
    assert row["analysis"]["conditions"][0].startswith("네트워크로 원격")


def test_unknown_version_or_exposure_raises_needs_check_with_questions():
    _, view = run([nvd("CVE-2026-1002")], [product()])
    row = view["incidents"][0]
    assert row["kind"] == "needs_check"
    assert "설치 버전 확인" in row["gates"]["vulnerable"]["question"]
    assert view["counts"]["needs_check"] == 1


def test_any_not_met_drops_it_and_exploited_ones_go_to_observe():
    # 악용 사실이 있어도 기준 2를 건너뛰지 않는다(2026-10-21 결정).
    local = nvd("CVE-2026-1003", vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    _, view = run([local, kev("CVE-2026-1003")], [product(version="7.2.8", exposure="internet")])
    assert view["incidents"] == []
    assert view["observe"][0]["cve"] == "CVE-2026-1003"
    _, view = run([nvd("CVE-2026-1004")], [product(version="7.2.8", exposure="isolated")])
    assert view["incidents"] == [] and view["observe"] == []


def test_internal_core_asset_counts_as_exposed():
    _, view = run([nvd("CVE-2026-1005")], [product(version="7.2.8", exposure="internal_user", core=True)])
    assert view["incidents"][0]["gates"]["exposed"]["state"] == "met"
    _, view = run([nvd("CVE-2026-1005")], [product(version="7.2.8", exposure="internal_user")])
    assert view["incidents"] == []


def test_alias_only_match_is_a_candidate_and_text_only_needs_exploitation():
    advisory = {"source": "fortinet_psirt", "cves": ["CVE-2026-1006"], "title": "FortiWeb flaw",
                "affected_products": ["Fortinet FortiWeb"], "published_at": "2026-10-10T00:00:00Z"}
    _, view = run([advisory], [product()])
    assert view["incidents"] == [] and view["candidates"][0]["gates"]["in_use"]["state"] == "estimated"
    text_only = {"source": "thehackernews", "cves": ["CVE-2026-1007"], "title": "CVE-2026-1007 in FortiOS",
                 "summary": "x", "matched_assets": ["Fortigate"]}
    _, view = run([text_only], [product(cpe=[])])
    assert view["candidates"] == []


def test_kev_due_date_caps_urgent_deadline_and_ids_persist():
    state, view = run([nvd("CVE-2026-1008"), kev("CVE-2026-1008")], [product(version="7.2.8", exposure="internet")])
    row = view["incidents"][0]
    assert row["grade"] == "긴급" and row["due"] == "2026-10-22"
    assert row["analysis"]["compromise_check"]
    assert row["analysis"]["remediation"]["maturity"]["level"] == "in_the_wild"
    _, again = run([nvd("CVE-2026-1009")], [product(version="7.2.8", exposure="internet")], state=state)
    assert {r["id"] for r in again["incidents"]} == {"VC-2026-0001", "VC-2026-0002"}


def test_lookups_fill_vector_epss_and_poc(monkeypatch, tmp_path):
    monkeypatch.setattr(vi, "VECTOR_CACHE_PATH", tmp_path / "vectors.json")
    monkeypatch.setattr(vi, "fetch_vector", lambda cve: {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"})
    monkeypatch.setattr(vi, "fetch_epss", lambda cves: {c: {"score": 0.4, "percentile": 0.97} for c in cves})
    monkeypatch.setattr(vi, "fetch_poc", lambda cve: {"count": 2, "latest_url": "https://github.com/x/y"})
    event = nvd("CVE-2026-1010", vector="")
    _, view = vi.evaluate([event], state={}, inventory=[product(version="7.2.8", exposure="internet")], now=NOW)
    row = view["incidents"][0]
    assert row["gates"]["remote"]["state"] == "met"
    assert row["grade"] == "높음"  # EPSS 백분위 0.95 이상 + 인터넷 노출
    assert row["analysis"]["scores"]["epss_percentile"] == 0.97
    assert row["analysis"]["remediation"]["maturity"]["label"] == "PoC 후보(미검증)"


def test_public_view_has_no_internal_identifiers():
    _, view = run([nvd("CVE-2026-1011")], [product(version="7.2.8", exposure="internet")])
    raw = str(view)
    for word in ("asset_id", "hostname", "owner", "ip_address"):
        assert word not in raw


def test_elk_export_writes_only_changed_docs(monkeypatch, tmp_path):
    monkeypatch.setattr(vi, "CVES_EXPORT", tmp_path / "vuln_cves.jsonl")
    monkeypatch.setattr(vi, "EXPOSURE_EXPORT", tmp_path / "vuln_exposure.jsonl")
    monkeypatch.setattr(vi, "VECTOR_CACHE_PATH", tmp_path / "vectors.json")
    events = [nvd("CVE-2026-2001"), kev("CVE-2026-2001")]
    state, _ = run(events, [product(version="7.2.8", exposure="internet")])
    assert vi.export_for_elk(state, events, now=NOW) == (1, 1)
    import json as _json
    exposure = _json.loads((tmp_path / "vuln_exposure.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert exposure["doc_id"] == "CVE-2026-2001__Fortigate"
    assert exposure["vuln"]["gate"] == {"in_use": "met", "remote": "met", "vulnerable": "met", "exposed": "met"}
    assert exposure["vuln"]["severity"] == "critical" and exposure["vuln"]["exploited"] is True
    cve = _json.loads((tmp_path / "vuln_cves.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert cve["vuln"]["attack_vector"] == "N" and cve["vuln"]["kev"] is True
    assert vi.export_for_elk(state, events, now=NOW) == (0, 0)  # 바뀐 게 없으면 다시 쓰지 않는다
