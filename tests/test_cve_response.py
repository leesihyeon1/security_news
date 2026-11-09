import json
from collections import Counter

import generate_report as report
import send_cve_daily
import send_github_advisory_daily as github


def test_github_advisory_uses_official_fixed_version_field():
    rows = github.extract_vulnerabilities({"vulnerabilities": [{
        "package": {"ecosystem": "npm", "name": "example-package"},
        "vulnerable_version_range": "< 2.4.1",
        "first_patched_version": "2.4.1",
    }]})
    assert rows[0]["patched_versions"] == "2.4.1"
    assert github.has_patched_version({"affected": rows}) is True
    assert "2.4.1" in github.build_remediation({"affected": rows})


def test_nvd_range_does_not_infer_fixed_version():
    cve = {"configurations": [{"nodes": [{"cpeMatch": [{
        "vulnerable": True,
        "criteria": "cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.0",
        "versionEndExcluding": "2.0",
    }, {
        "vulnerable": False,
        "criteria": "cpe:2.3:o:vendor:platform:1.0:*:*:*:*:*:*:*",
    }]}]}]}
    assert send_cve_daily.extract_affected_packages(cve) == [{
        "product": "vendor widget", "affected": ">= 1.0, < 2.0", "fixed": "",
    }]
    cve["configurations"][0]["nodes"][0]["cpeMatch"][1]["vulnerable"] = True
    assert send_cve_daily.extract_affected_packages(cve)[1]["product"] == "vendor platform"


def _event(cve, source, product, affected, fixed, action):
    return {
        "id": "{}:{}".format(source, cve), "source": source,
        "cves": [cve], "url": "https://example.org/{}".format(cve),
        "title": cve, "summary": "한국어 요약", "ai_summary": "한국어 요약",
        "affected_products": [product],
        "affected_packages": [{"product": product, "affected": affected, "fixed": fixed}],
        "fix_available": bool(fixed), "remediation": action,
        "exploitation_status": "none", "matched_assets": [], "fetched_at": "2026-09-28T00:00:00Z",
    }


def test_grouped_card_keeps_versions_and_actions_with_each_cve(monkeypatch):
    first = _event("CVE-2026-0001", "github_advisory", "npm/a", "< 2", "2.0", "a 2.0으로 업데이트")
    second = _event("CVE-2026-0002", "nvd", "vendor b", "< 4", "", "")
    second["fix_available"] = None
    card = report.build_cve_card("CVE-2026-0001 / CVE-2026-0002",
                                 ["CVE-2026-0001", "CVE-2026-0002"], [first, second],
                                 ["github_advisory", "nvd"])
    details = {item["id"]: item for item in card["cve_details"]}
    assert details["CVE-2026-0001"]["versions"][0]["fixed"] == "2.0"
    assert details["CVE-2026-0002"]["versions"][0]["fixed"] == ""
    assert details["CVE-2026-0002"]["fix_status"] == "unknown"
    assert details["CVE-2026-0002"]["remediation"] == ""

    monkeypatch.setattr(report.common_utils, "check_github_poc", lambda cve: {
        "count": 1, "latest_url": "https://github.com/example/cve", "latest_created_at": "2026-09-28",
    } if cve.endswith("0001") else None)
    report.enrich_cards_with_github_poc([card])
    assert details["CVE-2026-0001"]["poc"]["status"] == "candidate"
    assert details["CVE-2026-0002"]["poc"]["status"] == "error"

    stats = {"total": 2, "p1": [], "p2": [], "critical": [], "kev": [],
             "ransomware": [], "asset_hits": [], "by_source": Counter(), "info_by_category": Counter()}
    payload = report.build_dashboard_payload("제목", "daily", "기간", stats, "", [], [card], [])
    public = payload["cards"][0]
    assert public["cve_details"][0]["poc"]["url"] == "https://github.com/example/cve"
    assert public["cve_details"][1]["versions"][0]["product"] == "vendor b"
    assert "matched_assets" not in json.dumps(public)
