import goal_evidence
import pattern_synth


def _browser(status="review", after=True):
    return {"browser_research": {"results": [{"source": "isolated_browser",
        "status": "observed", "evidence": {"evidence_id": "browser:one",
        "after": {"dom_status": status},
        "clipboard": [{"executable": "powershell", "destinations": [{"host": "evil.example"}]}],
        "responses": [{"phase": "after", "status": 200}] if after else []}}]}}


def test_clickfix_question_stays_partial_without_confirmed_dom():
    block = _browser()
    verdict = {"question_status": [{"question": "ClickFix 유포지 동작은?", "status": "answered",
                                    "answer": "복사", "evidence": "브라우저"}]}
    checks = goal_evidence.reconcile(verdict, block)
    assert verdict["question_status"][0]["status"] == "partial"
    assert "현재 DOM" in checks[0]["missing"]


def test_web_pattern_needs_cross_host_observation():
    block = _browser(status="confirmed")
    verdict = {"question_status": [{"question": "같은 유포지 탐지 패턴은?", "status": "answered"}]}
    goal_evidence.reconcile(verdict, block)
    assert verdict["question_status"][0]["status"] == "partial"
    block["shared_web_fingerprints"] = [{"path": "/jsrepo", "query_keys": ["rnd"],
                                          "hosts": ["one.example", "two.example"]}]
    block["negative_controls"] = [{"label": "benign_confirmed", "http": []}]
    assert goal_evidence.review("같은 유포지 탐지 패턴은?", block)["ceiling"] == "answered"


def test_dynamic_analysis_requires_observed_sample_behavior():
    question = "샘플 동적 분석에서 C2 통신이 확인됐나?"
    assert goal_evidence.review(question, {"malware": {"files": [{"hash": "a" * 64}]}})["ceiling"] == "partial"
    assert goal_evidence.review(question, {"malware": {"files": [{"hash": "a" * 64,
        "behaviour": {"http_details": [{"host": "evil.example"}],
                      "processes": ["sample.exe"]}}]}})["ceiling"] == "answered"


def test_safe_version_requires_explicit_vendor_value():
    question = "패치된 안전 버전은?"
    assert goal_evidence.review(question, {"vulnerability": {"cves": [{"cve": "CVE-2026-1234"}]}})["ceiling"] == "partial"
    assert goal_evidence.review(question, {"vulnerability": {"cves": [{"cve": "CVE-2026-1234",
        "fixed_versions": ["1.2.3"]}]}})["ceiling"] == "answered"


def test_shared_fingerprint_requires_two_confirmed_hosts():
    row = {"dom_confirmed": True, "domain": "one.example",
           "http": [{"path": "/jsrepo", "query_keys": ["rnd"], "status": 200}]}
    assert pattern_synth.shared_web_fingerprints([row, dict(row)]) == []
    assert pattern_synth.shared_web_fingerprints([row, dict(row, domain="two.example")]) == [
        {"path": "/jsrepo", "query_keys": ["rnd"], "hosts": ["one.example", "two.example"]}]


def test_confirmed_benign_control_excludes_shared_pattern():
    row = {"dom_confirmed": True, "domain": "one.example",
           "http": [{"path": "/verify", "query_keys": ["token"], "status": 200}]}
    controls = [{"label": "benign_confirmed", "http": [{"path": "/verify",
                 "query_keys": ["token"]}]}]
    assert pattern_synth.shared_web_fingerprints(
        [row, dict(row, domain="two.example")], controls) == []
    assert pattern_synth.shared_web_fingerprints(
        [row, dict(row, domain="two.example")], [{"http": controls[0]["http"]}])
