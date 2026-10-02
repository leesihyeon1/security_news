import analysis_evaluation as evaluation


def test_evaluation_catches_normal_recon_domain_in_blocklist():
    record = {"investigation": {"response": {"blocklists": [
        {"values": ["evil.example", "twilio.com"]}]}}}
    result = evaluation.evaluate(record, required=["twilio.com"],
                                  forbidden_blocklist=["twilio.com"])
    assert result["passed"] is False
    assert result["checks"][-1]["name"] == "not_blocklisted:twilio.com"


def test_evaluation_accepts_information_brief_without_attack_actions():
    record = {"investigation": {"route": {"primary": ""},
        "response": {"blocklists": [], "kql": []}}}
    assert evaluation.evaluate(record, informational=True)["passed"]


def test_evaluation_requires_unverified_scope_for_patterns():
    record = {"investigation": {"patterns": [{"validation_status": "candidate"}]}}
    assert evaluation.evaluate(record, require_unverified_pattern=True)["passed"]


def test_evaluate_many_returns_regression_counts():
    result = evaluation.evaluate_many([{"record": {}, "expect": {}},
                                       {"record": {}, "expect": {"required": ["CVE"]}}])
    assert result["cases"] == 2
    assert result["passed"] == 1
