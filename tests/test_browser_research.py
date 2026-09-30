import browser_research
import pattern_synth
import response_synth
import vt_hunter


SEED = {"domain": "lure.example", "in_urlscan": True,
        "urlscan": "https://urlscan.io/result/abc/", "scan_url": "https://lure.example/verify",
        "scanned_at": "2026-09-28", "dom_status": "review",
        "dom_markers": {"clipboard": ["writeText"]},
        "http": [{"host": "lure.example", "path": "/verify", "status": 200}]}


def test_env_flags_enable_browser_research_only_when_both_are_on(monkeypatch):
    monkeypatch.setenv("BROWSER_RESEARCH_ENABLED", ' "1" ')
    monkeypatch.setenv("BROWSER_RESEARCH_ISOLATED_WORKER", "1")
    assert browser_research.enabled()
    monkeypatch.setenv("BROWSER_RESEARCH_ISOLATED_WORKER", "0")
    assert not browser_research.enabled()


def test_clickfix_question_is_investigated_even_for_malware_primary(monkeypatch):
    monkeypatch.setattr(browser_research, "enabled", lambda: False)
    target = {"questions": ["ClickFix 유포지에서 어떤 명령이 복사되는가", "AMD 패치 버전은?"]}
    result = browser_research.investigate(target, {"seeds": [SEED]}, {"primary": "malware"})
    assert result["questions"] == [target["questions"][0]]
    assert result["results"][0]["evidence"]["evidence_id"].startswith("urlscan:")
    assert result["results"][1]["status"] == "deferred"
    assert result["results"][1]["target"] == {"host": "lure.example", "path": "/verify",
                                               "query_keys": []}
    assert "비활성화" in result["results"][1]["reason"]


def test_browser_observation_reaches_answer_and_rule_prompts(monkeypatch):
    monkeypatch.setattr(browser_research, "enabled", lambda: True)
    monkeypatch.setattr(browser_research, "capture", lambda url: {
        "action": "clicked_lure_control", "before": {"dom_sha256": "a" * 64},
        "after": {"dom_sha256": "b" * 64}, "clipboard": [{"sha256": "c" * 64}],
        "responses": [{"host": "lure.example", "path": "/code.js", "status": 200,
                       "mime": "text/javascript", "body_sha256": "d" * 64,
                       "signals": ["writetext"]}],
    })
    result = browser_research.investigate(
        {"questions": ["ClickFix 페이지 동작은?"]}, {"seeds": [SEED]}, {"primary": "malware"})
    assert result["results"][1]["status"] == "observed"
    block = {"browser_research": result, "seeds": [SEED]}
    assert "격리 브라우저 관측" in response_synth._material(block, {})
    assert "code.js" in pattern_synth._web_evidence_text(block)


def test_browser_without_observed_url_records_the_missing_evidence(monkeypatch):
    monkeypatch.setattr(browser_research, "enabled", lambda: True)
    seed = dict(SEED, scan_url="", dom_markers={})
    result = browser_research.investigate(
        {"questions": ["유포지 페이지는?"]}, {"seeds": [seed]}, {"primary": "user_action"})
    assert result["results"][-1]["status"] == "deferred"
    assert "스캔 URL" in result["results"][-1]["reason"]


def test_browser_uses_scan_url_without_dom_marker_but_ignores_internal_log_question(monkeypatch):
    monkeypatch.setattr(browser_research, "enabled", lambda: False)
    result = browser_research.investigate(
        {"questions": ["사내 프록시 로그에서 URL 접속 이력 확인", "ClickFix 유포지의 HTTP 요청은?"]},
        {"seeds": [dict(SEED, dom_markers={}, dom_status="unobserved")]},
        {"primary": "malware"})
    assert result["questions"] == ["ClickFix 유포지의 HTTP 요청은?"]
    assert result["results"][-1]["target"]["host"] == "lure.example"


def test_cdp_initiator_keeps_script_origin_without_query_values():
    fact = browser_research._initiator_fact({"initiator": {"type": "script", "stack": {
        "callFrames": [{"url": "https://source.example/inject.js?secret=private-value"}]}}})
    assert fact == {"type": "script", "host": "source.example", "path": "/inject.js"}


def test_vt_http_context_survives_without_query_secret(monkeypatch):
    entry = {"url": "https://sample.example/api/send?token=private-value",
             "request_method": "POST", "status_code": 204,
             "response_body_filetype": "JSON"}
    behaviour = vt_hunter.parse_behaviour({"data": {"http_conversations": [entry]}})
    assert behaviour["http_details"] == [{"host": "sample.example", "path": "/api/send",
                                           "query_keys": ["token"], "method": "POST",
                                           "status": 204, "response_body_type": "JSON"}]
    monkeypatch.setattr(vt_hunter, "_request", lambda *a, **k: {"data": [{"attributes": {
        "sandbox_name": "Lab A", "processes_tree": [{"name": "sample.exe"}],
        "http_conversations": [entry]}}]})
    sandboxes = vt_hunter.fetch_sandboxes("hash", "key")
    assert sandboxes[0]["process_tree"] == ["sample.exe"]
    assert sandboxes[0]["http"][0]["method"] == "POST"
    assert "private-value" not in pattern_synth._web_evidence_text({
        "malware": {"files": [{"behaviour": behaviour}]}})
