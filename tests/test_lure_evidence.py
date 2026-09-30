import lure_hunter as lh
import pattern_synth as ps
import response_builder


def clipboard(value):
    return "navigator.clipboard." + "writeText('" + value + "')"


def test_dom_does_not_confirm_disconnected_clipboard_and_terminal_words():
    html = '<p>Windows Terminal setup guide</p><script>' + clipboard("hello") + '</script>'
    result = lh._inspect_dom(html)
    assert result["confirmed"] is False
    assert result["status"] == "review"


def test_dom_confirms_copied_executable_with_visible_paste_guidance():
    command = "power" + "shell -enc AAA"
    html = ('<p>Press Win + R, then paste and enter</p><button onclick="'
            + clipboard(command) + '">Copy</button>')
    result = lh._inspect_dom(html)
    assert result["confirmed"] is True
    assert result["copied_command"] == command


def test_benign_shell_example_is_not_malicious_lure():
    html = '<p>Press Win + R and paste</p><button onclick="' + clipboard("cmd /c echo demo") + '">Copy</button>'
    assert lh._inspect_dom(html)["confirmed"] is False


def test_hidden_instruction_and_command_do_not_confirm():
    html = '<script>' + clipboard("cmd /c echo demo") + ';const note="Win + R paste";</script>'
    assert lh._inspect_dom(html)["confirmed"] is False


def test_http_facts_retain_first_party_and_do_not_promote_empty_response(monkeypatch):
    empty = lh.EMPTY_BODY_SHA256

    def row(url, body_hash, status):
        return {"request": {"request": {"url": url, "method": "GET"}},
                "response": {"response": {"status": status, "mimeType": "text/javascript"},
                             "hash": body_hash}}

    monkeypatch.setattr(lh, "_request", lambda *a, **k: {"data": {"requests": [
        row("https://lure.example/verify?token=secret", "a" * 64, 200),
        row("https://cdn.other.test/payload.js", empty, 403)]}})
    facts = lh.resource_facts("uuid", "lure.example", "key")
    assert facts["http"][0]["first_party"] is True
    assert facts["http"][0]["query_keys"] == ["token"]
    assert "secret" not in str(facts)
    assert facts["empty_response_hosts"] == ["cdn.other.test"]
    assert all("payload.js" not in query for _, query, _ in lh.resource_pivots(facts))


def test_urlscan_hit_count_does_not_mean_validated(monkeypatch):
    monkeypatch.setattr(ps, "_search_urlscan", lambda query, api_key=None: (
        [{"page": {"domain": "benign.example"}}], 3, ""))
    ok, _, facts = ps.validate_urlscan({"query": 'page.title:"Verify"'},
                                        positive_hosts=["lure.example"])
    assert ok is True
    assert facts["matched_seeds"] == []
    assert facts["unverified"]


def test_structural_filename_survives_large_hit_count_as_review_candidate(monkeypatch):
    monkeypatch.setattr(ps, "_search_urlscan", lambda query, api_key=None: (
        [{"page": {"domain": "unknown.example"}}], 9826, ""))
    ok, _, facts = ps.validate_urlscan({"query": 'filename:"jsrepo?rnd="'},
                                        positive_hosts=["lure.example"])
    assert ok is True
    assert facts["hits"] == 9826
    assert "검토" in facts["unverified"]


def test_historical_http_path_and_query_key_reach_pattern_prompt():
    block = {"seeds": [{"in_urlscan": True, "domain": "lure.example", "http": [],
                        "historical_scans": [{"scanned_at": "2026-08-28", "http": [
                            {"host": "tds.example", "path": "/jsrepo", "query_keys": ["rnd"],
                             "filename": "jsrepo?rnd=", "initiator": {"host": "lure.example",
                                                                     "path": "/script.js"}}]}]}]}
    evidence = ps._web_evidence_text(block)
    assert "jsrepo?rnd=" in evidence
    assert "시작점=lure.example/script.js" in evidence


def test_pattern_prompt_receives_http_and_dom_evidence():
    block = {"seeds": [{"domain": "lure.example", "in_urlscan": True,
                         "dom_status": "confirmed", "copied_command": "cmd /c echo demo",
                         "http": [{"method": "GET", "host": "lure.example", "path": "/verify",
                                   "status": 200, "mime": "text/html", "first_party": True}]}]}
    prompt = ps.build_prompt("title", "analysis", "body", [], web_evidence=block)
    assert "GET lure.example/verify" in prompt
    assert "cmd /c echo demo" in prompt


def test_urlscan_hosting_ip_is_not_an_automatic_block_candidate():
    block = {"seeds": [{"domain": "lure.example", "dom_confirmed": True,
                         "ip": "45.67.89.123", "asnname": "Example Hosting"}]}
    values = response_builder._collect(block, [])
    assert "45.67.89.123" not in values["ips"]
    assert any("45.67.89.123" in line for line in values["shared_hosting"])
