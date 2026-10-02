import lookup_plan
import research_entities


def test_shared_platform_keeps_content_path_and_exact_url_query():
    assert research_entities.shared("https://chatgpt.com")
    assert research_entities.content_url("https://chatgpt.com/g/g-123/custom")
    assert not research_entities.content_url("https://chatgpt.com/")
    query = research_entities.exact_query("https://chatgpt.com/g/g-123/custom")
    assert "task.url.keyword" in query
    assert "page.domain" not in query


def test_sample_order_prefers_role_evidence_and_keeps_hashes_valid():
    loader = "a" * 64
    payload = "b" * 64
    selected = research_entities.sample_order(
        [loader, payload],
        evidence="loader.dll hash {} and final RAT payload hash {}".format(loader, payload),
        limit=2,
    )
    assert set(selected) == {loader, payload}


def test_lookup_plan_does_not_attach_web_lookup_to_dynamic_question():
    question = "RAT의 C2 통신과 지속성 행위는 무엇인가"
    tasks = lookup_plan.build_task_graph(
        "샘플 행위 확인", [question], ["user_action", "malware"], {"user_action", "malware"},
        [{"question": question, "lookups": [{"key": "user_action"}]}],
    )
    assert tasks[0]["lookup_keys"] == ["malware"]
