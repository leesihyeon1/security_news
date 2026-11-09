import json
from types import SimpleNamespace

import pytest

import analysis_trace
import common_utils
import worker_progress


def test_nested_operations_are_isolated_and_never_store_prompts_or_keys():
    @analysis_trace.step("대상 추출", "artifacts", "extraction", inputs=("body", "api_key"))
    def extract(body, api_key):
        with analysis_trace.span("역할 확인", kind="validation"):
            return [{"type": "domain", "value": "payload.example", "role": "unknown"}]

    with analysis_trace.session() as trace:
        assert extract("PRIVATE BODY", "SECRET KEY")[0]["value"] == "payload.example"
    data = trace.export()
    assert data["events"][1]["parent_id"] == data["events"][0]["id"]
    assert data["events"][1]["stage"] == "artifacts"
    assert data["events"][0]["inputs"]["body"]["chars"] == 12
    assert data["events"][0]["output"]["count"] == 1
    raw = json.dumps(data)
    assert "PRIVATE BODY" not in raw and "SECRET KEY" not in raw
    with analysis_trace.session() as second:
        pass
    assert second.export()["events"] == []


def test_llm_retry_records_actual_http_attempts_and_usage(monkeypatch):
    responses = [SimpleNamespace(status_code=429), SimpleNamespace(status_code=200, json=lambda: {
        "choices": [{"message": {"content": "usable response"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}})]
    monkeypatch.setattr(common_utils.requests, "post", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(common_utils.time, "sleep", lambda *args: None)
    monkeypatch.setattr(common_utils, "LLM_PROVIDERS", ["nvidia"])
    monkeypatch.setattr(common_utils, "NVIDIA_API_KEY", "DO NOT EXPORT")
    with analysis_trace.session() as trace:
        with analysis_trace.span("이슈 판단", "issues"):
            assert common_utils.llm_generate("PRIVATE PROMPT") == "usable response"
    rows = trace.export()["events"]
    calls = [row for row in rows if row["kind"] == "llm_attempt"]
    assert [row["http_status"] for row in calls] == [429, 200]
    assert [row["status"] for row in calls] == ["failed", "completed"]
    assert all(row["stage"] == "issues" for row in calls)
    assert calls[1]["usage"]["total_tokens"] == 110
    assert "PRIVATE PROMPT" not in json.dumps(rows)
    assert "DO NOT EXPORT" not in json.dumps(rows)


def test_cached_stage_is_not_a_new_llm_call():
    client = SimpleNamespace(get=lambda key: json.dumps({"digest": "same", "value": "saved result"}))
    with analysis_trace.session() as trace:
        assert worker_progress.load(client, "article", "base", "same") == "saved result"
    rows = trace.export()["events"]
    assert len(rows) == 1 and rows[0]["kind"] == "cache"
    assert rows[0]["status"] == "cached"


def test_exception_keeps_type_without_exposing_message_and_resets_context():
    with analysis_trace.session() as trace:
        with pytest.raises(RuntimeError):
            with analysis_trace.span("조회", "lookup"):
                raise RuntimeError("secret internal host")
    assert trace.export()["events"][0]["error"] == "RuntimeError"
    assert "secret internal host" not in json.dumps(trace.export())
    with analysis_trace.span("outside") as row:
        assert row == {}


def test_public_size_limit_is_explicit_and_keeps_real_totals():
    with analysis_trace.session() as trace:
        for _ in range(500):
            analysis_trace.note("검증 " * 40, "verify", "validation", query="X" * 300)
    data = trace.export()
    assert len(json.dumps(data, ensure_ascii=False).encode()) <= analysis_trace.PUBLIC_BYTES
    assert data["omitted_events"] > 0
    assert data["total_events"] == data["kind_counts"]["validation"] == 500
    assert data["total_events"] == len(data["events"]) + data["omitted_events"]


def test_size_limit_trims_repeated_runs_before_losing_a_stage():
    # 실측 2026-10-12(UAT-11587): 가운데부터 버려 조회·후속 조회 단계가 통째로 빠졌다.
    with analysis_trace.session() as trace:
        analysis_trace.note("기사 수집", "source", query="article")
        for index in range(120):
            analysis_trace.note("해시 조회 " * 8, "lookup", "lookup", value="hash-{}".format(index))
        analysis_trace.note("후속 조회", "followup", "lookup", value="next")
        analysis_trace.note("목표 재검증", "verify", "validation", status="failed", question="answered?")
        for index in range(120):
            analysis_trace.note("차단 후보 검증 " * 8, "actions", "validation", value="ioc-{}".format(index))
        analysis_trace.note("최종 판단", "synthesis", "llm", verdict="done")
    data = trace.export()
    assert len(json.dumps(data, ensure_ascii=False).encode()) <= analysis_trace.PUBLIC_BYTES
    assert data["total_events"] == len(data["events"]) + data["omitted_events"]
    stages = {row["stage"] for row in data["events"]}
    assert {"source", "lookup", "followup", "verify", "actions", "synthesis"} <= stages
    kept = {stage: sum(row["stage"] == stage for row in data["events"]) for stage in ("lookup", "actions")}
    assert abs(kept["lookup"] - kept["actions"]) <= 1  # 긴 반복은 고르게 줄인다
    assert any(row["status"] == "failed" for row in data["events"])


def test_url_credentials_are_removed_and_trace_attaches_to_record():
    @analysis_trace.capture
    def run():
        analysis_trace.note("링크", "source", url="https://user:pass@example.test/path?token=SECRET&v=1")
        return {"analysis": "saved"}
    result = run()
    assert result["analysis"] == "saved"
    raw = json.dumps(result["execution_trace"])
    assert "user:pass" not in raw and "SECRET" not in raw
    assert "example.test/path" in raw
