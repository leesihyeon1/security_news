"""제한 시간을 다 쓰고 끊긴 LLM 호출을 다시 보내지 않는지 확인한다.

실측(2026-11-19): 실행 기록이 남은 심층분석 13건에서 이렇게 끊긴 뒤의 재시도 8회가 모두
실패했고, 기다린 시간만 97분이었다. Gootloader 건은 30분 중 17분이 이 대기였다.
"""
import pytest
import requests

import common_utils
import pattern_synth
import response_synth


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.fixture
def nvidia(monkeypatch):
    clock = Clock()
    calls = []
    monkeypatch.setattr(common_utils.time, "monotonic", clock)
    monkeypatch.setattr(common_utils.time, "sleep", lambda seconds: None)

    def install(error, elapsed):
        def request(*args, **kwargs):
            calls.append(kwargs.get("timeout"))
            clock.now += elapsed
            raise error
        monkeypatch.setattr(common_utils.analysis_trace, "llm_request", request)
        return calls
    return install


def test_slow_timeout_is_not_retried_when_the_caller_has_a_fallback(nvidia):
    calls = nvidia(requests.exceptions.ReadTimeout("read timed out"), elapsed=181)
    with pytest.raises(requests.exceptions.ReadTimeout):
        common_utils._generate_nvidia("p", 180, max_attempts=2, retry_slow_failures=False)
    assert calls == [180]


def test_slow_connection_drop_is_not_retried_either(nvidia):
    calls = nvidia(requests.exceptions.ConnectionError("reset"), elapsed=341)
    with pytest.raises(requests.exceptions.ConnectionError):
        common_utils._generate_nvidia("p", 420, max_attempts=2, retry_slow_failures=False)
    assert len(calls) == 1


def test_fast_failure_is_still_retried(nvidia):
    calls = nvidia(requests.exceptions.ConnectionError("refused"), elapsed=2)
    with pytest.raises(requests.exceptions.ConnectionError):
        common_utils._generate_nvidia("p", 180, max_attempts=2, retry_slow_failures=False)
    assert len(calls) == 2


def test_report_calls_keep_retrying_slow_failures_by_default(nvidia):
    calls = nvidia(requests.exceptions.ReadTimeout("read timed out"), elapsed=300)
    with pytest.raises(requests.exceptions.ReadTimeout):
        common_utils._generate_nvidia("p", 300, max_attempts=3)
    assert len(calls) == 3


def test_synthesis_does_not_resend_a_compact_prompt_after_the_call_failed(monkeypatch):
    calls = []

    def failed(prompt, **kwargs):
        calls.append(kwargs)
        return None

    monkeypatch.setattr(common_utils, "llm_generate", failed)
    assert response_synth.synthesize("제목", "", {}, {"findings": ["x.example urlscan 관측"]}) is None
    assert len(calls) == 1
    assert calls[0]["retry_slow_failures"] is False


def test_pattern_synthesis_does_not_repeat_a_failed_call(monkeypatch):
    calls = []
    monkeypatch.setattr(common_utils, "llm_generate", lambda *a, **k: calls.append(k))
    result = pattern_synth.synthesize("제목", "분석", "본문", [])
    assert result["patterns"] == []
    assert len(calls) == 1
