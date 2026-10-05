import json
from types import SimpleNamespace

import analysis_worker
import generate_report


REPORT_ID = "2026-09-27T23:37:42Z"
MISSING = "[총평]\n한국어 요약을 준비하지 못했습니다."


class FakeRedis:
    def __init__(self):
        self.queue = [json.dumps({"id": REPORT_ID})]
        self.values = {"report-summary:lock:" + REPORT_ID: "pending"}

    def lpop(self, key):
        assert key == analysis_worker.SUMMARY_QUEUE_KEY
        return self.queue.pop(0) if self.queue else None

    def set(self, key, value, ex=None):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)


def test_summary_job_uses_public_report_format(monkeypatch):
    client = FakeRedis()
    report = {
        "period": "daily", "generated_at": REPORT_ID, "period_label": "기간",
        "narrative": MISSING, "stats": {"total": 2}, "cards": [],
    }
    monkeypatch.setattr(analysis_worker.requests, "get", lambda *args, **kwargs: SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: report))
    calls = []

    def generate(payload):
        calls.append(payload)
        payload["narrative"] = "[총평]\n확인했습니다.\n\n[핵심 위협 TOP 3]\n1. 위협입니다.\n\n[권고 조치]\n1. 점검합니다."
        payload["briefing"] = {"version": 1, "status": "ready", "issues": []}
        return payload

    monkeypatch.setattr(generate_report, "refresh_public_summary", generate)
    assert analysis_worker.process_summary_job(client) is True
    assert calls == [report]
    stored = json.loads(client.values["report-summary:result:" + REPORT_ID])
    assert stored["id"] == REPORT_ID
    assert "[권고 조치]" in stored["narrative"]
    assert stored["briefing"]["status"] == "ready"
    assert "report-summary:lock:" + REPORT_ID not in client.values


def test_summary_job_rejects_replaced_report(monkeypatch):
    client = FakeRedis()
    report = {"period": "daily", "generated_at": "2026-09-28T00:00:00Z", "narrative": MISSING}
    monkeypatch.setattr(analysis_worker.requests, "get", lambda *args, **kwargs: SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: report))
    assert analysis_worker.process_summary_job(client) is True
    assert "report-summary:result:" + REPORT_ID not in client.values
    assert "report-summary:error:" + REPORT_ID in client.values
    assert "report-summary:lock:" + REPORT_ID not in client.values
