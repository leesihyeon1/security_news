import json

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

    def rpush(self, key, value):
        assert key == analysis_worker.SUMMARY_QUEUE_KEY
        self.queue.append(value)


def write_report(tmp_path, monkeypatch, report):
    monkeypatch.setenv("REPORT_DATA_DIR", str(tmp_path))
    (tmp_path / "daily-2026-09-27.json").write_text(json.dumps(report), encoding="utf-8")


def test_summary_job_uses_public_report_format(monkeypatch, tmp_path):
    client = FakeRedis()
    report = {
        "period": "daily", "generated_at": REPORT_ID, "period_label": "기간",
        "narrative": MISSING, "stats": {"total": 2}, "cards": [],
    }
    write_report(tmp_path, monkeypatch, report)
    calls = []

    def generate(payload):
        calls.append(payload)
        payload["narrative"] = "[총평]\n확인했습니다.\n\n[핵심 위협 TOP 3]\n1. 위협입니다.\n\n[권고 조치]\n1. 점검합니다."
        payload["briefing"] = {"version": 1, "status": "ready", "issues": []}
        return payload

    monkeypatch.setattr(generate_report, "refresh_public_summary", generate)
    assert analysis_worker.process_summary_job(client) is True
    assert len(calls) == 1
    stored = json.loads(client.values["report-summary:result:" + REPORT_ID])
    assert stored["id"] == REPORT_ID
    assert "[권고 조치]" in stored["narrative"]
    assert stored["briefing"]["status"] == "ready"
    assert "report-summary:lock:" + REPORT_ID not in client.values


def test_summary_job_rejects_replaced_report(monkeypatch, tmp_path):
    client = FakeRedis()
    report = {"period": "daily", "generated_at": "2026-09-28T00:00:00Z", "narrative": MISSING}
    write_report(tmp_path, monkeypatch, report)
    assert analysis_worker.process_summary_job(client) is True
    assert "report-summary:result:" + REPORT_ID not in client.values
    assert "report-summary:error:" + REPORT_ID in client.values
    assert "report-summary:lock:" + REPORT_ID not in client.values


def test_summary_job_retries_model_failure_once(monkeypatch, tmp_path):
    client = FakeRedis()
    write_report(tmp_path, monkeypatch, {"period": "daily", "generated_at": REPORT_ID,
                                      "narrative": MISSING})
    monkeypatch.setattr(generate_report, "refresh_public_summary",
                        lambda payload: (_ for _ in ()).throw(RuntimeError("HTTP 503")))

    assert analysis_worker.process_summary_job(client) is True
    assert len(client.queue) == 1
    assert json.loads(client.queue[0])["attempts"] == 1
    assert "report-summary:lock:" + REPORT_ID in client.values
    assert "report-summary:error:" + REPORT_ID not in client.values

    assert analysis_worker.process_summary_job(client) is True
    assert client.queue == []
    assert "report-summary:error:" + REPORT_ID in client.values
    assert "report-summary:lock:" + REPORT_ID not in client.values
