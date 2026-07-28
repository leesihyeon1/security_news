from datetime import datetime, timedelta

import common_utils
import train_weights as tw


def _patch_reminder_file(tmp_path, monkeypatch):
    state_file = tmp_path / "feedback_reminder_state.json"
    monkeypatch.setattr(tw, "REMINDER_STATE_FILE", state_file)
    return state_file


def test_maybe_remind_slack_sends_when_no_prior_reminder(tmp_path, monkeypatch):
    state_file = _patch_reminder_file(tmp_path, monkeypatch)
    sent = {}

    def fake_send(payload, webhook_url=None):
        sent["text"] = payload["text"]
        return True

    monkeypatch.setattr(common_utils, "send_slack_webhook", fake_send)
    tw.maybe_remind_slack(total=12, useful=8, noise=4)

    assert "12건" in sent["text"]
    assert "useful 8" in sent["text"]
    assert "noise 4" in sent["text"]
    assert state_file.exists()


def test_maybe_remind_slack_respects_cooldown(tmp_path, monkeypatch):
    state_file = _patch_reminder_file(tmp_path, monkeypatch)
    common_utils.save_json_state(state_file, {"last_reminded_at": common_utils.utc_now_iso()})

    calls = {"n": 0}

    def fake_send(payload, webhook_url=None):
        calls["n"] += 1
        return True

    monkeypatch.setattr(common_utils, "send_slack_webhook", fake_send)
    tw.maybe_remind_slack(total=12, useful=8, noise=4)

    assert calls["n"] == 0  # 쿨다운 기간 내라 발송 안 함


def test_maybe_remind_slack_resends_after_cooldown_expires(tmp_path, monkeypatch):
    state_file = _patch_reminder_file(tmp_path, monkeypatch)
    stale = (datetime.utcnow() - timedelta(days=tw.REMINDER_COOLDOWN_DAYS + 1)).isoformat() + "Z"
    common_utils.save_json_state(state_file, {"last_reminded_at": stale})

    calls = {"n": 0}

    def fake_send(payload, webhook_url=None):
        calls["n"] += 1
        return True

    monkeypatch.setattr(common_utils, "send_slack_webhook", fake_send)
    tw.maybe_remind_slack(total=12, useful=8, noise=4)

    assert calls["n"] == 1
