"""Persistent health for RSS feeds, with one alert per failure streak."""

import os

import common_utils


STATE_FILE = common_utils.STATE_DIR / "rss_feed_health.json"
ALERT_AFTER = max(1, int(os.environ.get("RSS_FEED_HEALTH_ALERT_AFTER", "3")))


def _load():
    state = common_utils.load_json_state(STATE_FILE, dict)
    return state if isinstance(state, dict) else {}


def _notify(label, recovered, failures=0):
    if not common_utils.SLACK_WEBHOOK_URL:
        return False
    message = ("[RSS 복구] {} 피드가 다시 수집됩니다." if recovered else
               "[RSS 수집 장애] {} 피드가 {}회 연속 실패했습니다.")
    text = message.format(label) if recovered else message.format(label, failures)
    return common_utils.send_slack_webhook({"text": text}, common_utils.SLACK_WEBHOOK_URL)


def record_success(feed):
    state = _load()
    name = feed["name"]
    row = state.get(name) or {}
    was_alerted = bool(row.get("alerted"))
    row.update({"label": feed.get("label") or name,
                "last_success_at": common_utils.utc_now_iso(),
                "consecutive_failures": 0, "last_error": "", "alerted": False})
    if was_alerted and not _notify(row["label"], recovered=True):
        row["alerted"] = True
    state[name] = row
    common_utils.save_json_state(STATE_FILE, state)
    return row


def record_failure(feed, error):
    state = _load()
    name = feed["name"]
    row = state.get(name) or {}
    failures = int(row.get("consecutive_failures") or 0) + 1
    row.update({"label": feed.get("label") or name,
                "last_failure_at": common_utils.utc_now_iso(),
                "consecutive_failures": failures,
                "last_error": " ".join(str(error).split())[:200]})
    if failures >= ALERT_AFTER and not row.get("alerted"):
        row["alerted"] = _notify(row["label"], recovered=False, failures=failures)
    state[name] = row
    common_utils.save_json_state(STATE_FILE, state)
    return row
