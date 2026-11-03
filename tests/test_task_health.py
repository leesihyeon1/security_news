from datetime import datetime, timedelta, timezone

import task_health

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def task(name, result=0, ago=timedelta(minutes=3), interval="PT5M", **extra):
    return dict({"name": name, "state": "Ready", "result": result,
                 "last_run": (NOW - ago).isoformat(), "interval": interval}, **extra)


def test_intervals():
    assert task_health.interval_of({"interval": "PT5M"}) == timedelta(minutes=5)
    assert task_health.interval_of({"interval": "PT4H"}) == timedelta(hours=4)
    assert task_health.interval_of({"interval": "", "weekly": True}) == timedelta(days=7)
    assert task_health.interval_of({"interval": None}) == timedelta(days=1)


def test_failures_and_stale_tasks_are_reported_running_is_not():
    found = dict(task_health.problems([
        task("ok"), task("running", result=0x41301),
        task("broken", result=1), task("stuck", ago=timedelta(hours=2)),
        task("daily", interval="", ago=timedelta(hours=30)),
    ], NOW))
    assert set(found) == {"broken", "stuck"}
    assert "결과 코드 1" in found["broken"]
