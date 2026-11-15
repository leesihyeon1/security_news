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


def write_task(tmp_path, bat, log, lines):
    (tmp_path / "tasks").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "tasks" / bat).write_text(r'python scripts\x.py >> "logs\%s" 2>&1' % log + "\n", encoding="utf-8")
    (tmp_path / "logs" / log).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return task(bat[:-4], action="C:\\repo\\tasks\\" + bat)


def append(path, lines):
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")


def test_repeated_failures_in_the_log_are_reported_even_with_exit_code_zero(tmp_path):
    item = write_task(tmp_path, "send_cve.bat", "cve_run_log.txt", ["Traceback (most recent call last):", "OldError: fixed long ago"])
    found, offsets = task_health.log_problems([item], {}, root=tmp_path)
    assert found == []   # an unseen log only sets the baseline: its old lines carry no time
    lines = (["[-] 슬랙 발송 중 오류 발생: HTTP Error 404: Not Found"] * 6
             + ["[-] 업데이트된 새로운 게시글이 없습니다."] * 50
             + ["[-] NVIDIA 호출 실패, 재시도 1/2 (5초 후): timeout"] * 9
             + ["[-] LLM 생성 실패 (nvidia): overloaded"] * 2)
    append(tmp_path / "logs" / "cve_run_log.txt", lines)
    found, offsets = task_health.log_problems([item], offsets, root=tmp_path)
    assert [why for _, why, _ in found] == ["로그에 실패 6회: [-] 슬랙 발송 중 오류 발생: HTTP Error 404: Not Found"]
    assert offsets["cve_run_log.txt"] == (tmp_path / "logs" / "cve_run_log.txt").stat().st_size
    again, _ = task_health.log_problems([item], offsets, root=tmp_path)
    assert again == []   # only lines written after the last check count


def test_a_traceback_is_reported_once_with_its_exception_line(tmp_path):
    item = write_task(tmp_path, "send_kisa.bat", "send_kisa_run_log.txt", ["start"])
    _, offsets = task_health.log_problems([item], {}, root=tmp_path)
    append(tmp_path / "logs" / "send_kisa_run_log.txt", [
        "Traceback (most recent call last):", '  File "x.py", line 1, in <module>', "    main()",
        "urllib.error.HTTPError: HTTP Error 403: Forbidden"])
    found, _ = task_health.log_problems([item], offsets, root=tmp_path)
    assert [why for _, why, _ in found] == ["로그에 실패 1회: 예외 발생: urllib.error.HTTPError: HTTP Error 403: Forbidden"]


def test_alerts_fall_back_to_email_when_slack_fails(monkeypatch):
    sent = []
    monkeypatch.setattr(task_health.common_utils, "send_slack_webhook", lambda payload: False)
    monkeypatch.setattr(task_health.common_utils, "send_email_message",
                        lambda subject, body, *a, **k: sent.append((subject, body)) or True)
    assert task_health.deliver("*[예약 작업 점검]* `x` — 실패")
    assert sent and "`" not in sent[0][1] and "Slack 웹훅" in sent[0][1]
