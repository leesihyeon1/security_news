"""예약 작업 상태 점검 — 실패했거나 오래 성공하지 못한 작업만 Slack으로 알린다.

조용한 실패를 잡으려는 것이다(실측: GitHub Advisory 수집이 6월부터 멈췄는데 몰랐고,
slack_feedback은 정상 상황을 실패로 찍어 진짜 실패와 구분되지 않았다).
작업 스케줄러에서 이 저장소의 .bat을 실행하는 작업을 읽기만 한다 — 설정은 바꾸지 않는다.
daily_report.bat 끝에서 하루 한 번 돈다. 같은 문제는 하루에 한 번만 알린다.
"""

import argparse
import json
import subprocess
from datetime import datetime, timedelta, timezone

import common_utils

STATE_PATH = common_utils.STATE_DIR / "task_health.json"
# 작업 스케줄러 결과 코드 중 실패가 아닌 것: 0 성공, 0x41301 실행 중, 0x41303 아직 실행 전.
OK_RESULTS = {0, 0x41301, 0x41303}
# 마지막 실행이 반복 주기의 이 배수보다 오래되면 멈춘 것으로 본다.
STALE_FACTOR = 3
ALERT_EVERY = timedelta(hours=20)

QUERY = r"""
$repo = '{repo}'
Get-ScheduledTask | Where-Object {{ ($_.Actions | ForEach-Object {{ "$($_.Execute) $($_.Arguments)" }}) -match [regex]::Escape($repo) }} |
ForEach-Object {{
  $info = $_ | Get-ScheduledTaskInfo
  [pscustomobject]@{{
    name = $_.TaskName; state = [string]$_.State
    result = [int64]$info.LastTaskResult
    last_run = if ($info.LastRunTime) {{ $info.LastRunTime.ToUniversalTime().ToString('o') }} else {{ '' }}
    interval = ($_.Triggers | ForEach-Object {{ [string]$_.Repetition.Interval }} | Where-Object {{ $_ }} | Select-Object -First 1)
    daily = [bool]($_.Triggers | Where-Object {{ $_.CimClass.CimClassName -match 'Daily' }})
    weekly = [bool]($_.Triggers | Where-Object {{ $_.CimClass.CimClassName -match 'Weekly' }})
  }}
}} | ConvertTo-Json -Depth 3
"""


def read_tasks():
    script = QUERY.format(repo=str(common_utils.PROJECT_ROOT))
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    rows = json.loads(out.stdout or "[]")
    return rows if isinstance(rows, list) else [rows]


def interval_of(task):
    """반복 주기(PT5M 같은 ISO 기간)를 timedelta로. 일간·주간 작업은 그 길이."""
    text = str(task.get("interval") or "")
    if text.startswith("PT"):
        number, total = "", timedelta()
        for ch in text[2:]:
            if ch.isdigit():
                number += ch
            elif number:
                total += {"H": timedelta(hours=int(number)), "M": timedelta(minutes=int(number)),
                          "S": timedelta(seconds=int(number))}.get(ch, timedelta())
                number = ""
        if total:
            return total
    if task.get("weekly"):
        return timedelta(days=7)
    return timedelta(days=1)


def problems(tasks, now):
    found = []
    for task in tasks:
        result = int(task.get("result") or 0)
        if result not in OK_RESULTS:
            found.append((task["name"], "마지막 실행 실패(결과 코드 {})".format(result)))
            continue
        try:
            last = datetime.fromisoformat(str(task.get("last_run")).replace("Z", "+00:00"))
        except ValueError:
            continue
        limit = interval_of(task) * STALE_FACTOR
        if now - last > limit:
            found.append((task["name"], "{}시간째 실행되지 않음".format(int((now - last).total_seconds() // 3600))))
        if str(task.get("state")) == "Disabled":
            found.append((task["name"], "작업이 꺼져 있음"))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="알리지 않고 결과만 출력")
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    tasks = read_tasks()
    found = problems(tasks, now)
    print("[*] 예약 작업 {}개 점검, 문제 {}건".format(len(tasks), len(found)))
    for name, why in found:
        print("  - {}: {}".format(name, why))
    if not found or args.dry_run:
        return
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    fresh = []
    for name, why in found:
        key = name + "|" + why.split("(")[0]
        last = state.get(key)
        if last and now - datetime.fromisoformat(last) < ALERT_EVERY:
            continue
        state[key] = now.isoformat()
        fresh.append((name, why))
    if not fresh:
        return
    text = "*[예약 작업 점검]* 확인이 필요한 작업 {}개\n".format(len(fresh)) + "\n".join(
        "• `{}` — {}".format(name, why) for name, why in fresh)
    if common_utils.send_slack_webhook({"text": text}):
        STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
