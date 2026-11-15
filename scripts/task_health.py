"""예약 작업 상태 점검 — 실패했거나 오래 성공하지 못한 작업만 알린다.

조용한 실패를 잡으려는 것이다(실측: GitHub Advisory 수집이 6월부터 멈췄는데 몰랐고,
slack_feedback은 정상 상황을 실패로 찍어 진짜 실패와 구분되지 않았다).
작업 스케줄러에서 이 저장소의 .bat을 실행하는 작업을 읽기만 한다 — 설정은 바꾸지 않는다.
daily_report.bat 끝에서 하루 한 번 돈다. 같은 문제는 하루에 한 번만 알린다.

종료 코드만 보면 놓치는 실패가 있다. 스크립트가 예외를 삼키고 0으로 끝나는 경우다
(실측 2026-11-15: Slack 웹훅이 전부 폐기돼 엿새 동안 모든 Slack 발송이 404였는데 작업은
모두 "정상"이었고, 이 점검의 알림도 같은 웹훅으로 가서 전달되지 않았다). 그래서
1) 각 작업의 실행 로그에서 지난 점검 이후 반복된 실패 줄을 찾고,
2) Slack 발송이 실패하면 메일로 대신 보낸다.
"""

import argparse
import json
import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import common_utils

STATE_PATH = common_utils.STATE_DIR / "task_health.json"
# 작업 스케줄러 결과 코드 중 실패가 아닌 것: 0 성공, 0x41301 실행 중, 0x41303 아직 실행 전.
OK_RESULTS = {0, 0x41301, 0x41303}
# 마지막 실행이 반복 주기의 이 배수보다 오래되면 멈춘 것으로 본다.
STALE_FACTOR = 3
ALERT_EVERY = timedelta(hours=20)

# 로그 점검: 지난 점검 뒤에 늘어난 부분만 읽는다. 로그에는 시각이 없어 처음 보는 로그의 기존 내용이
# 언제 것인지 알 수 없다(실측: 이미 고친 예외가 끝부분에 남아 있었다) — 처음에는 기준점만 잡는다.
LOG_SCAN_BYTES = 400_000
# 같은 실패가 이만큼 반복돼야 알린다. 한두 번의 외부 장애(API 과부하 등)로 매일 알림이 가지 않게 한다.
MIN_REPEATS = 5
MAX_LOG_PROBLEMS = 3
FAILURE = re.compile(r"실패|오류 발생|Failed to |HTTP Error \d+")
# 실패 표시([-])를 쓰지만 실패가 아닌 줄: 새 글 없음, 설정이 없어 건너뜀, 재시도 진행 중, 품질 점검 메모.
BENIGN = re.compile(r"재시도 \d+/\d+|재시도 예약|없습니다|건너뜁니다|미달|총평 점검")
TRACEBACK = "Traceback (most recent call last)"

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
    action = (($_.Actions | ForEach-Object {{ "$($_.Execute) $($_.Arguments)" }}) -join ' ')
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


# ── 로그 점검 ─────────────────────────────────────────────────────────────────
def task_logs(task, root=None):
    """작업이 실행하는 .bat이 출력을 쌓는 로그 파일들."""
    root = Path(root or common_utils.PROJECT_ROOT)
    logs = []
    for name in re.findall(r"([\w.-]+\.bat)", str(task.get("action") or ""), re.I):
        bat = root / "tasks" / name
        try:
            text = bat.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for log in re.findall(r'>>\s*"?(logs[\\/][\w.-]+)"?', text):
            path = root / log.replace("\\", "/")
            if path not in logs:
                logs.append(path)
    return logs


def read_new(path, offset):
    """offset 이후에 추가된 로그 내용과 새 offset. 처음 보는 로그는 읽지 않고 기준점만 잡는다.
    파일이 줄었으면(새로 만들어졌으면) 처음부터 읽는다."""
    try:
        size = path.stat().st_size
    except OSError:
        return "", offset or 0
    if not isinstance(offset, int):
        return "", size
    start = offset if 0 <= offset <= size else 0
    start = max(start, size - LOG_SCAN_BYTES)
    with path.open("rb") as stream:
        stream.seek(start)
        raw = stream.read()
    for encoding in ("utf-8", "cp949"):
        try:
            return raw.decode(encoding), size
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), size


def log_failures(text):
    """반복된 실패 줄을 (대표 문구, 횟수)로. 예외 추적은 마지막 예외 줄로 묶는다."""
    counts, samples = Counter(), {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        line = line.strip()
        if line.startswith(TRACEBACK):
            # 추적 본문(들여쓴 줄) 다음의 첫 줄이 예외 종류와 메시지다.
            error = next((later.strip() for later in lines[index + 1:index + 60]
                          if later.strip() and not later.startswith((" ", "\t"))), "")
            message = "예외 발생: " + (error or "내용 없음")
        elif FAILURE.search(line) and not BENIGN.search(line):
            message = line
        else:
            continue
        key = re.sub(r"\d+", "N", re.sub(r"https?://\S+", "<url>", message))[:110]
        counts[key] += 1
        samples.setdefault(key, re.sub(r"https?://\S+", "<url>", message)[:160])
    return [(samples[key], count) for key, count in counts.most_common()
            if count >= MIN_REPEATS or key.startswith("예외 발생")][:MAX_LOG_PROBLEMS]


def log_problems(tasks, offsets, root=None):
    """(작업 이름, 설명, 중복 방지 키) 목록과 갱신된 offset. 한 로그는 한 번만 읽는다."""
    found, updated, seen = [], dict(offsets), set()
    for task in tasks:
        for path in task_logs(task, root):
            if path in seen:
                continue
            seen.add(path)
            text, updated[path.name] = read_new(path, offsets.get(path.name))
            for message, count in log_failures(text):
                found.append((task["name"], "로그에 실패 {}회: {}".format(count, message),
                              task["name"] + "|log|" + re.sub(r"\d+", "N", message)[:80]))
    return found, updated


def deliver(text):
    """Slack으로 보내고, 실패하면 메일로 보낸다. 알림 경로 자체가 죽어 있어도 전달되게 한다."""
    if common_utils.send_slack_webhook({"text": text}):
        return True
    print("[!] Slack 발송 실패 — 메일로 대신 보냅니다.")
    plain = text.replace("*", "").replace("`", "")
    return bool(common_utils.send_email_message("[예약 작업 점검] 확인이 필요한 작업", plain +
                                                "\n\n(Slack 발송이 실패해 메일로 보냈습니다. Slack 웹훅 설정을 확인하세요.)"))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="알리지 않고 결과만 출력")
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    tasks = read_tasks()
    found = [(name, why, name + "|" + why.split("(")[0]) for name, why in problems(tasks, now)]
    from_logs, offsets = log_problems(tasks, state.get("log_offsets") or {})
    found += from_logs
    print("[*] 예약 작업 {}개 점검, 문제 {}건(로그 {}건)".format(len(tasks), len(found), len(from_logs)))
    for name, why, _ in found:
        print("  - {}: {}".format(name, why))
    if args.dry_run:
        return
    fresh = []
    for name, why, key in found:
        last = state.get(key)
        if last and now - datetime.fromisoformat(last) < ALERT_EVERY:
            continue
        fresh.append((name, why, key))
    if fresh:
        text = "*[예약 작업 점검]* 확인이 필요한 작업 {}개\n".format(len({name for name, _, _ in fresh})) + "\n".join(
            "• `{}` — {}".format(name, why) for name, why, _ in fresh)
        if not deliver(text):
            return   # 전달하지 못했으면 기록하지 않는다 — 다음 점검에서 같은 내용을 다시 알린다.
        for _, _, key in fresh:
            state[key] = now.isoformat()
    state["log_offsets"] = offsets
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
