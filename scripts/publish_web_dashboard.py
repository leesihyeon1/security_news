"""boannews_vercel 정적 사이트로 일간/주간 리포트 JSON을 발행한다.

WEB_DASHBOARD_REPO_PATH(.env)가 boannews_vercel 저장소의 **로컬 클론 경로**를
가리켜야 한다. 이 저장소는 dashboard/·click-tracker/ 두 하위 프로젝트를 담고 있고,
각각 별도 Vercel 프로젝트(Root Directory 설정)로 배포된다 — 데이터는 그중
dashboard/ 쪽에 쓴다. generate_report.py가 리포트를 만든 직후 이미 계산된 데이터로
dashboard/data/<period>-latest.json(최신본)과 dashboard/data/<period>-<날짜>.json
(히스토리)을 쓰고, 그 클론에서 git add/commit/push까지 수행한다 — 새 토큰·API 연동
없이 이 기기에 이미 설정된 git 자격증명(Credential Manager)을 그대로 쓴다. 동시에
dashboard/data/search-index.json(대시보드 History 탭·검색용 인덱스)도 data/events.jsonl
에서 직접 통째로 재구성한다 — 특정 리포트가 뭘 하이라이트로 뽑았는지와 무관하게
항상 최근 SEARCH_INDEX_RETENTION_DAYS일치 전체 기사가 들어있고, 과거에 이미 수집된
기사도 그대로 백필된다(리포트 발행이 그날 실패해도 인덱스는 영향받지 않음).

실패해도(경로 미설정, git 오류, push 실패 등) 예외를 절대 밖으로 던지지 않는다 —
대시보드 발행은 부가 기능이라 이것 때문에 메인 리포트 발송이 막히면 안 된다.

필요 설정(.env):
    WEB_DASHBOARD_REPO_PATH=C:\\path\\to\\local\\clone\\of\\boannews_vercel
"""

import contextlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import common_utils
import event_calendar
import live_news
import incident_archive
from dashboard_text import event_summary, public_text

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

REPO_PATH = os.environ.get("WEB_DASHBOARD_REPO_PATH", "")
SEARCH_INDEX_FILE = "search-index.json"
SEARCH_INDEX_RETENTION_DAYS = 365
EXPECTED_REMOTE_REPO = "leesihyeon1/boannews_vercel"

# 작업 스케줄러에서 돌 때는 입력을 받을 사람이 없다. 자격증명이 없으면 git이
# credential manager UI를 띄우고 영원히 대기하는데, 그 상태로 발행 잠금을 쥐고 있어
# 이후 모든 발행이 잠금 타임아웃으로 실패한다(실제로 2026-08-25부터 그렇게 막혔다).
# 프롬프트를 전부 막아 "인증 실패"로 즉시 떨어뜨리고, 그래도 안 끝나면 타임아웃으로 끊는다.
GIT_TIMEOUT_SECONDS = 120
GIT_NONINTERACTIVE_ARGS = ["-c", "credential.interactive=never"]


# remote URL에 토큰을 심어 인증하는 구성을 지원한다(Windows 자격증명 관리자에 넣어둔
# 자격증명이 원인 미상으로 반복 삭제돼, 지워질 주체가 없는 방식으로 옮긴 결과다).
# 그 경우 URL 자체가 비밀이므로 로그·예외 메시지에 그대로 실리면 안 된다.
CREDENTIAL_IN_URL_RE = re.compile(r"(https?://)[^/\s:@]+(?::[^/\s@]*)?@")


def redact_url(text):
    """URL에 박힌 자격증명(user:token@)을 가린다. 로그로 나가는 모든 문자열에 적용."""
    return CREDENTIAL_IN_URL_RE.sub(r"\1***@", text or "")


def _git_env():
    """git이 어떤 경로로도 입력을 기다리지 않게 만든다.

    주의: 여기에 GIT_ASKPASS를 넣으면 안 된다. askpass가 빈 문자열을 돌려주면
    git은 "자격증명 없음"이 아니라 "빈 자격증명"으로 요청을 보내고, GitHub이 401을
    주면 git이 credential helper에 erase를 호출해 저장돼 있던 멀쩡한 토큰까지
    지워버린다(실측: 무기한 PAT가 몇 시간 만에 사라지던 원인). 미설정으로 두면
    git이 요청을 보내기 전에 "could not read Username"으로 즉시 실패하므로
    401도, erase도 발생하지 않는다.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"   # 터미널 프롬프트 금지
    env["GCM_INTERACTIVE"] = "never"   # Git Credential Manager UI 금지
    env.pop("GIT_ASKPASS", None)
    env.pop("SSH_ASKPASS", None)
    return env


def _run_git_raw(args, cwd):
    """git 실행 공통 래퍼 — 비대화형 환경 + 타임아웃을 항상 적용한다."""
    try:
        return subprocess.run(
            ["git"] + GIT_NONINTERACTIVE_ARGS + args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_env(),
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "git {} 이(가) {}초 안에 끝나지 않아 중단했습니다 "
            "(자격증명 대기 가능성 — git push 를 한 번 대화형으로 실행해 인증을 갱신하세요)".format(
                " ".join(args), GIT_TIMEOUT_SECONDS
            )
        )


def _run_git(args, cwd):
    result = _run_git_raw(args, cwd)
    if result.returncode != 0:
        # stderr에 remote URL이 실려 올 수 있어 그대로 올리면 토큰이 로그에 남는다.
        raise RuntimeError(redact_url("git {} 실패: {}".format(" ".join(args), result.stderr.strip())))
    return result.stdout


def _has_staged_changes(pathspec, cwd):
    result = _run_git_raw(["diff", "--cached", "--quiet", "--", pathspec], cwd=cwd)
    if result.returncode == 0:
        return False
    if result.returncode == 1:
        return True
    raise RuntimeError("git diff --cached 실패: {}".format(result.stderr.strip()))


def _validate_publish_repo(repo):
    git_dir = repo / ".git"
    if not git_dir.exists():
        print("[-] WEB_DASHBOARD_REPO_PATH는 독립 Git 클론이어야 합니다: {}".format(repo))
        return False

    remote_url = _run_git(["remote", "get-url", "origin"], cwd=repo).strip()
    normalized = remote_url.replace("\\", "/").lower()
    if EXPECTED_REMOTE_REPO.lower() not in normalized:
        print("[-] 대시보드 원격 저장소가 예상과 다릅니다: {}".format(redact_url(remote_url)))
        return False
    return True


ISSUE_HISTORY_FILE = "issues-history.json"
ISSUE_HISTORY_DAYS = 30


def _rebuild_issue_history(data_dir):
    """이미 발행된 일간 파일들에서 카드 이력을 뽑아 issues-history.json으로 만든다.

    카드 라벨(CVE ID·위협 행위자명)은 날짜를 넘어 유지되므로 별도 저장 없이도
    "이 이슈가 어제와 달라졌는가"를 알 수 있다. 실측(2026-09-01)으로는 그날 카드
    37개 중 32개(86%)가 8일째 등급·소스·EPSS가 완전히 같은 반복이었다 — 이 정보가
    없으면 신규 3건이 그 안에 묻힌다.

    새 화면을 만들지 않는다. 카드 배지와 정렬 순서에만 쓰는 참조 데이터다.
    """
    entries = sorted(data_dir.glob("daily-2026-*.json")) + sorted(data_dir.glob("daily-202[0-9]-*.json"))
    seen_paths = []
    for path in entries:
        if path.name not in [p.name for p in seen_paths]:
            seen_paths.append(path)
    seen_paths = seen_paths[-ISSUE_HISTORY_DAYS:]

    history = {}
    for path in seen_paths:
        day = path.stem.replace("daily-", "")
        try:
            with path.open("r", encoding="utf-8") as file:
                payload = json.load(file)
        except (OSError, json.JSONDecodeError):
            continue
        for card in payload.get("cards") or []:
            label = card.get("cve")
            if not label:
                continue
            history.setdefault(label, []).append({
                "date": day,
                "level": card.get("level") or "",
                "sources": len(card.get("sources") or []),
            })

    out_path = data_dir / ISSUE_HISTORY_FILE
    with out_path.open("w", encoding="utf-8") as file:
        json.dump({"days": len(seen_paths), "issues": history}, file, ensure_ascii=False, indent=2)


def _rebuild_search_index_from_events(repo):
    """search-index.json을 data/events.jsonl에서 통째로 재구성한다(어느 리포트가 뭘 하이라이트로
    뽑았는지와 무관 — 그래서 과거에 이미 수집된 기사도 그대로 백필되고, 리포트 발행이 실패한
    날에도 인덱스는 영향받지 않는다).

    CVE 상관관계 카드(같은 CVE를 여러 소스로 묶은 것)는 여기서 다시 계산하지 않고 개별 기사만
    담는다 — correlate_by_cve() 로직을 옮겨오는 복잡도 없이도, CVE 번호로 검색하면 그걸 언급한
    기사가 다 나오므로 검색 용도로는 충분하다.

    끝에서부터 거슬러 읽다가 보관 기간(SEARCH_INDEX_RETENTION_DAYS)보다 오래된 이벤트를 만나면
    멈춘다 — 로그 전체 크기와 무관하게 그 기간만큼만 읽는다. cutoff 판정은 fetched_at(수집
    순서와 같은 방향으로 단조 증가) 기준이고, 화면에 보여줄 date는 기사 자체의 published_at을
    우선한다.
    """
    cutoff = (datetime.utcnow() - timedelta(days=SEARCH_INDEX_RETENTION_DAYS)).isoformat()

    by_key = {}
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        fetched_at = event.get("fetched_at") or ""
        if fetched_at < cutoff:
            break

        source = event.get("source") or ""
        if source in common_utils.NON_NEWS_SOURCES:
            continue

        url = event.get("url") or ""
        key = url or "{}|{}".format(source, event.get("title") or "")
        if key in by_key:
            continue  # 끝에서부터 훑으므로 먼저 만난(더 최근에 수집된) 것을 유지

        date_stamp = (event.get("published_at") or fetched_at)[:10]
        by_key[key] = {
            "date": date_stamp,
            "type": "article",
            # 검색 결과에서도 심층분석을 누를 수 있게 한다 — generate_report의
            # serialize_event와 같은 해시라 이미 분석된 기사면 캐시가 그대로 맞는다.
            "ref": common_utils.event_ref(event.get("id")),
            "title": event.get("title") or "",
            "url": common_utils.tracking_url(event.get("id"), url) or url,
            "source_label": common_utils.source_label(source),
            "category": (event.get("category") or "").strip() or "미분류",
            "level": (event.get("triage") or {}).get("level") or "",
            "summary": public_text(event_summary(event, 200)) or "요약 미제공 · 원문 확인",
        }

    entries = sorted(by_key.values(), key=lambda e: e.get("date") or "", reverse=True)

    index_path = repo / "dashboard" / "data" / SEARCH_INDEX_FILE
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("w", encoding="utf-8") as file:
        json.dump(entries, file, ensure_ascii=False, separators=(",", ":"))


PUBLISH_RETRIES = 3
PUBLISH_RETRY_DELAY_SECONDS = 5
LOCK_TIMEOUT_SECONDS = 120
LOCK_POLL_INTERVAL_SECONDS = 2
LOCK_FILE_NAME = ".dashboard_publish.lock"
# 정상 발행은 git 타임아웃(120초)에 묶여 있으므로 이보다 한참 오래된 잠금은 유실된 것이다
LOCK_STALE_SECONDS = 900


def _lock_is_stale(lock_path):
    try:
        return (time.time() - lock_path.stat().st_mtime) > LOCK_STALE_SECONDS
    except OSError:
        return False  # 그사이 정상 해제됨


@contextlib.contextmanager
def repo_lock(repo):
    """같은 로컬 클론(repo)에 대한 git 작업이 두 곳(이 스크립트의 일간/주간 발행과
    publish_trending_titles.py의 30분 주기 발행)에서 동시에 실행되는 걸 막는다 —
    동시에 fetch/reset/commit/push가 겹치면 재시도를 몇 번을 하든 서로가 서로를
    "원격이 앞서 있음"으로 계속 보게 되거나 .git/index.lock 충돌이 날 수 있다.
    파일 하나를 뮤텍스로 써서, 한쪽이 끝날 때까지 다른 쪽은 대기한다.
    """
    lock_path = repo / LOCK_FILE_NAME
    deadline = time.time() + LOCK_TIMEOUT_SECONDS
    fd = None
    while fd is None:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            # 발행 프로세스가 강제 종료되면 잠금 파일만 남아 이후 모든 발행이 영구히
            # 막힌다(2026-08-25~30 실제 사례). 정상 발행보다 훨씬 오래된 잠금은
            # 주인이 죽은 것으로 보고 회수한다.
            if _lock_is_stale(lock_path):
                print("[!] 오래된 잠금을 회수합니다(주인 프로세스가 죽은 것으로 판단): {}".format(lock_path))
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                continue

            if time.time() > deadline:
                raise RuntimeError("다른 발행 작업이 잠금을 오래 쥐고 있어 타임아웃: {}".format(lock_path))
            time.sleep(LOCK_POLL_INTERVAL_SECONDS)
    try:
        yield
    finally:
        os.close(fd)
        try:
            lock_path.unlink()
        except OSError:
            pass


# 이 스크립트가 소유하는 경로. 여기 밖의 변경은 사람이 손으로 고친 것이라 지우면 안 된다.
OWNED_PATHS = ("dashboard/data",)


def _dirty_paths_outside_data(repo):
    """dashboard/data 밖에서 커밋되지 않은 변경 파일 목록."""
    out = _run_git(["status", "--porcelain", "--untracked-files=no"], cwd=repo)
    paths = []
    for line in out.splitlines():
        path = line[3:].strip().strip('"')
        if " -> " in path:                       # 이름이 바뀐 경우 새 이름을 본다
            path = path.split(" -> ", 1)[1]
        if path and not any(path.startswith(owned) for owned in OWNED_PATHS):
            paths.append(path)
    return paths


def _sync_to_remote_head(repo, branch):
    """로컬 클론을 원격 HEAD에 강제로 맞춘다.

    이전 실행이 실패해 남긴 미푸시 커밋이나, 다른 환경에서 origin이 앞서나가 생긴
    어긋남을 여기서 정리한다. 이렇게 안 하면 오래된 로컬 상태 위에 커밋해봐야 push가
    매번 거부된다.

    예전에는 이 클론을 데이터 전용으로 보고 무조건 reset --hard 했다. 그런데 대시보드
    코드(dashboard/assets/app.js·style.css)도 같은 저장소에 있어서, 커밋하지 않은 코드
    수정이 발행이 돌 때마다 조용히 사라졌다(2026-09-10에 두 번 발생). 그래서 우리가
    만들지 않은 변경은 지우기 전에 stash로 옮겨 두고, 리셋 뒤에 되돌려 놓는다.
    되돌리다 충돌하면 stash를 남긴 채로 알린다 — 자동으로 풀려다 덮어쓰는 것보다
    사람이 확인하는 편이 낫다.
    """
    _run_git(["fetch", "origin", branch], cwd=repo)

    dirty = _dirty_paths_outside_data(repo)
    stashed = False
    if dirty:
        print("[!] 발행이 소유하지 않은 변경 {}건을 보관합니다(리셋에 지워지지 않게): {}".format(
            len(dirty), ", ".join(dirty[:5])))
        label = "publish-guard {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        _run_git(["stash", "push", "-m", label, "--"] + dirty, cwd=repo)
        stashed = True

    # 아직 밀지 못한 로컬 커밋이 있으면 reset --hard는 그것을 통째로 버린다. stash
    # 보호는 미커밋 변경만 지키므로 커밋한 작업은 그대로 사라졌다 — 실측(2026-09-18):
    # 대시보드 코드 커밋 3개가 발행이 돌 때마다 하나씩 날아가, 세 번째에야 화면에서
    # 기능이 사라진 것으로 발견됐다. 커밋이 남아 있으면 리셋 대신 그 위로 rebase한다.
    unpushed = _run_git(
        ["rev-list", "--count", "origin/{}..HEAD".format(branch)], cwd=repo).strip()
    if unpushed and unpushed != "0":
        print("[*] 아직 푸시하지 않은 커밋 {}개가 있어 리셋 대신 rebase합니다.".format(unpushed))
        result = _run_git_raw(["rebase", "origin/{}".format(branch)], cwd=repo)
        if result.returncode != 0:
            _run_git_raw(["rebase", "--abort"], cwd=repo)
            if stashed:
                _run_git_raw(["stash", "pop"], cwd=repo)
            raise RuntimeError(
                "로컬 커밋 {}개를 origin 위로 옮기지 못했습니다(충돌). 발행을 중단합니다 — "
                "직접 정리한 뒤 다시 실행하세요.".format(unpushed))
    else:
        _run_git(["reset", "--hard", "origin/{}".format(branch)], cwd=repo)

    if stashed:
        result = _run_git_raw(["stash", "pop"], cwd=repo)
        if result.returncode != 0:
            print("[!] 보관해 둔 변경을 되돌리지 못했습니다(충돌로 보입니다). "
                  "stash에 그대로 있으니 확인 후 직접 적용하세요: git stash list")
        else:
            print("[*] 보관했던 변경을 되돌렸습니다.")


def _write_and_commit(repo, payload, period, date_stamp, data_dir):
    """데이터 파일을 쓰고 변경사항이 있으면 커밋. 커밋했으면 True, 변경 없으면 False."""
    data_dir.mkdir(parents=True, exist_ok=True)
    latest_path = data_dir / "{}-latest.json".format(period)
    history_path = data_dir / "{}-{}.json".format(period, date_stamp)
    for path in (latest_path, history_path):
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
    _rebuild_search_index_from_events(repo)
    live_news.write_snapshot(data_dir / "latest-news.json")
    _rebuild_issue_history(data_dir)
    calendar_path = data_dir / "calendar-events.json"
    with calendar_path.open("w", encoding="utf-8") as file:
        json.dump(event_calendar.from_collected_events(), file, ensure_ascii=False,
                  separators=(",", ":"))

    # Archive errors must not replace the last reviewed edition or stop news delivery.
    try:
        incident_archive.publish(data_dir)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("[!] 사고 아카이브 발행 보류: {}".format(error))
    try:
        added = incident_archive.discover()
        if added:
            print("[*] 사고 아카이브 검토 후보 {}건 추가".format(added))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("[!] 사고 아카이브 후보 수집 보류: {}".format(error))

    _run_git(["add", "dashboard/data"], cwd=repo)
    if not _has_staged_changes("dashboard/data", cwd=repo):
        return False
    _run_git(["commit", "-m", "Update {} report ({})".format(period, date_stamp)], cwd=repo)
    return True


def publish(payload, repo_path=None):
    """payload(generate_report.build_dashboard_payload 결과)를 로컬 clone에 쓰고 커밋·푸시.

    다른 환경에서 이미 발행했거나 원격 쪽만 갱신된 경우 로컬 클론이 뒤처져 push가
    거부될 수 있다 — 매 시도 전 원격 HEAD로 강제 동기화 후 다시 쓰고 커밋·푸시하는
    과정을 최대 PUBLISH_RETRIES번 반복해 race를 흡수한다.

    성공하면 True, 발행을 건너뛰었거나 실패하면 False — 어느 쪽이든 예외는 던지지 않는다.
    """
    repo = Path(repo_path or REPO_PATH) if (repo_path or REPO_PATH) else None
    if not repo:
        print("[*] WEB_DASHBOARD_REPO_PATH가 설정되지 않아 대시보드 발행을 건너뜁니다.")
        return False
    if not repo.exists():
        print("[-] WEB_DASHBOARD_REPO_PATH 경로가 없습니다: {}".format(repo))
        return False
    if not _validate_publish_repo(repo):
        return False

    period = payload.get("period") or "daily"
    date_stamp = (payload.get("generated_at") or "")[:10] or "unknown"
    data_dir = repo / "dashboard" / "data"

    try:
        with repo_lock(repo):
            branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).strip()

            last_error = None
            for attempt in range(1, PUBLISH_RETRIES + 1):
                try:
                    _sync_to_remote_head(repo, branch)

                    if not _write_and_commit(repo, payload, period, date_stamp, data_dir):
                        print("[*] 변경사항 없음 — 커밋 생략")
                        return True

                    _run_git(["push", "origin", branch], cwd=repo)
                    print("[+] {} 리포트를 boannews_vercel에 발행했습니다({})".format(period, date_stamp))
                    return True
                except Exception as error:
                    last_error = error
                    if attempt < PUBLISH_RETRIES:
                        print("[-] 발행 시도 {}/{} 실패({}) — {}초 대기 후 원격과 재동기화하여 재시도".format(
                            attempt, PUBLISH_RETRIES, error, PUBLISH_RETRY_DELAY_SECONDS
                        ))
                        time.sleep(PUBLISH_RETRY_DELAY_SECONDS)

            print("[-] 웹 대시보드 발행 실패(리포트 발송 자체에는 영향 없음): {}".format(last_error))
            return False
    except Exception as error:
        print("[-] 웹 대시보드 발행 실패(잠금/브랜치 확인 불가): {}".format(error))
        return False
