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
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

REPO_PATH = os.environ.get("WEB_DASHBOARD_REPO_PATH", "")
SEARCH_INDEX_FILE = "search-index.json"
SEARCH_INDEX_RETENTION_DAYS = 365
EXPECTED_REMOTE_REPO = "leesihyeon1/boannews_vercel"


def _run_git(args, cwd):
    result = subprocess.run(
        ["git"] + args, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError("git {} 실패: {}".format(" ".join(args), result.stderr.strip()))
    return result.stdout


def _has_staged_changes(pathspec, cwd):
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet", "--", pathspec],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
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
        print("[-] 대시보드 원격 저장소가 예상과 다릅니다: {}".format(remote_url))
        return False
    return True


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
            "title": event.get("title") or "",
            "url": common_utils.tracking_url(event.get("id"), url) or url,
            "source_label": common_utils.source_label(source),
            "category": event.get("category") or "",
            "level": (event.get("triage") or {}).get("level") or "",
            "summary": (event.get("ai_summary") or event.get("summary") or "")[:200],
        }

    entries = sorted(by_key.values(), key=lambda e: e.get("date") or "", reverse=True)

    index_path = repo / "dashboard" / "data" / SEARCH_INDEX_FILE
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("w", encoding="utf-8") as file:
        json.dump(entries, file, ensure_ascii=False, indent=2)


PUBLISH_RETRIES = 3
PUBLISH_RETRY_DELAY_SECONDS = 5
LOCK_TIMEOUT_SECONDS = 120
LOCK_POLL_INTERVAL_SECONDS = 2
LOCK_FILE_NAME = ".dashboard_publish.lock"


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


def _sync_to_remote_head(repo, branch):
    """로컬 클론을 원격 HEAD에 강제로 맞춘다.

    이 클론은 generate_report.py가 실행마다 새로 만들어내는 데이터 전용이라
    로컬에만 있는 지켜야 할 변경사항이 없다는 전제다 — 이전 실행이 실패해 남긴
    미푸시 커밋이나, 다른 환경에서 origin이 앞서나가 생긴 어긋남을 여기서 정리한다.
    이렇게 안 하면 오래된 로컬 상태 위에 커밋해봐야 push가 매번 거부된다.
    """
    _run_git(["fetch", "origin", branch], cwd=repo)
    _run_git(["reset", "--hard", "origin/{}".format(branch)], cwd=repo)


def _write_and_commit(repo, payload, period, date_stamp, data_dir):
    """데이터 파일을 쓰고 변경사항이 있으면 커밋. 커밋했으면 True, 변경 없으면 False."""
    data_dir.mkdir(parents=True, exist_ok=True)
    latest_path = data_dir / "{}-latest.json".format(period)
    history_path = data_dir / "{}-{}.json".format(period, date_stamp)
    for path in (latest_path, history_path):
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
    _rebuild_search_index_from_events(repo)

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
