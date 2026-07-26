"""boannews_vercel 정적 사이트로 일간/주간 리포트 JSON을 발행한다.

WEB_DASHBOARD_REPO_PATH(.env)가 boannews_vercel 저장소의 **로컬 클론 경로**를
가리켜야 한다. 이 저장소는 dashboard/·click-tracker/ 두 하위 프로젝트를 담고 있고,
각각 별도 Vercel 프로젝트(Root Directory 설정)로 배포된다 — 데이터는 그중
dashboard/ 쪽에 쓴다. generate_report.py가 리포트를 만든 직후 이미 계산된 데이터로
dashboard/data/<period>-latest.json(최신본)과 dashboard/data/<period>-<날짜>.json
(히스토리)을 쓰고, 그 클론에서 git add/commit/push까지 수행한다 — 새 토큰·API 연동
없이 이 기기에 이미 설정된 git 자격증명(Credential Manager)을 그대로 쓴다. 동시에
dashboard/data/search-index.json(대시보드 History 탭·검색용 누적 인덱스, 기사/CVE
카드를 평평한 목록으로 저장)도 갱신한다 — SEARCH_INDEX_RETENTION_DAYS보다 오래된
항목은 정리된다.

실패해도(경로 미설정, git 오류, push 실패 등) 예외를 절대 밖으로 던지지 않는다 —
대시보드 발행은 부가 기능이라 이것 때문에 메인 리포트 발송이 막히면 안 된다.

필요 설정(.env):
    WEB_DASHBOARD_REPO_PATH=C:\\path\\to\\local\\clone\\of\\boannews_vercel
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

REPO_PATH = os.environ.get("WEB_DASHBOARD_REPO_PATH", "")
SEARCH_INDEX_FILE = "search-index.json"
SEARCH_INDEX_RETENTION_DAYS = 365


def _run_git(args, cwd):
    result = subprocess.run(
        ["git"] + args, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError("git {} 실패: {}".format(" ".join(args), result.stderr.strip()))
    return result.stdout


def _index_entries_from_payload(payload, period, date_stamp):
    """대시보드 History 탭·검색용으로 이번 payload의 기사/CVE 카드를 평평한 목록으로 뽑는다."""
    entries = []

    def add_article(event):
        entries.append({
            "date": date_stamp,
            "period": period,
            "type": "article",
            "title": event.get("title") or "",
            "url": event.get("url") or "",
            "source_label": event.get("source_label") or event.get("source") or "",
            "category": event.get("category") or "",
            "level": event.get("level") or "",
            "summary": (event.get("summary") or "")[:200],
        })

    for region in ("domestic", "overseas"):
        bucket = payload.get(region) or {}
        for event in bucket.get("highlights") or []:
            add_article(event)
        for event in bucket.get("trend_reads") or []:
            add_article(event)

    for card in payload.get("cards") or []:
        items = card.get("items") or []
        entries.append({
            "date": date_stamp,
            "period": period,
            "type": "cve",
            "title": card.get("cve") or "",
            "url": (items[0].get("url") if items else "") or "",
            "source_label": ", ".join(card.get("sources") or []),
            "category": "CVE",
            "level": card.get("level") or "",
            "summary": (card.get("summary") or "")[:200],
        })

    return entries


def _index_dedup_key(entry):
    """기사는 URL로, CVE 카드는 제목(CVE ID)으로 동일 항목을 판별한다.

    일간 리포트가 실은 기사가 나중에 주간 롤업에도 다시 실리면(같은 기사, 다른
    period+date) 검색 결과에 두 번 뜨는 걸 막기 위한 키다.
    """
    url = entry.get("url")
    if url:
        return url
    return "{}|{}".format(entry.get("type") or "", entry.get("title") or "")


def _update_search_index(repo, payload, period, date_stamp):
    """검색 인덱스를 갱신 — 같은 (period, date) 재발행 시 그날 항목을 통째로 교체(중복 누적 방지),
    보관 기간(SEARCH_INDEX_RETENTION_DAYS)이 지난 항목은 정리하고, 같은 기사가 daily/weekly에
    걸쳐 중복 등재되면 가장 먼저(오래된 날짜) 등재된 것만 남긴다."""
    index_path = repo / "dashboard" / "data" / SEARCH_INDEX_FILE

    existing = []
    if index_path.exists():
        try:
            with index_path.open("r", encoding="utf-8") as file:
                existing = json.load(file)
        except (json.JSONDecodeError, OSError):
            existing = []

    existing = [e for e in existing if not (e.get("period") == period and e.get("date") == date_stamp)]
    existing.extend(_index_entries_from_payload(payload, period, date_stamp))

    cutoff = (datetime.utcnow() - timedelta(days=SEARCH_INDEX_RETENTION_DAYS)).strftime("%Y-%m-%d")
    existing = [e for e in existing if (e.get("date") or "") >= cutoff]

    existing.sort(key=lambda e: e.get("date") or "")  # 오래된 것부터 훑어 첫 등장(가장 이른 날짜)을 유지
    deduped = {}
    for entry in existing:
        deduped.setdefault(_index_dedup_key(entry), entry)
    existing = list(deduped.values())

    existing.sort(key=lambda e: e.get("date") or "", reverse=True)

    with index_path.open("w", encoding="utf-8") as file:
        json.dump(existing, file, ensure_ascii=False, indent=2)


def publish(payload, repo_path=None):
    """payload(generate_report.build_dashboard_payload 결과)를 로컬 clone에 쓰고 커밋·푸시.

    성공하면 True, 발행을 건너뛰었거나 실패하면 False — 어느 쪽이든 예외는 던지지 않는다.
    """
    repo = Path(repo_path or REPO_PATH) if (repo_path or REPO_PATH) else None
    if not repo:
        print("[*] WEB_DASHBOARD_REPO_PATH가 설정되지 않아 대시보드 발행을 건너뜁니다.")
        return False
    if not repo.exists():
        print("[-] WEB_DASHBOARD_REPO_PATH 경로가 없습니다: {}".format(repo))
        return False

    period = payload.get("period") or "daily"
    date_stamp = (payload.get("generated_at") or "")[:10] or "unknown"

    data_dir = repo / "dashboard" / "data"

    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        latest_path = data_dir / "{}-latest.json".format(period)
        history_path = data_dir / "{}-{}.json".format(period, date_stamp)
        for path in (latest_path, history_path):
            with path.open("w", encoding="utf-8") as file:
                json.dump(payload, file, ensure_ascii=False, indent=2)
        _update_search_index(repo, payload, period, date_stamp)

        _run_git(["add", "dashboard/data"], cwd=repo)
        status = _run_git(["status", "--porcelain"], cwd=repo)
        if not status.strip():
            print("[*] 변경사항 없음 — 커밋 생략")
            return True

        _run_git(["commit", "-m", "Update {} report ({})".format(period, date_stamp)], cwd=repo)
        _run_git(["push"], cwd=repo)
        print("[+] {} 리포트를 boannews_vercel에 발행했습니다({})".format(period, date_stamp))
        return True
    except Exception as error:
        print("[-] 웹 대시보드 발행 실패(리포트 발송 자체에는 영향 없음): {}".format(error))
        return False
