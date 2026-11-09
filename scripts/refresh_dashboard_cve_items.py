"""이미 게시된 대시보드 JSON에 "수집된 CVE" 목록(cve_items)만 채워 넣는다.

각 파일의 data_status에 적힌 기간을 그대로 써서 events.jsonl에서 목록을 다시 만든다 —
다른 필드(총평·카드·통계)는 건드리지 않는다. 모델을 부르지 않고 게시(커밋·푸시)도
하지 않는다. 사용: python scripts/refresh_dashboard_cve_items.py ../boannews_vercel_deploy
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import generate_report as report


def _parse(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)


def refresh_file(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    status = payload.get("data_status") or {}
    if not (status.get("period_start") and status.get("period_end")):
        return None
    events = report.load_events_between(_parse(status["period_start"]), _parse(status["period_end"]))
    payload["cve_items"] = report.build_cve_items(events, report.correlate_by_cve(events))
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(payload["cve_items"])


def refresh(repo):
    """latest 파일과, 그와 같은 기간의 날짜별 사본을 채운다."""
    data_dir = Path(repo) / "dashboard" / "data"
    done = {}
    for period in ("daily", "weekly"):
        latest = data_dir / "{}-latest.json".format(period)
        period_of = lambda path: (json.loads(path.read_text(encoding="utf-8")).get("data_status") or {}).get("period_end")
        target_end = period_of(latest)
        for path in [latest] + sorted(data_dir.glob("{}-2*.json".format(period))):
            if path == latest or period_of(path) == target_end:
                count = refresh_file(path)
                if count is not None:
                    done[path.name] = count
    return done


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    for name, count in refresh(parser.parse_args().repo).items():
        print("{}: 수집된 CVE {}건".format(name, count))
