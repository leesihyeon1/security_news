"""3~4시간마다 최근 수집분만 훑어 "읽을만한 것"만 짧게 Slack으로 보내는 큐레이터 다이제스트.

일간/주간 리포트(generate_report.py)의 "읽을만한 동향"과 같은 로직
(generate_report.pick_trend_reads)을 재사용하지만 두 가지가 다르다:
①대상 기간이 하루/일주일이 아니라 마지막 실행 이후로 짧고, ②이미 알림이
나간 이벤트도 후보에 포함한다(include_alerted=True) — 일간 리포트에서는
알림 건이 카드·TOP N 섹션에 이미 나오니 여기(읽을만한 동향)선 제외하는 게
맞지만, 이 다이제스트는 그런 별도 섹션 없이 단독 발송되므로 "알림 여부와
무관하게 이 기간에 읽을 가치가 있는 것 전체"를 추려야 SOC 분석가가 몇
시간마다 전체를 훑어보는 것과 같은 의미가 있다.

일간/주간 리포트와는 독립적으로 동작한다 — 같은 기사가 리포트에도, 이 다이제스트에도
나올 수 있다(의도적 선택: 중복 제거 로직을 얹으면 두 실행 순서에 상태가 얽혀 복잡해짐).

새로 볼만한 게 없으면 조용히 스킵한다 — 3~4시간마다 빈 알림이 오면 그게 노이즈다.

사용법:
    python scripts/curator_digest.py
    python scripts/curator_digest.py --hours 4   # 상태 파일 무시하고 직접 기간 지정(테스트용)
    python scripts/curator_digest.py --dry-run   # 발송 없이 콘솔 출력만
"""

import argparse
import os
import sys
from datetime import datetime, timedelta

import common_utils
import generate_report as gr

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

STATE_FILE = common_utils.STATE_DIR / "curator_digest_state.json"
DEFAULT_LOOKBACK_HOURS = 4  # 상태 파일이 없을 때(최초 실행)만 사용
MAX_CURATOR_ITEMS = 3  # 일간 리포트(5건)보다 적게 — 훑는 창이 짧으니 진짜 상위만


def load_state():
    return common_utils.load_json_state(STATE_FILE, lambda: {"last_run_at": None})


def save_state(run_at):
    common_utils.save_json_state(STATE_FILE, {"last_run_at": run_at})


def build_slack_payload(picks, period_label):
    lines = ["🧭 *지난 {} 동안 수집된 기사 중 읽을만한 것*".format(period_label)]
    for idx, event in enumerate(picks, start=1):
        bits = gr.trend_bits(event)
        suffix = " ({})".format(" | ".join(bits)) if bits else ""
        lines.append(
            "{}. [{}] <{}|{}>{}".format(
                idx, gr.source_label(event.get("source")),
                common_utils.tracking_url(event.get("id"), event.get("url")) or "#",
                event.get("title") or "(제목 없음)", suffix,
            )
        )
    text = "\n".join(lines)
    return {
        "text": "읽을만한 기사 {}건".format(len(picks)),
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }


def main():
    parser = argparse.ArgumentParser(description="주기적 큐레이터 다이제스트 (읽을만한 기사만 짧게)")
    parser.add_argument("--hours", type=float, default=None, help="상태 파일 대신 직접 조회 기간(시간) 지정 — 테스트용")
    parser.add_argument("--dry-run", action="store_true", help="발송 없이 콘솔에 출력")
    args = parser.parse_args()

    now = datetime.utcnow()
    state = load_state()
    if args.hours is not None:
        since = now - timedelta(hours=args.hours)
    elif state.get("last_run_at"):
        since = gr.parse_iso(state["last_run_at"]) or (now - timedelta(hours=DEFAULT_LOOKBACK_HOURS))
    else:
        since = now - timedelta(hours=DEFAULT_LOOKBACK_HOURS)

    events = gr.load_events(since)
    if not events:
        print("[*] 조회 기간 내 수집된 이벤트가 없습니다.")
        if not args.hours:
            save_state(common_utils.utc_now_iso())
        return

    picks = gr.pick_trend_reads(events, exclude_ids=set(), max_items=MAX_CURATOR_ITEMS, include_alerted=True)
    period_label = "{:.1f}시간".format((now - since).total_seconds() / 3600)

    if not picks:
        print("[*] {} 동안 {}건 수집됐지만 읽을만한 것으로 뽑힌 게 없습니다 — 발송 생략.".format(period_label, len(events)))
        if not args.hours:
            save_state(common_utils.utc_now_iso())
        return

    payload = build_slack_payload(picks, period_label)

    if args.dry_run:
        print("===== DRY RUN: 발송 생략 =====")
        print(payload["blocks"][0]["text"]["text"])
        return

    webhook_url = (
        os.environ.get("SLACK_WEBHOOK_CURATOR")
        or os.environ.get("SLACK_WEBHOOK_REPORT")
        or common_utils.SLACK_WEBHOOK_URL
    )
    sent = common_utils.send_slack_webhook(payload, webhook_url)
    if sent:
        save_state(common_utils.utc_now_iso())
        print("[+] 큐레이터 다이제스트 발송 완료: {}건 (조회 {}건 중)".format(len(picks), len(events)))
    else:
        print("[-] 발송 실패 — 상태를 저장하지 않아 다음 실행에서 같은 기간을 다시 조회합니다.")


if __name__ == "__main__":
    main()
