"""슬랙 알림 메시지의 👍/👎 반응을 피드백 라벨로 수집하는 폴러.

알림 메시지에는 rss_collector가 `ref:<10자리 해시>`를 심어둔다. 이 스크립트는
채널 히스토리에서 반응이 달린 메시지를 찾아 ref를 이벤트로 역매핑하고
👍 → useful, 👎 → noise 라벨을 data/feedback.jsonl에 기록한다.

주의: 메시지 하나에 기사 여러 건이 담긴 경우 반응은 그 메시지의 모든 기사에
적용된다. 기사별로 다르게 평가하려면 feedback.py CLI를 사용한다.

필요 설정(.env):
    SLACK_BOT_TOKEN=xoxb-...        # channels:history, reactions:read 권한
    SLACK_FEEDBACK_CHANNELS=C012345 # 쉼표 구분 채널 ID. 봇이 채널에 초대되어 있어야 함

사용법:
    python slack_feedback_poller.py            # 최근 7일 폴링
    python slack_feedback_poller.py --days 3
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

import requests

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
CHANNELS = [c.strip() for c in os.environ.get("SLACK_FEEDBACK_CHANNELS", "").split(",") if c.strip()]
REF_RE = re.compile(r"ref:([0-9a-f]{10})")
USEFUL_REACTIONS = {"+1", "thumbsup"}
NOISE_REACTIONS = {"-1", "thumbsdown"}
MAX_PAGES = 5
RECENT_LINES = 5000


def slack_api(method, params):
    resp = requests.get(
        "https://slack.com/api/{}".format(method),
        headers={"Authorization": "Bearer {}".format(BOT_TOKEN)},
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError("Slack API {} 실패: {}".format(method, data.get("error")))
    return data


def build_ref_map():
    """최근 이벤트의 ref 해시 → 이벤트 ID 매핑"""
    if not common_utils.EVENTS_FILE.exists():
        return {}
    with common_utils.EVENTS_FILE.open("r", encoding="utf-8") as file:
        lines = file.readlines()[-RECENT_LINES:]
    ref_map = {}
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("id"):
            ref_map[common_utils.event_ref(event["id"])] = event["id"]
    return ref_map


def message_verdict(message):
    """메시지 반응을 useful/noise/None으로 판정 (둘 다 있으면 무시)"""
    names = {reaction.get("name", "").split("::")[0] for reaction in message.get("reactions") or []}
    useful = bool(names & USEFUL_REACTIONS)
    noise = bool(names & NOISE_REACTIONS)
    if useful == noise:
        return None
    return "useful" if useful else "noise"


def poll_channel(channel, oldest_ts, ref_map, existing):
    records = []
    cursor = None
    for _ in range(MAX_PAGES):
        params = {"channel": channel, "oldest": oldest_ts, "limit": 200}
        if cursor:
            params["cursor"] = cursor
        data = slack_api("conversations.history", params)

        for message in data.get("messages") or []:
            verdict = message_verdict(message)
            if not verdict:
                continue
            refs = set(REF_RE.findall(json.dumps(message, ensure_ascii=False)))
            for ref in refs:
                event_id = ref_map.get(ref)
                if not event_id:
                    continue
                if (existing.get(event_id) or {}).get("label") == verdict:
                    continue  # 이미 같은 라벨
                records.append({
                    "event_id": event_id,
                    "label": verdict,
                    "labeled_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                    "via": "slack",
                })
                print("[+] {} ← {} (채널 {})".format(verdict, event_id[:60], channel))

        cursor = ((data.get("response_metadata") or {}).get("next_cursor") or "").strip()
        if not cursor:
            break
    return records


def main():
    parser = argparse.ArgumentParser(description="슬랙 반응 → 피드백 라벨 폴러")
    parser.add_argument("--days", type=int, default=7, help="며칠 전까지 폴링할지 (기본 7)")
    args = parser.parse_args()

    if not BOT_TOKEN or not CHANNELS:
        print("[-] SLACK_BOT_TOKEN / SLACK_FEEDBACK_CHANNELS가 설정되지 않아 건너뜁니다.")
        print("    Slack App에 channels:history, reactions:read 권한을 주고 봇을 채널에 초대하세요.")
        return

    ref_map = build_ref_map()
    if not ref_map:
        print("[-] events.jsonl에 이벤트가 없어 역매핑할 수 없습니다.")
        return

    existing = common_utils.load_feedback()
    oldest_ts = str(time.time() - args.days * 86400)

    all_records = []
    for channel in CHANNELS:
        try:
            all_records.extend(poll_channel(channel, oldest_ts, ref_map, existing))
        except Exception as error:
            print("[-] 채널 {} 폴링 실패: {}".format(channel, error))

    if all_records:
        common_utils.append_feedback(all_records)
    print("[*] 신규 라벨 {}건 수집 (누적 {}건)".format(
        len(all_records), len(common_utils.load_feedback())
    ))


if __name__ == "__main__":
    main()
