"""알림 유용성 피드백 라벨링 CLI.

받아본 알림이 유용했는지(useful) 노이즈였는지(noise)를 기록한다.
라벨은 data/feedback.jsonl에 쌓이고, train_weights.py가 이를 학습해
중요도 스코어링 가중치를 사용자 판단에 맞게 조정한다.

사용법:
    python feedback.py --list            # 최근 알림된 이벤트 목록 (ref와 제목)
    python feedback.py --list-all        # 알림 안 된 것 포함 전체
    python feedback.py --useful a1b2c3d4e5 --useful thehackernews
    python feedback.py --noise f6e5d4c3b2
    python feedback.py --stats

ref는 --list가 보여주는 10자리 해시, 이벤트 ID 전체, 또는 ID에 포함된
부분 문자열(제목 아님) 아무거나 쓸 수 있다. 유일하게 매칭되어야 한다.
"""

import argparse
import json
import sys
from datetime import datetime

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

RECENT_LINES = 3000


def load_recent_events():
    """events.jsonl 뒤쪽 이벤트를 최신순으로 반환 (id 기준 중복 제거).

    파일 끝에서부터 거슬러 읽어 RECENT_LINES줄만 훑는다 — 로그 전체 크기와
    무관하게 읽는 양이 고정된다.
    """
    events = {}
    count = 0
    for line in common_utils.iter_lines_reverse(common_utils.EVENTS_FILE):
        line = line.strip()
        if not line:
            continue
        count += 1
        if count > RECENT_LINES:
            break
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("id") and event["id"] not in events:
            events[event["id"]] = event  # 역순 순회라 처음 만나는 게 최신 버전
    return list(events.values())


def was_alerted(event):
    delivery = event.get("delivery") or {}
    return bool(delivery.get("email_sent") or delivery.get("slack_sent"))


def resolve(token, events):
    """ref 해시 / 전체 ID / ID 부분 문자열로 이벤트를 유일하게 찾는다"""
    matches = [
        event for event in events
        if token == common_utils.event_ref(event["id"]) or token == event["id"] or token in event["id"]
    ]
    unique_ids = {event["id"] for event in matches}
    if len(unique_ids) == 1:
        return matches[0], None
    if not matches:
        return None, "'{}'와 일치하는 이벤트가 없습니다. --list로 확인하세요.".format(token)
    candidates = "\n".join(
        "    {} {}".format(common_utils.event_ref(event["id"]), event.get("title", "")[:60])
        for event in matches[:5]
    )
    return None, "'{}'가 {}건과 일치합니다. ref 해시로 지정하세요:\n{}".format(token, len(unique_ids), candidates)


def print_events(events, labels, alerted_only=True, limit=30):
    shown = 0
    for event in events:
        if alerted_only and not was_alerted(event):
            continue
        label = (labels.get(event["id"]) or {}).get("label")
        mark = {"useful": "👍", "noise": "👎"}.get(label, "  ")
        print("{} {}  [{}] {}".format(
            mark, common_utils.event_ref(event["id"]), event.get("source"), (event.get("title") or "")[:70]
        ))
        if event.get("category"):
            reason = event.get("category_reason")
            print("      └ {}{}".format(event["category"], ": {}".format(reason) if reason else ""))
        review = event.get("analyst_review")
        if review:
            score = lambda key: review.get(key) if review.get(key) is not None else "-"
            detail = (review.get("reasoning") or {}).get("technical_detail")
            print("      └ rubric 기술{}·실행{}·신뢰{}{}".format(
                score("technical_substance"), score("actionability"), score("credibility"),
                ": {}".format(detail) if detail else "",
            ))
        shown += 1
        if shown >= limit:
            break
    if not shown:
        print("표시할 이벤트가 없습니다.")


def add_labels(tokens, label, events):
    records = []
    for token in tokens:
        event, error = resolve(token, events)
        if error:
            print("[-] {}".format(error))
            continue
        records.append({
            "event_id": event["id"],
            "label": label,
            "labeled_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "via": "cli",
        })
        print("[+] {} ← {} ({})".format(label, (event.get("title") or "")[:60], common_utils.event_ref(event["id"])))
    common_utils.append_feedback(records)
    return len(records)


def main():
    parser = argparse.ArgumentParser(description="알림 유용성 피드백 라벨링")
    parser.add_argument("--useful", action="append", default=[], metavar="REF")
    parser.add_argument("--noise", action="append", default=[], metavar="REF")
    parser.add_argument("--list", action="store_true", help="최근 알림된 이벤트 표시")
    parser.add_argument("--list-all", action="store_true", help="알림 안 된 이벤트도 표시")
    parser.add_argument("--stats", action="store_true", help="라벨 통계")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    events = load_recent_events()
    labels = common_utils.load_feedback()

    if args.useful or args.noise:
        count = add_labels(args.useful, "useful", events) + add_labels(args.noise, "noise", events)
        labels = common_utils.load_feedback()
        print("[*] 저장 {}건 / 누적 라벨 {}건 (useful {} / noise {})".format(
            count, len(labels),
            sum(1 for r in labels.values() if r["label"] == "useful"),
            sum(1 for r in labels.values() if r["label"] == "noise"),
        ))
        return

    if args.stats:
        useful = sum(1 for r in labels.values() if r["label"] == "useful")
        noise = len(labels) - useful
        print("누적 라벨 {}건: useful {} / noise {}".format(len(labels), useful, noise))
        print("학습 권장 최소치: 총 30건, 클래스별 10건 이상 → {}".format(
            "충족 (train_weights.py 실행 가능)" if len(labels) >= 30 and min(useful, noise) >= 10 else "미충족"
        ))
        return

    print_events(events, labels, alerted_only=not args.list_all, limit=args.limit)


if __name__ == "__main__":
    main()
