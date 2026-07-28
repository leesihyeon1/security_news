"""피드백 라벨로 중요도 가중치를 학습해 data/learned_weights.json을 생성한다.

feedback.py(또는 슬랙 폴러)가 기록한 useful/noise 라벨과 events.jsonl의 신호를
연결해 로지스틱 회귀(순수 파이썬, L2 정규화, 샘플 가중치 적용)를 학습한다. 결과
파일이 존재하면 score_importance()가 규칙 기반 대신 '유용 확률 x100'을 점수로
사용하고, 삭제(--reset)하면 규칙 기반으로 즉시 복귀한다.

라벨마다 confidence_weight()로 학습 반영 비중을 다르게 준다 — 클릭(via=click)은
"읽고 싶어서 눌렀다"는 약한 신호일 뿐이라, 슬랙 반응·수동 라벨(명시적 판단, 가중치
1.0)보다 낮게(기본 0.4, click_count가 쌓이면 최대 0.8까지) 반영한다.

라벨이 총 30건 + 클래스별 10건 미만이면 과적합 위험으로 학습을 거부한다.

사용법:
    python train_weights.py              # 학습 후 저장
    python train_weights.py --dry-run    # 가중치 출력만
    python train_weights.py --reset      # 학습 파일 삭제 (규칙 기반 복귀)
"""

import argparse
import json
import math
import os
import sys
from datetime import datetime, timedelta

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

MIN_TOTAL_LABELS = 30
MIN_CLASS_LABELS = 10
EPOCHS = 3000
LEARNING_RATE = 0.1
L2 = 0.01

REMINDER_COOLDOWN_DAYS = 3  # 라벨 부족 알림 최소 간격 — 매일 밤 도는 배치라 이게 없으면 매일 스팸됨
REMINDER_STATE_FILE = common_utils.STATE_DIR / "feedback_reminder_state.json"


def maybe_remind_slack(total, useful, noise):
    """라벨이 아직 부족할 때 슬랙으로 능동 알림 — 로그 파일에만 찍히면 아무도 안 봄.
    쿨다운 동안은 조용히 넘어가고, 학습 가능해지면(충분해지면) 더 이상 호출 안 됨."""
    state = common_utils.load_json_state(REMINDER_STATE_FILE, lambda: {})
    last = state.get("last_reminded_at")
    if last:
        try:
            last_dt = datetime.fromisoformat(str(last).replace("Z", "+00:00")).replace(tzinfo=None)
        except (TypeError, ValueError):
            last_dt = None
        if last_dt and datetime.utcnow() - last_dt < timedelta(days=REMINDER_COOLDOWN_DAYS):
            return

    need_useful = max(0, MIN_CLASS_LABELS - useful)
    need_noise = max(0, MIN_CLASS_LABELS - noise)
    class_note = ", useful {}건/noise {}건 부족".format(need_useful, need_noise) if (need_useful or need_noise) else ""
    text = (
        "\U0001F3F7️ *피드백 라벨링 부족* — 현재 {}건(useful {} / noise {}), "
        "학습에는 총 30건 + 클래스별 10건 필요{}\n"
        "> `python scripts\\feedback.py --list` 로 최근 알림 확인 후 --useful/--noise로 라벨링해주세요."
    ).format(total, useful, noise, class_note)

    webhook_url = os.environ.get("SLACK_WEBHOOK_REPORT") or common_utils.SLACK_WEBHOOK_URL
    if common_utils.send_slack_webhook({"text": text}, webhook_url):
        state["last_reminded_at"] = common_utils.utc_now_iso()
        common_utils.save_json_state(REMINDER_STATE_FILE, state)


confidence_weight = common_utils.feedback_confidence_weight


def features_from_event(event):
    """저장된 이벤트에서 score_importance와 동일한 특징 벡터를 복원"""
    triage = event.get("triage") or {}
    return common_utils.importance_features(
        exploitation=event.get("exploitation_status") or triage.get("exploitation") or "none",
        asset_matched=bool(event.get("matched_assets")),
        impact=triage.get("impact") or "",
        severity=event.get("severity"),
        relevance=event.get("relevance"),
        category=event.get("category"),
        has_cve=bool(event.get("cves")),
        has_actor=bool(event.get("threat_actor") or event.get("malware_family")),
        reliability=(event.get("importance") or {}).get("reliability") or "",
        pir_ids=event.get("pirs") or (),
        confidence=event.get("confidence") or "",
    )


def load_dataset():
    labels = common_utils.load_feedback()
    if not common_utils.EVENTS_FILE.exists():
        return [], labels
    events = {}
    with common_utils.EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("id") in labels:
                events[event["id"]] = event

    dataset = []
    for event_id, record in labels.items():
        event = events.get(event_id)
        if event is None:
            continue
        dataset.append((
            features_from_event(event),
            1 if record["label"] == "useful" else 0,
            confidence_weight(record),
        ))
    return dataset, labels


def train(dataset, feature_names):
    weights = {name: 0.0 for name in feature_names}
    bias = 0.0
    total_weight = sum(sample_weight for _, _, sample_weight in dataset) or 1.0
    for _ in range(EPOCHS):
        grad_w = {name: 0.0 for name in feature_names}
        grad_b = 0.0
        for features, y, sample_weight in dataset:
            z = bias + sum(weights[name] * features.get(name, 0) for name in feature_names)
            error = ((1.0 / (1.0 + math.exp(-z))) - y) * sample_weight
            grad_b += error
            for name in feature_names:
                if features.get(name):
                    grad_w[name] += error
        bias -= LEARNING_RATE * grad_b / total_weight
        for name in feature_names:
            weights[name] -= LEARNING_RATE * (grad_w[name] / total_weight + L2 * weights[name])
    return weights, bias


def accuracy(dataset, weights, bias):
    correct = 0
    for features, y, _ in dataset:
        z = bias + sum(weights[name] * features.get(name, 0) for name in weights)
        correct += int((z >= 0) == (y == 1))
    return correct / len(dataset)


def main():
    parser = argparse.ArgumentParser(description="피드백 라벨로 중요도 가중치 학습")
    parser.add_argument("--dry-run", action="store_true", help="저장하지 않고 결과만 출력")
    parser.add_argument("--reset", action="store_true", help="학습 파일 삭제 후 규칙 기반 복귀")
    args = parser.parse_args()

    if args.reset:
        if common_utils.LEARNED_WEIGHTS_FILE.exists():
            common_utils.LEARNED_WEIGHTS_FILE.unlink()
            print("[+] {} 삭제 — 규칙 기반 스코어링으로 복귀".format(common_utils.LEARNED_WEIGHTS_FILE))
        else:
            print("[*] 학습 파일이 없습니다 (이미 규칙 기반).")
        return

    dataset, labels = load_dataset()
    useful = sum(1 for _, y, _ in dataset if y == 1)
    noise = len(dataset) - useful
    print("[*] 라벨 {}건 중 이벤트 매칭 {}건 (useful {} / noise {})".format(
        len(labels), len(dataset), useful, noise
    ))
    if len(dataset) < MIN_TOTAL_LABELS or min(useful, noise) < MIN_CLASS_LABELS:
        print("[-] 학습 최소치 미달 (총 {}건, 클래스별 {}건 필요). 라벨을 더 모아주세요.".format(
            MIN_TOTAL_LABELS, MIN_CLASS_LABELS
        ))
        if not args.dry_run:
            maybe_remind_slack(len(dataset), useful, noise)
        sys.exit(1)

    feature_names = list(common_utils.IMPORTANCE_FEATURE_LABELS)
    weights, bias = train(dataset, feature_names)
    acc = accuracy(dataset, weights, bias)

    print("[*] 학습 완료 — 훈련 정확도 {:.0%}, bias {:+.2f}".format(acc, bias))
    print("[*] 특징별 가중치 (양수=유용 방향, 절대값 클수록 영향 큼):")
    for name, weight in sorted(weights.items(), key=lambda kv: -abs(kv[1])):
        if abs(weight) >= 0.01:
            print("    {:+.2f}  {}".format(weight, common_utils.IMPORTANCE_FEATURE_LABELS[name]))

    if args.dry_run:
        print("[*] dry-run — 저장 생략")
        return

    payload = {
        "bias": round(bias, 4),
        "weights": {name: round(weight, 4) for name, weight in weights.items()},
        "samples": len(dataset),
        "class_counts": {"useful": useful, "noise": noise},
        "train_accuracy": round(acc, 3),
        "trained_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }
    common_utils.LEARNED_WEIGHTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with common_utils.LEARNED_WEIGHTS_FILE.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2, sort_keys=True)
    print("[+] 저장: {} — 다음 수집부터 학습 모델이 점수를 계산합니다.".format(common_utils.LEARNED_WEIGHTS_FILE))
    print("    되돌리기: python train_weights.py --reset")


if __name__ == "__main__":
    main()
