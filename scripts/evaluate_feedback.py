"""피드백 라벨(useful/noise) 기반 오프라인 성능 측정.

알림(긴급 발송) 로직과 추천(읽을만한 동향 등 비알림) 로직이 실제로 사람 판단과
얼마나 맞는지, 소스·카테고리·트리아지 레벨별로 어디가 노이즈가 많은지 정량으로
보여준다. `feedback.py --stats`가 전체 useful/noise 건수만 보여주는 것과 달리,
이 스크립트는 그 라벨을 이벤트 메타데이터와 조인해 "어디가 문제인지"까지 짚어준다.

라벨이 아직 없으면(신규 프로젝트라 흔함) 안내만 출력한다 — 라벨이 쌓이기 시작하면
다음 실행부터 바로 의미 있는 결과가 나오도록 미리 만들어 둔 것이다.

사용법:
    python scripts/evaluate_feedback.py
"""

import json
import sys

import common_utils
import generate_report as gr

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

MIN_LABELS_FOR_STATS = 10  # 이 미만 표본은 비율이 통계적으로 의미가 약해 참고용으로만 표시


def load_labeled_events():
    """피드백 라벨이 붙은 이벤트만 (label, event) 쌍으로 반환. 통합 로그 + 구 로그 모두 조회."""
    labels = common_utils.load_feedback()
    if not labels:
        return []

    events_by_id = {}
    for path, legacy in ((common_utils.EVENTS_FILE, False), (gr.LEGACY_BOANNEWS_EVENTS_FILE, True)):
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = gr.normalize_legacy_boannews(raw) if legacy else raw
                if event.get("id"):
                    events_by_id[event["id"]] = event

    pairs = []
    for event_id, record in labels.items():
        event = events_by_id.get(event_id)
        if event:
            pairs.append((record["label"], event))
    return pairs


def useful_rate(pairs):
    if not pairs:
        return None
    useful = sum(1 for label, _ in pairs if label == "useful")
    return useful, len(pairs)


def print_breakdown(pairs, key_fn, section_name):
    counts = {}
    for label, event in pairs:
        bucket = counts.setdefault(key_fn(event), {"useful": 0, "noise": 0})
        bucket[label] = bucket.get(label, 0) + 1

    print()
    print("[{}별 useful 비율]".format(section_name))
    rows = sorted(counts.items(), key=lambda kv: -(kv[1].get("useful", 0) + kv[1].get("noise", 0)))
    for key, bucket in rows:
        useful, noise = bucket.get("useful", 0), bucket.get("noise", 0)
        total = useful + noise
        note = "" if total >= MIN_LABELS_FOR_STATS else " (표본 {}건 — 참고용)".format(total)
        print("  {}: {:.0%} ({}/{}){}".format(key, useful / total if total else 0, useful, total, note))


def print_alerted_noise_mismatches(pairs, limit=10):
    """알림까지 나갔는데 noise로 라벨된 사례 — 모델이 확신했는데 틀린, 가장 정보량 큰 오답.
    라벨 1건보다 이런 불일치 사례가 스코어링 개선에 훨씬 유용하다."""
    mismatches = [event for label, event in pairs if label == "noise" and gr.event_alerted(event)]
    if not mismatches:
        return

    mismatches.sort(key=gr.importance_score, reverse=True)
    print()
    print("[알림됐지만 noise로 라벨된 사례 — 우선 검토 대상 {}건]".format(len(mismatches)))
    for event in mismatches[:limit]:
        print("  {} 점수{} [{}] {}".format(
            common_utils.event_ref(event.get("id") or ""),
            gr.importance_score(event),
            gr.source_label(event.get("source")),
            (event.get("title") or "")[:70],
        ))
    if len(mismatches) > limit:
        print("  ...외 {}건".format(len(mismatches) - limit))


def main():
    pairs = load_labeled_events()
    if not pairs:
        print("피드백 라벨이 아직 없습니다.")
        print("python scripts/feedback.py --list 로 최근 알림을 확인하고 --useful/--noise로")
        print("라벨링을 시작하면, 다음 실행부터 이 스크립트가 실제 통계를 보여줍니다.")
        return

    useful, total = useful_rate(pairs)
    print("전체 라벨 {}건 — useful {:.0%} ({}/{})".format(total, useful / total, useful, total))
    if total < MIN_LABELS_FOR_STATS:
        print("(표본이 {}건 미만이라 아래 분석은 참고용입니다)".format(MIN_LABELS_FOR_STATS))

    alerted_pairs = [(label, event) for label, event in pairs if gr.event_alerted(event)]
    trend_pairs = [(label, event) for label, event in pairs if not gr.event_alerted(event)]

    print()
    print("[두 트랙 비교 — 알림 vs 추천]")
    for name, subset in (("알림(긴급 발송)", alerted_pairs), ("추천(읽을만한 동향 등 비알림)", trend_pairs)):
        result = useful_rate(subset)
        if result:
            sub_useful, sub_total = result
            print("  {}: useful {:.0%} ({}/{})".format(name, sub_useful / sub_total, sub_useful, sub_total))
        else:
            print("  {}: 라벨 없음".format(name))

    print_breakdown(pairs, lambda e: gr.source_label(e.get("source")), "소스")
    print_breakdown(pairs, lambda e: e.get("category") or "미분류", "카테고리")
    print_breakdown(pairs, lambda e: gr.event_level(e) or "P3", "트리아지 레벨")
    print_alerted_noise_mismatches(pairs)


if __name__ == "__main__":
    main()
