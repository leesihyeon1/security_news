"""CISA KEV 사후 등재를 근거로 한 자동 useful 라벨링.

알림·추천된 이벤트의 CVE가 나중에 CISA KEV(실제 악용 확인 목록)에 등재되면,
"이 정보가 실제로 중요했다"는 사람 판단과 무관한 객관적 증거다. 이런 경우
자동으로 useful 라벨을 남긴다.

이 자동화는 useful 쪽에만 적용한다 — "나중에도 KEV에 안 올라감"은 noise였다는
증거로 쓰기엔 너무 약하다(조용히 묻힌 진짜 좋은 정보일 수도 있음). noise는
여전히 사람이 명시적으로 판단해야 한다(feedback.py / 슬랙 반응).

이미 라벨(수동이든 자동이든)이 있는 이벤트는 건드리지 않는다.

사용법:
    python scripts/kev_feedback_labeler.py
    python scripts/kev_feedback_labeler.py --dry-run
"""

import argparse
import json
import sys

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


def load_kev_cve_first_seen(events_file=None):
    """CISA KEV로 수집된 이벤트에서 CVE -> 최초 관측 시각(fetched_at, ISO8601) 맵을 만든다."""
    path = events_file or common_utils.EVENTS_FILE
    kev_first_seen = {}
    if not path.exists():
        return kev_first_seen
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("source") != "cisa_kev":
                continue
            fetched = event.get("fetched_at") or ""
            if not fetched:
                continue
            for cve in event.get("cves") or []:
                cve = str(cve).upper()
                if cve and (cve not in kev_first_seen or fetched < kev_first_seen[cve]):
                    kev_first_seen[cve] = fetched
    return kev_first_seen


def find_auto_useful_candidates(kev_first_seen, existing_labels, events_file=None):
    """자기 관측 시점 '이후'에 CVE가 KEV 등재된(=사후 확인된) 미라벨 이벤트를 찾는다."""
    path = events_file or common_utils.EVENTS_FILE
    candidates = []
    if not path.exists():
        return candidates
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("source") == "cisa_kev":
                continue  # KEV 카탈로그 자기 자신은 대상 아님
            event_id = event.get("id")
            if not event_id or event_id in existing_labels:
                continue  # 이미 라벨(수동/자동 불문) 있으면 건드리지 않음
            fetched = event.get("fetched_at") or ""
            for cve in event.get("cves") or []:
                kev_seen_at = kev_first_seen.get(str(cve).upper())
                if kev_seen_at and kev_seen_at > fetched:
                    candidates.append((event, str(cve).upper(), kev_seen_at))
                    break
    return candidates


def main():
    parser = argparse.ArgumentParser(description="CISA KEV 등재 기반 사후 자동 useful 라벨링")
    parser.add_argument("--dry-run", action="store_true", help="라벨 저장 없이 대상만 출력")
    args = parser.parse_args()

    existing_labels = common_utils.load_feedback()
    kev_first_seen = load_kev_cve_first_seen()
    candidates = find_auto_useful_candidates(kev_first_seen, existing_labels)

    if not candidates:
        print("[*] 사후 KEV 등재로 자동 라벨링할 대상이 없습니다.")
        return

    print("[*] 자동 useful 라벨링 대상 {}건".format(len(candidates)))
    records = []
    for event, cve, kev_seen_at in candidates:
        print("  {} [{}] {} — {} KEV 등재 확인({})".format(
            common_utils.event_ref(event["id"]), event.get("source"),
            (event.get("title") or "")[:60], cve, kev_seen_at[:10],
        ))
        records.append({
            "event_id": event["id"],
            "label": "useful",
            "labeled_at": common_utils.utc_now_iso(),
            "via": "auto_kev",
            "evidence": "{} KEV 등재 확인({})".format(cve, kev_seen_at[:10]),
        })

    if args.dry_run:
        print("[*] dry-run — 저장 생략")
        return

    common_utils.append_feedback(records)
    print("[+] {}건 자동 라벨링 완료".format(len(records)))


if __name__ == "__main__":
    main()
