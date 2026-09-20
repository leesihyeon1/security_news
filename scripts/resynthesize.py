# -*- coding: utf-8 -*-
"""조사는 끝났는데 판단만 없는 기록에 판단을 다시 붙인다.

왜 필요한가
    조사와 판단은 한 회차 안에서 이어 돌지만 실패하는 방식이 다르다. 조사는 조회가
    몇 개 실패해도 나머지로 굴러간다 — 실패한 조회는 "결과 없음"도 판단 재료다.
    판단은 LLM 한 번이라 그 한 번이 타임아웃 나면 아무것도 안 남는다.

    실측(2026-09-18): 그날 분석한 6건 중 2건이 그렇게 끝났다. DPRK APT 건은 조사
    53단계·확인된 사실 44건·차단 후보 55건·헌팅 쿼리 9개까지 다 만들어 놓고
    판단만 비었고, Chosen Brick 건도 42단계까지 돌고 같은 자리에서 멈췄다. 둘 다
    NVIDIA read timeout이었다.

    그런데 고칠 방법이 재분석뿐이었다 — 멀쩡한 조사 53단계를 처음부터 다시 돌리느라
    15~20분과 조회 한도를 쓴다. 조회 결과는 기록에 다 들어 있으니 판단만 다시
    받으면 되는데 그 경로가 없었다.

어떻게 쓰나
    python scripts/resynthesize.py --list          판단이 빈 기록을 보여준다
    python scripts/resynthesize.py --all           그 기록들을 모두 고친다
    python scripts/resynthesize.py "제목 일부"      한 건만 고친다

무엇을 건드리나
    synthesis·action_plan과 조사 과정에 남길 줄만 새로 쓴다. 조사 결과(seeds·malware·
    intel·response·patterns)는 그대로 둔다 — 그건 그때 실제로 조회한 것이고, 지금
    다시 조회하면 다른 답이 나올 수도 있어서 판단만 바꿔 끼우는 것이 맞다.
"""

import argparse
import json
import os
import sys

import common_utils
import investigation
import output_critic
import past_analyses
import primary_sources
import response_synth

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

INSIGHTS_LIST_KEY = "insights:list"


def log(message):
    print(message)


def _client():
    url = os.environ.get("REDIS_URL", "")
    if not url:
        log("[-] REDIS_URL이 없습니다.")
        return None
    try:
        import redis
    except ImportError:
        log("[-] redis 패키지가 없습니다.")
        return None
    client = redis.from_url(url, decode_responses=True,
                            socket_connect_timeout=10, socket_timeout=30)
    client.ping()
    return client


def _needs_verdict(record):
    block = record.get("investigation") or {}
    if not block.get("steps"):
        return False       # 조사 자체가 안 돈 기록은 여기서 고칠 것이 없다
    return not (block.get("synthesis") or {}).get("verdict")


def rebuild(record):
    """한 기록의 판단을 다시 받는다. 성공하면 True."""
    block = record.get("investigation") or {}
    targets = record.get("targets") or {}
    title = record.get("title") or ""

    # 그때 읽은 1차 자료를 판단 재료로 다시 넣는다. 주소는 기록에 남아 있으므로
    # 그 글만 다시 받아 온다 — 조회 한도를 쓰는 외부 조회는 다시 돌리지 않는다.
    evidence = ""
    urls = [{"url": source.get("url")} for source
            in (block.get("primary") or {}).get("sources") or [] if source.get("url")]
    if urls:
        try:
            again = primary_sources.collect(urls, article_url=record.get("url") or "")
            evidence = primary_sources.as_evidence(again.get("sources"))
        except Exception as error:
            log("    [-] 1차 자료를 다시 읽지 못했습니다: {}".format(str(error)[:70]))

    history = ""
    try:
        history = past_analyses.as_evidence(
            past_analyses.find_related(targets, exclude_title=title))
    except Exception:
        history = ""

    verdict = response_synth.synthesize(
        title, record.get("analysis") or "", targets, block,
        primary=evidence, history=history)
    if not verdict:
        return False

    block["synthesis"] = verdict
    try:
        spared = output_critic.review(verdict, block.get("response"), block)
        if spared and output_critic.apply(block.get("response"), spared):
            block["steps"] = (block.get("steps") or []) + [
                {"track": "산출물 검토", "text": line}
                for line in output_critic.steps(spared)]
    except Exception as error:
        log("    [-] 산출물 검토 실패(판단에는 영향 없음): {}".format(str(error)[:70]))
    block["action_plan"] = investigation.merge_actions(verdict, block.get("response"))
    block["steps"] = (block.get("steps") or []) + [
        {"track": "종합 판단", "text": line} for line in verdict.get("steps") or []]
    record["investigation"] = block
    record["resynthesized_at"] = common_utils.utc_now_iso() \
        if hasattr(common_utils, "utc_now_iso") else ""
    return True


def main():
    parser = argparse.ArgumentParser(description="판단이 빈 분석 기록에 판단만 다시 붙인다")
    parser.add_argument("title", nargs="?", default="", help="제목 일부(한 건만 고칠 때)")
    parser.add_argument("--list", action="store_true", help="판단이 빈 기록만 보여준다")
    parser.add_argument("--all", action="store_true", help="판단이 빈 기록을 모두 고친다")
    args = parser.parse_args()

    client = _client()
    if client is None:
        return 1
    rows = client.lrange(INSIGHTS_LIST_KEY, 0, -1)
    records = []
    for index, raw in enumerate(rows):
        try:
            records.append((index, json.loads(raw)))
        except (ValueError, TypeError):
            continue

    broken = [(i, r) for i, r in records if _needs_verdict(r)]
    if args.list or not (args.all or args.title):
        log("판단이 비어 있는 기록 {}건".format(len(broken)))
        for _, record in broken:
            block = record["investigation"]
            log("  · {}  (조사 {}단계 · 확인된 사실 {}건 · {})".format(
                (record.get("title") or "")[:52], len(block.get("steps") or []),
                len(block.get("findings") or []),
                (record.get("analyzed_at") or "")[:16]))
        return 0

    if args.title:
        wanted = args.title.lower()
        targets = [(i, r) for i, r in records
                   if wanted in (r.get("title") or "").lower()]
        if not targets:
            log("[-] 제목에 \"{}\"가 들어간 기록이 없습니다.".format(args.title))
            return 1
    else:
        targets = broken

    fixed = 0
    for index, record in targets:
        log("[*] 판단 다시 받는 중: {}".format((record.get("title") or "")[:56]))
        try:
            ok = rebuild(record)
        except Exception as error:
            log("[-] 실패: {}".format(str(error)[:120]))
            continue
        if not ok:
            log("[-] 판단을 받지 못했습니다 — 기록은 그대로 둡니다.")
            continue
        client.lset(INSIGHTS_LIST_KEY, index, json.dumps(record, ensure_ascii=False))
        block = record["investigation"]
        log("[+] 저장 완료: 판단 {} · 할 일 {}건 · 시간축 {}건".format(
            (block.get("synthesis") or {}).get("verdict") or "?",
            len(block.get("action_plan") or []),
            len((block.get("synthesis") or {}).get("timeline") or [])))
        fixed += 1
    log("[+] {}건 중 {}건 복구".format(len(targets), fixed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
