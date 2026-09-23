"""Apply the reviewed correction to one insight and its cache, with CAS and backup."""

import argparse
from copy import deepcopy
import json
from pathlib import Path

import analysis_worker
import common_utils


FIXTURE = Path(__file__).with_name("corrections") / "threat_report_2026_09_21.json"


def corrected_record(record, correction, reviewed_at):
    if record.get("ref") != correction["ref"] or "21st September" not in record.get("title", ""):
        raise ValueError("Unexpected insight; no update performed")
    result = deepcopy(record)
    source = correction["source_url"]
    result.update(analysis=correction["analysis"], links=correction["links"], iocs=[],
                  url=source, reviewed_at=reviewed_at, correction_revision=correction["revision"])
    result["attack_techniques"] = analysis_worker.extract_mitre(result["analysis"])
    result["attack_grouped"] = analysis_worker.build_attack_groups(result["analysis"])
    result["glossary"] = analysis_worker.extract_glossary(result["analysis"])
    result["targets"] = {
        "urls": [], "domains": [], "cves": ["CVE-2026-91843", "CVE-2026-76460", "CVE-2026-76461", "CVE-2026-77692"],
        "objective": "독립 사건별 원문 근거와 미확인 항목을 구분하고 사내 적용 여부를 점검합니다.",
        "investigable": True,
        "gaps": ["사내 자산·로그 대조", "사건별 실제 악성 IOC와 샘플", "벤더별 최신 영향·수정판 확인"],
    }
    synthesis = {
        "verdict": "부분 확인",
        "headline": "종합 기사의 독립 사건을 분리해 원문 기준으로 정정했습니다. 사내 피해와 사건별 악성 IOC는 미확인입니다.",
        "confirmed": [
            "원문 확인: GhostCode는 정상 디바이스 인증 흐름을 악용하며 비밀번호 탈취나 MFA 직접 우회로 설명되지 않습니다.",
            "원문 확인: Telegram C2는 HEAVYGRAM 설명입니다. WaterPlum의 Run 키·예약 작업·횡적 이동은 이 기사에 없습니다.",
            "출처 확인: research.checkpoint.com의 해당 URL은 기사 출처이며 차단 지표가 아닙니다.",
        ],
        "unconfirmed": [
            "사내 감염·정보 유출·노출 자산: 내부 로그와 자산 대조를 수행하지 않았습니다.",
            "사건별 공격 URL·C2·해시: 기사에 명시된 악성 IOC가 없어 차단 목록을 생성하지 않았습니다.",
            "이전 urlscan 결과는 같은 호스트의 다른 기사(MonikerLink)이며 이번 사건의 스크립트 유무를 입증하지 못합니다.",
            "이전 KEV·EPSS·NVD 조회는 이번 정정에서 재조회하지 않았습니다. 기존 기록의 9월 17일·19일 기한은 검토일 9월 22일 기준 이미 경과했으며 임박한 기한이 아닙니다.",
            "낮은 EPSS와 KEV 미등재는 안전의 증거가 아닙니다. 외부 조회의 무결과도 기사 주장의 반증이 아닙니다.",
        ],
        "contradictions": [], "plan": correction["plan"], "followups": [],
        "open_questions": result["targets"]["gaps"],
        "exposure": {
            "who": "관련 장비·Brevo 구성요소·Microsoft 365를 사용하는 자산과 계정이 점검 대상입니다. 실제 사용·피해는 미확인입니다.",
            "basis": "기사의 영향 대상에 근거한 조건부 판단입니다. 사내 환경에서 확인된 사실이 아닙니다.",
            "confirm": "제품·버전·외부 노출과 인증·기기 등록·실행 로그를 사건별로 대조합니다.",
        },
        "timeline": [{"when": "2025-12 ~ 2026-07", "what": "WaterPlum의 지갑 관련 자금·자격 증명 탈취 기간으로 원문에 명시됩니다.", "source": source},
                     {"when": "2023년부터", "what": "HEAVYGRAM 활동 시점으로 원문에 명시됩니다.", "source": source}],
    }
    result["investigation"] = {
        "route": {"primary": "", "label": "종합 보고서 - 사건별 근거 검토",
                  "explain": "단일 악성코드 분석이 아닌 여러 사건의 종합 기사입니다. 원문 보도와 사내 검증을 구분합니다.",
                  "tracks": [], "scores": {}},
        "source_urls": [source], "seeds": [], "patterns": [], "findings": [],
        "primary": {"sources": [{"url": source, "host": "research.checkpoint.com"}]},
        "steps": [{"track": "원문 정정", "text": "기사 본문과 인용 링크를 대조해 사건 혼합·MFA 설명·ATT&CK 오매핑을 정정했습니다."},
                  {"track": "산출물 검토", "text": "출처 URL 차단과 근거 부족 쿼리를 철회했습니다. 이전 조회 원본은 별도 백업에 보존하며 외부 조회를 새로 수행한 것으로 표시하지 않습니다."}],
        "steps_summary": "원문 대조 정정 완료. 근거가 불충분한 기존 차단·헌팅 산출물은 철회했습니다.",
        "gaps": result["targets"]["gaps"], "synthesis": synthesis,
        "response": dict(correction.get("display_response") or {},
                         kql=[], commands=[], generated_at=reviewed_at),
        "action_plan": [dict(step, source="원문 대조 검토") for step in correction["plan"]],
        "generated_at": reviewed_at,
    }
    return result


def repair(client, correction, apply=False):
    from redis.exceptions import WatchError

    list_key = analysis_worker.INSIGHTS_LIST_KEY
    cache_key = "analysis:" + correction["ref"]
    backup_key = "analysis:correction-backup:" + correction["ref"] + ":" + correction["revision"]
    with client.pipeline() as pipe:
        pipe.watch(list_key, cache_key)
        matches = []
        for index, raw in enumerate(pipe.lrange(list_key, 0, -1)):
            try:
                record = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if record.get("ref") == correction["ref"]:
                matches.append((index, raw, record))
        if len(matches) != 1:
            raise ValueError("Expected exactly one insight; no update performed")
        index, original, record = matches[0]
        if record.get("correction_revision") == correction["revision"]:
            return {"status": "already_corrected", "ref": correction["ref"]}
        reviewed_at = common_utils.utc_now_iso()
        updated = corrected_record(record, correction, reviewed_at)
        previous_cache = pipe.get(cache_key)
        ttl = pipe.ttl(cache_key)
        cached = {key: updated.get(key) for key in (
            "analysis", "links", "iocs", "category", "attack_techniques", "glossary",
            "attack_grouped", "investigation", "targets", "reviewed_at", "correction_revision")}
        cached["partial"] = False
        if not apply:
            return {"status": "dry_run", "ref": correction["ref"],
                    "techniques": updated["attack_techniques"], "links": len(updated["links"])}
        pipe.multi()
        pipe.set(backup_key, json.dumps({"insight": original, "cache": previous_cache,
                                        "reviewed_at": reviewed_at}, ensure_ascii=False),
                 nx=True, ex=analysis_worker.ANALYSIS_CACHE_TTL_SECONDS)
        pipe.lset(list_key, index, json.dumps(updated, ensure_ascii=False))
        pipe.set(cache_key, json.dumps(cached, ensure_ascii=False),
                 ex=ttl if ttl > 0 else analysis_worker.ANALYSIS_CACHE_TTL_SECONDS)
        try:
            pipe.execute()
        except WatchError as error:
            raise RuntimeError("Insight changed concurrently; no update performed. Review before retrying.") from error
    return {"status": "updated", "ref": correction["ref"], "reviewed_at": reviewed_at,
            "backup_key": backup_key}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Update the reviewed insight and cache")
    args = parser.parse_args()
    client = analysis_worker.get_client()
    if client is None:
        raise SystemExit("Redis unavailable; no changes made")
    correction = json.loads(FIXTURE.read_text(encoding="utf-8"))
    print(json.dumps(repair(client, correction, apply=args.apply), ensure_ascii=False))


if __name__ == "__main__":
    main()
