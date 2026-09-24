"""Prepare one revised verdict, then apply that reviewed artifact with backup and CAS."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import analysis_worker
import analyst_workflow
import common_utils
import dashboard_text
import investigation
import primary_sources
import response_synth
import source_evidence
import vuln_hunter


def digest(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def locate(rows, ref):
    matches = []
    for index, raw in enumerate(rows):
        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if record.get("ref") == ref:
            matches.append((index, raw, record))
    if len(matches) != 1:
        raise ValueError("Expected one record for requested ref")
    return matches[0]


def prepare(record):
    result = deepcopy(record)
    block = result.get("investigation") or {}
    if not block or record.get("collection_failed"):
        raise ValueError("No collected investigation to revise")
    body, _ = analysis_worker.fetch_article_text(record.get("url"))
    if len(body) < analysis_worker.BODY_MIN_CHARS or (len(body) < analysis_worker.BLOCKED_PAGE_MAX_CHARS
                                                    and analysis_worker.BLOCKED_PAGE_RE.search(body)):
        raise ValueError("Cannot verify the source article; record unchanged")
    source = source_evidence.article_url(record.get("url"))
    targets = result.get("targets") or {}
    old_sources = (block.get("primary") or {}).get("sources") or []
    sources = primary_sources.collect(old_sources, article_url=source, limit=2)
    block["primary"] = {"sources": [{k: s.get(k) for k in ("url", "host", "chars", "retrieved_at")}
                                     for s in sources.get("sources") or []]}
    block["source_urls"] = [source] + [s["url"] for s in sources.get("sources") or []]
    block["lookup_status"] = [{"key": key, "status": "historical",
                               "detail": "기존 조회 결과 재사용; 이번에 재조회하지 않음",
                               "completed_at": block.get("generated_at") or record.get("analyzed_at")}
                              for key in (block.get("route") or {}).get("tracks") or []]
    block["lookup_status"].extend(sources.get("attempts") or [])
    vuln = block.get("vulnerability") or {}
    if vuln.get("cves"):
        vuln["findings"] = [line for entry in vuln["cves"] for line in vuln_hunter._findings_for_cve(entry)]
    response = block.get("response") or {}
    analyst_workflow.prepare_queries(response)
    block["response"] = response
    verdict = response_synth.synthesize(record.get("title") or "", record.get("analysis") or "",
                                        targets, block, article=body,
                                        primary=primary_sources.as_evidence(sources.get("sources")), timeout=180)
    if not verdict:
        raise ValueError("No usable revised verdict; record unchanged")
    proposed = verdict.pop("followups", [])
    verdict["pending_followups"] = proposed
    verdict["followups"] = []
    block["synthesis"] = verdict
    block["action_plan"] = investigation.merge_actions(verdict, response)
    block["steps"] = (block.get("steps") or []) + [
        {"track": "판단 갱신", "text": "원문을 다시 읽고 실행 조건·증거 보존·대안을 보완했습니다. 외부 인텔 조회는 기존 시점의 결과입니다."}]
    block["steps"].extend({"track": "원문 확인", "text": s} for s in sources.get("steps") or [])
    analyst_workflow.finalize(block, targets)
    result["investigation"] = dashboard_text.redact_private_environment(block, common_utils.inventory_product_terms())
    result["workflow_reviewed_at"] = common_utils.utc_now_iso()
    return result


def apply_prepared(client, artifact):
    ref = artifact["ref"]
    key = "analysis:" + ref
    updated = artifact["record"]
    if updated.get("ref") != ref:
        raise ValueError("Prepared record ref mismatch")
    with client.pipeline() as pipe:
        pipe.watch(analysis_worker.INSIGHTS_LIST_KEY, key)
        index, raw, _ = locate(pipe.lrange(analysis_worker.INSIGHTS_LIST_KEY, 0, -1), ref)
        if digest(raw) != artifact["expected_sha256"]:
            raise ValueError("Record changed since preparation; review the newer record")
        old_cache, ttl = pipe.get(key), pipe.ttl(key)
        try:
            cached = json.loads(old_cache) if old_cache else {}
        except (ValueError, TypeError):
            cached = {}
        if not isinstance(cached, dict):
            cached = {}
        cached.update({k: updated.get(k) for k in ("analysis", "links", "iocs", "category", "attack_techniques",
                       "glossary", "attack_grouped", "investigation", "targets", "workflow_reviewed_at")})
        cached["partial"] = False
        backup = "analysis:workflow-backup:" + ref + ":" + artifact["expected_sha256"][:16]
        pipe.multi()
        pipe.set(backup, json.dumps({"insight": raw, "cache": old_cache}, ensure_ascii=False),
                 nx=True, ex=analysis_worker.ANALYSIS_CACHE_TTL_SECONDS)
        pipe.lset(analysis_worker.INSIGHTS_LIST_KEY, index, json.dumps(updated, ensure_ascii=False))
        pipe.set(key, json.dumps(cached, ensure_ascii=False), ex=ttl if ttl > 0 else analysis_worker.ANALYSIS_CACHE_TTL_SECONDS)
        pipe.execute()
    return {"updated": ref, "backup_key": backup, "quality": updated["investigation"]["quality"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--ref")
    modes.add_argument("--apply", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    client = analysis_worker.get_client()
    if client is None:
        raise SystemExit("Redis unavailable")
    if args.apply:
        print(json.dumps(apply_prepared(client, json.loads(args.apply.read_text(encoding="utf-8"))), ensure_ascii=False))
        return
    if not args.output:
        parser.error("--ref requires --output")
    _, raw, record = locate(client.lrange(analysis_worker.INSIGHTS_LIST_KEY, 0, -1), args.ref)
    updated = prepare(record)
    artifact = {"ref": args.ref, "expected_sha256": digest(raw), "record": updated}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"prepared": args.ref, "quality": updated["investigation"]["quality"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
