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
import response_builder
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


def prepare(record, rebuild=False):
    if rebuild:
        result = analysis_worker.analyze_one({key: record.get(key) for key in
                                             ("ref", "title", "url", "source_label")})
        if not result or result.get("collection_failed"):
            raise ValueError("Article rebuild failed; record unchanged")
        result["workflow_reviewed_at"] = common_utils.utc_now_iso()
        return dashboard_text.redact_private_environment(result, common_utils.inventory_product_terms())
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
    source_urls = list(dict.fromkeys([source] + [s["url"] for s in sources.get("sources") or []]))
    block["source_urls"] = source_urls
    primary_text = " ".join(s.get("text") or "" for s in sources.get("sources") or [])
    documents = [{"url": source, "text": body}] + (sources.get("sources") or [])
    existing_iocs = list(result.get("iocs") or [])
    fresh_iocs = common_utils.extract_iocs(primary_text, limit=200) if primary_text else []
    seen = {str(item.get("value") or "").lower() for item in existing_iocs
            if isinstance(item, dict)}
    merged_iocs = existing_iocs + [item for item in fresh_iocs
                                   if str(item.get("value") or "").lower() not in seen]
    merged_iocs, _ = source_evidence.filter_iocs(merged_iocs, source_urls)
    assessed = source_evidence.assess_iocs(merged_iocs, documents)
    actionable_iocs = source_evidence.lookup_iocs(assessed)
    targets = source_evidence.restrict_targets(targets, assessed)
    for item in actionable_iocs:
        if item.get("type") in ("md5", "sha1", "sha256"):
            targets.setdefault("hashes", [])
            if item["value"] not in targets["hashes"]:
                targets["hashes"].append(item["value"])
    result["iocs"] = source_evidence.display_iocs(assessed)
    block["indicator_assessments"] = assessed
    block["targets"] = targets
    route = investigation.classify(
        actionable_iocs, text=result.get("analysis") or "", title=result.get("title") or "",
        category=result.get("category") or "", targets=targets,
        raw_body=body + "\n" + primary_text,
        pinned=(block.get("route") or {}).get("primary") or "")
    block["route"] = {key: route[key] for key in
                       ("primary", "label", "explain", "tracks", "scores")}
    block["lookup_status"] = [{"key": key, "status": "historical",
                               "detail": "기존 조회 결과 재사용; 이번에 재조회하지 않음",
                               "completed_at": block.get("generated_at") or record.get("analyzed_at")}
                              for key in (block.get("route") or {}).get("tracks") or []]
    block["lookup_status"].extend(sources.get("attempts") or [])
    vuln = block.get("vulnerability") or {}
    if vuln.get("cves"):
        vuln["findings"] = [line for entry in vuln["cves"] for line in vuln_hunter._findings_for_cve(entry)]
    response = response_builder.build(block, actionable_iocs,
                                      primary=route.get("primary") or "",
                                      text=result.get("analysis") or "")
    analyst_workflow.prepare_queries(response)
    block["response"] = response
    verdict = response_synth.synthesize(record.get("title") or "", record.get("analysis") or "",
                                        targets, block, article=body,
                                        primary=primary_sources.as_evidence(sources.get("sources")))
    if not verdict:
        raise ValueError("No usable revised verdict; record unchanged")
    proposed = verdict.pop("followups", [])
    verdict["pending_followups"] = proposed
    verdict["followups"] = []
    block["synthesis"] = verdict
    block["action_plan"] = investigation.merge_actions(verdict, response)
    block["steps"] = (block.get("steps") or []) + [
        {"track": "IOC 재평가", "text": "1차 자료에서 지표 {}건을 다시 읽고 역할을 판정했습니다. 정찰 대상·메타데이터 주소는 차단 후보에서 제외하고 해시 {}건은 헌팅 재료로 보존했습니다.".format(
            len(assessed), sum(1 for item in actionable_iocs if item.get("type") in ("md5", "sha1", "sha256")))},
        {"track": "판단 갱신", "text": "원문을 다시 읽고 실행 조건·증거 보존·대안을 보완했습니다. 외부 인텔 조회는 기존 시점의 결과입니다."}]
    block["steps"].extend({"track": "원문 확인", "text": s} for s in sources.get("steps") or [])
    block["steps_summary"] = investigation.summarize(block)
    analyst_workflow.finalize(block, targets)
    result["investigation"] = dashboard_text.redact_private_environment(block, common_utils.inventory_product_terms())
    result["targets"] = targets
    result["workflow_reviewed_at"] = common_utils.utc_now_iso()
    return result


def attach_question_paths(record, mapping):
    """Attach reviewed links to lookups already recorded for this article."""
    result = deepcopy(record)
    block = result.get("investigation") or {}
    if result.get("ref") != mapping.get("ref") or not block:
        raise ValueError("Question path mapping does not match an investigated record")
    questions = set((block.get("targets") or result.get("targets") or {}).get("questions") or [])
    executed = {row.get("key") for row in block.get("lookup_status") or []
                if row.get("status") in ("returned", "partial", "failed", "unavailable")}
    allowed = {item["key"] for item in investigation.LOOKUPS} | {"primary"}
    rows = mapping.get("question_lookups") or []
    if not questions or len(rows) != len(questions):
        raise ValueError("Every original question needs one reviewed path")
    seen = set()
    for row in rows:
        question = row.get("question")
        if question not in questions or question in seen:
            raise ValueError("Question must exactly match one original question")
        seen.add(question)
        for lookup in row.get("lookups") or []:
            if lookup.get("key") not in allowed or lookup.get("key") not in executed:
                raise ValueError("Cannot link a lookup that was not executed")
            if not str(lookup.get("why") or "").strip():
                raise ValueError("Each historical lookup needs a reviewed reason")
        row["source"] = "historical"
    block["question_lookups"] = rows
    result["investigation"] = dashboard_text.redact_private_environment(
        block, common_utils.inventory_product_terms())
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
    parser.add_argument("--rebuild", action="store_true", help="Rebuild this article's analysis and investigation before review")
    parser.add_argument("--question-paths", type=Path,
                        help="Attach reviewed question-to-lookup links from an existing analysis")
    args = parser.parse_args()
    client = analysis_worker.get_client()
    if client is None:
        raise SystemExit("Redis unavailable")
    if args.apply:
        print(json.dumps(apply_prepared(client, json.loads(args.apply.read_text(encoding="utf-8"))), ensure_ascii=False))
        return
    if not args.output:
        parser.error("--ref requires --output")
    if args.rebuild and args.question_paths:
        parser.error("--rebuild and --question-paths cannot be combined")
    _, raw, record = locate(client.lrange(analysis_worker.INSIGHTS_LIST_KEY, 0, -1), args.ref)
    updated = (attach_question_paths(record, json.loads(args.question_paths.read_text(encoding="utf-8")))
               if args.question_paths else prepare(record, rebuild=args.rebuild))
    artifact = {"ref": args.ref, "expected_sha256": digest(raw), "record": updated}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"prepared": args.ref, "quality": updated["investigation"]["quality"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
