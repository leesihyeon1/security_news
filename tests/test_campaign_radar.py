import json
from datetime import datetime, timedelta, timezone

import pytest

import campaign_radar as radar


NOW = datetime(2026, 10, 1, 8, tzinfo=timezone.utc)


def event(identifier="one", **overrides):
    value = {
        "id": identifier, "url": "https://www.microsoft.com/security/" + identifier,
        "source": "microsoft_security", "title": "ExampleRat used in targeted operations",
        "summary": "Researchers observed ExampleRat in targeted intrusions.",
        "malware_family": "ExampleRat", "threat_actor": "", "category": "악성코드",
        "body_chars": 2400, "novelty": "new", "exploitation_status": "active",
        "attack_techniques": ["T1059"], "iocs": [{"type": "domain", "value": "bad.example"}],
        "fetched_at": "2026-09-28T10:00:00Z", "pirs": ["private-pir"],
        "triage": {"level": "P2"},
    }
    value.update(overrides)
    return value


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.queue = []

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def get(self, key):
        return self.values.get(key)

    def delete(self, key):
        self.values.pop(key, None)

    def lrange(self, key, start, stop):
        return self.queue[:]

    def rpush(self, key, value):
        self.queue.append(value)

    def llen(self, key):
        return len(self.queue)

    def lpop(self, key):
        return self.queue.pop(0) if self.queue else None


@pytest.fixture
def client(monkeypatch, tmp_path):
    client = FakeRedis()
    monkeypatch.setattr(radar, "_queue_client", lambda: client)
    monkeypatch.setattr(radar, "QUEUE_STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(radar, "_known_cache", set())
    return client


def row(ref="ref-one", names=None, eligible=True):
    return {
        "names": names or ["ExampleRat"],
        "assessment": {"auto_eligible": eligible, "auto_reason": "reason"},
        "items": [{"ref": ref, "url": "https://www.microsoft.com/security/" + ref,
                   "title": "ExampleRat observed", "category": "악성코드",
                   "source_label": "Microsoft", "body_available": True, "research_source": True}],
    }


def test_primary_report_separates_malware_from_campaign():
    result = radar.assess_evidence([event()], ["ExampleRat"])
    assert result["kind"] == "malware"
    assert result["activity"] == "reported"
    assert result["auto_eligible"] is True
    assert result["novelty_label"] == "신규 캠페인 여부 미확인"


def test_secondary_ai_claim_is_not_primary_attack_confirmation():
    e = event(url="https://news.example/1", summary="ExampleRat malware report")
    e["ai_summary"] = "실제 공격에 사용됨"
    result = radar.assess_evidence([e], ["ExampleRat"])
    assert result["activity"] == "unknown"
    assert result["auto_eligible"] is False


@pytest.mark.parametrize("negative", [
    "We do not have confirmation of in-the-wild deployment.",
    "현재까지 실제 환경에서의 배포는 관측되지 않았으나 연구를 계속한다.",
])
def test_unconfirmed_deployment_blocks_auto_analysis(negative):
    result = radar.assess_evidence([event(summary=negative)], ["ExampleRat"])
    assert result["activity"] == "unconfirmed"
    assert result["auto_eligible"] is False


def test_conflicting_evidence_remains_visible_and_is_held():
    result = radar.assess_evidence([
        event(), event("two", summary="No evidence of in-the-wild deployment.")
    ], ["ExampleRat"])
    assert result["activity"] == "conflicting"
    assert len(result["evidence"]) == 2
    assert result["auto_eligible"] is False


def test_thin_body_and_technical_evidence_gate_auto_analysis():
    assert not radar.assess_evidence([event(body_chars=90)], ["ExampleRat"])["auto_eligible"]
    assert not radar.assess_evidence([event(iocs=[], attack_techniques=[])], ["ExampleRat"])["auto_eligible"]


def test_research_host_spoof_is_not_primary():
    assert not radar.research_source(event(url="https://microsoft.com.example/1"))
    assert not radar.research_source(event(url="https://[invalid"))
    assert not radar.usable_body(event(body_chars="unknown"))


def test_primary_is_representative_and_iocs_are_deduplicated(monkeypatch):
    monkeypatch.setattr(radar, "_known_cache", {"examplerat"})
    primary = event()
    secondary = event("two", source="darkreading", url="https://www.darkreading.com/2", body_chars=92)
    rows = radar._build_rows([{"names": ["ExampleRat"], "first": "2026-09-28",
                              "events": {"two": secondary, "one": primary}}])
    assert len(rows) == 1  # A known actor's new developments must not disappear.
    assert rows[0]["items"][0]["source_label"] == "Microsoft Security Blog"
    assert rows[0]["ioc_count"] == 1


def test_story_groups_do_not_merge_through_bridge():
    ab = [event(str(i), malware_family="AlphaRat, BetaRat") for i in range(2)]
    bc = [event(str(i), malware_family="BetaRat, CharlieRat") for i in range(2, 4)]
    groups = radar._merge_by_story({
        "alpharat": {"name": "AlphaRat", "events": ab, "first": "2026-09-28"},
        "betarat": {"name": "BetaRat", "events": ab + bc, "first": "2026-09-28"},
        "charlierat": {"name": "CharlieRat", "events": bc, "first": "2026-09-28"},
    })
    assert len(groups) == 2
    assert not any({"AlphaRat", "CharlieRat"}.issubset(g["names"]) for g in groups)


def test_old_name_update_is_retained_and_corpus_date_uses_supplied_file(tmp_path, monkeypatch):
    monkeypatch.setattr(radar, "_known_cache", {"examplerat"})
    path = tmp_path / "events.jsonl"
    entries = [event("old", fetched_at="2026-07-01T00:00:00Z"), event("new", novelty="update"),
               event("other", source="other", url="https://other.example/2", novelty="update")]
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    rows = radar.detect(path, now=NOW.replace(tzinfo=None))
    assert len(rows) == 1
    assert rows[0]["first_seen"] == "2026-07-01"
    assert rows[0]["corpus_start"] == "2026-07-01"


def test_legacy_queued_marker_does_not_block_retry_forever(client):
    radar.QUEUE_STATE_FILE.write_text(json.dumps({"queued": ["examplerat"]}), encoding="utf-8")
    candidate = row()
    assert radar.queue_deep_analysis([candidate], now=NOW) == 1
    job = json.loads(client.queue[0])
    assert job["source_label"] == "Microsoft"
    assert job["category"] == "악성코드"
    assert candidate["auto_analysis"]["status"] == "queued"


def test_completed_related_article_prevents_new_representative_reanalysis(client):
    candidate = row("new")
    candidate["items"].append(row("old")["items"][0])
    client.set("analysis:old", json.dumps({"analysis": "report", "partial": False}))
    assert radar.queue_deep_analysis([candidate], now=NOW) == 0
    assert candidate["analysis_ref"] == "old"
    assert candidate["auto_analysis"]["status"] == "completed"


@pytest.mark.parametrize("cache", [{"analysis": "partial", "partial": True},
                                    {"analysis": "[원문 수집 실패]"}])
def test_partial_or_failure_cache_is_not_success(client, cache):
    client.set("analysis:ref-one", json.dumps(cache))
    candidate = row()
    radar.queue_deep_analysis([candidate], now=NOW)
    assert candidate["auto_analysis"]["status"] != "completed"


def test_existing_manual_queue_and_running_job_are_not_duplicated(client):
    client.queue.append(json.dumps({"ref": "pending"}))
    client.set(radar.STATUS_PREFIX + "running", json.dumps({"status": "running", "updated_at": NOW.isoformat()}))
    candidates = [row("pending"), row("running")]
    assert radar.queue_deep_analysis(candidates, now=NOW) == 0
    assert [r["auto_analysis"]["status"] for r in candidates] == ["queued", "running"]


def test_failure_retry_has_cooldown_and_limit_despite_added_names(client):
    assert radar.queue_deep_analysis([row()], now=NOW) == 1
    client.queue.clear()
    client.set(radar.STATUS_PREFIX + "ref-one", json.dumps({"status": "failed"}))
    assert radar.queue_deep_analysis([row(names=["ExampleRat", "AnotherRat"])], now=NOW + timedelta(hours=1)) == 0
    assert radar.queue_deep_analysis([row()], now=NOW + timedelta(days=1, seconds=1)) == 1
    client.queue.clear()
    candidate = row()
    assert radar.queue_deep_analysis([candidate], now=NOW + timedelta(days=3)) == 0
    assert candidate["auto_analysis"]["status"] == "failed"


def test_daily_budget_is_shared_across_report_runs(client):
    assert radar.queue_deep_analysis([row(str(i), ["Rat" + str(i)]) for i in range(4)], now=NOW) == 3
    client.queue.clear()
    assert radar.queue_deep_analysis([row("next", ["OtherRat"])], now=NOW) == 0
    assert radar.queue_deep_analysis([row("next", ["OtherRat"])], now=NOW + timedelta(days=1)) == 1


def test_backlog_and_unconfirmed_candidates_are_held(client):
    client.queue = [json.dumps({"ref": str(i)}) for i in range(radar.MAX_QUEUE_DEPTH)]
    assert radar.queue_deep_analysis([row()], now=NOW) == 0
    client.queue.clear()
    assert radar.queue_deep_analysis([row(eligible=False)], now=NOW) == 0


def test_worker_status_is_written_without_breaking_analysis(client):
    radar.mark_analysis_status(client, {"ref": "one"}, "failed")
    assert json.loads(client.get(radar.STATUS_PREFIX + "one"))["status"] == "failed"


@pytest.mark.parametrize("record,stored,expected", [
    (None, True, "failed"),
    ({"title": "failure", "collection_failed": True}, True, "failed"),
    ({"title": "success"}, False, "failed"),
    ({"title": "success"}, True, "completed"),
])
def test_worker_records_terminal_outcomes(client, monkeypatch, record, stored, expected):
    import analysis_worker

    monkeypatch.setattr(analysis_worker, "get_client", lambda: client)
    monkeypatch.setattr(analysis_worker, "process_summary_job", lambda c: False)
    monkeypatch.setattr(analysis_worker, "analyze_one", lambda job: record)
    def store(c, result):
        if not stored:
            raise RuntimeError("unavailable")
    monkeypatch.setattr(analysis_worker, "store_result", store)
    client.queue.append(json.dumps({"ref": "one", "title": "one"}))
    analysis_worker._run_once()
    assert json.loads(client.get(radar.STATUS_PREFIX + "one"))["status"] == expected


def test_public_row_does_not_include_internal_context():
    public = radar.public_row({"names": ["ExampleRat"], "pirs": ["private-pir"],
                               "assets": ["private-asset"], "summary": "report"})
    assert "pirs" not in public
    assert "assets" not in public


def test_refresh_only_changes_existing_campaigns():
    from refresh_campaign_evidence import refresh_payload

    e = event()
    payload = {"generated_at": "2026-09-30T00:00:00Z", "narrative": "original summary",
               "period_label": "original period", "campaigns": [
                   {"names": ["ExampleRat"], "first_seen": "2026-09-28",
                    "items": [{"ref": radar.common_utils.event_ref(e["id"])}]}]}
    result = refresh_payload(payload, {radar.common_utils.event_ref(e["id"]): e})
    assert result["narrative"] == "original summary"
    assert result["period_label"] == "original period"
    assert result["campaigns"][0]["assessment"]["kind"] == "malware"


def test_recollection_does_not_reset_first_seen(tmp_path):
    path = tmp_path / "events.jsonl"
    entries = [event("same", fetched_at="2026-07-01T00:00:00Z"),
               event("same", novelty="update"),
               event("other", source="other", url="https://other.example/2", novelty="update"),
               event("future", fetched_at="2027-01-01T00:00:00Z", malware_family="FutureRat", title="FutureRat")]
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    rows = radar.detect(path, now=NOW)
    assert len(rows) == 1
    assert rows[0]["first_seen"] == "2026-07-01"
    assert len(rows[0]["items"]) == 2


def test_informational_article_does_not_seed_a_campaign(tmp_path):
    path = tmp_path / "events.jsonl"
    entries = [event("a", category="제품행사"), event("b", category="기술동향", source="other")]
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    assert radar.detect(path, now=NOW) == []
