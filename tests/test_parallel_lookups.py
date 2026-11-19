"""조회 트랙을 동시에 돌려도 결과 기록은 예전과 같은지 확인한다."""
import threading
import time

import analysis_trace
import investigation


def _lookup(key, run):
    return {"key": key, "label": key + " 조회", "consumes": key, "run": run,
            "merge": investigation._merge_named(key)}


def _slow(key, seconds, active, peak):
    def run(ctx):
        with lock:
            active.append(key)
            peak[0] = max(peak[0], len(active))
        time.sleep(seconds)
        with lock:
            active.remove(key)
        return {"findings": [key + " 관측"], "steps": [key + " 완료"]}
    return run


lock = threading.Lock()


def _run(monkeypatch, lookups, tracks):
    monkeypatch.setattr(investigation, "LOOKUPS", tuple(lookups))
    block, steps = {}, []
    ctx = {"route": {"tracks": tracks}, "block": block}
    with analysis_trace.session() as trace:
        with analysis_trace.span("사건별 조사 실행", "investigation"):
            investigation.run_lookups(ctx, block, steps)
    return block, steps, trace


def test_independent_tracks_run_together_and_merge_in_plan_order(monkeypatch):
    active, peak = [], [0]
    lookups = [_lookup(key, _slow(key, 0.3, active, peak)) for key in ("malware", "intel", "vulnerability")]
    started = time.monotonic()
    block, steps, trace = _run(monkeypatch, lookups, ["vulnerability", "malware", "intel"])
    assert time.monotonic() - started < 0.8          # 차례로 돌면 0.9초 이상
    assert peak[0] == 3
    assert [row["key"] for row in block["lookup_status"]] == ["vulnerability", "malware", "intel"]
    assert [step["text"] for step in steps] == ["vulnerability 완료", "malware 완료", "intel 완료"]
    assert all(row["status"] == "returned" for row in block["lookup_status"])
    # 스레드에서 연 실행 기록도 남고, 번호가 겹치지 않으며, 상위 단계에 연결된다.
    lookups_seen = [row for row in trace.events if row["kind"] == "lookup"]
    assert len(lookups_seen) == 3
    assert len({row["id"] for row in trace.events}) == len(trace.events)
    parent = next(row["id"] for row in trace.events if row["label"] == "사건별 조사 실행")
    assert all(row.get("parent_id") == parent for row in lookups_seen)


def test_web_search_waits_for_intel_references(monkeypatch):
    seen = {}

    def intel(ctx):
        time.sleep(0.1)
        return {"references": [{"name": "GSocket"}], "steps": []}

    def web(ctx):
        seen["intel"] = (ctx["block"].get("intel") or {}).get("references")
        return {"findings": [], "steps": []}

    lookups = [_lookup("intel", intel), _lookup("web", web)]
    _run(monkeypatch, lookups, ["web", "intel"])
    assert seen["intel"] == [{"name": "GSocket"}]


def test_one_failing_track_does_not_hide_the_others(monkeypatch):
    def broken(ctx):
        raise TimeoutError("OTX")

    lookups = [_lookup("intel", broken),
               _lookup("malware", lambda ctx: {"files": [], "steps": ["VT 완료"]})]
    block, steps, _ = _run(monkeypatch, lookups, ["intel", "malware"])
    states = {row["key"]: row["status"] for row in block["lookup_status"]}
    assert states == {"intel": "failed", "malware": "returned"}
    assert "malware" in block and "intel" not in block


def test_single_worker_setting_runs_tracks_one_by_one(monkeypatch):
    active, peak = [], [0]
    monkeypatch.setattr(investigation, "LOOKUP_WORKERS", 1)
    lookups = [_lookup(key, _slow(key, 0.05, active, peak)) for key in ("malware", "intel")]
    _run(monkeypatch, lookups, ["malware", "intel"])
    assert peak[0] == 1
