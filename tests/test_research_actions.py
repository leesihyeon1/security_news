import goal_evidence
import pattern_synth
import research_actions as ra

GPT = "https://chatgpt.com/g/g-abc123-fake-helper"
LURE = "https://sites.google.com/view/fake-verify-page"


class FakeLure:
    def __init__(self):
        self.calls = []

    def investigation_for_iocs(self, iocs, api_key=None, max_seeds=3, **kwargs):
        self.calls.append(("follow", [i["value"] for i in iocs]))
        return {"seeds": [{"domain": "sites.google.com", "target_url": LURE, "in_urlscan": True,
                           "dom_confirmed": True,
                           "http": [{"path": "/jsrepo", "query_keys": ["rnd"], "status": 200}],
                           "queries": []}]}

    def urlscan_search(self, query, size=10, api_key=None):
        self.calls.append(("search", query))
        return ([{"_id": "seed", "page": {"url": GPT}},
                 {"_id": "b1", "page": {"url": "https://chatgpt.com/g/g-other"}},
                 {"_id": "b2", "page": {"url": "https://chatgpt.com/"}}], 3)

    def resource_facts(self, uuid, host, api_key):
        return {"http": [{"path": "/backend-api/flush", "query_keys": ["lightweight_authenticated"],
                          "status": 200}]}

    def seed_facts(self, url, api_key=None, article_url=""):
        return None


def _block():
    return {
        "seeds": [{"domain": "chatgpt.com", "target_url": GPT, "in_urlscan": True,
                   "outgoing_links": ["https://chatgpt.com/auth/login", LURE],
                   "http": [{"path": "/backend-api/flush",
                             "query_keys": ["lightweight_authenticated"], "status": 200}],
                   "queries": []}],
        "research_plan": [{"id": "goal-1", "goal": "Custom GPT에서 ClickFix 유포지로 연결되는가?"},
                          {"id": "goal-2", "goal": "RAT 샘플의 C2 통신은?"}],
        "goal_evidence": [
            {"question": "Custom GPT에서 ClickFix 유포지로 연결되는가?", "status": "partial",
             "missing": "개별 콘텐츠 응답에서 외부 유인 페이지로 이어지는 링크·전환, 정상 비교군의 오탐 검증"},
            {"question": "RAT 샘플의 C2 통신은?", "status": "partial",
             "missing": "샘플의 네트워크 목적지·요청"},
        ],
        "malware": {"files": [{"hash": "a" * 64}]},
    }


def test_missing_evidence_drives_distinct_actions():
    actions = [a["action"] for a in ra.plan_actions(_block())]
    assert actions == ["follow_links", "platform_baseline", "more_samples"]


def test_execute_follows_external_link_builds_baseline_and_queries_new_hashes():
    block, lure = _block(), FakeLure()
    hashes_run = []
    iocs = [{"type": "sha256", "value": "a" * 64}, {"type": "sha256", "value": "b" * 64}]

    def run_hash(values):
        hashes_run.extend(values)
        return ["{} 샌드박스 통신 관측".format(v[:8]) for v in values]

    lines, steps = ra.execute(block, iocs, "key", run_hash, lure_hunter=lure)
    # 플랫폼 내부 로그인 링크는 따라가지 않고 외부 유인 페이지만 따라간다.
    assert ("follow", [LURE]) in lure.calls
    assert block["seeds"][-1]["linked_from"] == GPT
    # 시드 자신은 비교군에서 빠진다.
    assert [c["uuid"] for c in block["negative_controls"]] == ["b1", "b2"]
    assert all(c["label"] == "platform_baseline" for c in block["negative_controls"])
    # 이미 본 해시는 다시 조회하지 않는다.
    assert hashes_run == ["b" * 64]
    assert any("sites.google.com" in line for line in lines)
    tasks = {t["id"]: t for t in block["research_plan"]}
    assert {a["action"] for a in tasks["goal-1"]["attempts"]} == {"follow_links", "platform_baseline"}
    assert tasks["goal-2"]["attempts"][0]["action"] == "more_samples"


def test_same_input_is_not_retried():
    block, lure = _block(), FakeLure()
    ra.execute(block, [], "key", lambda values: [], lure_hunter=lure)
    first = len(lure.calls)
    ra.execute(block, [], "key", lambda values: [], lure_hunter=lure)
    assert len(lure.calls) == first


def test_platform_common_request_is_not_a_cross_site_invariant():
    block = _block()
    block["seeds"].append({"domain": "evil-one.example", "dom_confirmed": True,
                           "http": [{"path": "/backend-api/flush",
                                     "query_keys": ["lightweight_authenticated"], "status": 200}]})
    block["seeds"][0]["dom_confirmed"] = True
    controls = [{"label": "platform_baseline",
                 "http": [{"path": "/backend-api/flush", "query_keys": ["lightweight_authenticated"]}]}]
    assert pattern_synth.shared_web_fingerprints(block["seeds"], controls) == []
    assert pattern_synth.shared_web_fingerprints(block["seeds"], []) != []


def test_query_tiers_separate_lookup_discovery_and_validated():
    block = {
        "seeds": [{"domain": "a.example", "target_url": "https://a.example/x", "queries": [
            {"query": 'page.domain:"a.example"', "validation": "unverified"},
            {"query": 'filename:"jsrepo?rnd="', "validation": "unverified"},
            {"query": 'page.asn:"AS13335"', "validation": "validated"}]}],
        "negative_controls": [{"label": "platform_baseline", "http": []}],
        "shared_web_fingerprints": [{"path": "/jsrepo", "query_keys": ["rnd"],
                                     "hosts": ["a.example", "b.example"]}],
    }
    ra.assign_tiers(block)
    tiers = [row["tier"] for row in block["seeds"][0]["queries"]]
    assert tiers == ["lookup", "validated", "discovery"]
    # 근거 없이 "검증"으로 표시된 검색식은 후보로 내린다.
    assert block["seeds"][0]["queries"][2]["validation"] == "unverified"


def test_without_controls_nothing_is_validated():
    block = {"seeds": [{"domain": "a.example", "queries": [{"query": 'filename:"jsrepo?rnd="'}]}],
             "shared_web_fingerprints": [{"path": "/jsrepo", "query_keys": ["rnd"], "hosts": ["a", "b"]}]}
    ra.assign_tiers(block)
    assert block["seeds"][0]["queries"][0]["tier"] == "discovery"


def test_followed_link_satisfies_link_requirement():
    block = _block()
    question = block["goal_evidence"][0]["question"]
    before = goal_evidence.review(question, block)
    assert "외부 유인 페이지" in before["missing"]
    block["seeds"].append({"domain": "sites.google.com", "target_url": LURE,
                           "in_urlscan": True, "linked_from": GPT})
    after = goal_evidence.review(question, block)
    assert "외부 유인 페이지" not in after["missing"]


def test_past_analyses_skips_informational_records():
    import json
    import past_analyses

    class Client:
        def lrange(self, *args):
            return [json.dumps({"title": "LG U+ 제휴 발표", "analyzed_at": "2026-09-30",
                                "targets": {"actors": ["LG유플러스"], "article_kind": "informational"},
                                "investigation": {"route": {"primary": "supply_chain"}}}),
                    json.dumps({"title": "LG유플러스 침해 사고", "analyzed_at": "2026-09-20",
                                "targets": {"actors": ["LG유플러스"]}})]

    related = past_analyses.find_related({"actors": ["LG유플러스"]}, client=Client())
    assert [r["title"] for r in related] == ["LG유플러스 침해 사고"]
    assert past_analyses.stored_axis("LG U+ 제휴 발표", client=Client()) == ""


def test_quality_check_flags_attack_outputs_on_informational_record():
    import check_analysis_quality as q
    bad = {"targets": {"article_kind": "informational"},
           "investigation": {"article_kind": "informational", "patterns": [{"platform": "mde_kql"}],
                             "synthesis": {"verdict": "미확인", "plan": [{"action": "도메인 차단"}]}}}
    found = q.informational_violations(bad)
    assert any("탐지 패턴" in v for v in found) and any("판정값" in v for v in found)
    assert q.informational_violations({"targets": {}, "investigation": {"patterns": [1]}}) == []


def test_inline_numbered_items_are_split_onto_lines():
    import analysis_worker
    text = "[참고 사항] 1. 유스케이스 매핑 2. 버전 1.2 보안 검증 3. 예산 반영\n일반 문장 2. 그대로"
    out = analysis_worker.split_inline_numbering(text).split("\n")
    assert out == ["[참고 사항]", "1. 유스케이스 매핑", "2. 버전 1.2 보안 검증", "3. 예산 반영",
                   "일반 문장 2. 그대로"]
    text2 = "1. 유스케이스 매핑 2. 버전 1.2 보안 검증 3. 예산 반영"
    assert analysis_worker.split_inline_numbering(text2).split("\n") == [
        "1. 유스케이스 매핑", "2. 버전 1.2 보안 검증", "3. 예산 반영"]


def test_rdap_uses_host_and_skips_shared_platform(monkeypatch):
    import intel_hunter
    asked = []
    monkeypatch.setattr(intel_hunter, "rdap", lambda domain: asked.append(domain) or None)
    monkeypatch.setattr(intel_hunter, "PAUSE_SECONDS", 0)
    monkeypatch.setattr(intel_hunter, "otx", lambda *a, **k: None)
    monkeypatch.setattr(intel_hunter, "_pick", lambda iocs, kinds: (
        ["chatgpt.com/g/g-abc", "evil.example/path", "evil.example"] if "domain" in kinds else []))
    try:
        intel_hunter.analyze(iocs=[{"type": "domain", "value": "x"}])
    except Exception:
        pass
    assert asked == ["evil.example"]


def test_follow_links_falls_back_to_urls_named_in_the_report():
    block, lure = _block(), FakeLure()
    block["seeds"][0]["outgoing_links"] = []
    lines, note = ra.follow_links(block, "key", set(), lure,
                                  evidence_text="the GPT sends users to sites.google[.]com/view/fake-verify-page")
    assert ("follow", [LURE]) in lure.calls
    assert block["seeds"][-1]["linked_from"] == "원문 서술"


def test_internal_log_questions_are_not_reinvestigated_externally():
    question = "프록시·방화벽·EDR 네트워크 로그에서 위 Custom GPT URL로의 접속 기록이 존재하는가?"
    check = goal_evidence.review(question, _block())
    assert check["internal"] and check["missing"] == ""
    block = _block()
    block["goal_evidence"] = [dict(check, question=question, status="open")]
    # 사내 로그 질문 자체는 재조사를 만들지 않는다 — 남는 것은 공유 플랫폼 기본 확인뿐.
    actions = ra.plan_actions(block)
    assert {a["action"] for a in actions} == {"follow_links", "platform_baseline"}
    assert all(a["reason"].startswith("공유") for a in actions)


def test_baseline_skips_duplicate_and_suspicious_pages():
    class Lure(FakeLure):
        def urlscan_search(self, query, size=10, api_key=None):
            return ([{"_id": "p1", "page": {"url": "https://chatgpt.com/g/g-sign-in-verify"}},
                     {"_id": "m1", "page": {"url": "https://chatgpt.com/g/g-x"}, "verdicts": {"malicious": True}},
                     {"_id": "b1", "page": {"url": "https://chatgpt.com/g/g-recipes"}},
                     {"_id": "b2", "page": {"url": "https://chatgpt.com/g/g-recipes"}}], 4)
    block = _block()
    ra.platform_baseline(block, "key", set(), Lure())
    assert [c["uuid"] for c in block["negative_controls"]] == ["b1"]


def test_text_links_skip_service_pages_and_baseline_reads_env_key(monkeypatch):
    block = _block()
    rows = ra._text_links(block, "see https://chatgpt.com/create and sites.google[.]com/view/lure-x")
    assert [r["url"] for r in rows] == ["https://sites.google.com/view/lure-x"]
    monkeypatch.setenv("URLSCAN_API_KEY", "env-key")
    lines, note = ra.platform_baseline(_block(), None, set(), FakeLure())
    assert "비교군" in note and "없어" not in note
