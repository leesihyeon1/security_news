import time

import lure_hunter as lh

FACTS = {"domain": "uasputnik.com", "scan_count": 3, "uuid": "seed-uuid", "scanned_at": "2026-09-14",
         "url": "https://uasputnik.com/", "ip": "176.53.159.40", "asn": "AS1", "asnname": "Host",
         "server": "nginx", "tls_issuer": "R11", "title": "Захист від автоматичних запитів", "country": "UA",
         "domain_age_days": 5, "requests": 10}


def _result(domain, uuid, age=400):
    return {"_id": uuid, "page": {"domain": domain, "domainAgeDays": age, "ip": "1.1.1.1"},
            "task": {"time": "2026-09-20T00:00:00Z", "url": "https://{}/".format(domain)}}


def test_web_files_from_keeps_kit_files_and_drops_common_names():
    targets = {"files": ["admin777111777.php", "psychedeliclove.exe", "index.php", "tracker.js"]}
    assert lh.web_files_from(targets) == ["admin777111777.php", "tracker.js"]


def test_technique_pivots_find_sites_loading_the_lure_and_the_same_file():
    dom = {"markers": {"fake_captcha": ["Ray ID"]}}
    pivots = lh.technique_pivots("uasputnik.com", FACTS, dom, ["admin777111777.php"])
    queries = [query for _, query, _ in pivots]
    assert 'domain:"uasputnik.com" AND NOT page.domain:"uasputnik.com"' in queries
    assert 'filename:"admin777111777.php"' in queries
    assert any(q.startswith("page.title:\"Захист") for q in queries)


def test_technique_pivots_without_urlscan_facts_only_use_the_file():
    pivots = lh.technique_pivots("unseen.example", None, {}, ["admin777111777.php"])
    assert [query for _, query, _ in pivots] == ['filename:"admin777111777.php"']


def test_run_pivots_attaches_totals_scores_candidates_and_confirms_by_dom(monkeypatch):
    monkeypatch.setattr(lh, "REQUEST_PAUSE_SECONDS", 0)
    answers = {
        'domain:"uasputnik.com" AND NOT page.domain:"uasputnik.com"':
            ([_result("hair-clinic.ua", "u1"), _result("books.ua", "u2")], 6),
        'filename:"admin777111777.php"': ([_result("hair-clinic.ua", "u1")], 1),
    }
    monkeypatch.setattr(lh, "urlscan_search",
                        lambda query, size=100, api_key=None: answers.get(query, ([], 0)))
    monkeypatch.setattr(lh, "verify_dom", lambda uuid, api_key: {"confirmed": uuid == "u1"})
    pivots = lh.technique_pivots("uasputnik.com", FACTS, {}, ["admin777111777.php"])
    queries = [lh._query_row(name, query) for name, query, _ in pivots]
    state = {"runs": 0, "deadline": time.time() + 30}
    ran, candidates = lh.run_pivots("uasputnik.com", FACTS, queries, pivots, "key", state)
    assert ran == 2
    assert [q.get("total") for q in queries] == [6, 1]
    assert candidates[0]["domain"] == "hair-clinic.ua"          # 두 질의에 모두 걸림 + DOM 확정
    assert candidates[0]["dom_confirmed"] is True
    assert "uasputnik.com" not in [c["domain"] for c in candidates]  # 시드 자신은 후보가 아니다


def test_generic_or_self_named_titles_are_not_used_as_pivots():
    assert not lh._usable_title("Account disabled by server administrator", "fsputnik.com")
    assert not lh._usable_title("uasputnik.com", "uasputnik.com")
    assert not lh._usable_title("Just a moment...", "x.example")
    assert lh._usable_title("Захист від автоматичних запитів", "x.example")
    names = [name for name, _, _ in lh.build_pivots(dict(FACTS, title="403 Forbidden"))]
    assert "동일 제목(클론 킷) + 신규 도메인" not in names


def test_too_broad_queries_record_totals_but_give_no_candidates(monkeypatch):
    monkeypatch.setattr(lh, "REQUEST_PAUSE_SECONDS", 0)
    monkeypatch.setattr(lh, "urlscan_search", lambda query, size=100, api_key=None: (
        [_result("random-{}.example".format(i), "u{}".format(i)) for i in range(20)], 10000))
    pivots = [("동일 ASN + 신규 도메인", "page.asn:AS1", 2)]
    queries = [lh._query_row(*pivots[0][:2])]
    ran, candidates = lh.run_pivots("seed.example", FACTS, queries, pivots, None,
                                    {"runs": 0, "deadline": time.time() + 30})
    assert ran == 1 and candidates == []
    assert queries[0]["total"] == 10000 and queries[0]["too_broad"] is True


def test_run_pivots_respects_the_shared_budget(monkeypatch):
    monkeypatch.setattr(lh, "REQUEST_PAUSE_SECONDS", 0)
    monkeypatch.setattr(lh, "urlscan_search", lambda query, size=100, api_key=None: ([], 0))
    pivots = [("p{}".format(i), "q{}".format(i), 1) for i in range(20)]
    state = {"runs": 0, "deadline": time.time() + 30}
    ran, _ = lh.run_pivots("seed.example", None, [], pivots, None, state)
    assert ran == lh.MAX_PIVOT_RUNS


def test_investigation_reports_pivot_results_in_findings(monkeypatch):
    monkeypatch.setattr(lh, "REQUEST_PAUSE_SECONDS", 0)
    monkeypatch.setattr(lh, "seed_facts", lambda domain, api_key=None: dict(FACTS))
    monkeypatch.setattr(lh, "resource_facts", lambda uuid, host, api_key: None)
    monkeypatch.setattr(lh, "verify_dom", lambda uuid, api_key: {"confirmed": False, "markers": {}})
    monkeypatch.setattr(lh, "urlscan_search", lambda query, size=100, api_key=None: (
        [_result("hair-clinic.ua", "u1")], 6) if "NOT page.domain" in query else ([], 0))
    block = lh.investigation_for_iocs([{"type": "domain", "value": "uasputnik.com"}],
                                      api_key="key", web_files=["admin777111777.php"])
    seed = block["seeds"][0]
    assert seed["candidates"][0]["domain"] == "hair-clinic.ua"
    totals = {q["name"]: q.get("total") for q in seed["queries"]}
    assert totals["이 유포지를 불러오는 다른 사이트(감염 사이트 후보)"] == 6
    assert any("hair-clinic.ua" in line and "차단 대상이 아니라" in line for line in block["findings"])
