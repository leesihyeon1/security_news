import investigation
import response_builder
import vuln_hunter


def entry(cve, **extra):
    return dict({"cve": cve, "kev": {}, "epss": 0.9, "nvd": {"products": []}}, **extra)


def test_only_the_articles_cves_become_patch_targets():
    track = {"cves": [entry("CVE-2026-43284"), entry("CVE-2018-13379", kev={"name": "x"}),
                      entry("CVE-2019-19781", origin="followup")]}
    material = vuln_hunter.response_material(track, ["CVE-2026-43284"])
    labels = {group["label"]: group["values"] for group in material["blocklists"]}
    assert labels["패치 대상 — CVE"] == ["CVE-2026-43284 EPSS 90%"]
    assert labels["참고 — 조사 중 함께 확인된 CVE"] == ["CVE-2018-13379 [KEV]", "CVE-2019-19781"]
    assert all("CVE-2018-13379" not in action for action in material["actions"])
    assert all("CVE-2018-13379" not in query["query"] for query in material["kql"])


def test_without_known_article_cves_everything_stays_a_target_except_follow_ups():
    track = {"cves": [entry("CVE-2026-1111"), entry("CVE-2026-2222", origin="followup")]}
    material = vuln_hunter.response_material(track)
    assert material["blocklists"][0]["values"] == ["CVE-2026-1111 EPSS 90%"]


def test_names_without_a_cve_number_stay_out_of_queries():
    track = {"cves": [entry("CVE-2026-109618"), entry("FRAGNESIA (CVE 번호 미기재)"), entry("Fragnesia")]}
    material = vuln_hunter.response_material(track, ["CVE-2026-109618"])
    labels = {group["label"]: group["values"] for group in material["blocklists"]}
    assert labels["점검 대상 — CVE 미배정 취약점"] == ["FRAGNESIA"]
    assert "Fragnesia" not in material["kql"][0]["query"] and "FRAGNESIA" not in material["kql"][0]["query"]


def test_finalize_resolves_block_and_spare_conflicts_across_incidents():
    md5, sha = "35f0d4d0c5519a2957338e448fce53bc", "97d4c9b5750d614face73d11ba8532e53594332af53f4c07c1543195225b76eb"
    other = "3a259ad7e5c19a782f7736b5ac50aac4ba4d03b921ffc6a3ff6a48d720f02012"
    response = {"blocklists": [
        {"label": "[A] 차단 금지 — 정상 인프라(공격에 악용됨)", "values": [sha]},
        {"label": "[B] 차단 후보 — 파일 해시(SHA-256)", "values": [sha, other, md5, other]},
    ], "kql": [{"name": "q", "query": "x"}, {"name": "q2", "query": "x"}],
        "actions": ["같은 조치", "같은 조치"], "commands": []}
    result = response_builder.finalize(response)
    labels = {group["label"]: group["values"] for group in result["blocklists"]}
    assert labels["[B] 차단 후보 — 파일 해시(SHA-256)"] == [other]
    assert labels["[B] 차단 후보 — 파일 해시(MD5)"] == [md5]
    assert labels["[A] 차단 금지 — 정상 인프라(공격에 악용됨)"] == [sha]
    assert result["actions"] == ["같은 조치"] and len(result["kql"]) == 1
    assert response_builder.finalize(result) == result   # idempotent


def test_multi_incident_record_has_the_same_top_level_shape_as_a_single_one():
    """실측(SilentAir): 사건 2건 기사에는 synthesis_status·coverage·quality와 인텔·웹 조회
    결과가 최상위에 없어 화면의 관측 결과와 PDF 한계 표시가 비었다."""
    def block(label, intel, status, cover, quality):
        return {"incident_id": label, "incident_label": label, "route": {"label": label},
                "intel": {"findings": intel, "steps": [], "references": []},
                "web": {"findings": [], "steps": [], "used_today": 3, "cap": 20},
                "vulnerability": {"cves": [{"cve": "CVE-2026-0001", "kev": False}], "findings": []},
                "synthesis_status": status, "coverage": cover, "quality": quality,
                "research_attempts": [], "generated_at": "2026-11-17T00:0{}:00Z".format(label[-1])}
    first = block("사건 1", ["A"], {"status": "completed"},
                  {"done": [{"key": "blocklist"}, {"key": "hunting_query"}], "missing": []},
                  {"version": "v1", "query_count": 1, "plan_count": 2, "issues": ["x"]})
    second = block("사건 2", ["A", "B"], {"status": "failed", "retryable": True},
                   {"done": [{"key": "blocklist"}], "missing": [{"key": "hunting_query"}]},
                   {"version": "v1", "query_count": 2, "plan_count": 3, "issues": ["x", "y"]})
    combined = investigation._combine_incidents([first, second])
    assert combined["intel"]["findings"] == ["A", "B"]
    assert combined["web"]["cap"] == 20 and combined["web"]["findings"] == []
    assert combined["vulnerability"]["cves"] == [{"cve": "CVE-2026-0001", "kev": False}]
    assert combined["synthesis_status"] == {"status": "failed", "retryable": True, "failed_incidents": 1}
    assert combined["coverage"] == {"done": [{"key": "blocklist"}], "missing": [{"key": "hunting_query"}]}
    assert combined["quality"]["query_count"] == 3 and combined["quality"]["issues"] == ["x", "y"]
    assert combined["research_attempts"] == []
    assert combined["generated_at"] == "2026-11-17T00:01:00Z"
    assert "incident_label" not in combined and len(combined["incidents"]) == 2
