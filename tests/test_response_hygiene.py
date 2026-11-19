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
