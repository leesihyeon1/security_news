import analysis_targets
import common_utils
import lure_hunter
import response_builder
import source_evidence


def test_host_from_indicator_rejects_paths_and_filenames():
    for value in ("admin777111777.php", "/api/v1/agent/", "api/v1/ext", "tracker.js",
                  "tracker[.]js", "payload.exe", ""):
        assert common_utils.host_from_indicator(value) == "", value


def test_host_from_indicator_accepts_hosts_ips_and_urls():
    assert common_utils.host_from_indicator("uasputnik[.]com") == "uasputnik.com"
    assert common_utils.host_from_indicator("hxxps://uasputnik[.]com/admin777111777.php") == "uasputnik.com"
    assert common_utils.host_from_indicator("193.178.159[.]128:8080") == "193.178.159.128"
    assert common_utils.host_from_indicator("evil.zip") == "evil.zip"  # 실제 TLD는 살린다


def test_extract_iocs_skips_defanged_filenames():
    found = common_utils.extract_iocs("load tracker[.]js from uasputnik[.]com")
    assert found == [{"type": "domain", "value": "uasputnik.com"}]


PSYCHEDELIC_TARGETS = """
[조사 대상]
도메인: uasputnik[.]com, tracker.js
IP: 193.178.159[.]128
해시: 없음
URL: uasputnik[.]com, admin777111777.php, /api/v1/agent/, /api/v1/ext/
CVE: 없음
제품: 없음
패키지: 없음
행위자: 없음
악성코드: Psychedelic Stealer
파일: 없음
경로: 없음
레지스트리키: 없음
명령: 없음
조사가능: 예
목표: 확인한다
성공기준: 없음
부족한것: 없음
확인질문: 없음
주력: user_action
"""


def test_parse_moves_path_only_urls_and_filename_domains_out_of_host_fields():
    targets = analysis_targets.parse(PSYCHEDELIC_TARGETS)
    assert targets["urls"] == ["uasputnik[.]com"]
    # 이름.확장자만 있으면 파일, 슬래시가 든 것은 요청 경로다.
    assert targets["url_paths"] == ["/api/v1/agent/", "/api/v1/ext/"]
    assert "admin777111777.php" in targets["files"]
    assert targets["domains"] == ["uasputnik[.]com"]
    assert "tracker.js" in targets["files"]


def test_parse_keeps_the_filename_at_the_end_of_a_full_url():
    text = PSYCHEDELIC_TARGETS.replace(
        "URL: uasputnik[.]com, admin777111777.php, /api/v1/agent/, /api/v1/ext/",
        "URL: hxxp://uasputnik[.]com/admin777111777.php")
    targets = analysis_targets.parse(text)
    assert targets["urls"] == ["hxxp://uasputnik[.]com/admin777111777.php"]
    assert "admin777111777.php" in targets["files"]


def test_seed_hosts_are_not_crowded_out_by_paths():
    # 경로가 URL 칸을 먼저 채우면 조사 칸(3개)에서 진짜 도메인이 밀려났다.
    iocs = [{"type": "url", "value": "admin777111777.php"},
            {"type": "url", "value": "/api/v1/agent/"},
            {"type": "url", "value": "/api/v1/ext/"},
            {"type": "domain", "value": "uasputnik.com"}]
    assert lure_hunter._raw_hosts_from_iocs(iocs) == ["uasputnik.com"]


ARTICLE = ("The domain at the center of this, uasputnik[.]com, was registered September 9, "
           "2026, and associated with lure URLs appearing on compromised sites. A later-stage "
           "sign is traffic to 193.178.159[.]128:8080 , particularly requests to /api/v1/agent/.")


def _assessed():
    iocs = [{"type": "domain", "value": "uasputnik.com"}, {"type": "ip", "value": "193.178.159.128"}]
    return source_evidence.assess_iocs(iocs, [{"url": "https://news.example/a", "text": ARTICLE}])


def test_lure_wording_after_the_value_marks_distribution():
    domain, ip = _assessed()
    assert domain["role"] == "distribution" and domain["actionable"] is True
    assert ip["role"] == "unknown"  # 원문 문장만으로는 역할이 안 정해진다


def test_sandbox_contact_stays_a_non_actionable_candidate_without_request_context():
    assessed = _assessed()
    block = {"indicator_assessments": assessed,
             "malware": {"files": [{"hash": "06f434695f93d7fd", "behaviour": {
                 "ip_traffic": ["193.178.159.128:8080", "57.150.53.97:443"]}}]}}
    upgraded = source_evidence.corroborate(block)
    assert [item["value"] for item in upgraded] == ["193.178.159.128"]
    assert assessed[1]["role"] == "unknown" and assessed[1]["actionable"] is False
    assert assessed[1]["corroborated_by"] == "sandbox_contact"


def test_corroboration_leaves_conflicted_and_context_roles_alone():
    assessed = [
        {"type": "ip", "value": "1.1.1.1", "role": "unknown",
         "evidence": source_evidence.CONFLICT_EVIDENCE, "actionable": False},
        {"type": "domain", "value": "target.example", "role": "recon_target", "actionable": False},
    ]
    block = {"indicator_assessments": assessed,
             "malware": {"files": [{"hash": "h", "behaviour": {"ip_traffic": ["1.1.1.1:53"],
                                                               "dns": ["target.example"]}}]}}
    assert source_evidence.corroborate(block) == []
    assert assessed[0]["role"] == "unknown" and assessed[1]["role"] == "recon_target"


def test_urlscan_dom_confirmation_upgrades_unknown_domain_to_distribution():
    assessed = [{"type": "domain", "value": "lure.example", "role": "unknown", "actionable": False,
                 "evidence": "원문 언급만으로 악성 인프라를 확정할 수 없습니다."}]
    block = {"indicator_assessments": assessed,
             "seeds": [{"domain": "lure.example", "dom_confirmed": True}]}
    source_evidence.corroborate(block)
    assert assessed[0]["role"] == "distribution"
    assert assessed[0]["corroborated_by"] == "urlscan_dom"


def test_url_paths_become_a_hunting_query_not_a_blocklist(monkeypatch):
    monkeypatch.setattr(lure_hunter, "classify_ioc_hosts", lambda iocs, text="": {
        "lure": [], "public_service": [], "leak_site": [], "tor": []})
    block = {"targets": {"url_paths": ["/api/v1/agent/", "admin777111777.php"]}}
    result = response_builder.build(block, [], primary="user_action", text="")
    query = next(q for q in result["kql"] if q["name"] == "원문이 지목한 요청 경로·파일")
    assert '"api/v1/agent"' in query["query"] and '"admin777111777.php"' in query["query"]
    values = [v for group in result["blocklists"] for v in group.get("values") or []]
    assert not any("api/v1" in str(v) or "admin777" in str(v) for v in values)
