import analysis_targets as at
import incident_scope


def test_single_incident_returns_original_objects_unchanged():
    targets = {"objective": "x", "domains": ["a.com"]}
    iocs = [{"type": "domain", "value": "a.com"}]
    result = incident_scope.split(targets, iocs)
    assert len(result) == 1
    assert result[0]["incident_id"] == "1"
    assert result[0]["label"] == ""
    assert result[0]["targets"] is targets
    assert result[0]["iocs"] is iocs


def test_no_incidents_declared_is_treated_as_single():
    assert len(incident_scope.split({}, [])) == 1
    assert len(incident_scope.split({"incidents": ["only one"]}, [])) == 1


MULTI_TEXT = """
[조사 대상]
사건구분: GhostCode 침해, WaterPlum 캠페인
도메인: a.example.com(1), b.example.com(2), c.example.com(1,2)
IP: 없음
해시: aaaa000000000000000000000000000000000000000000000000000000000a(1)
URL: 없음
CVE: 없음
제품: 없음
패키지: 없음
행위자: GhostCode(1), WaterPlum(2)
악성코드: 없음
파일: 없음
경로: 없음
레지스트리키: 없음
명령: 없음
조사가능: 예
목표1: GhostCode 침해의 유포 경로를 확인한다
목표2: WaterPlum의 표적을 확인한다
확인질문1: 유포지가 살아있는가
확인질문2: 표적 조직이 우리와 겹치는가
성공기준1: block_domains
성공기준2: block_domains
부족한것1: 없음
부족한것2: 없음
주력1: user_action
주력2: malware
"""


def _multi_targets():
    return at.parse(MULTI_TEXT)


def test_multi_incident_splits_targets_and_shares_dual_tagged_value():
    targets = _multi_targets()
    result = incident_scope.split(targets, [])
    assert len(result) == 2
    assert result[0]["incident_id"] == "1" and result[0]["label"] == "GhostCode 침해"
    assert result[1]["incident_id"] == "2" and result[1]["label"] == "WaterPlum 캠페인"
    assert result[0]["targets"]["domains"] == ["a.example.com", "c.example.com"]
    assert result[1]["targets"]["domains"] == ["b.example.com", "c.example.com"]
    assert result[0]["targets"]["objective"] == "GhostCode 침해의 유포 경로를 확인한다"
    assert result[1]["targets"]["objective"] == "WaterPlum의 표적을 확인한다"
    assert result[0]["targets"]["primary"] == "user_action"
    assert result[1]["targets"]["primary"] == "malware"


def test_multi_incident_splits_raw_iocs_by_type_and_value():
    targets = _multi_targets()
    iocs = [
        {"type": "domain", "value": "a.example.com"},
        {"type": "domain", "value": "b.example.com"},
        {"type": "domain", "value": "c.example.com"},
        {"type": "sha256", "value": "aaaa000000000000000000000000000000000000000000000000000000000a"},
        {"type": "domain", "value": "untagged.example.com"},
    ]
    result = incident_scope.split(targets, iocs)
    inc1_values = {i["value"] for i in result[0]["iocs"]}
    inc2_values = {i["value"] for i in result[1]["iocs"]}
    assert inc1_values == {"a.example.com", "c.example.com",
                           "aaaa000000000000000000000000000000000000000000000000000000000a",
                           "untagged.example.com"}
    assert inc2_values == {"b.example.com", "c.example.com"}


def test_missing_per_incident_field_falls_back_to_shared_value():
    # 모델이 목표2를 빼먹었으면(부분 준수) 조용히 비우는 대신 기사 전체 공유 값으로
    # 대체한다 — incident_scope.py의 설계 문서화 사항.
    targets = at.parse(MULTI_TEXT)
    del targets["objectives_by_incident"][2]
    targets["objective"] = "공유 목표"
    result = incident_scope.split(targets, [])
    assert result[1]["targets"]["objective"] == "공유 목표"


def test_incident_cap_limits_split_count():
    # analysis_targets.parse()는 저장 시점에 이미 "(N)" 태그를 떼어 낸 깨끗한 값을
    # targets[field]에 담는다 — 여기서도 그 계약을 그대로 흉내 낸다.
    targets = {
        "incidents": ["a", "b", "c", "d", "e", "f"],
        "domains": ["x.com", "y.com"],
        "incident_map": {"domains": {"x.com": [1], "y.com": [6]}},
    }
    result = incident_scope.split(targets, [])
    assert len(result) == incident_scope.MAX_INCIDENTS_PER_ARTICLE
