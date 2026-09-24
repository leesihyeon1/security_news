import analysis_targets as at


SINGLE = """
분석 본문...

[조사 대상]
도메인: a.example.com, b.example.com
IP: 없음
해시: 없음
URL: 없음
CVE: 없음
제품: 없음
패키지: 없음
행위자: 없음
악성코드: 없음
파일: 없음
경로: 없음
레지스트리키: 없음
명령: 없음
조사가능: 예
목표: 유포지가 아직 살아있는지 확인한다
성공기준: block_domains
부족한것: 없음
확인질문: 유포지가 살아있는가, 다른 도메인도 있는가
주력: user_action
"""

MULTI = """
분석 본문...

[조사 대상]
사건구분: GhostCode 침해, WaterPlum 캠페인
도메인: a.example.com(1), b.example.com(2), c.example.com(1,2)
IP: 없음
해시: 없음
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


def test_single_incident_parse_has_no_incident_keys():
    result = at.parse(SINGLE)
    assert "incidents" not in result
    assert "incident_map" not in result
    assert "objectives_by_incident" not in result
    assert result["objective"] == "유포지가 아직 살아있는지 확인한다"
    assert result["domains"] == ["a.example.com", "b.example.com"]
    assert result["questions"] == ["유포지가 살아있는가", "다른 도메인도 있는가"]
    assert result["primary"] == "user_action"


def test_single_incident_line_with_stray_digit_suffix_is_not_treated_as_multi():
    # "사건구분" 없이 값 뒤에 우연히 괄호 숫자가 붙어도(예: 버전 표기) 사건 분리로
    # 오인해 값이 잘리면 안 된다 — multi=False 분기에서는 태그를 아예 안 본다.
    text = """
[조사 대상]
도메인: 없음
IP: 없음
해시: 없음
URL: 없음
CVE: 없음
제품: Product(2)
패키지: 없음
행위자: 없음
악성코드: 없음
파일: 없음
경로: 없음
레지스트리키: 없음
명령: 없음
조사가능: 예
목표: 확인한다
성공기준: 없음
부족한것: 없음
확인질문: 없음
주력: 없음
"""
    result = at.parse(text)
    assert "incidents" not in result
    assert result["products"] == ["Product(2)"]


def test_multi_incident_parse_splits_fields_and_tags_by_number():
    result = at.parse(MULTI)
    assert result["incidents"] == ["GhostCode 침해", "WaterPlum 캠페인"]
    assert result["domains"] == ["a.example.com", "b.example.com", "c.example.com"]
    assert result["incident_map"]["domains"] == {
        "a.example.com": [1], "b.example.com": [2], "c.example.com": [1, 2]}
    assert result["incident_map"]["actors"] == {"ghostcode": [1], "waterplum": [2]}
    assert result["objectives_by_incident"] == {
        1: "GhostCode 침해의 유포 경로를 확인한다", 2: "WaterPlum의 표적을 확인한다"}
    assert result["questions_by_incident"] == {
        1: ["유포지가 살아있는가"], 2: ["표적 조직이 우리와 겹치는가"]}
    assert result["primary_by_incident"] == {1: "user_action", 2: "malware"}
    # 사건이 여럿이면 공유 단일 필드는 안 남는다 — build_for_article이 폴백으로만 쓴다.
    assert "objective" not in result


def test_single_declared_incident_is_not_treated_as_multi():
    text = """
[조사 대상]
사건구분: 하나뿐인 사건
도메인: a.example.com
IP: 없음
해시: 없음
URL: 없음
CVE: 없음
제품: 없음
패키지: 없음
행위자: 없음
악성코드: 없음
파일: 없음
경로: 없음
레지스트리키: 없음
명령: 없음
조사가능: 예
목표: 확인한다
성공기준: 없음
부족한것: 없음
확인질문: 없음
주력: 없음
"""
    result = at.parse(text)
    assert "incidents" not in result
    assert result["domains"] == ["a.example.com"]


def test_strip_removes_section_from_both_single_and_multi():
    for text in (SINGLE, MULTI):
        stripped = at.strip(text)
        assert "[조사 대상]" not in stripped
        assert "사건구분" not in stripped
        assert "분석 본문..." in stripped
