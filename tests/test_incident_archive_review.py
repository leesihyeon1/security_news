import incident_archive as archive
import incident_archive_review as review


def _assess(title, summary="", url="https://news.example/a", published_at="2026-10-01"):
    return review.assess({"url": url, "title": title, "summary": summary, "published_at": published_at},
                         archive.load_catalog())


# 아래 제목들은 2026-10-10 전체 이벤트 재검토에서 신규 사고로 잘못 올라온 실제 기사들이다.
def test_vendor_and_event_news_are_not_incident_candidates():
    for title, summary in [
        ("카스퍼스키-KCC정보통신, 국내 총판 계약 체결하며 보안 사업 전방위 확장", "해킹 대응 역량을 강화한다."),
        ("엘세븐시큐리티, 한국남부발전에 AI OCR 이메일 개인정보 유출 탐지 솔루션 구축", ""),
        ("씨티아이랩 “금융권 AI 기반 공격, 개인정보 유출 전 이상행위 탐지 가능”", ""),
        ("[기자수첩] 정보보호의 날, 대통령이 꼭 참석해야 했을까?", "해킹 사고가 잇따랐다."),
        ("[김혁준의 실전형 K-시큐리티] 사이버 공유지의 비극, 해법은 ‘통합 가시성’", "국내 해킹"),
        ("[긴급] 한-미 수사기관, ‘Gunra 랜섬웨어’ 공동 경보...VPN 뚫고 백업까지 파괴", "국내 기업 주의"),
        ("2026년 7월 랜섬웨어 동향 보고서", "국내 랜섬웨어 피해"),
    ]:
        assert _assess(title, summary) is None, title


def test_incident_words_only_in_the_summary_do_not_make_a_new_incident():
    assert _assess("국민은행, 메타디펜더 엔진 도입", "국내 해킹 사고에 대비한다.") is None


def test_foreign_reports_need_a_korean_link():
    assert _assess("Coca-Cola Confirms Data Breach After Fairlife Ransomware Attack", "Fairlife was hit.") is None
    assert _assess("독일, 정보기관 ‘능동적 해킹’ 허용 법안 추진", "국내에도 시사점") is None
    kept = _assess("Hackers leak data stolen in ransomware attack on South Korean retailer",
                   "A South Korean retailer confirmed the breach.")
    assert kept and kept["domestic"] == "confirmed"


def test_unfamiliar_organization_stays_in_review_without_claiming_domestic():
    item = _assess("카카오게임즈, 140명 개인정보 유출... \"악용 위험 낮다\"", "")
    assert item["organizations"] == ["카카오게임즈"]
    assert item["kind"] == "needs_context" and item["domestic"] == "unknown"
    # 인용문이나 말줄임표 앞 문구는 기관명이 아니다.
    assert _assess("“지체할 시간없다, 협업하자”... 해킹 대응 인터뷰", "") is None


def test_known_institution_report_is_a_new_incident_with_scale_signal():
    item = _assess("OO카드, 해킹으로 고객 300만 명 정보 유출", "롯데카드와 무관한 국내 카드사 사고")
    assert item["kind"] in {"new_incident", "needs_context"}
    item = _assess("현대캐피탈 해킹으로 고객 300만 명 정보 유출", "2026년 9월 발생한 사고")
    assert item["kind"] == "new_incident"
    assert item["incident_time"]["year"] == 2026
    assert any(signal["criterion"] == "scale" for signal in item["significance"]["signals"])
    assert item["significance"]["publication_eligible"] is False


def test_alleged_numbers_do_not_count_toward_scale():
    item = _assess("[단독] 딥웹에 해커 “배달의민족 이용자 4,200만명 정보 판매” 주장...우아한형제들 긴급 조사 필요",
                   "국내 배달 플랫폼 이용자 정보라는 주장이다.")
    assert item["claim_status"] == "alleged"
    assert item["significance"]["people"] is None
    assert all(signal["criterion"] != "scale" for signal in item["significance"]["signals"])


def test_comma_without_digits_does_not_break_measurement():
    # "유출, 명"처럼 숫자 없는 쉼표가 수치로 잡히면 float("")에서 후보 수집 전체가 멈췄다.
    item = _assess("신한은행 고객 정보 유출, 명의도용 우려", "국내 은행 해킹")
    assert item["significance"]["measurements"] == []


def test_policy_and_meeting_articles_are_context_not_incidents():
    item = _assess("[긴급] 금융당국, 잇단 금융권 침해사고에 긴급회의...“대응 소홀로 재발하면 엄중 책임”", "")
    assert item["kind"] == "context"


def test_repeat_incident_is_not_merged_into_the_earlier_record():
    item = _assess("SK텔레콤 또 해킹... 유심정보 유출 정황", "2025년 SK텔레콤 침해사고 이후 다시 발생")
    assert item["linked_incident_id"] == ""
    assert item["kind"] == "new_incident"


def test_drafts_group_followups_by_record_and_skip_excluded_or_rejected():
    catalog = archive.load_catalog()
    base = {"summary": "", "published_at": "2026-10-01", "source_updated_at": "", "source_type": "report",
            "claim_status": "reported", "significance": {"priority": "review", "signals": [], "measurements": []},
            "organizations": ["SK텔레콤"], "domestic": "confirmed", "incident_time": {"date": "", "year": 2025},
            "category": "data_breach",
            "content_fingerprint": "x"}
    rows = [dict(base, id="a", url="https://n.example/a", title="후속1", kind="followup", linked_incident_id="kr-2025-skt"),
            dict(base, id="b", url="https://n.example/b", title="후속2", kind="followup", linked_incident_id="kr-2025-skt"),
            dict(base, id="c", url="https://n.example/c", title="제외", kind="excluded", linked_incident_id=""),
            dict(base, id="d", url="https://n.example/d", title="반려", kind="new_incident", linked_incident_id="",
                 review_state="rejected")]
    drafts = review.build_drafts({"candidates": rows}, catalog)
    assert [group["id"] for group in drafts["groups"]] == ["kr-2025-skt"]
    group = drafts["groups"][0]
    assert group["operation"] == "update" and len(group["evidence"]) == 2
    assert group["publication_eligible"] is False


def test_report_soon_after_a_recorded_incident_is_a_followup_without_a_year():
    catalog = archive.load_catalog()
    record = next(row for row in catalog["incidents"] if row["organizations"] == ["SK텔레콤", "에스케이텔레콤"])
    title = "SK텔레콤 인증 우회로 2만5천여 명 정보유출 확인"
    soon = review.assess({"url": "https://news.example/s", "title": title, "summary": "",
                          "published_at": record["date"]}, catalog)
    assert soon["kind"] == "followup" and soon["linked_incident_id"] == record["id"]
    later = review.assess({"url": "https://news.example/l", "title": title, "summary": "",
                           "published_at": "2030-01-01"}, catalog)
    assert later["linked_incident_id"] == "" and record["id"] in later["possible_incident_ids"]


def test_descriptive_catalog_names_do_not_match_unrelated_articles():
    # 2009 DDoS 기록의 "국가기관"이 기관명으로 쓰여 선박 해킹 기사가 그 기록의 후보로 붙었다.
    item = _assess("韓 선박, 해킹에 멈췄다... 선박 보안 경각심", "국가기관 대응이 필요하다.")
    assert item is None or "kr-2009-ddos" not in item["possible_incident_ids"]
