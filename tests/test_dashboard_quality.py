from copy import deepcopy

from check_dashboard_quality import check_report, check_narrative


def report():
    return {
        "narrative": "[총평]\n취약점 대응을 확인해야 합니다.\n[핵심 위협 TOP 3]\n1. 제품 취약점이 확인됐습니다.\n[권고 조치]\n1. 공식 패치를 확인해야 합니다.",
        "stats": {"total": 3, "p1": 1, "p2": 0, "info": 2, "actionable": 2,
                  "actionable_by_category": {"취약점": 2}},
        "generated_at": "2026-09-22T01:00:00Z",
        "data_status": {"period_start": "2026-09-21T00:00:00Z", "period_end": "2026-09-22T00:00:00Z",
                        "latest_collected_at": "2026-09-21T23:00:00Z"},
    }


def test_valid_report_and_mismatched_category_total():
    value = report()
    assert not check_report(value)
    bad = deepcopy(value)
    bad["stats"]["actionable_by_category"]["취약점"] = 1
    assert "actionable category sum does not match total" in check_report(bad)


def test_rejects_data_outside_period_and_timezone_missing():
    value = report()
    value["data_status"]["latest_collected_at"] = "2026-09-22T00:00:00Z"
    assert "latest collected time is outside the report period" in check_report(value)
    value["generated_at"] = "2026-09-22T01:00:00"
    assert "report period/generation timestamps are missing or invalid" in check_report(value)


def test_detects_english_sentence_mixed_into_korean_and_missing_action():
    text = report()["narrative"]
    assert check_narrative(text + "\nThis paragraph should not be published in English.")
    assert check_narrative(text.replace("[권고 조치]", "2. 추가 위협이 있습니다.\n[권고 조치]"))
    assert check_narrative(text.replace("공식 패치를 확인해야 합니다.", "한국어 요약을 준비하지 못했습니다."))
