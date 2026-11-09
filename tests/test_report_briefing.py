import json

import common_utils
import generate_report
from report_briefing import bind_briefing, narrative_problem, select_issues


def article(ref="one", **extra):
    return {"ref": ref, "title": "Antino 백도어 분석", "summary": "Antino가 Microsoft Graph API를 명령 제어에 악용합니다.",
            "url": "https://example.test/" + ref, "source_label": "리서치", "level": "P1",
            "category": "공격캠페인", **extra}


def test_article_without_cve_card_is_selected_and_public(monkeypatch):
    captured = []
    narrative = "[총평]\n클라우드 서비스를 악용하는 통신에 주의해야 합니다.\n\n[핵심 위협 TOP 3]\n1. **Antino의 클라우드 통신 악용** Graph API가 명령 제어에 악용됩니다.\n\n[권고 조치]\n1. Graph API에 접근하는 비정상 프로세스와 앱 권한을 점검하세요."

    def generate(prompt, **kwargs):
        captured.append(prompt)
        return narrative

    monkeypatch.setattr(common_utils, "llm_generate", generate)
    payload = {"period": "daily", "stats": {"total": 89}, "cards": [],
               "overseas": {"highlights": [article(matched_assets=["PRIVATE-HOST"], pirs=["PIR-SECRET"])]}}
    generate_report.refresh_public_summary(payload)
    assert payload["briefing"]["status"] == "ready"
    issue = payload["briefing"]["issues"][0]
    assert issue["ref"] == "one"
    assert issue["sources"][0]["url"] == "https://example.test/one"
    assert "앱 권한" in issue["action"]
    assert "PRIVATE-HOST" not in json.dumps(payload["briefing"])
    assert "PIR-SECRET" not in captured[0]
    assert len(captured) == 1


def test_duplicate_article_urls_and_same_cve_do_not_fill_top_three():
    rows = [article("a", summary="CVE-2026-12345를 악용합니다."),
            article("b", url="https://tracker.test/api/click?url=https%3A%2F%2Fexample.test%2Fa"),
            article("c", summary="CVE-2026-12345의 공격 후속 보도입니다."),
            article("d", summary="서로 다른 공격 캠페인입니다.")]
    assert [row["ref"] for row in select_issues([], rows)] == ["a", "d"]


def test_p1_non_cve_campaign_is_not_crowded_out_by_cards():
    cards = [{"cve": f"CVE-2026-1234{i}", "level": "P1", "summary": f"CVE-2026-1234{i}가 악용됩니다.",
              "items": [{"url": f"https://vendor.test/{i}", "source_label": "공급사"},
                        {"url": f"https://news.test/{i}", "source_label": "기사"}]} for i in range(3)]
    issues = select_issues(cards, [article()])
    assert len(issues) == 3
    assert any(row["ref"] == "one" for row in issues)


def test_p2_items_cover_distinct_threat_categories_before_repeating_one():
    rows = [article("one", category="공격캠페인"),
            article("second", category="취약점", summary="서버 취약점이 확인됐습니다."),
            article("third", category="취약점", summary="다른 서버 취약점이 확인됐습니다."),
            article("fourth", category="침해사고", summary="침해 사고가 확인됐습니다.")]
    for row in rows:
        row["level"] = "P2"
    assert [row["category"] for row in select_issues([], rows)] == ["취약점", "침해사고", "공격캠페인"]


def test_no_candidates_skips_model_and_reports_insufficient_evidence(monkeypatch):
    monkeypatch.setattr(common_utils, "llm_generate", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no call")))
    payload = {"stats": {"total": 0}}
    generate_report.refresh_public_summary(payload)
    assert payload["briefing"]["status"] == "empty"
    assert payload["narrative"] == ""


def test_repeated_empty_issues_summary_is_rejected():
    text = "[총평]\n세부 위협 정보가 없습니다.\n\n[핵심 위협 TOP 3]\n1. Issues 필드가 비어 있습니다.\n2. Issues 필드가 비어 있습니다.\n\n[권고 조치]\n1. 원문을 확인하세요.\n2. 원문을 확인하세요."
    assert narrative_problem(text)
    payload = bind_briefing({}, select_issues([], [article()]), text)
    assert payload["briefing"]["status"] == "needs_summary"
    assert payload["narrative"] == ""
    assert not payload["briefing"]["issues"][0]["action"]


def test_duplicated_actions_are_rejected_without_placeholder_words():
    text = "[총평]\n서로 다른 위협이 보도됐습니다.\n\n[핵심 위협 TOP 3]\n1. 위협 하나입니다.\n2. 위협 둘입니다.\n\n[권고 조치]\n1. 접근 로그를 점검하세요.\n2. 접근 로그를 점검하세요."
    assert "반복" in narrative_problem(text)


def test_weekly_prompt_has_distinct_scope_and_unknown_cves_are_rejected(monkeypatch):
    prompts = []
    def generate(prompt, **kwargs):
        prompts.append(prompt)
        return "[총평]\n이번 주 위협입니다.\n\n[핵심 위협 TOP 3]\n1. CVE-2026-99999를 악용합니다.\n\n[권고 조치]\n1. 관련 패치를 적용하세요."
    monkeypatch.setattr(common_utils, "llm_generate", generate)
    import pytest
    with pytest.raises(RuntimeError, match="CVE"):
        generate_report.ai_public_narrative("이번 주", {"total": 1}, [], articles=[article()], period="weekly")
    assert len(prompts) == 2
    assert "전주 자료가 없으므로" in prompts[0]
