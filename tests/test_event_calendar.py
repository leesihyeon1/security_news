from datetime import date
import json

import event_calendar
import publish_web_dashboard


TODAY = date(2026, 9, 30)


def article(title, summary, published="2026-09-22T18:02:38", source="boannews"):
    return {"id": "boannews:1", "title": title, "summary": summary,
            "published_at": published, "source": source,
            "url": "https://example.com/event"}


def test_upcoming_workshop_from_collected_article():
    row = article("능동적 사이버보안 워크숍 2026, 10월 8일 개최",
                  "한국정보보호학회가 오는 10월 8일 서울에서 보안 워크숍을 개최한다.")
    item = event_calendar.extract(row, today=TODAY)
    assert item["date"] == "2026-10-08"
    assert item["time"] == ""


def test_seminar_time_and_online_mode():
    row = article("공급망 보안 세미나 개최",
                  "오는 10월 14일 오후 2시부터 5시까지 온라인 보안 세미나를 개최한다.")
    item = event_calendar.extract(row, today=TODAY)
    assert (item["date"], item["time"], item["mode"]) == (
        "2026-10-14", "14:00", "온라인")


def test_past_event_report_and_deadline_are_not_calendar_events():
    past = article("보안 컨퍼런스 개최", "지난 9월 22일 보안 컨퍼런스를 개최했다.",
                   published="2026-09-23T10:00:00")
    deadline = article("보안 웨비나 참가 안내",
                       "10월 8일 신청 마감이며 행사 일정은 추후 발표한다.")
    assert event_calendar.extract(past, today=TODAY) is None
    assert event_calendar.extract(deadline, today=TODAY) is None


def test_build_deduplicates_and_sorts():
    first = article("보안 세미나 개최", "오는 10월 14일 보안 세미나를 개최한다.")
    second = article("사이버보안 워크숍 개최", "오는 10월 8일 워크숍을 개최한다.")
    result = event_calendar.build([first, first, second], today=TODAY)
    assert [item["date"] for item in result["events"]] == ["2026-10-08", "2026-10-14"]


def test_dashboard_publish_writes_calendar_data(tmp_path, monkeypatch):
    monkeypatch.setattr(publish_web_dashboard, "_rebuild_search_index_from_events", lambda repo: None)
    monkeypatch.setattr(publish_web_dashboard, "_rebuild_issue_history", lambda data_dir: None)
    monkeypatch.setattr(publish_web_dashboard, "_run_git", lambda *args, **kwargs: "")
    monkeypatch.setattr(publish_web_dashboard, "_has_staged_changes", lambda *args, **kwargs: True)
    monkeypatch.setattr(event_calendar, "from_collected_events",
                        lambda: {"generated_at": "2026-09-30T00:00:00Z", "events": []})
    path = tmp_path / "dashboard" / "data"
    publish_web_dashboard._write_and_commit(
        tmp_path, {"period": "daily", "generated_at": "2026-09-30T00:00:00Z"},
        "daily", "2026-09-30", path)
    assert json.loads((path / "calendar-events.json").read_text(encoding="utf-8"))["events"] == []
