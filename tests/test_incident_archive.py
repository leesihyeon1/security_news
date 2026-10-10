import copy
import json

import pytest

import incident_archive as archive


def _catalog():
    return archive.load_catalog()


def test_shipped_catalog_is_valid_and_every_fact_cites_a_source():
    catalog = _catalog()
    source_ids = {source["id"] for source in catalog["sources"]}
    assert catalog["incidents"]
    for row in catalog["incidents"]:
        for item in row["facts"] + row["milestones"]:
            assert item["source_ids"] and set(item["source_ids"]) <= source_ids


def _write(tmp_path, data):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def test_fact_without_source_is_rejected(tmp_path):
    data = copy.deepcopy(_catalog())
    data["incidents"][0]["facts"][0]["source_ids"] = []
    with pytest.raises(ValueError):
        archive.load_catalog(_write(tmp_path, data))


def test_unknown_source_and_related_ids_are_rejected(tmp_path):
    data = copy.deepcopy(_catalog())
    data["incidents"][0]["milestones"][0]["source_ids"] = ["missing"]
    with pytest.raises(ValueError):
        archive.load_catalog(_write(tmp_path, data))
    data = copy.deepcopy(_catalog())
    data["incidents"][0]["related_ids"] = ["kr-1999-unknown"]
    with pytest.raises(ValueError):
        archive.load_catalog(_write(tmp_path, data))


def test_public_payload_hides_review_fields_and_drafts():
    data = copy.deepcopy(_catalog())
    draft = data["incidents"][1]
    draft["review_state"] = "draft"
    payload = archive.public_payload(data)
    ids = [row["id"] for row in payload["incidents"]]
    assert draft["id"] not in ids
    assert all("aliases" not in row and "review_state" not in row for row in payload["incidents"])
    # 비공개 초안을 가리키는 연결과, 공개 기록이 쓰지 않는 출처는 내보내지 않는다.
    assert all(draft["id"] not in row["related_ids"] for row in payload["incidents"])
    used = {sid for row in payload["incidents"] for item in row["facts"] + row["milestones"]
            for sid in item["source_ids"]}
    assert {source["id"] for source in payload["sources"]} == used
    assert payload["incidents"] == sorted(payload["incidents"], key=lambda row: (row["date"], row["id"]))


def test_publish_writes_once_and_skips_identical_rewrites(tmp_path):
    archive.publish(tmp_path)
    target = tmp_path / "incident-archive.json"
    first = target.read_text(encoding="utf-8")
    assert json.loads(first)["schema_version"] == 1
    assert archive.write_json(target, json.loads(first)) is False


def test_alias_mention_becomes_followup_candidate():
    event = {"id": "e1", "url": "https://news.example/a?utm_source=x", "title": "SKT 유심정보 유출 1년, 소송 진행 상황",
             "summary": "2025년 SK텔레콤 침해사고 이후 집단소송이 이어지고 있다."}
    item = archive.candidate(event, _catalog())
    assert item["kind"] == "followup"
    assert item["possible_incident_ids"] == ["kr-2025-skt"]
    assert "utm_source" not in item["url"]


def test_organization_name_alone_does_not_link_to_a_past_incident():
    # 같은 회사라도 다른 해의 사고는 기존 기록의 후속으로 묶지 않는다 — 신규 후보로 남기고,
    # 같은 기관의 과거 기록은 검토자가 참고할 제안으로만 붙인다.
    event = {"id": "e2", "url": "https://news.example/b", "title": "롯데카드 해킹 사고로 고객 정보 유출",
             "summary": "2026년 롯데카드에서 개인정보 유출 사고가 발생했다고 국내 금융당국이 밝혔다."}
    item = archive.candidate(event, _catalog())
    assert item["kind"] == "new_incident"
    assert item["linked_incident_id"] == ""
    assert item["possible_incident_ids"] == ["kr-2014-card-data", "kr-2025-lotte-card"]
    # 같은 해의 사고라면 기존 기록의 후속 보도로 연결한다.
    same_year = dict(event, url="https://news.example/c",
                     summary="2025년 롯데카드에서 개인정보 유출 사고가 발생했다고 국내 금융당국이 밝혔다.")
    assert archive.candidate(same_year, _catalog())["linked_incident_id"] == "kr-2025-lotte-card"


def test_unrelated_or_exercise_articles_are_not_candidates():
    catalog = _catalog()
    assert archive.candidate({"url": "https://news.example/c", "title": "보안 제품 출시 행사"}, catalog) is None
    assert archive.candidate({"url": "https://news.example/d", "title": "금융권 해킹 사고 대응 모의 훈련 실시",
                              "summary": "국내 은행이 모의 훈련을 진행했다."}, catalog) is None
    known = catalog["sources"][0]["url"]
    assert archive.candidate({"url": known, "title": "1·25 인터넷 대란 그 이후"}, catalog) is None


def test_candidate_queue_keeps_review_decisions(tmp_path):
    path = tmp_path / "candidates.json"
    event = {"id": "e1", "url": "https://news.example/a", "title": "SKT 유심정보 유출 후속 조사",
             "summary": "2025년 SK텔레콤 침해사고 후속 조사 결과가 공개됐다."}
    assert archive.update_candidates([event], _catalog(), path) == 1
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["candidates"][0]["review_state"] = "accepted"
    path.write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")
    assert archive.update_candidates([event], _catalog(), path) == 0
    assert json.loads(path.read_text(encoding="utf-8"))["candidates"][0]["review_state"] == "accepted"


def test_columns_and_warnings_are_not_incident_candidates():
    catalog = _catalog()
    assert archive.candidate({"url": "https://news.example/e", "title": "[기술사 보안을 論하다] 왜 개인정보 유출사고는 반복되는가?",
                              "summary": "국내 개인정보 유출 사고"}, catalog) is None
    assert archive.candidate({"url": "https://news.example/f", "title": "“개인정보 유출 보상금 드립니다” KISA, 피싱 주의보",
                              "summary": "국내 금융권 해킹 악용"}, catalog) is None


def test_published_record_requires_selection_evidence(tmp_path):
    data = copy.deepcopy(_catalog())
    del data["incidents"][0]["selection"]
    with pytest.raises(ValueError):
        archive.load_catalog(_write(tmp_path, data))
    data = copy.deepcopy(_catalog())
    data["incidents"][0]["selection"]["criteria"] = ["famous_company"]
    with pytest.raises(ValueError):
        archive.load_catalog(_write(tmp_path, data))
    # 초안은 선정 근거 없이도 보관할 수 있다 — 공개되지 않기 때문이다.
    data = copy.deepcopy(_catalog())
    data["incidents"][0]["review_state"] = "draft"
    del data["incidents"][0]["selection"]
    data["incidents"][1]["related_ids"] = []
    assert archive.load_catalog(_write(tmp_path, data))


def test_public_payload_keeps_only_public_fact_fields():
    data = copy.deepcopy(_catalog())
    data["incidents"][0]["facts"][0]["evidence"] = "검토용 인용 원문"
    data["incidents"][0]["milestones"][0]["note"] = "내부 메모"
    payload = archive.public_payload(data)
    row = next(row for row in payload["incidents"] if row["id"] == data["incidents"][0]["id"])
    assert "selection" not in row
    assert all(set(fact) <= set(archive.FACT_FIELDS) for fact in row["facts"])
    assert all(set(item) <= set(archive.MILESTONE_FIELDS) for item in row["milestones"])
    # 원본 카탈로그는 바꾸지 않는다.
    assert data["incidents"][0]["facts"][0]["evidence"] == "검토용 인용 원문"


def _reviewed_record(catalog):
    record = copy.deepcopy(catalog["incidents"][-1])
    record.update(id="kr-2026-sample", title="표본 사고", aliases=["표본 사고"], related_ids=[])
    return record


def test_apply_reviewed_imports_only_published_records(tmp_path):
    catalog_path = _write(tmp_path, _catalog())
    incoming = tmp_path / "reviewed.json"
    record = _reviewed_record(_catalog())
    incoming.write_text(json.dumps({"incidents": [record]}, ensure_ascii=False), encoding="utf-8")
    archive.apply_reviewed(incoming, catalog_path)
    assert "kr-2026-sample" in {row["id"] for row in archive.load_catalog(catalog_path)["incidents"]}

    record["review_state"] = "draft"
    incoming.write_text(json.dumps({"incidents": [record]}, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError):
        archive.apply_reviewed(incoming, catalog_path)


def test_apply_reviewed_rejects_reusing_a_source_id_for_another_url(tmp_path):
    catalog = _catalog()
    catalog_path = _write(tmp_path, catalog)
    source = dict(catalog["sources"][0], url="https://www.korea.kr/news/policyNewsView.do?newsId=1")
    incoming = tmp_path / "reviewed.json"
    incoming.write_text(json.dumps({"sources": [source]}, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError):
        archive.apply_reviewed(incoming, catalog_path)


def _event(number, title, summary="국내 기업에서 개인정보 유출 사고가 발생했다."):
    return {"id": "e{}".format(number), "url": "https://news.example/{}".format(number),
            "title": title, "summary": summary, "published_at": "2026-10-0{}".format(number % 9 + 1)}


def test_reviewed_candidate_keeps_its_reviewed_version_when_the_article_changes(tmp_path):
    path = tmp_path / "candidates.json"
    event = _event(1, "가비아, 외부 공격으로 고객 2,998명 개인정보 유출")
    archive.update_candidates([event], _catalog(), path)
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["candidates"][0]["review_state"] = "accepted"
    path.write_text(json.dumps(stored, ensure_ascii=False), encoding="utf-8")

    corrected = dict(event, title="가비아, 외부 공격으로 고객 3,100명 개인정보 유출")
    assert archive.update_candidates([corrected], _catalog(), path) == 0
    row = json.loads(path.read_text(encoding="utf-8"))["candidates"][0]
    assert row["title"] == event["title"]
    assert row["latest_revision"]["title"] == corrected["title"]
    assert row["needs_review"] is True and row["changed_fields"] == ["title"]


def test_pending_candidate_records_previous_revision(tmp_path):
    path = tmp_path / "candidates.json"
    event = _event(2, "가비아, 외부 공격으로 고객 2,998명 개인정보 유출")
    archive.update_candidates([event], _catalog(), path)
    archive.update_candidates([dict(event, summary="정정: 유출 규모가 늘었다. 국내 개인정보 유출.")], _catalog(), path)
    row = json.loads(path.read_text(encoding="utf-8"))["candidates"][0]
    assert row["summary"].startswith("정정")
    assert [revision["summary"] for revision in row["revisions"]] == [event["summary"]]


def test_queue_written_by_older_rules_is_reclassified_once(tmp_path):
    path = tmp_path / "candidates.json"
    old = {"id": "old1", "url": "https://news.example/old", "title": "보안 기업, 개인정보 유출 탐지 솔루션 구축",
           "summary": "", "kind": "new_incident", "review_state": "pending"}
    path.write_text(json.dumps({"schema_version": 1, "candidates": [old]}, ensure_ascii=False), encoding="utf-8")
    archive.update_candidates([], _catalog(), path)
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["schema_version"] == 2
    assert stored["candidates"][0]["kind"] == "excluded"


def _write_lines(path, events, tail=""):
    path.write_bytes(("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events) + tail).encode("utf-8"))


def test_event_cursor_defers_a_partial_line_and_resumes(tmp_path):
    path = tmp_path / "events.jsonl"
    first = _event(1, "가비아, 외부 공격으로 고객 2,998명 개인정보 유출")
    second = _event(2, "룩핀, 개인정보 유출 공지")
    _write_lines(path, [first], tail=json.dumps(second, ensure_ascii=False)[:20])
    events, cursor = archive.read_event_batch(path)
    assert [event["id"] for event in events] == ["e1"]
    assert cursor["has_more"] is True
    _write_lines(path, [first, second])
    events, cursor = archive.read_event_batch(path, cursor)
    assert [event["id"] for event in events] == ["e2"]
    assert cursor["has_more"] is False


def test_event_cursor_replays_a_rewritten_file(tmp_path):
    path = tmp_path / "events.jsonl"
    _write_lines(path, [_event(1, "가비아, 외부 공격으로 고객 2,998명 개인정보 유출")])
    _, cursor = archive.read_event_batch(path)
    _write_lines(path, [_event(3, "룩핀, 개인정보 유출 공지"), _event(4, "위버스, 결제 API 뚫려 정보 유출")])
    events, _ = archive.read_event_batch(path, cursor)
    assert [event["id"] for event in events] == ["e3", "e4"]


def test_discover_catches_up_in_one_call_and_writes_private_drafts(tmp_path):
    path = tmp_path / "events.jsonl"
    titles = ["가비아, 외부 공격으로 고객 2,998명 개인정보 유출", "룩핀, 해킹으로 개인정보 유출",
              "위버스, 결제 API 뚫려 42만건 정보 유출", "보안 기업, 신제품 출시", "현대캐피탈 해킹 공격으로 146명 정보 유출"]
    _write_lines(path, [_event(number, title) for number, title in enumerate(titles, 1)])
    candidates, drafts = tmp_path / "candidates.json", tmp_path / "drafts.json"
    assert archive.discover(path, candidates, archive.CATALOG, drafts, max_lines=2) == 4
    stored = json.loads(candidates.read_text(encoding="utf-8"))
    assert stored["scan_state"]["has_more"] is False
    groups = json.loads(drafts.read_text(encoding="utf-8"))["groups"]
    assert len(groups) == 4
    assert all(group["publication_eligible"] is False and group["review_state"] == "draft" for group in groups)
    assert archive.discover(path, candidates, archive.CATALOG, drafts) == 0
