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
    # 같은 회사라도 다른 해의 사고는 기존 기록의 후속으로 묶지 않는다 — 신규 후보로 남긴다.
    event = {"id": "e2", "url": "https://news.example/b", "title": "롯데카드 해킹 사고로 고객 정보 유출",
             "summary": "2025년 롯데카드에서 개인정보 유출 사고가 발생했다고 국내 금융당국이 밝혔다."}
    item = archive.candidate(event, _catalog())
    assert item["kind"] == "new_incident"
    assert item["possible_incident_ids"] == []


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
