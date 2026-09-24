import json

import past_analyses


class FakeClient:
    def __init__(self, rows):
        self._rows = rows

    def lrange(self, key, start, end):
        return self._rows


def _record(title, actors=None, domains=None, iocs=None, analyzed_at="2026-09-01"):
    return json.dumps({
        "title": title,
        "analyzed_at": analyzed_at,
        "targets": {"actors": actors or [], "domains": domains or []},
        "iocs": iocs or [],
    }, ensure_ascii=False)


def test_find_related_carries_the_matched_records_iocs():
    iocs = [{"type": "domain", "value": "evil-shared.example"},
            {"type": "sha256", "value": "a" * 64}]
    client = FakeClient([
        _record("Past GhostCode report", actors=["GhostCode"], iocs=iocs),
        _record("Unrelated report", actors=["SomeOtherActor"], iocs=[{"type": "domain", "value": "x"}]),
    ])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert len(related) == 1
    assert related[0]["title"] == "Past GhostCode report"
    assert related[0]["iocs"] == iocs


def test_find_related_caps_iocs_per_candidate():
    many_iocs = [{"type": "domain", "value": "d{}.example".format(i)} for i in range(50)]
    client = FakeClient([_record("Past GhostCode report", actors=["GhostCode"], iocs=many_iocs)])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert len(related[0]["iocs"]) == past_analyses.MAX_RELATED_IOCS


def test_find_related_drops_iocs_without_a_value():
    iocs = [{"type": "domain", "value": "d.example"}, {"type": "domain", "value": ""}, {"type": "domain"}]
    client = FakeClient([_record("Past GhostCode report", actors=["GhostCode"], iocs=iocs)])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert related[0]["iocs"] == [{"type": "domain", "value": "d.example"}]


def test_find_related_returns_empty_when_no_names_or_values():
    assert past_analyses.find_related({}, client=FakeClient([])) == []


def test_as_evidence_and_steps_do_not_reference_iocs():
    # 원칙: as_evidence/steps는 여전히 "무엇을 같은 계열로 봤는지"만 준다. iocs
    # 필드는 investigation.py의 캠페인 IOC 체이닝 전용이지 프롬프트 문구가 아니다.
    related = [{"title": "T", "when": "2026-09-01", "why": "같은 이름: X",
               "objective": "", "iocs": [{"type": "domain", "value": "d.example"}]}]
    evidence = past_analyses.as_evidence(related)
    assert "d.example" not in evidence
    steps = past_analyses.steps(related)
    assert all("d.example" not in line for line in steps)
