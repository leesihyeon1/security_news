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
    iocs = [{"type": "domain", "value": "evil-shared.example", "role": "c2"},
            {"type": "sha256", "value": "a" * 64}]
    client = FakeClient([
        _record("Past GhostCode report", actors=["GhostCode"], iocs=iocs),
        _record("Unrelated report", actors=["SomeOtherActor"], iocs=[{"type": "domain", "value": "x"}]),
    ])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert len(related) == 1
    assert related[0]["title"] == "Past GhostCode report"
    assert related[0]["iocs"] == iocs


def test_find_related_drops_network_iocs_without_an_actionable_role():
    # 역할이 없던 예전 기록의 도메인·IP는 새 사건의 C2로 승격되지 않게 뺀다. 해시는 남긴다.
    iocs = [{"type": "domain", "value": "old-recon.example"},
            {"type": "ip", "value": "198.51.100.7", "role": "source"},
            {"type": "url", "value": "http://drop.example/p", "role": "distribution"},
            {"type": "sha256", "value": "b" * 64}]
    client = FakeClient([_record("Past GhostCode report", actors=["GhostCode"], iocs=iocs)])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert related[0]["iocs"] == [iocs[2], iocs[3]]


def test_find_related_caps_iocs_per_candidate():
    many_iocs = [{"type": "domain", "value": "d{}.example".format(i), "role": "c2"} for i in range(50)]
    client = FakeClient([_record("Past GhostCode report", actors=["GhostCode"], iocs=many_iocs)])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert len(related[0]["iocs"]) == past_analyses.MAX_RELATED_IOCS


def test_find_related_drops_iocs_without_a_value():
    iocs = [{"type": "domain", "value": "d.example", "role": "c2"},
            {"type": "domain", "value": "", "role": "c2"}, {"type": "domain", "role": "c2"}]
    client = FakeClient([_record("Past GhostCode report", actors=["GhostCode"], iocs=iocs)])
    related = past_analyses.find_related({"actors": ["GhostCode"]}, client=client)
    assert related[0]["iocs"] == [{"type": "domain", "value": "d.example", "role": "c2"}]


def test_find_related_returns_empty_when_no_names_or_values():
    assert past_analyses.find_related({}, client=FakeClient([])) == []


def test_as_evidence_marks_iocs_as_requery_candidates_and_steps_omit_them():
    # 원칙: 과거 지표는 이번 사건의 IOC로 확정하지 않는다. 판단 자료에는 "재조회 후보"로만
    # 보여 주고, 조사 경로(steps)에는 "무엇을 같은 계열로 봤는지"만 남긴다.
    related = [{"title": "T", "when": "2026-09-01", "why": "같은 이름: X",
               "objective": "", "iocs": [{"type": "domain", "value": "d.example"}]}]
    evidence = past_analyses.as_evidence(related)
    line = next(line for line in evidence.splitlines() if "d.example" in line)
    assert "재조회 후보" in line and "확정하지 않음" in line
    steps = past_analyses.steps(related)
    assert all("d.example" not in line for line in steps)
