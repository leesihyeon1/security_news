import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import analysis_flow
import analysis_worker


@pytest.fixture
def sample():
    return json.loads((Path(__file__).parent / "fixtures" / "analysis_flow_clickfix.json").read_text(encoding="utf-8"))


def build(sample):
    return analysis_flow.validate(**sample)


def test_clickfix_flow_has_correct_chain_and_independent_branches(sample):
    flow = build(sample)
    assert flow["status"] == "ready"
    pairs = {(edge["from"], edge["to"]) for edge in flow["edges"]}
    assert ("n3", "n4") in pairs
    assert ("n3", "n7") not in pairs
    assert {("n7", "n8"), ("n7", "n9"), ("n7", "n10")} <= pairs
    assert ("n8", "n9") not in pairs
    assert flow["basis"] == "article"


@pytest.mark.parametrize("category", ["정책규제", "제품행사", "기타"])
def test_non_attack_categories_skip_even_with_attack_indicators(sample, category):
    sample["category"] = category
    sample["targets"]["cves"] = ["CVE-2026-1234"]
    assert build(sample)["status"] == "skipped"


def test_informational_article_does_not_get_an_attack_flow(sample):
    sample["targets"]["article_kind"] = "informational"
    sample["category"] = "기술동향"
    assert build(sample)["status"] == "skipped"
    sample["candidate"]["kind"] = "architecture"
    assert build(sample)["title"] == "기술 구성과 데이터 흐름"


def test_vulnerability_uses_mechanism_label_not_observed_attack(sample):
    sample["candidate"]["kind"] = "vulnerability"
    sample["category"] = "취약점"
    flow = build(sample)
    assert flow["title"] == "취약점 악용 구조"
    assert flow["phases"] == ["공격 전제", "취약 구성요소와 악용", "가능한 영향"]


@pytest.mark.parametrize("scope", ["multiple", "none", ""])
def test_multiple_incidents_never_become_one_chain(sample, scope):
    sample["candidate"]["scope"] = scope
    assert build(sample)["status"] == "skipped"


def test_declared_multiple_incidents_override_single_graph(sample):
    sample["targets"]["incidents"] = ["별도 사건 1", "별도 사건 2"]
    assert build(sample)["status"] == "skipped"


@pytest.mark.parametrize("part", ["nodes", "edges"])
def test_hallucinated_evidence_rejects_whole_graph(sample, part):
    sample["candidate"][part][0]["evidence"] = "원문에 존재하지 않는 임의의 탈취 서버 주소를 확인했습니다."
    assert build(sample)["status"] == "skipped"


def test_missing_edge_does_not_get_filled_from_numbering(sample):
    sample["candidate"]["edges"].pop(2)
    assert build(sample)["status"] == "skipped"


def test_capability_cannot_be_followed_by_an_event(sample):
    candidate = sample["candidate"]
    candidate["edges"].append(dict(candidate["edges"][-1], **{"from": "n8", "to": "n9"}))
    assert build(sample)["status"] == "skipped"


def test_cycle_is_rejected(sample):
    candidate = sample["candidate"]
    candidate["edges"].append(dict(candidate["edges"][0], **{"from": "n3", "to": "n1"}))
    assert build(sample)["status"] == "skipped"


@pytest.mark.parametrize("bad", [None, [], {"kind": "attack"}, {"kind": "none"}])
def test_missing_or_invalid_model_output_is_nonfatal(sample, bad):
    sample["candidate"] = bad
    assert build(sample)["status"] == "skipped"


def test_split_removes_json_without_disturbing_target_section(sample):
    text = "[핵심 요약]\n본문\n[흐름도 데이터]\n```json\n" + json.dumps(sample["candidate"], ensure_ascii=False) + "\n```\n[조사 대상]\n도메인: 없음"
    clean, value = analysis_flow.split(text)
    assert "흐름도 데이터" not in clean
    assert "[조사 대상]" in clean
    assert value == sample["candidate"]


def test_truncated_graph_json_never_leaks_into_report():
    clean, value = analysis_flow.split('[핵심 요약]\n본문\n[흐름도 데이터]\n{"kind":')
    assert clean == "[핵심 요약]\n본문"
    assert value is None


def test_analysis_creates_flow_in_existing_llm_call_and_caches_it(sample, monkeypatch):
    raw = ("[분류: 공격캠페인]\n[핵심 요약]\n기사 기반 설명\n[기술적 세부사항]\n1. 기본 분석 내용\n"
           "[흐름도 데이터]\n" + json.dumps(sample["candidate"], ensure_ascii=False) +
           "\n[조사 대상]\n기사유형: 위협사건\n사건구분: 없음")
    monkeypatch.setattr(analysis_worker, "fetch_article_text", lambda _: (sample["body"], []))
    monkeypatch.setattr(analysis_worker, "BLOCKED_PAGE_MAX_CHARS", 0)
    monkeypatch.setattr(analysis_worker, "BODY_MIN_CHARS", 0)
    generate = MagicMock(return_value=raw)
    monkeypatch.setattr(analysis_worker.common_utils, "llm_generate", generate)
    monkeypatch.setattr(analysis_worker.worker_progress, "load", lambda *args: None)
    monkeypatch.setattr(analysis_worker.worker_progress, "save", lambda *args: None)
    monkeypatch.setattr(analysis_worker.issue_decision, "decide", lambda *args: None)
    monkeypatch.setattr(analysis_worker.investigation, "build_for_article", lambda *args, **kwargs: {})
    monkeypatch.setattr(analysis_worker.common_utils, "inventory_product_terms", lambda: [])
    record = analysis_worker.analyze_one({"ref": "flow-test", "url": sample["source_url"], "title": "Custom GPT ClickFix", "category": sample["category"]})
    assert generate.call_count == 1
    assert record["analysis_flow"]["status"] == "ready"
    assert "흐름도 데이터" not in record["analysis"]
    client = MagicMock()
    client.lrange.return_value = []
    analysis_worker.store_result(client, record)
    cached = json.loads(client.set.call_args.args[1])
    assert cached["analysis_flow"] == record["analysis_flow"]


def test_prompt_requests_flow_before_final_targets():
    prompt = analysis_worker.build_prompt("제목", "본문", "공격캠페인")
    assert analysis_flow.SPEC in prompt
    assert prompt.index(analysis_flow.SPEC) < prompt.index(analysis_worker.analysis_targets.indicator_spec())


def test_split_removes_flow_json_written_without_its_header():
    import analysis_flow
    text = ("[선수 정보]\n- RMM: 원격 관리 도구 설명 문장입니다.\n\n"
            '{"kind":"attack","scope":"single","nodes":[{"id":"n1"}],"edges":[]}\n\n'
            "[조사 대상]\n도메인: 없음")
    clean, value = analysis_flow.split(text)
    assert value["kind"] == "attack"
    assert '"nodes"' not in clean
    assert "[조사 대상]" in clean and "RMM" in clean


def test_split_drops_truncated_headerless_json():
    import analysis_flow
    clean, value = analysis_flow.split('[선수 정보]\n- A: 설명\n\n{"kind":"attack","nodes":[{"id":"n1","label":"잘')
    assert value is None
    assert "kind" not in clean and clean.startswith("[선수 정보]")


def test_evidence_accepts_stitched_verbatim_sentences_only():
    import analysis_flow
    source = ("The installer drops DLLs. It then registers two services. "
              "Later the attacker runs ScreenConnect through RunFile.")
    stitched = "The installer drops DLLs. Later the attacker runs ScreenConnect through RunFile."
    assert analysis_flow._evidence(stitched, source) == (
        "The installer drops DLLs. … Later the attacker runs ScreenConnect through RunFile.")
    assert analysis_flow._evidence("The installer drops DLLs ... It then registers two services.", source)
    assert analysis_flow._evidence("The installer drops DLLs. It steals every password.", source) == ""


def test_stitched_evidence_stays_within_display_limit():
    import analysis_flow
    first, second = "A" * 12 + " first sentence " + "x" * 300 + ".", "Second sentence " + "y" * 300 + "."
    source = first + " middle text here. " + second
    out = analysis_flow._evidence(first + " " + second, source)
    assert out and len(out) <= 500 and out in source
