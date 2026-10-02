import json

import issue_decision
import incident_scope
import analysis_worker
import analysis_targets


def _issue(title, kind, question):
    return {"title": title, "type": kind, "evidence": title,
            "disposition": "investigate", "reason": "영향 범위 확인 필요",
            "question": question, "decision": "영향 단말 조사"}


def test_lunex_decision_covers_clickfix_and_preserves_existing_indicators(monkeypatch):
    result = {"cases": [{"incident": 1, "primary": "malware",
                         "objective": "감염 단말과 필요한 조치를 가린다",
                         "criteria": ["hunting_query", "unknown"], "gaps": [],
                         "issues": [
                             _issue("ClickFix 유입", "user_action", "어떤 명령을 실행했는가"),
                             _issue("취약 드라이버 악용", "vulnerability", "어떤 드라이버인가"),
                             _issue("자격증명 탈취", "malware", "어디로 전송했는가")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    article = "ClickFix 유입 이후 취약 드라이버 악용과 자격증명 탈취를 시도했다."
    cases = issue_decision.decide("Lunex", article, "[기술적 세부사항]", {})
    targets = issue_decision.apply({"hashes": ["a" * 64], "questions": ["기존 질문"]}, cases)
    assert [issue["type"] for issue in targets["issues"]] == [
        "user_action", "vulnerability", "malware"]
    assert targets["hashes"] == ["a" * 64]
    assert targets["criteria"] == ["hunting_query"]
    assert targets["decision_status"] == "confirmed"
    assert len(targets["questions"]) == 3


def test_unquoted_issue_evidence_requires_review(monkeypatch):
    result = {"cases": [{"incident": 1, "objective": "유포 경로 확인",
                         "issues": [_issue("기사에 없는 웹스토어 배포", "supply_chain",
                                           "어떤 스토어 계정인가")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    case = issue_decision.decide("기사", "로컬 확장을 사용했다", "확장 연결을 설명한다", {})[0]
    assert case["decision_status"] == "review_required"
    assert case["issues"][0]["source_check"] == "review_required"


def test_unmapped_analysis_stage_becomes_an_explicit_question(monkeypatch):
    result = {"cases": [{"incident": 1, "objective": "영향 범위를 확인한다",
                         "issues": [{**_issue("ClickFix 유입", "user_action", "유입 명령은 무엇인가"),
                                     "step_ids": ["s1"]}]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    analysis = "[기술적 세부사항]\n1. ClickFix 유입\n2. 브라우저 자격증명 탈취\n[권장 대응]\n"
    case = issue_decision.decide("기사", "ClickFix 유입", analysis, {})[0]
    assert case["missing_steps"] == ["s2"]
    assert case["decision_status"] == "review_required"
    assert any("브라우저 자격증명 탈취" in question for question in case["questions"])
    assert any(issue["title"] == "2단계 · 브라우저 자격증명 탈취"
               for issue in case["issues"])
    assert all("공격 단계 s" not in issue["title"] for issue in case["issues"])


def test_missing_completion_criteria_is_not_marked_confirmed(monkeypatch):
    result = {"cases": [{"incident": 1, "objective": "유포지 확인",
                         "issues": [_issue("ClickFix 유입", "user_action", "어떤 명령인가")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    case = issue_decision.decide("기사", "ClickFix 유입", "", {})[0]
    assert case["decision_status"] == "review_required"
    assert "달성 기준과 조사 한계가 모두 비어 있음" in case["review_reasons"]


def test_basic_analysis_prompt_defers_goals_until_issue_decision():
    prompt = analysis_worker.build_prompt("기사", "ClickFix 유입", "악성코드")
    assert "목표·질문·대응 판단은 이 단계에서 만들지 마라" in prompt
    assert "확인질문:" not in analysis_targets.indicator_spec()
    assert "조사가능:" in analysis_targets.indicator_spec()


def test_omitted_clickfix_is_retained_as_review_required(monkeypatch):
    result = {"cases": [{"incident": 1, "primary": "malware", "objective": "샘플 조사",
                         "issues": [_issue("악성 샘플", "malware", "동적 행위는 무엇인가")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    case = issue_decision.decide("Lunex", "ClickFix로 설치", "악성 샘플", {})[0]
    assert case["decision_status"] == "review_required"
    assert case["missing_issues"] == ["ClickFix"]
    assert any("ClickFix" in question for question in case["questions"])


def test_multi_incident_decisions_stay_in_their_own_case(monkeypatch):
    result = {"cases": [
        {"incident": 1, "objective": "첫째", "issues": [_issue("ClickFix 유입", "user_action", "첫 질문")]},
        {"incident": 2, "objective": "둘째", "issues": [_issue("별도 악성코드", "malware", "둘째 질문")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    original = {"incidents": ["사건 A", "사건 B"], "incident_map": {},
                "investigable": True}
    cases = issue_decision.decide("종합 기사", "ClickFix와 별도 악성코드", "사건별 분석", original)
    split = incident_scope.split(issue_decision.apply(original, cases), [])
    assert split[0]["targets"]["questions"] == ["첫 질문"]
    assert split[1]["targets"]["questions"] == ["둘째 질문"]
    assert split[1]["targets"]["issues"][0]["title"] == "별도 악성코드"


def test_unscoped_multi_incident_stage_requires_review(monkeypatch):
    result = {"cases": [
        {"incident": 1, "objective": "첫째", "issues": [_issue("사건 A", "malware", "첫 질문")]},
        {"incident": 2, "objective": "둘째", "issues": [_issue("사건 B", "malware", "둘째 질문")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    targets = {"incidents": ["사건 A", "사건 B"]}
    analysis = "[기술적 세부사항]\n1. 소속이 명시되지 않은 파일 실행\n[권장 대응]"
    cases = issue_decision.decide("종합 기사", "파일 실행", analysis, targets)
    assert all(case["decision_status"] == "review_required" for case in cases)
    assert any("1단계 · 소속이 명시되지 않은 파일 실행" in reason
               for reason in cases[0]["review_reasons"])


def test_fallback_stage_uses_action_instead_of_internal_id(monkeypatch):
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate", lambda *a, **k: "{}")
    analysis = ("[기술적 세부사항]\n1. 첫 단계\n2. 둘째 단계\n"
                "3. **Custom GPT ClickFix RAT 캠페인(1)**: MSI 설치 후 DLL을 로드한다\n"
                "[권장 대응]\n")
    case = issue_decision.decide("기사", "사용자 실행", analysis, {})[0]
    third = next(issue for issue in case["issues"] if "s3" in issue["step_ids"])
    assert third["title"] == "3단계 · MSI 설치 후 DLL을 로드한다"
    assert "s3" not in third["question"]


def test_invalid_decision_keeps_source_grounded_questions_for_review(monkeypatch):
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate", lambda *a, **k: '{}')
    article = "ClickFix 유입 이후 취약 드라이버 악용과 자격증명 탈취가 보고됐다."
    analysis = "[기술적 세부사항]\n1. ClickFix 유입\n2. 브라우저 자격증명 탈취\n[권고 조치]"
    case = issue_decision.decide("기사", article, analysis, {})[0]
    assert case["decision_status"] == "review_required"
    assert {issue["title"] for issue in case["issues"]} >= {
        "ClickFix", "취약 드라이버 악용", "자격증명 탈취"}
    assert case["missing_steps"] == []
    assert all(issue["source_check"] == "matched" for issue in case["issues"])
    assert len(case["questions"]) >= 3


def test_partial_multi_incident_result_preserves_valid_case(monkeypatch):
    result = {"cases": [{"incident": 2, "objective": "둘째 조사",
                         "issues": [_issue("사건 B", "malware", "둘째 질문")]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *a, **k: json.dumps(result, ensure_ascii=False))
    cases = issue_decision.decide("종합 기사", "사건 A와 사건 B가 보고됐다", "사건별 분석",
                                  {"incidents": ["사건 A", "사건 B"]})
    assert cases[0]["decision_status"] == "review_required"
    assert cases[0]["issues"][0]["source_check"] == "review_required"
    assert cases[1]["objective"] == "둘째 조사"
    assert cases[1]["questions"] == ["둘째 질문"]


def test_llm_exception_still_produces_review_questions(monkeypatch):
    def fail(*args, **kwargs):
        raise TimeoutError("model unavailable")

    monkeypatch.setattr(issue_decision.common_utils, "llm_generate", fail)
    case = issue_decision.decide("기사", "ClickFix 유입", "[기술적 세부사항]\n1. 유포 페이지", {})[0]
    assert case["decision_status"] == "review_required"
    assert any("ClickFix" in question for question in case["questions"])


def test_json_parser_accepts_trailing_explanation_after_valid_object():
    assert issue_decision._json('{"cases": []}\n추가 설명 {검토}') == {"cases": []}


def test_worker_passes_post_analysis_decision_to_investigation(monkeypatch):
    article = "ClickFix 유입. " * 100
    monkeypatch.setattr(analysis_worker, "fetch_article_text", lambda url: (article, []))
    monkeypatch.setattr(analysis_worker, "build_prompt", lambda *args: "prompt")
    monkeypatch.setattr(analysis_worker.common_utils, "llm_generate", lambda *a, **k: "analysis")
    monkeypatch.setattr(analysis_worker, "extract_category", lambda raw: ("악성코드", "분석 완료"))
    monkeypatch.setattr(analysis_worker.analysis_targets, "parse",
                        lambda raw: {"objective": "기존 목표", "questions": ["기존 질문"]})
    monkeypatch.setattr(analysis_worker.analysis_targets, "strip", lambda raw: raw)
    monkeypatch.setattr(analysis_worker.common_utils, "extract_iocs", lambda raw: [])
    monkeypatch.setattr(analysis_worker.issue_decision, "decide",
                        lambda *args: [{"objective": "ClickFix 유입 조사", "questions": ["어떤 명령인가"],
                                        "issues": [_issue("ClickFix 유입", "user_action", "어떤 명령인가")],
                                        "decision_status": "confirmed"}])
    captured = {}

    def investigate(*args, **kwargs):
        captured.update(kwargs["targets"])
        return {"route": {}, "targets": kwargs["targets"]}

    monkeypatch.setattr(analysis_worker.investigation, "build_for_article", investigate)
    record = analysis_worker.analyze_one({"ref": "r1", "url": "https://example.test/article",
                                          "title": "Lunex", "source_label": "test"})
    assert captured["objective"] == "ClickFix 유입 조사"
    assert captured["questions"] == ["어떤 명령인가"]
    assert record["targets"]["issues"][0]["title"] == "ClickFix 유입"


def test_worker_recovers_when_decision_function_raises(monkeypatch):
    article = "ClickFix 유입. " * 100
    monkeypatch.setattr(analysis_worker, "fetch_article_text", lambda url: (article, []))
    monkeypatch.setattr(analysis_worker, "build_prompt", lambda *args: "prompt")
    monkeypatch.setattr(analysis_worker.common_utils, "llm_generate", lambda *a, **k: "analysis")
    monkeypatch.setattr(analysis_worker, "extract_category", lambda raw: ("악성코드", "기본 분석 완료"))
    monkeypatch.setattr(analysis_worker.analysis_targets, "parse", lambda raw: {"primary": "malware"})
    monkeypatch.setattr(analysis_worker.analysis_targets, "strip", lambda raw: raw)
    monkeypatch.setattr(analysis_worker.common_utils, "extract_iocs", lambda raw: [])

    def fail(*args):
        raise RuntimeError("invalid model output")

    monkeypatch.setattr(analysis_worker.issue_decision, "decide", fail)
    captured = {}

    def investigate(*args, **kwargs):
        captured.update(kwargs["targets"])
        return {"route": {}, "targets": kwargs["targets"]}

    monkeypatch.setattr(analysis_worker.investigation, "build_for_article", investigate)
    record = analysis_worker.analyze_one({"ref": "r1", "url": "https://example.test/article",
                                          "title": "ClickFix", "source_label": "test"})
    assert record["targets"]["decision_status"] == "review_required"
    assert captured["issues"][0]["title"] == "ClickFix"
    assert captured["questions"]
