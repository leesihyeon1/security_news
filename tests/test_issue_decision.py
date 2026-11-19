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


def test_unmapped_analysis_stage_is_reported_not_turned_into_a_question(monkeypatch):
    """실측(Gootloader 재분석): 판단이 다루지 않은 단계마다 단계 문장을 그대로 제목·질문·
    사내 확인 항목으로 붙여, 피해 통계·수사기관 압수에도 "로그에서 실행 흔적"을 묻게 됐다."""
    result = {"cases": [{"incident": 1, "objective": "영향 범위를 확인한다", "criteria": ["hunting_query"],
                         "issues": [{**_issue("ClickFix 유입", "user_action", "유입 명령은 무엇인가"),
                                     "step_ids": ["s1"]}]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    analysis = "[기술적 세부사항]\n1. ClickFix 유입\n2. 수사기관이 서버 235개를 압수\n[권장 대응]\n"
    case = issue_decision.decide("기사", "ClickFix 유입", analysis, {})[0]
    assert case["missing_steps"] == ["s2"]
    assert case["decision_status"] == "review_required"
    assert [issue["title"] for issue in case["issues"]] == ["ClickFix 유입"]
    assert case["questions"] == ["유입 명령은 무엇인가"]
    assert not any("압수" in check for check in case["internal_checks"])
    assert case["objective"] == "영향 범위를 확인한다"   # 목표에 "추가 조사" 꼬리를 달지 않는다
    assert case["review_reasons"] == ["판단에서 다루지 않은 기본 분석 단계: 2단계 — 공격 행위인지 확인 필요"]


def test_every_step_assigned_keeps_the_case_confirmed(monkeypatch):
    result = {"cases": [{"incident": 1, "objective": "유입 경로 헌팅", "criteria": ["hunting_query"],
                         "issues": [
                             {**_issue("SEO 포이즈닝 유입", "malware", "유포 URL 패턴은 무엇인가"), "step_ids": ["s1"]},
                             {"title": "수사기관 인프라 압수", "type": "other", "evidence": "수사기관이 서버 235개를 압수",
                              "disposition": "established", "reason": "기사로 확인된 사실", "question": "",
                              "decision": "압수 도메인 목록 공개 시 차단 반영", "step_ids": ["s2"]}]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *args, **kwargs: json.dumps(result, ensure_ascii=False))
    analysis = "[기술적 세부사항]\n1. SEO 포이즈닝 유입\n2. 수사기관이 서버 235개를 압수\n[권장 대응]\n"
    case = issue_decision.decide("기사", "SEO 포이즈닝 유입. 수사기관이 서버 235개를 압수", analysis, {})[0]
    assert case["decision_status"] == "confirmed"
    assert case["missing_steps"] == [] and case["review_reasons"] == []
    assert case["questions"] == ["유포 URL 패턴은 무엇인가"]


def test_prompt_asks_to_assign_every_step_and_park_non_attack_facts():
    assert "모든 단계 ID를 빠짐없이" in issue_decision.PROMPT
    assert "수사기관의 압수" in issue_decision.PROMPT
    assert "[기본 분석의 공격 단계]" not in issue_decision.PROMPT


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


def test_long_fallback_stage_preserves_full_action_in_issue_and_question(monkeypatch):
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate", lambda *a, **k: "{}")
    detail = ("피싱 이메일로 디지털 서명된 MSP360 설치 파일 VIP_ECARD_INVITATION.exe를 전달하고 "
              + "여러 정상 클라우드 저장소에서 내려받게 한 뒤 " * 8
              + "ScreenConnect를 설치해 원격 접속을 유지함")
    analysis = "[기술적 세부사항]\n1. {}\n[권장 대응]\n".format(detail)
    case = issue_decision.decide("MSP360", "원격 관리 도구의 피싱 악용", analysis, {})[0]
    issue = next(item for item in case["issues"] if item["step_ids"] == ["s1"])
    assert issue["title"] == "1단계 · " + detail
    assert detail in issue["question"]
    assert detail in issue["evidence"]
    assert "…" not in issue["title"] + issue["question"]
    assert "VIP_ECARD_INVITATION.exe" in issue["title"]


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


def test_fallback_questions_ask_public_sources_and_keep_internal_checks_apart(monkeypatch):
    """실측(2026-11-19): 판단 응답을 못 쓴 기사의 단계 질문이 모두 "원문·샘플·로그 근거"를
    물어 외부 조회로는 하나도 확인되지 않았다. 로그 확인은 사내 확인 항목으로 따로 둔다."""
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate", lambda *a, **k: "{}")
    analysis = "[기술적 세부사항]\n1. 변조된 웹사이트로 방문자를 유도\n2. C2 서버와 통신\n[권고 조치]"
    case = issue_decision.decide("Gootloader", "변조된 웹사이트", analysis, {})[0]
    assert len(case["questions"]) == 2
    assert not any(issue_decision.INTERNAL_RE.search(question) for question in case["questions"])
    assert len(case["internal_checks"]) == 2
    assert all("로그" in check for check in case["internal_checks"])
    assert "1단계 · 변조된 웹사이트로 방문자를 유도" in case["internal_checks"][0]


def test_internal_only_model_question_moves_to_internal_check(monkeypatch):
    result = {"cases": [{"incident": 1, "objective": "침해 단말을 가린다", "criteria": ["hunting_query"],
                         "issues": [
                             _issue("웹셸 설치", "malware", "사내 서버에 웹셸이 실행됐는지 로그로 확인되는가"),
                             {**_issue("C2 통신", "malware", "C2 도메인은 무엇인가"),
                              "internal_check": "프록시 로그에서 C2 도메인 접속 확인"},
                             {**_issue("기존 블로그 분석", "other", "공개 블로그가 제시한 해시는 무엇인가")}]}]}
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate",
                        lambda *a, **k: json.dumps(result, ensure_ascii=False))
    article = "웹셸 설치 이후 C2 통신이 있었고 기존 블로그 분석이 있다."
    case = issue_decision.decide("기사", article, "", {})[0]
    webshell, c2, blog = case["issues"]
    assert webshell["internal_check"] == "사내 서버에 웹셸이 실행됐는지 로그로 확인되는가"
    assert webshell["question"].startswith("웹셸 설치: 원문과 공개 보고서")
    assert c2["question"] == "C2 도메인은 무엇인가"
    assert c2["internal_check"] == "프록시 로그에서 C2 도메인 접속 확인"
    # "블로그"의 "로그"는 사내 로그가 아니다.
    assert blog["question"] == "공개 블로그가 제시한 해시는 무엇인가"
    assert "internal_check" not in blog
    assert case["internal_checks"] == [webshell["internal_check"], c2["internal_check"]]
    assert not any(issue_decision.INTERNAL_RE.search(question) for question in case["questions"])


def test_internal_checks_follow_each_incident(monkeypatch):
    monkeypatch.setattr(issue_decision.common_utils, "llm_generate", lambda *a, **k: "{}")
    analysis = "[기술적 세부사항]\n1. 사건 A가 백도어를 설치\n2. 사건 B가 SMS를 가로챔\n[권고 조치]"
    targets = {"incidents": ["사건 A", "사건 B"]}
    cases = issue_decision.decide("종합", "사건 A와 사건 B", analysis, targets)
    applied = issue_decision.apply(targets, cases)
    scoped = incident_scope._split_targets(applied, ["사건 A", "사건 B"], {})
    assert ["백도어" in " ".join(slot["internal_checks"]) for slot in scoped] == [True, False]
    assert ["SMS" in " ".join(slot["internal_checks"]) for slot in scoped] == [False, True]
