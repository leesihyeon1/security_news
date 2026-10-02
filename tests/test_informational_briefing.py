import json

import pytest

import article_kind
import analysis_worker
import briefing
import investigation
import reference_lookup
import refresh_analysis_workflow
import resynthesize
import response_synth
import web_search


def _targets():
    return {"article_kind": "informational", "article_subtype": "제품·사업 발표",
            "article_kind_reason": "특정 공격 사건이 아닌 사업 발표입니다.",
            "topics": ["카테나-X(Catena-X)"], "questions": ["Catena-X는 무엇인가?"],
            "criteria": ["background_brief", "reading_list"]}


def test_article_kind_keeps_informational_business_news_out_of_threat_route():
    result = article_kind.classify("제품행사", {"article_type_declared": "informational",
                                             "topics": ["Catena-X"]}, [],
                                   text="LG U+가 Catena-X 지원을 발표했다")
    assert result["kind"] == "informational"
    assert article_kind.classify("기술동향", {"article_type_declared": "informational",
                                         "cves": ["CVE-2026-12345"]}, [])["kind"] == "threat"


def test_informational_route_skips_attack_build(monkeypatch):
    monkeypatch.setattr(investigation, "build", lambda *args, **kwargs:
                        (_ for _ in ()).throw(AssertionError("attack build ran")))
    monkeypatch.setattr(briefing, "_lookup_background", lambda *args: [])
    monkeypatch.setattr(briefing, "_search_web", lambda *args: None)
    monkeypatch.setattr(briefing, "_read_sources", lambda *args: [])
    block = investigation.build_for_article([], title="Catena-X 사업 발표",
                                            targets=_targets(), synthesize=False)
    assert block["article_kind"] == "informational"
    assert block["patterns"] == []
    assert block["seeds"] == []
    assert block["response"] is None
    assert not block.get("followup_results")


def test_background_search_does_not_add_malware_context(monkeypatch):
    queries = []

    def fake_search(query, num=4):
        queries.append(query)
        return ([{"title": "Catena-X official documentation",
                  "link": "https://catena-x.net/docs", "site": "catena-x.net",
                  "snippet": "Catena-X data space"}], "")

    monkeypatch.setattr(web_search, "search", fake_search)
    result = web_search.background(["카테나-X(Catena-X)"])
    assert queries == ['"Catena-X"']
    assert result["results"][0]["url"] == "https://catena-x.net/docs"


class _WikiResponse:
    status_code = 200

    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data


def _wiki(pages, summary):
    def fake_get(url, **kwargs):
        return _WikiResponse({"pages": pages} if "/search/" in url else summary)
    return fake_get


def test_wikipedia_lookup_rejects_unrelated_title(monkeypatch):
    summary = {"title": "Catena", "extract": "A different subject",
               "content_urls": {"desktop": {"page": "https://en.wikipedia.org/wiki/Catena"}}}
    monkeypatch.setattr(reference_lookup.network_safety, "safe_get",
                        _wiki([{"title": "Catena"}], summary))
    assert reference_lookup.lookup_many(["카테나-X(Catena-X)"]) == []


def test_wikipedia_lookup_rejects_section_redirect_and_accepts_exact_title(monkeypatch):
    redirect = [{"title": "Produce traceability", "matched_title": "Digital Product Passport",
                 "anchor": "Legislative"}]
    summary = {"title": "Produce traceability", "extract": "x" * 40,
               "content_urls": {"desktop": {"page": "https://en.wikipedia.org/wiki/Produce_traceability"}}}
    monkeypatch.setattr(reference_lookup.network_safety, "safe_get", _wiki(redirect, summary))
    assert reference_lookup.wikipedia("디지털 제품 여권(Digital product passport)") is None

    exact = {"title": "General Data Protection Regulation", "extract": "EU regulation",
             "content_urls": {"desktop": {"page": "https://en.wikipedia.org/wiki/GDPR"}}}
    monkeypatch.setattr(reference_lookup.network_safety, "safe_get",
                        _wiki([{"title": "General Data Protection Regulation",
                                "matched_title": "GDPR"}], exact))
    assert reference_lookup.wikipedia("GDPR")["lang"] == "en"


def test_briefing_synthesis_grounding_and_no_attack_followups(monkeypatch):
    seen = {}

    def fake_llm(prompt, **kwargs):
        seen["prompt"] = prompt
        return json.dumps({"verdict": "확인됨", "headline": "Catena-X 제휴 발표",
                           "confirmed": ["기사: Catena-X 제휴를 발표했다"],
                           "unconfirmed": ["내부 적용 여부는 미확인"],
                           "plan": [{"action": "evil.example 차단", "owner": "SOC"}],
                           "question_status": [], "exposure": {"who": "내부 적용 미확인"}},
                          ensure_ascii=False)

    monkeypatch.setattr(response_synth.common_utils, "llm_generate", fake_llm)
    result = response_synth.synthesize_briefing(
        "Catena-X 제휴", "사업 발표", _targets(), {},
        article="Catena-X 제휴를 발표했다", materials="")
    assert "malware OR" not in seen["prompt"]
    assert result["verdict"] == "정보성 기사"
    assert result["exposure"]["who"].startswith("공격 사건이 아니어서")
    assert result["plan"] == []
    assert result["followups"] == []


def test_worker_classifies_before_decision_and_routes_informational_article(monkeypatch):
    body = "카테나-X 협력 사업을 발표했다. " * 60
    analysis = ("[핵심 요약]\n카테나-X 협력 사업을 발표했다.\n"
                "[조사 대상]\n기사유형: 정보성\n주제: 카테나-X(Catena-X)\n"
                "조사가능: 아니오\n")
    captured = {}
    monkeypatch.setattr(analysis_worker, "fetch_article_text", lambda url: (body, []))
    monkeypatch.setattr(analysis_worker.common_utils, "llm_generate", lambda *args, **kwargs: "ok")
    monkeypatch.setattr(analysis_worker, "extract_category", lambda raw: ("제품행사", analysis))

    def fake_decide(title, article, summary, targets):
        captured["at_decision"] = targets.get("article_kind")
        return []

    def fake_build(*args, **kwargs):
        captured["at_investigation"] = kwargs["targets"].get("article_kind")
        return {"article_kind": "informational", "route": {"label": "정보성 기사"}}

    monkeypatch.setattr(analysis_worker.issue_decision, "decide", fake_decide)
    monkeypatch.setattr(analysis_worker.investigation, "build_for_article", fake_build)
    result = analysis_worker.analyze_one({"ref": "sample", "title": "카테나-X 협력 발표",
                                          "url": "https://example.com/article"})
    assert captured == {"at_decision": "informational", "at_investigation": "informational"}
    assert result["targets"]["article_kind"] == "informational"


def test_resynthesize_uses_briefing_model_for_informational_record(monkeypatch):
    record = {"title": "Catena-X 사업 발표", "url": "https://example.com/article",
              "analysis": "사업 발표", "targets": _targets(),
              "investigation": {"article_kind": "informational", "lookup_status": [],
                                "background": [{"url": "https://en.wikipedia.org/wiki/Catena-X",
                                                "title": "Catena-X", "summary": "자료"}],
                                "route": {"label": "정보성 기사"}}}
    called = []
    monkeypatch.setattr(resynthesize.response_synth, "synthesize", lambda *a, **k:
                        (_ for _ in ()).throw(AssertionError("incident model ran")))
    monkeypatch.setattr(resynthesize.response_synth, "synthesize_briefing", lambda *a, **k:
                        (called.append(True) or {"verdict": "부분 확인", "headline": "사업 발표",
                                                 "confirmed": [], "unconfirmed": [], "plan": [],
                                                 "question_status": [], "steps": []}))
    monkeypatch.setattr(resynthesize.common_utils, "inventory_product_terms", lambda: [])
    assert resynthesize.rebuild(record)
    assert called
    assert record["investigation"]["synthesis"]["headline"] == "사업 발표"


def test_attack_workflow_refresh_does_not_reclassify_informational_record():
    record = {"targets": _targets(), "investigation": {"article_kind": "informational"}}
    with pytest.raises(ValueError, match="정보성 기사"):
        refresh_analysis_workflow.prepare(record)
