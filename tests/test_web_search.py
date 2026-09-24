import web_search


def test_terms_from_uses_fixed_targets_first():
    targets = {"malware": ["GhostCode"], "actors": ["WaterPlum"], "cves": ["CVE-2026-1234"]}
    terms = web_search.terms_from(targets)
    assert terms == ["GhostCode", "WaterPlum"][:web_search.MAX_QUERIES_PER_ARTICLE]


def test_terms_from_excludes_already_answered():
    targets = {"malware": ["GhostCode", "OtherMal"]}
    terms = web_search.terms_from(targets, exclude=["GhostCode"])
    assert "GhostCode" not in terms
    assert "OtherMal" in terms


def test_terms_from_adds_question_keyword_when_room_left():
    targets = {"malware": ["GhostCode"]}  # 고정 용어가 한 자리만 채움
    terms = web_search.terms_from(targets, open_questions=["유포지가 아직 살아있는가"])
    assert terms[0] == "GhostCode"
    assert len(terms) == 2
    assert terms[1] != "GhostCode"


def test_terms_from_question_keyword_skips_stopwords_and_short_tokens():
    keyword = web_search._question_keyword("이것이 그것인가")
    assert keyword == "" or len(keyword) >= 2


def test_terms_from_does_not_exceed_article_plus_question_cap():
    targets = {"malware": ["A", "B", "C"]}  # 고정 용어만으로 이미 상한 도달
    terms = web_search.terms_from(
        targets, open_questions=["질문 하나 유포지가 살아있는가", "질문 둘 표적이 누구인가"])
    assert len(terms) <= web_search.MAX_QUERIES_PER_ARTICLE + web_search.MAX_QUESTION_TERMS


def test_security_query_wraps_names_but_not_cves():
    assert "malware" in web_search.security_query("GhostCode").lower()
    assert web_search.security_query("CVE-2026-12345") == "CVE-2026-12345"


def test_analyze_returns_none_without_provider(monkeypatch):
    monkeypatch.delenv("BRAVE_SEARCH_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_CSE_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_CSE_CX", raising=False)
    assert web_search.analyze({"malware": ["GhostCode"]}) is None


def test_analyze_passes_open_questions_into_terms_from(monkeypatch):
    monkeypatch.setattr(web_search, "available", lambda: True)
    captured = {}

    def fake_terms_from(targets, exclude=(), open_questions=None):
        captured["open_questions"] = open_questions
        return []

    monkeypatch.setattr(web_search, "terms_from", fake_terms_from)
    result = web_search.analyze({"malware": ["X"]}, open_questions=["질문"])
    assert result is None  # terms_from 빈 목록 -> analyze는 None
    assert captured["open_questions"] == ["질문"]
