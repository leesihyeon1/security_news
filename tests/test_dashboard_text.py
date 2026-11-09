import json
import re
from datetime import datetime

from dashboard_text import (event_summary, summary_excerpt, public_text, public_evidence,
                             public_narrative, redact_private_environment, redact_asset_mentions)
import publish_web_dashboard as publisher


def test_excerpt_keeps_complete_sentence():
    assert summary_excerpt("Patch available. " + "Details " * 30, 40) == "Patch available."


def test_excerpt_preserves_versions_and_marks_incomplete_sentence():
    value = summary_excerpt("Version 1.2.3 requires " + "updates " * 20, 40)
    assert value.startswith("Version 1.2.3 requires")
    assert value.endswith("\u2026")
    assert len(value) <= 40


def test_summary_uses_nonblank_source_and_explicit_missing_state():
    assert event_summary({"ai_summary": "  ", "summary": "원문 요약입니다."}, 200) == "원문 요약입니다."
    assert event_summary({"summary": "An English article."}, 200) == "요약 미제공 · 원문 확인"
    assert event_summary({}, 200) == "요약 미제공 · 원문 확인"


def test_index_backfills_missing_values_and_preserves_schema(tmp_path, monkeypatch):
    event = {"id": "asec:1", "source": "asec", "title": "Article",
             "url": "https://example.com/1", "fetched_at": datetime.utcnow().isoformat(),
             "category": "  ", "ai_summary": "  ", "summary": ""}
    monkeypatch.setattr(publisher.common_utils, "iter_lines_reverse", lambda _: iter([json.dumps(event)]))
    publisher._rebuild_search_index_from_events(tmp_path)
    raw = (tmp_path / "dashboard/data/search-index.json").read_text(encoding="utf-8")
    entries = json.loads(raw)
    assert len(entries) == 1
    assert entries[0]["category"] == "미분류"
    assert entries[0]["summary"] == "요약 미제공 · 원문 확인"
    assert entries[0]["type"] == "article"
    assert "\n" not in raw


def test_public_text_removes_private_context_but_preserves_public_products():
    assert public_text("자사 Check Point 장비가 영향받습니다. Check Point 패치가 공개됐습니다.") == "Check Point 패치가 공개됐습니다."


def test_public_text_catches_insight_leak_phrasings_without_needing_product_names():
    """실측(2026-09-22, 심층분석 insights API): 아래 문장들이 인증 없는 공개 API로
    그대로 나갔다. 이 넷은 우리가 무엇을 쓰는지 몰라도 그 자체로 유출이다 — 내부
    파일명, PIR 식별자, "당사가 이런 내부 목록을 갖고 있다"는 문구 자체가 정찰
    정보다. 그래서 product_names 없이 public_text()만으로 걸러져야 한다."""
    leaked = [
        "당사 관리 자산 목록(Arista, Juniper, Citrix, Fortigate 등)에 Orkes Conductor가 없어 직접 노출 대상 아님",
        "당사 관리 자산 인벤토리 27종에 Orkes Conductor가 없으므로",
        "사내 자산 목록(inventory.yml)과 대조",
        "우리 환경: Windows 단말 보유, 웹 프록시 경유 아웃바운드 허용",
    ]
    for sentence in leaked:
        assert public_text(sentence) == "", sentence


def test_public_text_keeps_generic_advice_that_names_no_real_product():
    """실측(2026-09-22): 첫 시도에서 "사내"·"자산 목록"만으로 걸렀더니, 모든 취약점
    리포트에 붙는 정형 조치 문구까지 같이 사라졌다(384개 필드, 36개 레코드). 실제
    보유 제품 이름이 없으면 "확인하라"는 조치 문구는 유용한 정보이지 유출이 아니다."""
    kept = [
        "개발자가 설치 스니펫을 붙여넣는 정상 작업도 걸리니, 먼저 1~2주 돌려 사내 정상 패턴을 예외 처리한 뒤 알림으로 올린다.",
        "사내에서 이 저장소·패키지를 내려받은 이력이 있는지 확인한다.",
        "우리 환경의 해당 제품 보유 여부로 정해집니다.",
        "· 영향 제품: huggingface diffusers < 0.38.0. 자산 목록과 대조해 해당 버전이 있는지 확인합니다.",
        "아래 쿼리로 해당 제품·버전이 사내에 있는지부터 확인한다.",
        "Defender 취약점 관리(TVM)가 수집한 소프트웨어 인벤토리에서 직접 찾는다.",
        "공격자가 운영 중인 C2 서버는 45.33.12.9였다.",
        "이 취약점은 Cisco ISE 3.2 이상 버전에 영향을 준다.",
        "패치를 적용하고 로그를 확인하십시오.",
    ]
    for sentence in kept:
        # public_text()는 문장 경계에서 줄바꿈으로 다시 잇는다(여러 문장을 한 문단으로
        # 두지 않는 원래 동작) — 아무것도 지워지지 않았는지는 공백을 정규화해서 비교한다.
        normalized = re.sub(r"\s+", " ", public_text(sentence)).strip()
        expected = re.sub(r"\s+", " ", sentence).strip()
        assert normalized == expected, sentence


def test_redact_asset_mentions_strips_only_when_a_real_product_co_occurs():
    names = ["Cisco", "IOS XR", "Citrix"]
    leaked = [
        "자산 목록에 Cisco 장비 포함.",
        "사내 운영 중인 Cisco IOS XR 버전이 조회된 4개 CVE 영향 버전에 포함되는가?",
    ]
    for sentence in leaked:
        assert redact_asset_mentions(sentence, names) == "", sentence

    # 기사 자체가 Cisco 제품을 다루는 문장은 "사내/자산" 표시가 없으면 그대로 남는다 —
    # 실제 침해 대상(공격자 쪽)을 설명하는 문장까지 지우면 판단이 무의미해진다.
    kept = "이 취약점은 Cisco ISE 3.2 이상 버전에 영향을 준다."
    assert redact_asset_mentions(kept, names) == kept


def test_redact_private_environment_walks_nested_investigation_record():
    names = ["Cisco", "Arista", "Fortigate", "Citrix", "Juniper"]
    record = {
        "route": {"explain": "이 도메인은 공격자 인프라로 확인됩니다."},
        "synthesis": {
            "headline": "당사 관리 자산 목록(Arista, Juniper 등)에 없어 직접 노출 대상 아님",
            "confirmed": ["원문 확인: CVE-2026-0001은 CVSS 9.8입니다.",
                          "자산 목록에 Cisco 장비 포함."],
            "exposure": {"who": "우리 환경: Windows 단말 보유",
                        "basis": "기사의 영향 대상에 근거한 조건부 판단입니다."},
        },
        "action_plan": [{"action": "패치를 적용한다", "when": "즉시"},
                        {"action": "아래 쿼리로 해당 제품·버전이 사내에 있는지부터 확인한다.", "when": "오늘"}],
    }
    cleaned = redact_private_environment(record, names)
    dumped = json.dumps(cleaned, ensure_ascii=False)
    assert "Arista" not in dumped and "Fortigate" not in dumped and "당사" not in dumped
    assert "우리 환경" not in dumped and "자산 목록에 Cisco" not in dumped
    # 공개 가능한 사실과, 제품 이름 없는 정형 조치 문구는 그대로 남아야 한다
    assert "공격자 인프라로 확인됩니다" in dumped
    assert "CVSS 9.8" in dumped
    assert "패치를 적용한다" in dumped
    assert "아래 쿼리로 해당 제품·버전이 사내에 있는지부터 확인한다." in dumped
    assert cleaned["action_plan"][0]["when"] == "즉시"


def test_evidence_does_not_invent_verification_or_expose_assets():
    result = public_evidence({"url": "https://example.com", "kev": True,
                              "matched_assets": ["private"], "fetched_at": "2026-09-22T00:00:00Z"}, "Source")
    assert result["collected_at"] == "2026-09-22T00:00:00Z"
    assert "verified_at" not in result
    assert "private" not in json.dumps(result)
    assert public_evidence({"url": "javascript:alert(1)"}, "Source")["url"] == ""


def test_dashboard_never_reuses_internal_narrative():
    import generate_report as report
    from collections import Counter
    stats = {"total": 0, "p1": [], "p2": [], "info_by_category": Counter(), "by_source": Counter()}
    result = report.build_dashboard_payload("Report", "daily", "Period", stats,
                                            "자사 비밀장비 보유 현황", [], [], [])
    assert "비밀장비" not in json.dumps(result, ensure_ascii=False)


def test_narrative_preserves_original_sections_and_korean_body():
    text = "[총평]\n보안 업데이트가 필요합니다.\n[핵심 위협 TOP 3]\n1. Cisco 장비의 취약점이 확인됐습니다.\n[자사 자산 관련]\n자사 비밀 장비가 있습니다.\n[권고 조치]\n1. 최신 패치를 적용하는 것이 좋습니다."
    result = public_narrative(text)
    assert "[총평]" in result and "[핵심 위협 TOP 3]" in result and "[권고 조치]" in result
    assert "Cisco 장비" in result
    assert "비밀" not in result and "자사 자산 관련" not in result
    assert "Please patch" not in public_narrative("[권고 조치]\nPlease patch immediately.")
    empty = public_narrative("[핵심 위협 TOP 3]\n\n[권고 조치]\n패치를 적용하는 것이 좋습니다.")
    assert "1. [권고 조치]" not in empty
    assert "한국어 요약을 준비하지 못했습니다" in empty
