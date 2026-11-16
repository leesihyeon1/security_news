import json
from datetime import datetime, timezone

import threat_discovery as d

NOW = datetime(2026, 11, 13, 3, 0, tzinfo=timezone.utc)


def news(n, source, **extra):
    row = {"id": "s:%d" % n, "source": source, "url": "https://e.com/%d" % n, "title": "Gootloader returns %d" % n,
           "summary": "Gootloader campaign uses CVE-2026-11111 against WordPress sites.", "category": "악성코드",
           "published_at": "2026-11-12T01:00:00Z", "fetched_at": "2026-11-12T02:00:00Z",
           "exploitation_status": "active", "malware_family": "Gootloader", "affected_products": ["WordPress"],
           "cves": ["CVE-2026-11111"], "matched_assets": ["Fortigate"], "pirs": ["PIR-1"],
           "triage": {"level": "P1", "reasons": ["자사 자산 일치"]}}
    row.update(extra)
    return row


EVENTS = [news(1, "a"), news(2, "b"), news(3, "c"), news(4, "a")]


def model(final=None, review=None, hypothesis=None):
    """A fake model that answers the three prompts in order and records what it was shown."""
    answers = [
        hypothesis or {"hypothesis": "Gootloader가 다시 유포되고 있다.", "event_type": "악성코드 유포", "noise_risk": "low",
                       "claims": [{"text": "Gootloader 유포가 재개됐다.", "refs": ["A1", "A2"]},
                                  {"text": "WordPress 사이트가 이용된다.", "refs": ["A3"]},
                                  {"text": "근거 없는 주장.", "refs": ["A99"]}]},
        review or {"claims": [{"index": 0, "supported": "yes", "reason": "ok"}, {"index": 1, "supported": "yes", "reason": "ok"}],
                   "single_event": True, "new_or_escalating": True, "material_uncertainty": False, "problems": [], "recommendation": "confirm"},
        final or {"verdict": "confirmed", "confidence": "high", "title": "Gootloader 유포 재개", "summary": "요약.",
                  "why_now": "지금.", "who_is_affected": "WordPress 운영 조직.", "actions": ["CVE-2026-11111 패치"],
                  "detection": [], "reason": "근거 충분."},
    ]
    seen = []

    def generate(prompt):
        seen.append(prompt)
        return json.dumps(answers[len(seen) - 1], ensure_ascii=False)
    generate.seen = seen
    return generate


def test_spike_becomes_one_candidate_and_passes_every_stage():
    generate = model()
    result = d.discover(EVENTS, generate, now=NOW, model="m")
    [finding] = result["findings"]
    assert finding["verdict"] == "confirmed" and finding["malware"] == ["Gootloader"]
    assert result["funnel"]["signals"] == 1 and result["funnel"]["confirmed"] == 1   # malware, product and CVE signals merged
    assert [c["text"] for c in finding["stages"]["claims"]] == ["Gootloader 유포가 재개됐다.", "WordPress 사이트가 이용된다."]
    assert all(check["passed"] for check in finding["stages"]["checks"])
    assert len(generate.seen) == 3


def test_model_never_sees_internal_context_and_output_never_carries_it():
    generate = model()
    result = d.discover(EVENTS, generate, now=NOW, model="m")
    blob = " ".join(generate.seen) + json.dumps(result, ensure_ascii=False)
    assert all(word not in blob for word in ("Fortigate", "PIR-1", "자사 자산", "P1"))


def test_reviewer_rejection_and_code_rules_override_the_final_answer():
    rejected = d.discover(EVENTS, model(review={"claims": [], "single_event": True, "new_or_escalating": False,
                                                 "problems": ["제품 홍보"], "recommendation": "reject"}), now=NOW, model="m")
    assert rejected["findings"][0]["verdict"] == "rejected"
    reason = rejected["findings"][0]["reason"]
    assert reason.startswith("코드 검증에서 기각:") and "신규 또는 확대 여부를 확인하지 못함" in reason
    two_sources = [news(1, "a"), news(2, "b"), news(3, "a")]
    assert d.discover(two_sources, model(), now=NOW, model="m")["findings"][0]["verdict"] == "watch"


def test_text_naming_a_cve_absent_from_the_evidence_is_dropped():
    final = {"verdict": "confirmed", "confidence": "high", "title": "t", "summary": "CVE-2026-99999도 악용된다.", "why_now": "지금.",
             "who_is_affected": "x", "actions": ["CVE-2026-99999 패치", "플러그인 점검"], "detection": [], "reason": "r"}
    finding = d.discover(EVENTS, model(final=final), now=NOW, model="m")["findings"][0]
    assert finding["verdict"] == "watch" and finding["summary"] == "" and finding["actions"] == []
    assert "CVE-2026-99999" not in json.dumps({k: finding[k] for k in ("summary", "actions", "detection")})


def test_model_failure_publishes_numbers_only_and_cache_skips_repeat_calls():
    silent = d.discover(EVENTS, lambda prompt: "", now=NOW, model="m")
    assert silent["findings"][0]["verdict"] == "unreviewed" and silent["findings"][0]["stages"] is None
    cache = {}
    d.discover(EVENTS, model(), now=NOW, cache=cache, model="m")
    again = model()
    result = d.discover(EVENTS, again, now=NOW, cache=cache, model="m")
    assert again.seen == [] and result["findings"][0]["verdict"] == "confirmed"


def test_steady_topics_and_single_source_bursts_are_not_candidates():
    quiet = {"exploitation_status": "none", "cves": []}   # an actively exploited CVE is a candidate on its own
    steady = [news(n, "abc"[n % 3], published_at="2026-10-%02dT01:00:00Z" % (10 + n), fetched_at="2026-10-%02dT02:00:00Z" % (10 + n), **quiet)
              for n in range(1, 20)] + [news(n, "abc"[n % 3], **quiet) for n in range(21, 25)]
    assert d.discover(steady, None, now=NOW)["findings"] == []
    assert d.discover([news(1, "a"), news(2, "a"), news(3, "a")], None, now=NOW)["findings"] == []


def test_string_false_cannot_confirm_an_event_or_publish_mixed_event_guidance():
    review = {"claims": [{"index": 0, "supported": "yes"}, {"index": 1, "supported": "yes"}],
              "single_event": "false", "new_or_escalating": "false", "material_uncertainty": False,
              "problems": [], "recommendation": "confirm"}
    finding = d.discover(EVENTS, model(review=review), now=NOW)["findings"][0]
    assert finding["verdict"] == "watch" and finding["actions"] == []


def test_guidance_requires_real_excerpt_and_valid_reference():
    evidence = [{"title": "Update the affected plugin", "summary": "Install the vendor security update."}]
    good = {"text": "영향 플러그인 보안 업데이트 적용", "refs": ["A1"], "quote": "Install the vendor security update."}
    assert d.grounded_items([good], evidence, 4) == [good]
    assert d.grounded_items(["패치", {**good, "refs": ["A99"]}, {**good, "quote": "Disable all services immediately."}], evidence, 4) == []


def test_unknown_cve_in_title_is_removed_and_downgraded():
    finding = d.discover(EVENTS, model(final={"verdict": "confirmed", "title": "CVE-2026-99999 악용"}), now=NOW)["findings"][0]
    assert finding["verdict"] == "watch" and "99999" not in finding["title"]


def test_cache_changes_when_summary_or_reference_order_changes():
    articles, _, _ = d.td.scan(EVENTS, NOW)
    [facts], _ = d.candidates(list(articles.values()), NOW.astimezone(d.td.KST).date())
    original = d.signature(facts, "m")
    facts["evidence"].reverse()
    assert d.signature(facts, "m") != original
    original = d.signature(facts, "m")
    facts["evidence"][0]["summary"] = "Corrected article summary"
    assert d.signature(facts, "m") != original


def test_small_subset_does_not_merge_with_a_broad_product_topic():
    broad = {"articles": [{"url": str(i)} for i in range(10)]}
    narrow = {"articles": [{"url": str(i)} for i in range(3)]}
    assert len(d.merge_signals([broad, narrow])) == 2


def test_uncertainty_prevents_confirmation_even_when_final_model_confirms():
    review = {"claims": [{"index": 0, "supported": "yes"}, {"index": 1, "supported": "yes"}],
              "single_event": True, "new_or_escalating": True, "material_uncertainty": True,
              "problems": ["영향 버전 상충"], "recommendation": "confirm"}
    assert d.discover(EVENTS, model(review=review), now=NOW)["findings"][0]["verdict"] == "watch"
