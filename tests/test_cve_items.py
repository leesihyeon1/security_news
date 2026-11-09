import json

import generate_report as gr


def _event(source, cves, **extra):
    base = {"id": "{}:{}".format(source, cves[0]), "source": source, "cves": cves,
            "published_at": "2026-09-26T10:00:00", "title": cves[0], "summary": ""}
    base.update(extra)
    return base


def test_one_row_per_cve_merging_sources_and_keeping_public_fields_only():
    events = [
        _event("nvd", ["CVE-2026-1000"], severity="CRITICAL", score=9.8,
               summary="In the Linux kernel, the following vulnerability has been resolved: ocfs2: bound namelen.",
               matched_assets=["Cisco"], pirs=["PIR-1"], triage={"level": "P3", "reasons": ["자사 자산 매칭"]}),
        _event("cisa_kev", ["CVE-2026-1000"], severity="KEV", kev=True,
               title="CVE-2026-1000 - Linux Kernel Out-of-Bounds Write Vulnerability",
               triage={"level": "P1", "matched_assets": ["Cisco"]}),
    ]
    items = gr.build_cve_items(events)
    assert len(items) == 1
    row = items[0]
    assert row["cve"] == "CVE-2026-1000"
    assert row["sources"] == ["NVD CVE", "CISA KEV"]
    assert row["severity"] == "CRITICAL" and row["cvss"] == 9.8 and row["kev"] is True
    assert row["level"] == "P1"
    assert row["title"] == "Linux Kernel Out-of-Bounds Write Vulnerability"
    # 리눅스 커널 상용구는 뗀다
    assert row["summary"].startswith("ocfs2: bound namelen")
    serialized = json.dumps(items, ensure_ascii=False)
    assert "Cisco" not in serialized and "PIR" not in serialized and "자사" not in serialized


def test_korean_summary_that_names_the_cve_wins():
    events = [
        _event("nvd", ["CVE-2026-2000"], severity="HIGH", score=8.1, summary="English NVD description."),
        _event("thehackernews", ["CVE-2026-2000", "CVE-2026-2001"],
               ai_summary="CISA가 CVE-2026-2001 취약점을 KEV에 추가했다."),
        _event("boannews", ["CVE-2026-2000"], ai_summary="CVE-2026-2000 원격 코드 실행 취약점이 공개됐다."),
    ]
    by_cve = {row["cve"]: row for row in gr.build_cve_items(events)}
    assert by_cve["CVE-2026-2000"]["summary"] == "CVE-2026-2000 원격 코드 실행 취약점이 공개됐다."


def test_specific_description_beats_an_off_topic_roundup_summary():
    events = [
        _event("nvd", ["CVE-2026-2100"], severity="HIGH", score=8.0,
               summary="Buffer overflow in Example Router allows remote code execution."),
        _event("securityaffairs", ["CVE-2026-2100", "CVE-2026-2101"],
               ai_summary="시스코 ISE 인증 우회 제로데이(CVE-2026-2101)가 실제 악용 중이다."),
    ]
    by_cve = {row["cve"]: row for row in gr.build_cve_items(events)}
    assert by_cve["CVE-2026-2100"]["summary"].startswith("Buffer overflow in Example Router")
    assert by_cve["CVE-2026-2101"]["summary"].startswith("시스코 ISE")


def test_roundup_article_does_not_lend_its_level_or_products_to_unmentioned_cves():
    events = [_event("thehackernews", ["CVE-2026-2200", "CVE-2026-2201"], epss=0.1,
                     title="Weekly Recap: Cisco ISE zero-day, AI plugin supply chain attacks",
                     ai_summary="시스코 ISE 인증 우회 제로데이(CVE-2026-2201)가 실제 악용 중이다.",
                     affected_products=["Cisco ISE", "Claude Code"], triage={"level": "P1"})]
    by_cve = {row["cve"]: row for row in gr.build_cve_items(events)}
    assert by_cve["CVE-2026-2200"] == {"cve": "CVE-2026-2200", "sources": ["The Hacker News"]}
    assert by_cve["CVE-2026-2201"]["level"] == "P1"
    assert by_cve["CVE-2026-2201"]["products"] == ["Cisco ISE", "Claude Code"]


def test_order_puts_carded_then_kev_then_level_then_severity_then_cvss():
    events = [
        _event("nvd", ["CVE-2026-3001"], severity="HIGH", score=7.0),
        _event("nvd", ["CVE-2026-3002"], severity="CRITICAL", score=9.9),
        _event("nvd", ["CVE-2026-3003"], severity="HIGH", score=7.5, kev=True),
        _event("nvd", ["CVE-2026-3004"], severity="HIGH", score=7.2, triage={"level": "P2"}),
        _event("nvd", ["CVE-2026-3005"], severity="HIGH", score=7.1),
    ]
    cards = [{"cve_ids": ["CVE-2026-3005"]}]
    order = [row["cve"] for row in gr.build_cve_items(events, cards)]
    assert order == ["CVE-2026-3005", "CVE-2026-3003", "CVE-2026-3004", "CVE-2026-3002", "CVE-2026-3001"]
    carded = [row for row in gr.build_cve_items(events, cards) if row.get("in_cards")]
    assert [row["cve"] for row in carded] == ["CVE-2026-3005"]


def test_empty_fields_are_not_serialized():
    row = gr.build_cve_items([_event("nvd", ["CVE-2026-4000"], severity="HIGH", score=7.3)])[0]
    assert set(row) == {"cve", "sources", "severity", "cvss", "published"}


def test_payload_carries_cve_items():
    stats = gr.build_stats([])
    payload = gr.build_dashboard_payload("t", "daily", "2026-09-26 00:00 ~ 2026-09-27 00:00 (UTC)", stats, "",
                                         [], [], [], cve_items=[{"cve": "CVE-2026-5000"}])
    assert payload["cve_items"] == [{"cve": "CVE-2026-5000"}]
