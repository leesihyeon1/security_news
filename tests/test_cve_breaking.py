"""취약점 속보 묶음 — 첫 보도로 잡는 신호와 잡음 제외."""
from datetime import datetime, timedelta, timezone

import cve_breaking

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def ev(source, title, hours_ago=1, summary="", **extra):
    at = (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")
    return dict({"id": source + title, "source": source, "title": title, "summary": summary,
                 "url": "https://news.example/{}/{}".format(source, abs(hash(title))),
                 "published_at": at, "fetched_at": at, "category": "취약점"}, **extra)


def items(events):
    return cve_breaking.build(events, now=NOW)["items"]


def test_named_vulnerability_is_shown_from_its_first_report():
    rows = items([ev("dailysecu", "[긴급] “로그인 없이 서버에서 코드 실행”…엔진엑스 취약점 5건 공개",
                     summary="티오리가 NGINX2Root 원격 코드 실행 취약점을 공개했다.")])
    assert len(rows) == 1
    assert rows[0]["group_label"] == "NGINX2Root"
    assert rows[0]["signals"] == ["named", "urgent"]
    assert rows[0]["outlets"] == 1


def test_contest_names_recap_jokes_and_product_posts_are_not_vulnerabilities():
    rows = items([
        ev("securityweek", "Researchers find 47 zero-days at Pwn2Own Berlin", summary="RCE exploits"),
        ev("thehackernews", "Weekly Recap: This2Shell, That2Shell, Everything's an RCE?"),
        ev("helpnetsecurity", "Product showcase: virtual patching stops HTTP2Shell", category="제품행사",
           summary="remote code execution"),
        ev("securityweek", "AI agents are a bane for website operators", summary="PHP2SHELL exploit traffic"),
    ])
    assert rows == []


def test_comparison_article_does_not_merge_two_named_vulnerabilities():
    rows = items([
        ev("thehackernews", "PHP2Shell: critical PHP RCE flaws", hours_ago=20, summary="remote code execution"),
        ev("dailysecu", "[긴급] PHP2Shell 이어 이번엔 Node2Shell… 인증 없이 서버 장악", hours_ago=2,
           summary="Node2Shell 원격 코드 실행"),
    ])
    labels = sorted(row["group_label"] for row in rows)
    assert labels == ["PHP2Shell"] or labels == ["Node2Shell", "PHP2Shell"]
    # 비교 기사의 주된 이름(제목 첫 이름)으로만 묶여, 두 이름이 한 카드에 함께 묶이지 않는다.
    assert all(len(row["names"]) == 1 for row in rows)


def test_name_and_cve_in_one_headline_join_the_same_card():
    rows = items([
        ev("thehackernews", "CVE-2026-123007: Critical NGINX HTTP/2 flaw lets attackers execute code", hours_ago=5,
           severity="critical"),
        ev("estsecurity_alyac", "엔진엑스 ‘NGINX2Root’ 취약점(CVE-2026-123007) 긴급 업데이트", hours_ago=2,
           summary="원격 코드 실행"),
    ])
    assert len(rows) == 1 and rows[0]["group_label"] == "NGINX2Root"
    assert rows[0]["cves"] == ["CVE-2026-123007"] and rows[0]["outlets"] == 2


def test_routine_patch_notices_do_not_count_as_multi_outlet_news():
    title = "Zoom 제품 보안 업데이트 권고 (CVE-2026-108187)"
    rows = items([ev(source, title, hours_ago=3, severity="critical") for source in ("kisa", "boannews", "dailysecu")])
    assert rows == []


def test_three_outlets_reporting_an_exploited_flaw_are_shown():
    rows = items([ev(source, "OpenSSH flaw CVE-2026-123158 exploited in the wild", hours_ago=hours,
                     exploitation_status="active")
                  for source, hours in (("securityweek", 6), ("thehackernews", 4), ("boannews", 2))])
    assert len(rows) == 1 and rows[0]["signals"] == ["outlets"] and rows[0]["outlets"] == 3


def test_kev_entry_leads_when_articles_only_mention_the_cve_in_passing():
    rows = items([
        ev("cisa_kev", "CVE-2026-41709 - Broadcom VMware ESX Insufficient Logging Vulnerability", hours_ago=3),
        ev("crowdstrike", "2026 Legal Threat Landscape Report", hours_ago=10, summary="CVE-2026-41709 was exploited"),
    ])
    assert len(rows) == 1 and rows[0]["kev"] is True
    assert rows[0]["source_label"] == "CISA KEV"
    assert rows[0]["title"].startswith("CVE-2026-41709 - Broadcom")


def test_stale_reports_drop_off_after_the_show_window():
    rows = items([ev("dailysecu", "[긴급] Java4Shell 원격 코드 실행 취약점 공개", hours_ago=cve_breaking.SHOW_HOURS + 1)])
    assert rows == []


def test_kev_card_title_matches_its_label_when_two_kev_cves_are_grouped():
    rows = items([
        ev("cisa_kev", "CVE-2026-114713 - UnrealIRCd Improper Neutralization Vulnerability", hours_ago=30),
        ev("cisa_kev", "CVE-2026-123039 - Check Point Incorrect Permission Assignment", hours_ago=3),
        ev("securityaffairs", "U.S. CISA adds UnrealIRCd and Check Point flaws to its catalog", hours_ago=2,
           summary="CVE-2026-114713 and CVE-2026-123039"),
    ])
    assert len(rows) == 1
    assert rows[0]["title"].startswith(rows[0]["group_label"])
