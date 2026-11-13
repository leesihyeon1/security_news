import json
from datetime import datetime, timezone

import threat_dashboard as td

NOW = datetime(2026, 11, 13, 3, 0, tzinfo=timezone.utc)


def news(url, title, **extra):
    row = {"id": "s:" + url, "source": "thehackernews", "url": url, "title": title, "category": "공격캠페인",
           "published_at": "2026-11-12T01:00:00Z", "fetched_at": "2026-11-12T02:00:00Z", "exploitation_status": "none"}
    row.update(extra)
    return row


def test_names_split_aliases_and_drop_placeholders():
    assert td.names("Guildma (Astaroth operators), info, ShinyHunters, shinyhunters") == ["Guildma", "ShinyHunters"]
    assert td.names(["Microsoft Windows", "unknown"]) == ["Microsoft Windows"]


def test_threat_counts_exclude_informational_articles_and_merge_sub_techniques():
    events = [
        news("https://e.com/a", "Lazarus hits exchange", threat_actor="Lazarus Group", exploitation_status="active",
             attack_techniques=["T1566.001", "T1566.002", "T1190"]),
        news("https://e.com/b", "Vendor launches product", category="제품행사", threat_actor="Lazarus Group"),
    ]
    day = td.build(events, now=NOW)["daily"][-2]
    assert (day["collected"], day["threat"], day["active"]) == (2, 1, 1)
    assert day["actors"] == {"Lazarus Group": 1} and day["techniques"] == {"T1566": 1, "T1190": 1}


def test_cves_are_counted_once_across_catalogs_with_the_worst_severity():
    events = [
        {"id": "nvd:1", "source": "nvd", "cves": ["CVE-2026-11111"], "severity": "HIGH", "cwes": ["CWE-79"],
         "published_at": "2026-11-11T00:00:00Z", "fetched_at": "2026-11-11T01:00:00Z"},
        {"id": "msrc:1", "source": "msrc", "cves": ["CVE-2026-11111"], "severity": "", "score": 9.8,
         "published_at": "2026-Nov", "fetched_at": "2026-11-12T01:00:00Z"},
        {"id": "kev:1", "source": "cisa_kev", "cves": ["CVE-2026-11111"], "severity": "KEV", "kev": True,
         "exploitation_status": "active", "published_at": "2026-11-12", "fetched_at": "2026-11-12T05:00:00Z"},
    ]
    overview = td.build(events, now=NOW)
    total = {}
    for day in overview["daily"]:
        for key, value in day["cve"].items():
            total[key] = total.get(key, 0) + value
    assert total == {"new": 1, "critical": 1, "kev": 1, "active": 1}
    assert overview["labels"]["cwes"] == {"CWE-79": "크로스 사이트 스크립팅"}


def test_priority_uses_public_signals_and_never_exports_internal_context():
    events = [
        news("https://e.com/a", "Exploited flaw in gateway", exploitation_status="active", cves=["CVE-2026-22222"],
             severity="critical", matched_assets=["Fortigate"], pirs=["PIR-1"],
             triage={"level": "P1", "reasons": ["자사 자산 일치"]}, importance={"reasons": ["PIR 매칭 PIR-1"]}),
        news("https://e.com/b", "Another outlet on the same flaw", exploitation_status="active", cves=["CVE-2026-22222"]),
        news("https://e.com/c", "Old exploited flaw", exploitation_status="active",
             published_at="2026-10-01T00:00:00Z", fetched_at="2026-10-01T01:00:00Z"),
        news("https://e.com/d", "Trend article"),
    ]
    overview = td.build(events, now=NOW)
    assert [row["url"] for row in overview["priority"]] == ["https://e.com/a"]
    assert overview["priority"][0]["flags"] == ["실제 악용", "심각도 Critical"]
    text = json.dumps(overview, ensure_ascii=False)
    assert all(word not in text for word in ("Fortigate", "PIR", "자사", "P1"))


def test_sources_report_last_collection_and_recent_counts(tmp_path):
    events = [news("https://e.com/a", "A"), news("https://e.com/b", "B", fetched_at="2026-09-01T00:00:00Z",
                                                  published_at="2026-09-01T00:00:00Z")]
    overview = td.publish(tmp_path, events, now=NOW)
    assert overview["sources"] == [{"id": "thehackernews", "kind": "news", "last_collected_at": "2026-11-12T02:00:00Z",
                                    "count_7d": 1, "count_30d": 1}]
    assert json.loads((tmp_path / "threat-overview.json").read_text(encoding="utf-8"))["schema_version"] == 1
