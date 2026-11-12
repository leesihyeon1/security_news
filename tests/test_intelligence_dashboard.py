import json
from datetime import datetime, timezone

import intelligence_dashboard as idash

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def event(url, title, **extra):
    row = {"source": "thehackernews", "url": url, "title": title, "summary": "",
           "category": "기술동향", "published_at": "2026-11-10T01:00:00Z", "fetched_at": "2026-11-10T02:00:00Z"}
    row.update(extra)
    return row


def test_counts_each_url_once_and_skips_vulnerability_catalogs():
    events = [
        event("https://example.com/a", "GitHub adds push protection"),
        event("https://example.com/a", "GitHub adds push protection (updated)", fetched_at="2026-11-10T05:00:00Z"),
        event("https://nvd.example/cve", "CVE-2026-0001 in GitHub Enterprise", source="nvd"),
    ]
    overview, details = idash.build(events, now=NOW)
    assert overview["total_articles"] == 1
    assert [row["title"] for row in details["github"]] == ["GitHub adds push protection (updated)"]
    day = next(d for d in overview["daily"] if d["date"] == "2026-11-10")
    assert day["total"] == 1 and day["entities"] == {"github": 1} and day["tech_entities"] == {"github": 1}
    assert day["areas"]["development"] == 1


def test_subject_matching_is_whole_word_and_react_is_case_sensitive():
    assert idash.subject_ids("React Server Components flaw") == ["react"]
    assert idash.subject_ids("Attackers react quickly to npm takedown") == ["npm"]
    assert idash.subject_ids("Dockerfile linting tips") == []
    assert "kubernetes" in idash.subject_ids("쿠버네티스 클러스터 설정 오류")


def test_articles_outside_the_window_and_without_a_public_url_are_dropped():
    events = [
        event("https://example.com/old", "Old Linux story", published_at="2026-01-01T00:00:00Z", fetched_at="2026-01-01T01:00:00Z"),
        event("", "No link"),
        event("https://example.com/new", "Linux kernel update"),
    ]
    overview, details = idash.build(events, now=NOW)
    assert overview["total_articles"] == 1
    assert [row["url"] for row in details["linux"]] == ["https://example.com/new"]


def test_public_rows_carry_no_internal_fields():
    events = [event("https://example.com/a", "Fortinet VPN flaw", matched_assets=["Fortigate"], pirs=["PIR-1"],
                    asset_owner="infra-team")]
    _, details = idash.build(events, now=NOW)
    row = details["area-network"][0]
    assert set(row) == {"ref", "title", "url", "date", "date_basis", "source", "category", "entities", "areas"}
    assert "Fortigate" not in json.dumps(row) and "PIR-1" not in json.dumps(row)


def test_publish_uses_stable_file_names_and_removes_stale_ones(tmp_path):
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(json.dumps(event("https://example.com/a", "GitHub Actions change")) + "\n", encoding="utf-8")
    folder = tmp_path / "out" / "intelligence"
    folder.mkdir(parents=True)
    (folder / "github-0123456789ab.json").write_text("[]", encoding="utf-8")

    overview = idash.publish(tmp_path / "out", events_path, now=NOW)
    first = sorted(path.name for path in folder.iterdir())
    idash.publish(tmp_path / "out", events_path, now=NOW)

    assert "github.json" in first and "github-0123456789ab.json" not in first
    assert sorted(path.name for path in folder.iterdir()) == first  # 다시 발행해도 파일이 늘지 않는다
    assert overview["detail_files"]["github"] == "data/intelligence/github.json"
    assert len(first) == len(overview["entities"]) + len(overview["areas"])
    saved = json.loads((tmp_path / "out" / "intelligence-overview.json").read_text(encoding="utf-8"))
    assert saved["total_articles"] == 1 and len(saved["daily"]) == 180
    assert json.loads((folder / "github.json").read_text(encoding="utf-8"))[0]["url"] == "https://example.com/a"


def test_every_entity_has_a_known_group_and_area():
    groups = {row[0] for row in idash.GROUPS}
    areas = {row[0] for row in idash.AREAS}
    for key, _, group, area, aliases in idash.ENTITY_ROWS:
        assert group in groups and area in areas and aliases, key


def test_service_groups_follow_their_technical_roles():
    groups = {row[0]: row[2] for row in idash.ENTITY_ROWS}
    assert groups["chrome"] == groups["firefox"] == "client"
    assert groups["linux"] == groups["windows11"] == "os"
    assert groups["npm"] == groups["pypi"] == "packages"
    assert groups["python"] == groups["javascript"] == "language"
    assert groups["nginx"] == groups["apache"] == groups["cloudflare"] == "edge"
    assert groups["docker"] == groups["kubernetes"] == "container"
    assert groups["vscode"] == groups["vscodemarketplace"] == "ide"
    assert groups["githubactions"] == groups["jenkins"] == "cicd"
    assert groups["mongodb"] == groups["postgresql"] == "data"


def test_documented_relations_reference_distinct_known_assets():
    ids = {row[0] for row in idash.ENTITY_ROWS}
    links = {(source, target) for source, target, _, _ in idash.RELATIONS}
    assert len(links) == len(idash.RELATIONS)
    for source, target, label, url in idash.RELATIONS:
        assert source in ids and target in ids and source != target
        assert label and url.startswith("https://")
    overview, _ = idash.build([], now=NOW)
    assert len(overview["relations"]) == len(idash.RELATIONS)


def test_specific_new_subjects_are_not_generic_mentions():
    assert idash.subject_ids("GitHub Actions workflow") == ["github", "githubactions"]
    assert "githubactions" not in idash.subject_ids("The team takes actions")
    assert "vscodemarketplace" in idash.subject_ids("VS Code Marketplace extension")
