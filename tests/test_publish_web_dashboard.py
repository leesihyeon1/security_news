import json
from collections import Counter
from pathlib import Path

import generate_report as gr
import publish_web_dashboard as pwd


def _stats(total=2):
    return {
        "total": total, "p1": [], "p2": [], "critical": [], "kev": [],
        "ransomware": [], "asset_hits": [], "by_source": Counter({"asec": 1, "krebsonsecurity": 1}),
        "info_by_category": Counter({"악성코드": total}),
    }


def _event(event_id, source, title="t"):
    return {
        "id": "{}:{}".format(source, event_id), "source": source, "title": title,
        "url": "http://x/{}".format(event_id), "category": "악성코드",
        "matched_assets": [], "published_at": "2026-01-01T00:00:00Z", "summary": "요약",
    }


def test_build_dashboard_payload_splits_highlights_by_region():
    highlights = [_event(1, "asec"), _event(2, "krebsonsecurity")]
    payload = gr.build_dashboard_payload(
        "제목", "daily", "기간", _stats(), "총평", highlights, [], [],
    )
    assert [e["source"] for e in payload["domestic"]["highlights"]] == ["asec"]
    assert [e["source"] for e in payload["overseas"]["highlights"]] == ["krebsonsecurity"]


def test_build_dashboard_payload_keeps_cards_region_agnostic():
    cards = [{
        "cve": "CVE-2026-0001", "level": "P1", "sources": ["asec", "krebsonsecurity"],
        "products": [], "remediation": "", "due_date": "", "summary": "요약",
        "score": 0, "epss": None, "kev": False, "exploitation": "none",
        "ransomware": False, "assets": [],
        "items": [
            ("asec", "국내기사", "http://x/1", "asec:1"),
            ("krebsonsecurity", "해외기사", "http://x/2", "krebsonsecurity:2"),
        ],
    }]
    payload = gr.build_dashboard_payload("제목", "daily", "기간", _stats(), "", [], cards, [])
    assert len(payload["cards"]) == 1
    assert len(payload["cards"][0]["items"]) == 2  # 국내/해외 소스 다 그대로 포함


def test_build_dashboard_payload_omits_matched_assets_from_events():
    """공개 웹 대시보드에는 자사 보유 자산/제품 매칭 결과가 노출되면 안 된다."""
    event = _event(1, "asec")
    event["matched_assets"] = ["FortiGate", "내부시스템A"]
    payload = gr.build_dashboard_payload("제목", "daily", "기간", _stats(), "", [event], [], [])
    serialized = payload["domestic"]["highlights"][0]
    assert "matched_assets" not in serialized
    assert "FortiGate" not in json.dumps(payload, ensure_ascii=False)


def test_build_dashboard_payload_omits_asset_match_bit_from_cards():
    """CVE 카드의 severity_bits에도 자산매칭 문구가 들어가면 안 된다(영향 제품명(products)은 유지)."""
    cards = [{
        "cve": "CVE-2026-0002", "level": "P1", "sources": ["asec"],
        "products": ["FortiGate"], "remediation": "", "due_date": "", "summary": "",
        "score": 0, "epss": None, "kev": False, "exploitation": "none",
        "ransomware": False, "assets": ["FortiGate"],  # 자사 자산 매칭됨
        "items": [("asec", "t", "http://x/1", "asec:1")],
    }]
    payload = gr.build_dashboard_payload("제목", "daily", "기간", _stats(), "", [], cards, [])
    bits_text = " ".join(payload["cards"][0]["severity_bits"])
    assert "자산매칭" not in bits_text
    assert payload["cards"][0]["products"] == ["FortiGate"]  # 영향 제품명 자체는 유지(공개 취약점 정보)


def test_build_dashboard_payload_stats_shape():
    payload = gr.build_dashboard_payload("제목", "weekly", "기간", _stats(total=5), "", [], [], [])
    assert payload["period"] == "weekly"
    assert payload["stats"]["total"] == 5
    assert payload["stats"]["by_source"] == {"asec": 1, "krebsonsecurity": 1}


def test_build_dashboard_payload_omits_pir_info():
    """PIR 식별자·문항이 대시보드에 노출되면 조직의 우선순위(예: 특정 산업 표적 위협)가
    드러나므로, pir_groups/pir_gaps 자체를 출력에 포함하지 않는다."""
    payload = gr.build_dashboard_payload("제목", "daily", "기간", _stats(), "", [], [], [])
    assert "pir_groups" not in payload
    assert "pir_gaps" not in payload


def test_build_dashboard_payload_omits_asset_hits_count():
    """자산매칭 건수만으로도 '이 조직이 자산 인벤토리를 추적한다'는 사실이 드러나므로,
    이름뿐 아니라 stats.asset_hits 집계 자체를 대시보드 출력에서 뺀다."""
    payload = gr.build_dashboard_payload("제목", "daily", "기간", _stats(), "", [], [], [])
    assert "asset_hits" not in payload["stats"]


def test_publish_skips_when_repo_path_not_configured(monkeypatch):
    monkeypatch.setattr(pwd, "REPO_PATH", "")
    assert pwd.publish({"period": "daily", "generated_at": "2026-01-01T00:00:00Z"}) is False


def test_publish_skips_when_repo_path_does_not_exist(tmp_path, monkeypatch):
    missing = tmp_path / "does-not-exist"
    assert pwd.publish({"period": "daily", "generated_at": "2026-01-01T00:00:00Z"}, repo_path=str(missing)) is False


def test_publish_writes_json_and_commits(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    import subprocess
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True, check=True)
    # 커밋할 브랜치가 있어야 하니 초기 커밋 하나 생성
    (repo / "README.md").write_text("init", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)

    payload = {"period": "daily", "generated_at": "2026-01-02T00:00:00Z", "title": "t"}
    # push는 원격이 없어 실패할 것이므로 _run_git을 patch해서 push만 건너뛴다
    original_run_git = pwd._run_git

    def fake_run_git(args, cwd):
        if args and args[0] == "push":
            return ""
        return original_run_git(args, cwd)

    monkeypatch.setattr(pwd, "_run_git", fake_run_git)

    result = pwd.publish(payload, repo_path=str(repo))
    assert result is True

    latest = json.loads((repo / "dashboard" / "data" / "daily-latest.json").read_text(encoding="utf-8"))
    history = json.loads((repo / "dashboard" / "data" / "daily-2026-01-02.json").read_text(encoding="utf-8"))
    assert latest == payload
    assert history == payload


def test_publish_returns_false_on_git_error(tmp_path, monkeypatch):
    repo = tmp_path / "not-a-repo"
    repo.mkdir()  # git 저장소가 아님 -> git add가 실패해야 함
    payload = {"period": "daily", "generated_at": "2026-01-01T00:00:00Z"}
    result = pwd.publish(payload, repo_path=str(repo))
    assert result is False
