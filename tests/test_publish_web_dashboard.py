import json
from collections import Counter

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
    import subprocess

    def git(*args, cwd):
        subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)

    # publish()는 origin이 대시보드 저장소인지 확인하고 원격 HEAD에 맞춘 뒤 push한다 —
    # 같은 이름의 로컬 bare 저장소를 origin으로 둬서 네트워크 없이 전 과정을 탄다.
    remote = tmp_path / "leesihyeon1" / "boannews_vercel.git"
    remote.mkdir(parents=True)
    git("init", "--bare", "-b", "main", cwd=remote)
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-b", "main", cwd=repo)
    git("config", "user.email", "test@example.com", cwd=repo)
    git("config", "user.name", "Test", cwd=repo)
    (repo / "README.md").write_text("init", encoding="utf-8")
    git("add", "README.md", cwd=repo)
    git("commit", "-m", "init", cwd=repo)
    git("remote", "add", "origin", str(remote), cwd=repo)
    git("push", "-u", "origin", "main", cwd=repo)

    # 발행 때 함께 만드는 부가 파일(검색 색인·최신 기사·블로그·일정·사고 아카이브)은
    # 실제 수집 데이터를 읽으므로 여기서는 비운다 — 이 테스트는 보고서 JSON 발행만 본다.
    monkeypatch.setattr(pwd, "_rebuild_search_index_from_events", lambda repo: None)
    monkeypatch.setattr(pwd.live_news, "write_snapshot", lambda path, rows=None: None)
    monkeypatch.setattr(pwd.featured_sources, "publish", lambda data_dir, **kwargs: None)
    monkeypatch.setattr(pwd.intelligence_dashboard, "publish", lambda data_dir, **kwargs: None)
    monkeypatch.setattr(pwd.event_calendar, "from_collected_events", lambda *args, **kwargs: [])
    monkeypatch.setattr(pwd.incident_archive, "publish", lambda data_dir, **kwargs: None)
    monkeypatch.setattr(pwd.incident_archive, "discover", lambda *args, **kwargs: 0)

    payload = {"period": "daily", "generated_at": "2026-01-02T00:00:00Z", "title": "t"}
    assert pwd.publish(payload, repo_path=str(repo)) is True

    latest = json.loads((repo / "dashboard" / "data" / "daily-latest.json").read_text(encoding="utf-8"))
    history = json.loads((repo / "dashboard" / "data" / "daily-2026-01-02.json").read_text(encoding="utf-8"))
    assert latest == payload
    assert history == payload
    pushed = subprocess.run(["git", "log", "-1", "--format=%s", "main"], cwd=remote,
                            capture_output=True, text=True, check=True).stdout.strip()
    assert pushed == "Update daily report (2026-01-02)"


def test_publish_returns_false_on_git_error(tmp_path, monkeypatch):
    repo = tmp_path / "not-a-repo"
    repo.mkdir()  # git 저장소가 아님 -> git add가 실패해야 함
    payload = {"period": "daily", "generated_at": "2026-01-01T00:00:00Z"}
    result = pwd.publish(payload, repo_path=str(repo))
    assert result is False
