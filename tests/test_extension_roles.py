import extension_hunter as eh

METAMASK = "nkbihfbeogaeaoehlefnkodbefgpgknn"
OKX = "mcohilncbfahbmgdjkbpemcciiolgcge"
BAD = "aaaabbbbccccddddeeeeffffgggghhhh"
OBSCURE = "ppppoooonnnnmmmmllllkkkkjjjjiiii"


def test_ioc_table_heading_marks_wallet_ids_as_targets():
    text = ("Indicators Wallet-Extension Target IDs {} (MetaMask) {} (OKX Wallet) "
            "Additional notes".format(METAMASK, OKX))
    roles = eh.roles_from_text(text)
    assert roles[METAMASK]["role"] == "target"
    assert roles[OKX]["role"] == "target"
    assert "Target IDs" in roles[OKX]["evidence"]
    assert roles[METAMASK]["label"] == "MetaMask"
    assert roles[OKX]["label"] == "OKX Wallet"


def test_malicious_extension_article_is_still_malicious():
    roles = eh.roles_from_text("Researchers found 19 malicious extensions, including {}.".format(BAD))
    assert roles[BAD]["role"] == "malicious"


def test_stealer_enumerating_installed_extensions_is_not_malicious():
    roles = eh.roles_from_text(
        "The stealer enumerates installed browser extensions and reads data from {}.".format(METAMASK))
    assert roles[METAMASK]["role"] == "target"


def test_conflicting_mentions_fall_back_to_unknown():
    text = ("Wallet-Extension Target IDs {}. " + "x " * 400 +
            "Separately, a malicious extension {} was pushed.").format(BAD, BAD)
    assert eh.roles_from_text(text)[BAD]["role"] == "unknown"


def _patch_stores(monkeypatch, edge_by_id):
    monkeypatch.setattr(eh, "PAUSE_SECONDS", 0)
    monkeypatch.setattr(eh, "lookup_chrome", lambda extension_id: (True, ""))
    monkeypatch.setattr(eh, "lookup_edge", lambda extension_id: edge_by_id.get(
        extension_id, {"found": False, "error": ""}))


def test_analyze_keeps_targets_and_popular_unknowns_out_of_the_blocklist(monkeypatch):
    popular = {"found": True, "name": "MetaMask", "version": "13", "developer": "Consensys",
               "installs": 2634235, "rating": 4, "permissions": [], "matches": [], "error": ""}
    _patch_stores(monkeypatch, {METAMASK: popular, OKX: dict(popular, name="OKX Wallet")})
    roles = {METAMASK: {"role": "target", "evidence": "Target IDs ..."},
             BAD: {"role": "malicious", "evidence": "malicious extension"}}
    track = eh.analyze([METAMASK, OKX, BAD, OBSCURE], roles=roles)
    assert [e["id"] for e in track["target_ids"]] == [METAMASK]
    assert [e["id"] for e in track["review_ids"]] == [OKX]  # 문맥 없음 + 대형 정상 확장
    assert set(track["live_ids"]) == {BAD, OBSCURE}          # 악성 명시 + 문맥 없는 무명 확장


def test_popular_extension_named_malicious_is_still_blocked(monkeypatch):
    # 정상 확장 인수 후 악성 업데이트 — 원문이 malicious라고 쓰면 규모와 상관없이 막는다.
    popular = {"found": True, "name": "Big", "version": "1", "developer": "Dev",
               "installs": 5000000, "rating": 4, "permissions": [], "matches": [], "error": ""}
    _patch_stores(monkeypatch, {BAD: popular})
    track = eh.analyze([BAD], roles={BAD: {"role": "malicious", "evidence": ""}})
    assert track["live_ids"] == [BAD] and track["target_ids"] == [] and track["review_ids"] == []


def test_response_material_for_targets_never_blocks_them():
    block = {"live_ids": [], "removed_ids": [], "review_ids": [],
             "target_ids": [{"id": METAMASK, "name": "MetaMask", "developer": "Consensys",
                             "installs": 1, "listed": True, "evidence": ""}]}
    material = eh.response_material(block)
    labels = [group["label"] for group in material["blocklists"]]
    assert labels == ["차단 금지 — 탈취 대상 확장(정상 확장)"]
    assert not any("ExtensionInstallBlocklist" in action for action in material["actions"])
    assert any("새 지갑" in action for action in material["actions"])
    assert material["commands"] == []
    assert "피해 범위" in material["kql"][0]["name"]


def test_response_material_still_blocks_malicious_ids():
    material = eh.response_material({"live_ids": [BAD], "removed_ids": []})
    assert material["blocklists"][0]["label"].startswith("차단 대상")
    assert any("ExtensionInstallBlocklist" in action for action in material["actions"])
