import hashlib
import hmac
from io import BytesIO
from pathlib import Path

from puncture.web_app import (
    ENC_MAGIC,
    ENC_NONCE_SIZE,
    _asset_abs_path,
    _asset_lifecycle_state,
    _decrypt_blob,
    _encrypt_blob,
    _list_plaintext_rows,
    _next_ciphertext_relpath,
    _next_plaintext_relpath,
    _normalize_relpath,
    create_app,
)


def test_normalize_relpath_rejects_absolute_and_traversal() -> None:
    assert _normalize_relpath("docs/a.txt") == "docs/a.txt"

    try:
        _normalize_relpath("/etc/passwd")
        assert False, "absolute paths must fail"
    except ValueError:
        pass

    try:
        _normalize_relpath("../secret.txt")
        assert False, "path traversal must fail"
    except ValueError:
        pass


def test_asset_abs_path_stays_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()

    ok = _asset_abs_path(str(root), "a/b.txt")
    assert ok.startswith(str(root))

    try:
        _asset_abs_path(str(root), "../escape.txt")
        assert False, "escape should fail"
    except ValueError:
        pass


def test_next_plaintext_relpath_versions_collisions(tmp_path: Path) -> None:
    root = tmp_path / "assets"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.txt").write_text("x", encoding="utf-8")
    (root / "docs" / "a.v2.txt").write_text("x", encoding="utf-8")

    candidate = _next_plaintext_relpath(str(root), "docs/a.txt")
    assert candidate == "docs/a.v3.txt"


def test_next_ciphertext_relpath_versions_collisions(tmp_path: Path) -> None:
    root = tmp_path / "assets"
    (root / "docs").mkdir(parents=True)
    first = _next_ciphertext_relpath(str(root), "docs/a.txt", 42, 123)
    assert first == "docs/a.txt.enc.p42.k123.pke"
    (root / first).write_bytes(b"x")
    second = _next_ciphertext_relpath(str(root), "docs/a.txt", 42, 123)
    assert second == "docs/a.txt.enc.p42.k123.v2.pke"


def test_encrypt_blob_has_expected_format_and_tag() -> None:
    key = b"k" * 32
    plaintext = b"hello-world"
    blob = _encrypt_blob(key, plaintext)

    assert blob.startswith(ENC_MAGIC)
    nonce = blob[len(ENC_MAGIC) : len(ENC_MAGIC) + ENC_NONCE_SIZE]
    tag = blob[len(ENC_MAGIC) + ENC_NONCE_SIZE : len(ENC_MAGIC) + ENC_NONCE_SIZE + 32]
    ciphertext = blob[len(ENC_MAGIC) + ENC_NONCE_SIZE + 32 :]

    assert len(nonce) == ENC_NONCE_SIZE
    assert len(tag) == 32
    assert len(ciphertext) == len(plaintext)
    assert ciphertext != plaintext

    expected_tag = hmac.new(key, b"TAG" + nonce + ciphertext, hashlib.sha256).digest()
    assert tag == expected_tag


def test_decrypt_blob_roundtrip_and_authentication() -> None:
    key = b"z" * 32
    plaintext = b"secret-content"
    blob = _encrypt_blob(key, plaintext)
    assert _decrypt_blob(key, blob) == plaintext

    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF
    try:
        _decrypt_blob(key, bytes(tampered))
        assert False, "tampering should fail authentication"
    except ValueError as exc:
        assert "authentication" in str(exc)


def test_list_plaintext_rows_excludes_ciphertexts(tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "a.txt.enc.p42.k1.pke").write_bytes(b"cipher")

    rows = _list_plaintext_rows(str(root))
    assert len(rows) == 1
    assert rows[0]["relpath"] == "a.txt"
    assert rows[0]["size_bytes"] == 1
    assert rows[0]["size_label"].endswith("B")


def test_asset_lifecycle_state_machine_classification() -> None:
    assert _asset_lifecycle_state(mapping_count=0, blocked_count=0) == "eligible"
    assert _asset_lifecycle_state(mapping_count=2, blocked_count=0) == "encrypted_live"
    assert _asset_lifecycle_state(mapping_count=3, blocked_count=1) == "encrypted_partial"
    assert _asset_lifecycle_state(mapping_count=4, blocked_count=4) == "encrypted_blocked"


def test_assets_page_renders_state_machine_workflow(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()
    (root / "one.txt").write_text("1", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    resp = client.get("/assets")
    html = resp.data.decode("utf-8")

    assert resp.status_code == 200
    assert "Asset Workflow" in html
    assert "Single Lifecycle Flow" in html
    assert "id=\"upload_btn\"" in html
    assert "id=\"eligible_list\"" in html
    assert "id=\"encrypt_btn\"" in html
    assert "id=\"wipe_btn\"" in html
    assert "id=\"combo_quick\"" in html
    assert "const INITIAL_STATE" in html
    assert "/api/assets/workflow/upload" in html
    assert "/api/assets/workflow/encrypt" in html
    assert "/api/assets/workflow/decrypt" in html


def test_assets_workflow_api_shows_quick_key_combo_options(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()
    (root / "one.txt").write_text("1", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    client.post(
        "/derive",
        data={"provider_id": "42", "file_time_id": "999", "purpose": "seed combo"},
        follow_redirects=True,
    )
    payload = client.get("/api/assets/workflow").get_json()
    combos = payload["state"]["key_combo_options"]
    assert any(item["provider_id"] == 42 and item["file_time_id"] == 999 for item in combos)
    labels = [item["label"] for item in combos]
    assert any("Provider 42 | Key 999 | active" in label for label in labels)


def test_asset_workflow_encrypt_api_requires_selection(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()
    (root / "one.txt").write_text("1", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    resp = client.post(
        "/api/assets/workflow/encrypt",
        json={"provider_id": 42, "file_time_id": 7, "purpose": "none selected", "plaintext_relpaths": []},
    )
    assert resp.status_code == 400
    assert "select existing files or upload files before encrypting" in resp.get_json()["error"]


def test_asset_upload_duplicate_filename_is_versioned(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    client.post(
        "/assets/upload",
        data={"target_subdir": "docs", "files": [(BytesIO(b"a"), "dup.txt")]},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    client.post(
        "/assets/upload",
        data={"target_subdir": "docs", "files": [(BytesIO(b"b"), "dup.txt")]},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert (root / "docs" / "dup.txt").is_file()
    assert (root / "docs" / "dup.v2.txt").is_file()


def test_asset_page_renders_blocked_and_glow_mappings(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets"
    root.mkdir()
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    client.post(
        "/assets/encrypt",
        data={
            "plaintext_relpaths": ["a.txt"],
            "provider_id": "42",
            "file_time_id": "100",
            "purpose": "a via p42",
        },
        follow_redirects=True,
    )
    client.post(
        "/assets/encrypt",
        data={
            "plaintext_relpaths": ["a.txt"],
            "provider_id": "17",
            "file_time_id": "200",
            "purpose": "a via p17",
        },
        follow_redirects=True,
    )
    client.post("/puncture", data={"provider_id": "42", "file_time_id": "100"}, follow_redirects=True)

    payload = client.get("/api/assets/workflow").get_json()["state"]
    file_map = {row["plaintext_relpath"]: row for row in payload["asset_files"]}
    rows = {(r["provider_id"], r["file_time_id"]): r for r in file_map["a.txt"]["mappings"]}
    assert rows[(42, 100)]["show_red"] is True
    assert rows[(17, 200)]["show_glow"] is True


def test_asset_workflow_upload_api_makes_files_immediately_eligible(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_upload_eligible"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    resp = client.post(
        "/api/assets/workflow/upload",
        data={"target_subdir": "incoming", "files": [(BytesIO(b"hello"), "a.txt"), (BytesIO(b"world"), "b.txt")]},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert sorted(data["uploaded"]) == ["incoming/a.txt", "incoming/b.txt"]
    assert (root / "incoming" / "a.txt").is_file()
    assert (root / "incoming" / "b.txt").is_file()

    states = {row["relpath"]: row["lifecycle_state"] for row in data["state"]["files"]}
    assert states["incoming/a.txt"] == "eligible"
    assert states["incoming/b.txt"] == "eligible"


def test_asset_workflow_encrypt_api_saves_ciphertext_immediately(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_encrypt_now"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    upload = client.post(
        "/api/assets/workflow/upload",
        data={"target_subdir": "x", "files": [(BytesIO(b"alpha"), "one.txt")]},
        content_type="multipart/form-data",
    ).get_json()
    assert upload["ok"] is True

    enc = client.post(
        "/api/assets/workflow/encrypt",
        json={
            "provider_id": 17,
            "file_time_id": 987,
            "purpose": "encrypt now",
            "plaintext_relpaths": ["x/one.txt"],
        },
    )
    assert enc.status_code == 200
    data = enc.get_json()
    assert data["ok"] is True
    assert (root / "x" / "one.txt.enc.p17.k987.pke").is_file()

    file_states = {row["relpath"]: row for row in data["state"]["files"]}
    assert file_states["x/one.txt"]["lifecycle_state"] == "encrypted_live"
    assert file_states["x/one.txt"]["mapping_count"] == 1


def test_asset_workflow_clear_api_resets_saved_inputs(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_wipe"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    client.post(
        "/api/assets/workflow/encrypt",
        json={
            "provider_id": 42,
            "file_time_id": 111,
            "purpose": "will fail no files but sets no state",
            "plaintext_relpaths": [],
        },
    )
    clear = client.post("/api/assets/workflow/clear")
    assert clear.status_code == 200
    payload = clear.get_json()
    assert payload["ok"] is True
    assert payload["state"]["last_inputs"]["provider_id"] == 42
    assert payload["state"]["last_inputs"]["file_time_id"] == 123456


def test_index_shows_frontier_and_removes_share_step(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_frontier_index"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    resp = client.get("/")
    html = resp.data.decode("utf-8")

    assert resp.status_code == 200
    assert "Current Active Roots (Frontier)" in html
    assert "Tree/Subtree Visualization" in html
    assert "No puncture yet. Root frontier covers the full derivation space." in html
    assert "Step 1: Backup Shares (2-of-3)" not in html
    assert html.find("Current Active Roots (Frontier)") < html.find("Quick Start Walkthrough")


def test_api_state_includes_frontier_and_excludes_share_fields(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_frontier_api"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    payload = client.get("/api/state").get_json()

    assert payload["active_prefixes"] == [""]
    assert len(payload["active_frontier"]) == 1
    assert payload["active_frontier"][0]["is_root"] is True
    assert "seed_shares" not in payload
    assert "shares_acknowledged" not in payload


def test_frontier_moves_from_root_after_puncture(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_frontier_puncture"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()

    before = client.get("/api/state").get_json()
    assert before["active_prefixes"] == [""]

    client.post("/puncture", data={"provider_id": "42", "file_time_id": "123456"}, follow_redirects=True)
    after = client.get("/api/state").get_json()

    assert "" not in after["active_prefixes"]
    assert len(after["active_prefixes"]) > 1
    assert all(row["depth"] > 0 for row in after["active_frontier"])


def test_api_state_tracks_last_puncture_frontier_diff(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_last_diff"
    root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    client.post("/puncture", data={"provider_id": "42", "file_time_id": "123456"}, follow_redirects=True)
    payload = client.get("/api/state").get_json()

    diff = payload["last_puncture_diff"]
    assert diff["target_kind"] == "tag"
    assert diff["target"] == "01010100000000011110001001000000"
    assert "" in diff["removed"]
    assert isinstance(diff["added"], list)


def test_asset_workflow_decrypt_api_restores_cleartext(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_decrypt_ok"
    root.mkdir()
    (root / "p.txt").write_text("plain-alpha", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    enc = client.post(
        "/api/assets/workflow/encrypt",
        json={
            "provider_id": 42,
            "file_time_id": 456,
            "purpose": "decrypt-test",
            "plaintext_relpaths": ["p.txt"],
        },
    ).get_json()
    mapping = enc["state"]["asset_files"][0]["mappings"][0]
    record_id = int(mapping["record_id"])

    dec = client.post("/api/assets/workflow/decrypt", json={"record_ids": [record_id]})
    assert dec.status_code == 200
    payload = dec.get_json()
    assert payload["ok"] is True
    restored = payload["restored"][0]["decrypted_relpath"]
    assert (root / restored).is_file()
    assert (root / restored).read_text(encoding="utf-8") == "plain-alpha"


def test_asset_workflow_decrypt_fails_when_key_punctured(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "assets_decrypt_blocked"
    root.mkdir()
    (root / "q.txt").write_text("plain-beta", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(root))

    app = create_app()
    client = app.test_client()
    enc = client.post(
        "/api/assets/workflow/encrypt",
        json={
            "provider_id": 17,
            "file_time_id": 700,
            "purpose": "puncture-then-decrypt",
            "plaintext_relpaths": ["q.txt"],
        },
    ).get_json()
    mapping = enc["state"]["asset_files"][0]["mappings"][0]
    record_id = int(mapping["record_id"])

    client.post("/puncture", data={"provider_id": "17", "file_time_id": "700"}, follow_redirects=True)
    dec = client.post("/api/assets/workflow/decrypt", json={"record_ids": [record_id]})
    assert dec.status_code == 400
    assert "punctured" in dec.get_json()["error"]
