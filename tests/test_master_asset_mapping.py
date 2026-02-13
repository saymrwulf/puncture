from pathlib import Path
from io import BytesIO

from puncture.web_app import create_app


def test_asset_mapping_status_red_and_glow(monkeypatch, tmp_path: Path) -> None:
    asset_root = tmp_path / "assets"
    asset_root.mkdir()
    (asset_root / "a.txt").write_text("alpha", encoding="utf-8")
    (asset_root / "b.txt").write_text("beta", encoding="utf-8")

    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(asset_root))

    app = create_app()
    client = app.test_client()

    client.post(
        "/assets/encrypt",
        data={
            "plaintext_relpath": "a.txt",
            "provider_id": "42",
            "file_time_id": "100",
            "purpose": "a via p42",
        },
    )
    client.post(
        "/assets/encrypt",
        data={
            "plaintext_relpath": "a.txt",
            "provider_id": "17",
            "file_time_id": "200",
            "purpose": "a via p17",
        },
    )
    client.post(
        "/assets/encrypt",
        data={
            "plaintext_relpath": "b.txt",
            "provider_id": "42",
            "file_time_id": "100",
            "purpose": "b via p42",
        },
    )

    # Puncture shared key (provider 42 / key 100) used by two files.
    client.post("/puncture", data={"provider_id": "42", "file_time_id": "100"}, follow_redirects=True)

    live = client.get("/api/live/state").get_json()
    files = {row["plaintext_relpath"]: row for row in live["assets"]["asset_files"]}

    file_a = files["a.txt"]
    rows_a = {(r["provider_id"], r["file_time_id"]): r for r in file_a["mappings"]}
    assert rows_a[(42, 100)]["show_red"] is True
    assert rows_a[(42, 100)]["is_accessible"] is False
    assert rows_a[(17, 200)]["show_glow"] is True
    assert rows_a[(17, 200)]["is_accessible"] is True

    file_b = files["b.txt"]
    rows_b = {(r["provider_id"], r["file_time_id"]): r for r in file_b["mappings"]}
    assert rows_b[(42, 100)]["show_red"] is True
    assert rows_b[(42, 100)]["is_accessible"] is False


def test_remote_puncture_provider_endpoint_requires_token(monkeypatch, tmp_path: Path) -> None:
    asset_root = tmp_path / "assets2"
    asset_root.mkdir()
    (asset_root / "c.txt").write_text("content", encoding="utf-8")

    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(asset_root))
    monkeypatch.setenv("PUNCTURE_REMOTE_TOKEN", "tok")

    app = create_app()
    client = app.test_client()

    # Derive once pre-kill to verify accessibility.
    resp_pre = client.post(
        "/derive",
        data={"provider_id": "42", "file_time_id": "300", "purpose": "pre"},
        follow_redirects=True,
    )
    assert b"Derive succeeded" in resp_pre.data

    denied = client.post("/api/remote/puncture-provider", json={"provider_id": 42})
    assert denied.status_code == 403

    allowed = client.post(
        "/api/remote/puncture-provider",
        json={"provider_id": 42},
        headers={"X-Puncture-Token": "tok"},
    )
    assert allowed.status_code == 200
    assert allowed.get_json()["ok"] is True

    resp_post = client.post(
        "/derive",
        data={"provider_id": "42", "file_time_id": "300", "purpose": "post"},
        follow_redirects=True,
    )
    assert b"Derive blocked" in resp_post.data


def test_asset_page_can_encrypt_multiple_selected_files(monkeypatch, tmp_path: Path) -> None:
    asset_root = tmp_path / "assets3"
    asset_root.mkdir()
    (asset_root / "f1.txt").write_text("f1", encoding="utf-8")
    (asset_root / "f2.txt").write_text("f2", encoding="utf-8")
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(asset_root))

    app = create_app()
    client = app.test_client()

    client.post(
        "/assets/encrypt",
        data={
            "plaintext_relpaths": ["f1.txt", "f2.txt"],
            "provider_id": "42",
            "file_time_id": "444",
            "purpose": "batch",
        },
        follow_redirects=True,
    )

    ciphers = sorted(asset_root.glob("*.pke"))
    assert len(ciphers) == 2
    assert any(".enc.p42.k444.pke" in p.name for p in ciphers)

    live = client.get("/api/live/state").get_json()
    assert live["assets"]["mapping_count"] == 2
    files = {row["plaintext_relpath"]: row for row in live["assets"]["asset_files"]}
    assert "f1.txt" in files
    assert "f2.txt" in files


def test_asset_upload_persists_cleartext_files(monkeypatch, tmp_path: Path) -> None:
    asset_root = tmp_path / "assets4"
    asset_root.mkdir()
    monkeypatch.setenv("PUNCTURE_ASSET_ROOT", str(asset_root))

    app = create_app()
    client = app.test_client()

    resp = client.post(
        "/assets/upload",
        data={
            "target_subdir": "docs",
            "files": [
                (BytesIO(b"alpha"), "a.txt"),
                (BytesIO(b"beta"), "b.txt"),
            ],
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert (asset_root / "docs" / "a.txt").is_file()
    assert (asset_root / "docs" / "b.txt").is_file()
