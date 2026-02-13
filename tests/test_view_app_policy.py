from puncture import view_app


def _sample_live_state() -> dict:
    return {
        "generated_at": "2026-02-12 19:00:00 UTC",
        "providers": [
            {
                "provider_id": 42,
                "name": "Provider 42",
                "description": "Demo",
                "prefix": "0101010",
                "derived_count": 1,
                "punctured_count": 0,
                "key_count": 1,
            }
        ],
        "key_journal": [
            {
                "provider_id": 42,
                "file_time_id": 1001,
                "path_provider": "0101010",
                "path_resource": "0000000000000001111101001",
                "derive_count": 1,
                "puncture_count": 0,
                "description": "alpha",
                "ever_punctured": False,
            }
        ],
        "assets": {
            "mapping_count": 1,
            "blocked_count": 0,
            "glow_count": 0,
            "asset_files": [
                {
                    "plaintext_relpath": "docs/a.txt",
                    "mapping_count": 1,
                    "blocked_count": 0,
                    "mappings": [
                        {
                            "provider_id": 42,
                            "file_time_id": 1001,
                            "ciphertext_relpath": "docs/a.txt.enc.p42.k1001.pke",
                            "path_provider": "0101010",
                            "path_resource": "0000000000000001111101001",
                            "is_accessible": True,
                            "show_red": False,
                            "show_glow": False,
                        }
                    ],
                }
            ],
            "key_cards": [],
        },
    }


def test_secondary_login_success(monkeypatch) -> None:
    monkeypatch.setenv("PUNCTURE_SECONDARY_PASSWORD", "secret")
    monkeypatch.setattr(view_app, "_fetch_master_state", lambda: _sample_live_state())

    app = view_app.create_app()
    client = app.test_client()

    resp = client.post("/login", data={"password": "secret"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Secondary Live Viewer" in resp.data

    api_resp = client.get("/api/state")
    assert api_resp.status_code == 200
    assert api_resp.get_json()["ok"] is True


def test_secondary_kill_switch_password_triggers_remote_puncture(monkeypatch) -> None:
    monkeypatch.setenv("PUNCTURE_SECONDARY_PASSWORD", "secret")
    monkeypatch.setattr(view_app, "_fetch_master_state", lambda: _sample_live_state())

    called: dict[str, int] = {}

    def _fake_remote(provider_id: int) -> dict:
        called["provider_id"] = provider_id
        return {"ok": True, "provider_id": provider_id}

    monkeypatch.setattr(view_app, "_remote_puncture_provider", _fake_remote)

    app = view_app.create_app()
    client = app.test_client()

    resp = client.post("/login", data={"password": "secret42"}, follow_redirects=True)
    assert resp.status_code == 200
    assert called["provider_id"] == 42
    assert b"Kill switch activated" in resp.data
