from puncture.view_sync import (
    build_view_payload,
    extract_view_payload,
    sign_payload,
    verify_payload_signature,
    wrap_view_bundle,
)


def _sample_system() -> dict:
    return {
        "providers": {
            42: {
                "provider_id": 42,
                "name": "Provider 42",
                "description": "Demo",
                "created_at": "10:00:00 UTC",
            }
        },
        "key_journal": {
            "01010100000000000000000000000001": {
                "provider_id": 42,
                "file_time_id": 1,
                "path": "01010100000000000000000000000001",
                "description": "active",
                "ever_derived": True,
                "ever_punctured": False,
                "derive_count": 1,
                "puncture_count": 0,
                "last_derived_at": "10:01:00 UTC",
                "last_punctured_at": None,
            },
            "01010100000000000000000000000010": {
                "provider_id": 42,
                "file_time_id": 2,
                "path": "01010100000000000000000000000010",
                "description": "punctured",
                "ever_derived": True,
                "ever_punctured": True,
                "derive_count": 1,
                "puncture_count": 1,
                "last_derived_at": "10:02:00 UTC",
                "last_punctured_at": "10:03:00 UTC",
            },
            "01010100000000000000000000000011": {
                "provider_id": 42,
                "file_time_id": 3,
                "path": "01010100000000000000000000000011",
                "description": "never derived",
                "ever_derived": False,
                "ever_punctured": False,
                "derive_count": 0,
                "puncture_count": 0,
                "last_derived_at": None,
                "last_punctured_at": None,
            },
        },
        "deleted_providers": [],
    }


def test_build_view_payload_allows_only_derived_non_punctured() -> None:
    payload = build_view_payload(_sample_system(), puncture_log=["0101010"])
    assert payload["allowed_paths"] == ["01010100000000000000000000000001"]
    assert payload["puncture_log"] == ["0101010"]
    assert len(payload["known_keys"]) == 3


def test_sign_and_verify_bundle() -> None:
    payload = build_view_payload(_sample_system(), puncture_log=[])
    key = "sync-secret"
    signature = sign_payload(payload, key)
    assert verify_payload_signature(payload, signature, key)

    wrapped = wrap_view_bundle(payload, key)
    extracted = extract_view_payload(wrapped, sync_key=key, require_signature=True)
    assert extracted["allowed_paths"] == payload["allowed_paths"]


def test_extract_rejects_bad_signature() -> None:
    payload = build_view_payload(_sample_system(), puncture_log=[])
    wrapped = {"payload": payload, "hmac_sha256": "deadbeef", "signed": True}

    try:
        extract_view_payload(wrapped, sync_key="sync-secret", require_signature=True)
        assert False, "expected signature verification failure"
    except ValueError as exc:
        assert "signature" in str(exc).lower()
