"""Sync bundle helpers for read-only companion viewer app."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _utc_now_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sign_payload(payload: Dict[str, Any], sync_key: str) -> str:
    digest = hmac.new(sync_key.encode("utf-8"), _canonical_json(payload).encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def verify_payload_signature(payload: Dict[str, Any], signature_hex: str, sync_key: str) -> bool:
    expected = sign_payload(payload, sync_key)
    return hmac.compare_digest(expected, signature_hex)


def build_view_payload(system: Dict[str, Any], puncture_log: list[str]) -> Dict[str, Any]:
    providers = []
    for provider_id in sorted(system["providers"].keys()):
        src = system["providers"][provider_id]
        providers.append(
            {
                "provider_id": int(src["provider_id"]),
                "name": str(src["name"]),
                "description": str(src.get("description", "")),
                "created_at": str(src.get("created_at", "")),
            }
        )

    key_entries = []
    for entry in system.get("key_journal", {}).values():
        key_entries.append(
            {
                "provider_id": int(entry["provider_id"]),
                "file_time_id": int(entry["file_time_id"]),
                "path": str(entry["path"]),
                "description": str(entry.get("description", "")),
                "ever_derived": bool(entry.get("ever_derived", False)),
                "ever_punctured": bool(entry.get("ever_punctured", False)),
                "derive_count": int(entry.get("derive_count", 0)),
                "puncture_count": int(entry.get("puncture_count", 0)),
                "last_derived_at": entry.get("last_derived_at"),
                "last_punctured_at": entry.get("last_punctured_at"),
            }
        )

    key_entries.sort(key=lambda row: (row["provider_id"], row["file_time_id"]))

    allowed_paths = sorted(
        row["path"]
        for row in key_entries
        if row["ever_derived"] and not row["ever_punctured"]
    )

    return {
        "version": 1,
        "generated_at": _utc_now_label(),
        "providers": providers,
        "known_keys": key_entries,
        "allowed_paths": allowed_paths,
        "puncture_log": list(puncture_log),
        "deleted_providers": list(system.get("deleted_providers", [])),
    }


def wrap_view_bundle(payload: Dict[str, Any], sync_key: Optional[str] = None) -> Dict[str, Any]:
    if sync_key:
        signature = sign_payload(payload, sync_key)
        return {"payload": payload, "hmac_sha256": signature, "signed": True}
    return {"payload": payload, "hmac_sha256": None, "signed": False}


def extract_view_payload(
    bundle_or_payload: Dict[str, Any],
    *,
    sync_key: Optional[str] = None,
    require_signature: bool = False,
) -> Dict[str, Any]:
    if "payload" in bundle_or_payload and isinstance(bundle_or_payload["payload"], dict):
        payload = bundle_or_payload["payload"]
        signature = bundle_or_payload.get("hmac_sha256")
    else:
        payload = bundle_or_payload
        signature = None

    if require_signature and not signature:
        raise ValueError("signed bundle required")

    if signature:
        if not sync_key:
            raise ValueError("bundle is signed but no sync key is configured")
        if not verify_payload_signature(payload, str(signature), sync_key):
            raise ValueError("bundle signature verification failed")

    _validate_view_payload(payload)
    return payload


def _validate_view_payload(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")

    required_list_fields = ["providers", "known_keys", "allowed_paths", "puncture_log"]
    for field in required_list_fields:
        if not isinstance(payload.get(field), list):
            raise ValueError(f"payload['{field}'] must be a list")

    for provider in payload["providers"]:
        if not isinstance(provider, dict):
            raise ValueError("providers entries must be objects")
        if "provider_id" not in provider:
            raise ValueError("provider entries must contain provider_id")

    for key in payload["known_keys"]:
        if not isinstance(key, dict):
            raise ValueError("known_keys entries must be objects")
        for field in ["provider_id", "file_time_id", "path", "ever_derived", "ever_punctured"]:
            if field not in key:
                raise ValueError(f"known_keys entries must contain {field}")

    if payload.get("version") not in {1, None}:
        raise ValueError("unsupported payload version")
