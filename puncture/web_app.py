"""Beginner-friendly web UI for puncturable key management.

Run with:
    python -m puncture.web_app --port 9122
Then open from iPhone browser using your machine IP and port 9122.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, redirect, render_template_string, request, url_for
from werkzeug.utils import secure_filename

from .key_manager import PATH_BITS, PuncturableKeyManager, provider_id_to_prefix, tag_to_binary_path
from .view_sync import build_view_payload, wrap_view_bundle


ENC_MAGIC = b"PKE1"
ENC_NONCE_SIZE = 16
ENC_TAG_SIZE = 32
TREE_VIEW_DEPTH = 7


def _sort_prefixes(prefixes: list[str]) -> list[str]:
    return sorted(prefixes, key=lambda item: (len(item), item))


def _utc_now_label() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def _default_last_action() -> Dict[str, Any]:
    return {
        "tone": "info",
        "title": "Welcome",
        "body": (
            "This lab helps you derive a key, puncture it, and verify that the same key cannot be derived again. "
            "Start by deriving a key for a Provider ID + File/Time ID."
        ),
        "provider_id": None,
        "file_time_id": None,
        "path": None,
        "path_provider": None,
        "path_resource": None,
        "key_hex": None,
        "key_description": None,
    }


def _split_path_bits(path: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not path:
        return None, None
    return path[:7], path[7:]


def _set_last_action(
    system: Dict[str, Any],
    *,
    tone: str,
    title: str,
    body: str,
    provider_id: Optional[int] = None,
    file_time_id: Optional[int] = None,
    path: Optional[str] = None,
    key_hex: Optional[str] = None,
    key_description: Optional[str] = None,
) -> None:
    path_provider, path_resource = _split_path_bits(path)
    system["last_action"] = {
        "tone": tone,
        "title": title,
        "body": body,
        "provider_id": provider_id,
        "file_time_id": file_time_id,
        "path": path,
        "path_provider": path_provider,
        "path_resource": path_resource,
        "key_hex": key_hex,
        "key_description": key_description,
    }


def _record_history(
    system: Dict[str, Any],
    *,
    action: str,
    status: str,
    summary: str,
    provider_id: Optional[int] = None,
    file_time_id: Optional[int] = None,
    path: Optional[str] = None,
) -> None:
    history = system["history"]
    history.insert(
        0,
        {
            "time": _utc_now_label(),
            "action": action,
            "status": status,
            "summary": summary,
            "provider_id": provider_id,
            "file_time_id": file_time_id,
            "path": path,
        },
    )
    del history[24:]


def _default_providers() -> Dict[int, Dict[str, Any]]:
    created_at = _utc_now_label()
    return {
        42: {
            "provider_id": 42,
            "name": "Provider 42 (Demo)",
            "description": "Default provider used in Scenario A walkthrough.",
            "created_at": created_at,
        },
        17: {
            "provider_id": 17,
            "name": "Northwind Cloud",
            "description": "Example provider entry. Edit or delete as needed.",
            "created_at": created_at,
        },
        88: {
            "provider_id": 88,
            "name": "Blue Harbor Storage",
            "description": "Example provider entry. Edit or delete as needed.",
            "created_at": created_at,
        },
    }


def _ensure_key_entry(
    system: Dict[str, Any],
    *,
    provider_id: int,
    file_time_id: int,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    if path is None:
        path = tag_to_binary_path(provider_id, file_time_id)

    journal = system["key_journal"]
    entry = journal.get(path)
    if entry is None:
        path_provider, path_resource = _split_path_bits(path)
        entry = {
            "provider_id": provider_id,
            "file_time_id": file_time_id,
            "path": path,
            "path_provider": path_provider,
            "path_resource": path_resource,
            "description": "",
            "ever_derived": False,
            "ever_punctured": False,
            "derive_count": 0,
            "puncture_count": 0,
            "last_derived_at": None,
            "last_punctured_at": None,
        }
        journal[path] = entry
    return entry


def _touch_key_derive(
    system: Dict[str, Any],
    *,
    provider_id: int,
    file_time_id: int,
    path: str,
    description: str,
) -> Dict[str, Any]:
    entry = _ensure_key_entry(system, provider_id=provider_id, file_time_id=file_time_id, path=path)
    if description:
        entry["description"] = description
    entry["ever_derived"] = True
    entry["derive_count"] += 1
    entry["last_derived_at"] = _utc_now_label()
    return entry


def _touch_key_puncture(
    system: Dict[str, Any],
    *,
    provider_id: int,
    file_time_id: int,
    path: str,
    applied: bool,
) -> Dict[str, Any]:
    entry = _ensure_key_entry(system, provider_id=provider_id, file_time_id=file_time_id, path=path)
    entry["ever_punctured"] = True
    if applied:
        entry["puncture_count"] += 1
    entry["last_punctured_at"] = _utc_now_label()
    return entry


def _asset_root_dir() -> str:
    root = os.getenv("PUNCTURE_ASSET_ROOT", os.path.join(os.getcwd(), "assets"))
    abs_root = os.path.abspath(root)
    os.makedirs(abs_root, exist_ok=True)
    return abs_root


def _normalize_relpath(rel_path: str) -> str:
    if not rel_path:
        raise ValueError("relative file path is required")
    if os.path.isabs(rel_path):
        raise ValueError("absolute paths are not allowed")

    normalized = os.path.normpath(rel_path).replace("\\", "/")
    if normalized.startswith("../") or normalized == "..":
        raise ValueError("path traversal is not allowed")
    return normalized


def _asset_abs_path(asset_root: str, rel_path: str) -> str:
    rel = _normalize_relpath(rel_path)
    abs_path = os.path.abspath(os.path.join(asset_root, rel))
    if not abs_path.startswith(asset_root + os.sep) and abs_path != asset_root:
        raise ValueError("file path escapes asset root")
    return abs_path


def _list_plaintext_files(asset_root: str) -> list[str]:
    files: list[str] = []
    for base, dirs, filenames in os.walk(asset_root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in filenames:
            if name.endswith(".pke"):
                continue
            rel = os.path.relpath(os.path.join(base, name), asset_root)
            files.append(rel.replace(os.sep, "/"))
    return sorted(files)


def _format_bytes(count: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(count)
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.1f} {units[idx]}"


def _list_plaintext_rows(asset_root: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for rel in _list_plaintext_files(asset_root):
        abs_path = _asset_abs_path(asset_root, rel)
        try:
            size = os.path.getsize(abs_path)
        except OSError:
            size = 0
        try:
            modified_at = datetime.fromtimestamp(os.path.getmtime(abs_path), timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
        except OSError:
            modified_at = "unknown"
        rows.append(
            {
                "relpath": rel,
                "size_bytes": size,
                "size_label": _format_bytes(size),
                "modified_at": modified_at,
            }
        )
    return rows


def _asset_lifecycle_state(mapping_count: int, blocked_count: int) -> str:
    """Deterministic lifecycle state machine for a cleartext asset."""
    if mapping_count <= 0:
        return "eligible"
    if blocked_count <= 0:
        return "encrypted_live"
    if blocked_count < mapping_count:
        return "encrypted_partial"
    return "encrypted_blocked"


def _asset_lifecycle_label(state: str) -> str:
    labels = {
        "eligible": "Eligible",
        "encrypted_live": "Encrypted (live)",
        "encrypted_partial": "Encrypted (partially blocked)",
        "encrypted_blocked": "Encrypted (fully blocked)",
    }
    return labels.get(state, state)


def _stream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(
            key,
            b"ENC" + nonce + counter.to_bytes(8, byteorder="big"),
            hashlib.sha256,
        ).digest()
        chunk = data[offset : offset + len(block)]
        for i, value in enumerate(chunk):
            out[offset + i] = value ^ block[i]
        offset += len(chunk)
        counter += 1
    return bytes(out)


def _encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(ENC_NONCE_SIZE)
    ciphertext = _stream_xor(key, nonce, plaintext)
    tag = hmac.new(key, b"TAG" + nonce + ciphertext, hashlib.sha256).digest()
    return ENC_MAGIC + nonce + tag + ciphertext


def _decrypt_blob(key: bytes, encrypted_blob: bytes) -> bytes:
    minimum = len(ENC_MAGIC) + ENC_NONCE_SIZE + ENC_TAG_SIZE
    if len(encrypted_blob) < minimum:
        raise ValueError("ciphertext is too short")
    if not encrypted_blob.startswith(ENC_MAGIC):
        raise ValueError("ciphertext header mismatch")

    nonce_start = len(ENC_MAGIC)
    nonce_end = nonce_start + ENC_NONCE_SIZE
    tag_end = nonce_end + ENC_TAG_SIZE
    nonce = encrypted_blob[nonce_start:nonce_end]
    tag = encrypted_blob[nonce_end:tag_end]
    ciphertext = encrypted_blob[tag_end:]

    expected_tag = hmac.new(key, b"TAG" + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("ciphertext authentication failed")
    return _stream_xor(key, nonce, ciphertext)


def _next_ciphertext_relpath(asset_root: str, plaintext_relpath: str, provider_id: int, file_time_id: int) -> str:
    rel = _normalize_relpath(plaintext_relpath)
    directory = os.path.dirname(rel)
    filename = os.path.basename(rel)
    stem = f"{filename}.enc.p{provider_id}.k{file_time_id}"

    idx = 1
    while True:
        suffix = ".pke" if idx == 1 else f".v{idx}.pke"
        candidate_name = stem + suffix
        candidate_rel = os.path.join(directory, candidate_name) if directory else candidate_name
        candidate_abs = _asset_abs_path(asset_root, candidate_rel)
        if not os.path.exists(candidate_abs):
            return candidate_rel.replace(os.sep, "/")
        idx += 1


def _next_plaintext_relpath(asset_root: str, desired_relpath: str) -> str:
    rel = _normalize_relpath(desired_relpath)
    directory = os.path.dirname(rel)
    filename = os.path.basename(rel)
    stem, ext = os.path.splitext(filename)

    idx = 1
    while True:
        candidate_name = filename if idx == 1 else f"{stem}.v{idx}{ext}"
        candidate_rel = os.path.join(directory, candidate_name) if directory else candidate_name
        candidate_abs = _asset_abs_path(asset_root, candidate_rel)
        if not os.path.exists(candidate_abs):
            return candidate_rel.replace(os.sep, "/")
        idx += 1


def _next_decrypted_relpath(asset_root: str, plaintext_relpath: str, provider_id: int, file_time_id: int) -> str:
    rel = _normalize_relpath(plaintext_relpath)
    target = f"{rel}.dec.p{provider_id}.k{file_time_id}"
    return _next_plaintext_relpath(asset_root, target)


def _new_system() -> Dict[str, Any]:
    seed = PuncturableKeyManager.generate_master_seed()
    manager = PuncturableKeyManager(seed)
    return {
        "manager": manager,
        "history": [],
        "last_inputs": {"provider_id": 42, "file_time_id": 123456, "purpose": "Demo key for provider onboarding"},
        "last_action": _default_last_action(),
        "providers": _default_providers(),
        "deleted_providers": [],
        "providers_notice": None,
        "key_journal": {},
        "last_puncture_diff": None,
        "asset_root": _asset_root_dir(),
        "asset_records": [],
        "asset_notice": None,
    }


def _active_frontier_rows(manager: PuncturableKeyManager) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for prefix in manager.active_prefixes():
        depth = len(prefix)
        wildcard_bits = PATH_BITS - depth
        provider_bits = prefix[:7] if depth >= 1 else ""
        resource_bits = prefix[7:] if depth > 7 else ""
        rows.append(
            {
                "prefix": prefix,
                "depth": depth,
                "wildcard_bits": wildcard_bits,
                "is_root": depth == 0,
                "provider_bits": provider_bits,
                "resource_bits": resource_bits,
                "coverage_label": (
                    "Covers the entire 32-bit tag space (all providers, all file/time IDs)."
                    if depth == 0
                    else f"Covers all tags with this prefix; {wildcard_bits} wildcard bit(s) remain."
                ),
            }
        )
    return rows


def _prefix_intersects_active(prefix: str, active_prefixes: list[str]) -> bool:
    for frontier in active_prefixes:
        if frontier.startswith(prefix) or prefix.startswith(frontier):
            return True
    return False


def _project_prefixes(prefixes: list[str], max_depth: int) -> set[str]:
    return {item if len(item) <= max_depth else item[:max_depth] for item in prefixes}


def _derived_prefixes(system: Dict[str, Any], max_depth: int) -> set[str]:
    prefixes: set[str] = set()
    for entry in system["key_journal"].values():
        if not entry.get("ever_derived"):
            continue
        path = str(entry["path"])
        stop = min(max_depth, len(path))
        for depth in range(stop + 1):
            prefixes.add(path[:depth])
    return prefixes


def _set_last_puncture_diff(
    system: Dict[str, Any],
    *,
    before_frontier: list[str],
    after_frontier: list[str],
    target_bitstring: str,
    target_kind: str,
) -> None:
    before_set = set(before_frontier)
    after_set = set(after_frontier)
    removed = _sort_prefixes([prefix for prefix in before_frontier if prefix not in after_set])
    added = _sort_prefixes([prefix for prefix in after_frontier if prefix not in before_set])
    system["last_puncture_diff"] = {
        "time": _utc_now_label(),
        "target": target_bitstring,
        "target_kind": target_kind,
        "removed": removed,
        "added": added,
    }


def _node_x(prefix: str, *, depth: int, slot_width: float, margin_x: float) -> float:
    if not prefix:
        leaf_slots = 1 << depth
        return margin_x + (leaf_slots * slot_width) / 2.0

    left_index = int(prefix, 2) * (1 << (depth - len(prefix)))
    span = 1 << (depth - len(prefix))
    center_index = left_index + span / 2.0
    return margin_x + center_index * slot_width


def _tree_visualization_bundle(system: Dict[str, Any], manager: PuncturableKeyManager) -> Dict[str, Any]:
    depth = TREE_VIEW_DEPTH
    active_prefixes = manager.active_prefixes()
    derived_prefixes = _derived_prefixes(system, depth)

    frontier_exact = {prefix for prefix in active_prefixes if len(prefix) <= depth}
    frontier_proxy = {prefix[:depth] for prefix in active_prefixes if len(prefix) > depth}

    last_diff = system.get("last_puncture_diff") or {}
    removed_raw = list(last_diff.get("removed", []))
    removed_exact = {prefix for prefix in removed_raw if len(prefix) <= depth}
    removed_proxy = {prefix[:depth] for prefix in removed_raw if len(prefix) > depth}

    slot_width = 22.0
    level_height = 86.0
    margin_x = 26.0
    margin_top = 34.0
    leaf_slots = 1 << depth
    width = int(margin_x * 2 + leaf_slots * slot_width)
    height = int(margin_top + depth * level_height + 64)

    node_status: Dict[str, str] = {}
    node_title: Dict[str, str] = {}
    for level in range(depth + 1):
        for idx in range(1 << level):
            prefix = "" if level == 0 else format(idx, f"0{level}b")
            possible = _prefix_intersects_active(prefix, active_prefixes)

            if prefix in removed_exact:
                status = "removed"
            elif level == depth and prefix in removed_proxy:
                status = "removed_proxy"
            elif prefix in frontier_exact:
                status = "frontier"
            elif level == depth and prefix in frontier_proxy:
                status = "frontier_proxy"
            elif not possible:
                status = "blocked"
            elif prefix in derived_prefixes:
                status = "derived"
            else:
                status = "possible"

            node_status[prefix] = status

            if prefix == "":
                label = "seed root"
            else:
                label = f"prefix {prefix}"
            if status == "frontier":
                label += " (current frontier)"
            elif status == "frontier_proxy":
                label += " (frontier continues below visible depth)"
            elif status == "removed":
                label += " (deleted frontier from last puncture)"
            elif status == "removed_proxy":
                label += " (deleted frontier below visible depth)"
            elif status == "blocked":
                label += " (future derivation impossible)"
            elif status == "derived":
                label += " (contains previously derived path)"
            else:
                label += " (future derivation still possible)"
            node_title[prefix] = label

    edges_svg: list[str] = []
    for level in range(depth):
        for idx in range(1 << level):
            parent = "" if level == 0 else format(idx, f"0{level}b")
            px = _node_x(parent, depth=depth, slot_width=slot_width, margin_x=margin_x)
            py = margin_top + level * level_height
            for bit in ("0", "1"):
                child = parent + bit
                cx = _node_x(child, depth=depth, slot_width=slot_width, margin_x=margin_x)
                cy = margin_top + (level + 1) * level_height
                child_status = node_status[child]
                if child_status in {"removed", "removed_proxy"}:
                    edge_class = "edge-removed"
                elif child_status == "blocked":
                    edge_class = "edge-blocked"
                else:
                    edge_class = "edge-live"
                edges_svg.append(
                    f'<line class="{edge_class}" x1="{px:.2f}" y1="{py:.2f}" x2="{cx:.2f}" y2="{cy:.2f}" />'
                )

    nodes_svg: list[str] = []
    for level in range(depth + 1):
        radius = 10 if level == 0 else 7.5
        for idx in range(1 << level):
            prefix = "" if level == 0 else format(idx, f"0{level}b")
            x = _node_x(prefix, depth=depth, slot_width=slot_width, margin_x=margin_x)
            y = margin_top + level * level_height
            node_class = f"node-{node_status[prefix]}"
            title = node_title[prefix]
            nodes_svg.append(
                (
                    f'<circle class="{node_class}" cx="{x:.2f}" cy="{y:.2f}" r="{radius:.2f}">'
                    f"<title>{title}</title>"
                    "</circle>"
                )
            )

    current_frontier_count = sum(1 for status in node_status.values() if status in {"frontier", "frontier_proxy"})
    blocked_count = sum(1 for status in node_status.values() if status == "blocked")
    removed_count = sum(1 for status in node_status.values() if status in {"removed", "removed_proxy"})

    svg = (
        f'<svg class="tree-svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        'role="img" aria-label="Projected puncturable tree state">'
        "<style>"
        ".tree-svg{background:#fff;border:1px solid #ddd3bf;border-radius:12px}"
        ".edge-live{stroke:#8fbea3;stroke-width:1.3;opacity:.75}"
        ".edge-blocked{stroke:#d7a9a9;stroke-width:1.1;stroke-dasharray:4 4;opacity:.6}"
        ".edge-removed{stroke:#b42f2f;stroke-width:1.6;opacity:.95}"
        ".node-possible{fill:#d7f0df;stroke:#5d9a6f;stroke-width:1.3}"
        ".node-derived{fill:#ffe6ba;stroke:#c27a09;stroke-width:1.5}"
        ".node-blocked{fill:#f6d8d8;stroke:#b34f4f;stroke-width:1.2}"
        ".node-frontier{fill:#0f766e;stroke:#084a45;stroke-width:1.9}"
        ".node-frontier_proxy{fill:#8ecfc5;stroke:#0f766e;stroke-width:1.8}"
        ".node-removed{fill:#ef6a6a;stroke:#8e1a1a;stroke-width:2.0}"
        ".node-removed_proxy{fill:#f8b2b2;stroke:#9b1c1c;stroke-width:1.9}"
        "</style>"
        + "".join(edges_svg)
        + "".join(nodes_svg)
        + "</svg>"
    )

    return {
        "svg": svg,
        "depth": depth,
        "current_frontier_count": current_frontier_count,
        "blocked_count": blocked_count,
        "removed_count": removed_count,
        "last_puncture": last_diff or None,
    }


HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Puncture Lab</title>
  <style>
    :root {
      --bg: #f3efe5;
      --bg-soft: #fbf8f1;
      --card: #fffdf8;
      --ink: #172126;
      --muted: #5e6b70;
      --teal: #0f766e;
      --teal-soft: #d8f1ee;
      --orange: #c2410c;
      --orange-soft: #ffe8dd;
      --danger: #9b1c1c;
      --danger-soft: #ffe9e9;
      --line: #d9d1c0;
      --mono: Menlo, Consolas, Monaco, "Liberation Mono", monospace;
      --sans: "Avenir Next", "Trebuchet MS", "Lucida Grande", sans-serif;
      --radius: 16px;
      --shadow: 0 12px 28px rgba(23, 33, 38, 0.08);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(900px 450px at -10% -15%, #d8ece8 0%, transparent 60%),
        radial-gradient(700px 380px at 110% 0%, #f8dcc7 0%, transparent 55%),
        var(--bg);
      min-height: 100vh;
    }

    .layout {
      max-width: 1060px;
      margin: 0 auto;
      padding: 18px 14px 40px;
    }

    .reveal {
      opacity: 0;
      transform: translateY(14px);
      animation: rise 0.55s ease forwards;
    }

    .reveal:nth-of-type(1) { animation-delay: 0.03s; }
    .reveal:nth-of-type(2) { animation-delay: 0.08s; }
    .reveal:nth-of-type(3) { animation-delay: 0.13s; }
    .reveal:nth-of-type(4) { animation-delay: 0.18s; }
    .reveal:nth-of-type(5) { animation-delay: 0.23s; }
    .reveal:nth-of-type(6) { animation-delay: 0.28s; }

    @keyframes rise {
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px;
      margin-bottom: 14px;
    }

    .hero {
      padding: 20px;
      background: linear-gradient(135deg, #fffdf8 0%, #f4fbfa 55%, #fff3ea 100%);
    }

    .eyebrow {
      margin: 0;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-size: 0.75rem;
      color: var(--teal);
      font-weight: 700;
    }

    h1 {
      margin: 6px 0 8px;
      font-size: clamp(1.5rem, 4vw, 2.2rem);
      line-height: 1.15;
    }

    h2 {
      margin: 0 0 10px;
      font-size: 1.15rem;
    }

    h3 {
      margin: 0 0 8px;
      font-size: 1rem;
    }

    p { margin: 0 0 8px; }

    .muted { color: var(--muted); }

    .stats {
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .stat {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      background: rgba(255, 255, 255, 0.74);
    }

    .stat .label {
      color: var(--muted);
      font-size: 0.8rem;
      margin-bottom: 4px;
    }

    .stat .value {
      font-size: 1.4rem;
      font-weight: 700;
    }

    .status-pill {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 0.83rem;
      font-weight: 700;
    }

    .tone-info { background: #edf4ff; color: #23466b; }
    .tone-success { background: var(--teal-soft); color: #0a4f4a; }
    .tone-warn { background: var(--orange-soft); color: #7c2d11; }
    .tone-danger { background: var(--danger-soft); color: var(--danger); }

    .quickstart {
      margin: 0;
      padding-left: 20px;
    }

    .quickstart li {
      margin: 7px 0;
      color: var(--muted);
    }

    .quickstart li.done {
      color: var(--ink);
      font-weight: 600;
    }

    .progress {
      margin-top: 12px;
      height: 10px;
      background: #ece5d5;
      border-radius: 999px;
      overflow: hidden;
    }

    .progress > span {
      display: block;
      height: 100%;
      background: linear-gradient(90deg, var(--teal), #35a397);
      width: {{ progress.percent }}%;
      transition: width 0.35s ease;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }

    label {
      display: block;
      font-size: 0.84rem;
      font-weight: 700;
      margin: 10px 0 4px;
    }

    input, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px 11px;
      font: inherit;
      background: #fff;
      color: var(--ink);
    }

    textarea { min-height: 116px; resize: vertical; }

    .mono {
      font-family: var(--mono);
      font-size: 0.82rem;
      word-break: break-all;
    }

    .frontier-banner {
      border: 1px solid #c8ddd9;
      background: linear-gradient(135deg, #f6fffc 0%, #ecfaf6 100%);
      border-radius: 12px;
      padding: 10px;
      margin-top: 10px;
    }

    .frontier-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 10px;
    }

    .frontier-item {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      background: #fff;
    }

    .frontier-head {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 6px;
    }

    .frontier-pill {
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 0.72rem;
      font-weight: 700;
      border: 1px solid #cfe7e1;
      background: #e7f7f3;
      color: #0b4f49;
    }

    .frontier-bits {
      border: 1px dashed #d6c8a8;
      border-radius: 10px;
      padding: 8px;
      background: #fffaf0;
      margin-top: 6px;
    }

    .frontier-bits .split {
      color: #8d5a23;
      font-weight: 700;
      margin: 0 6px;
    }

    .tree-shell {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 10px;
      overflow-x: auto;
    }

    .tree-meta {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 8px;
    }

    .tree-meta-item {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fffdf8;
      padding: 8px;
    }

    .tree-meta-item .label {
      font-size: 0.76rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }

    .tree-meta-item .value {
      font-size: 1.1rem;
      font-weight: 700;
    }

    .tree-legend {
      margin-top: 8px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .tree-chip {
      display: inline-block;
      border-radius: 999px;
      padding: 5px 8px;
      font-size: 0.76rem;
      font-weight: 700;
      border: 1px solid var(--line);
      background: #fff;
    }

    .tree-chip.frontier { background: #d9f3ee; color: #0b4f49; border-color: #b8e6db; }
    .tree-chip.possible { background: #e8f7ec; color: #1d5c2f; border-color: #c8e9d1; }
    .tree-chip.derived { background: #fff0d0; color: #7b4d0a; border-color: #f0d7a2; }
    .tree-chip.blocked { background: #fee6e6; color: #7c1d1d; border-color: #efc2c2; }
    .tree-chip.removed { background: #f8d0d0; color: #8e1a1a; border-color: #e7abab; }

    .button-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }

    button {
      appearance: none;
      border: 0;
      border-radius: 10px;
      padding: 10px 12px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }

    .link-btn {
      display: inline-block;
      border-radius: 10px;
      padding: 10px 12px;
      font-weight: 700;
      text-decoration: none;
      border: 1px solid var(--line);
      background: white;
      color: var(--ink);
    }

    .btn-primary {
      background: var(--teal);
      color: white;
    }

    .btn-warn {
      background: var(--orange);
      color: white;
    }

    .btn-ghost {
      border: 1px solid var(--line);
      background: white;
      color: var(--ink);
    }

    .btn-danger {
      background: #f8d6d6;
      color: #7f1717;
      border: 1px solid #e5b2b2;
    }

    .form-hint {
      margin-top: 8px;
      padding: 9px;
      border-left: 4px solid var(--teal);
      background: #f1faf8;
      color: #264f4a;
      border-radius: 6px;
      font-size: 0.88rem;
    }

    .last-result {
      border-left: 5px solid var(--line);
      padding-left: 12px;
    }

    .last-result.tone-success { border-color: var(--teal); }
    .last-result.tone-warn { border-color: var(--orange); }
    .last-result.tone-danger { border-color: var(--danger); }
    .last-result.tone-info { border-color: #5479a5; }

    .tag-view {
      margin-top: 8px;
      padding: 9px;
      border: 1px dashed #b6ac95;
      border-radius: 10px;
      background: #fffaf0;
    }

    .tag-view .split {
      color: #8d5a23;
      font-weight: 700;
      margin: 0 6px;
    }

    .history {
      margin: 0;
      padding: 0;
      list-style: none;
      max-height: 320px;
      overflow: auto;
    }

    .history li {
      border-bottom: 1px solid #ece5d5;
      padding: 9px 0;
    }

    .history li:last-child { border-bottom: 0; }

    .history-meta {
      font-size: 0.78rem;
      color: var(--muted);
      margin-bottom: 3px;
    }

    .callout {
      background: #fff6ee;
      border: 1px solid #f0d5be;
      border-radius: 10px;
      padding: 10px;
      font-size: 0.9rem;
    }

    .footer-note {
      margin-top: 8px;
      color: var(--muted);
      font-size: 0.82rem;
    }

    @media (max-width: 840px) {
      .stats { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
      .frontier-grid { grid-template-columns: 1fr; }
      .tree-meta { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="layout">
    <section class="card hero reveal">
      <p class="eyebrow">Zero-Trust Cloud-Wide Forward Secrecy</p>
      <h1>Puncture Lab: human-readable key revocation</h1>
      <p class="muted">
        You can derive a key for a cloud file, puncture it, and prove that the same tag is permanently blocked while other tags keep working.
      </p>
      <div class="button-row">
        <a class="link-btn" href="{{ url_for('providers_page') }}">Manage Providers</a>
        <a class="link-btn" href="{{ url_for('assets_page') }}">Manage Assets</a>
      </div>
      <div class="stats">
        <div class="stat">
          <div class="label">Active tree nodes</div>
          <div class="value">{{ active_nodes }}</div>
          <div class="muted">Stored prefixes, not per-file keys</div>
        </div>
        <div class="stat">
          <div class="label">Punctures logged</div>
          <div class="value">{{ puncture_count }}</div>
          <div class="muted">Irreversible void events in this singleton</div>
        </div>
        <div class="stat">
          <div class="label">Walkthrough progress</div>
          <div class="value">{{ progress.done }}/3</div>
          <div class="muted">Newbie mode checklist</div>
        </div>
      </div>
    </section>

    <section class="card reveal">
      <h2>Current Active Roots (Frontier)</h2>
      <div class="frontier-banner">
        <p>
          This panel shows the <strong>only</strong> root prefixes currently active in memory.
          It does <strong>not</strong> show key material or seed bytes.
        </p>
        <p class="muted">After puncture, the single root is replaced by a minimal set of subtree roots.</p>
      </div>
      <div class="frontier-grid">
        {% for row in active_frontier %}
          <article class="frontier-item">
            <div class="frontier-head">
              <strong>{{ 'ROOT' if row.is_root else ('Prefix ' ~ row.prefix) }}</strong>
              <span class="frontier-pill">Depth {{ row.depth }} / 32</span>
            </div>
            <div class="frontier-bits mono">
              {% if row.is_root %}
                ROOT
              {% else %}
                <span>{{ row.provider_bits }}</span>
                {% if row.resource_bits %}
                  <span class="split">|</span><span>{{ row.resource_bits }}</span>
                {% endif %}
              {% endif %}
            </div>
            <p class="muted">{{ row.coverage_label }}</p>
          </article>
        {% endfor %}
      </div>
    </section>

    <section class="card reveal">
      <h2>Tree/Subtree Visualization</h2>
      <p class="muted">
        Projection of the first {{ tree_viz.depth }} bits of the 32-bit tree. Root starts as frontier;
        green nodes are derivable future space; amber marks branches that already had derivations.
      </p>
      <div class="tree-meta">
        <div class="tree-meta-item">
          <div class="label">Visible frontier nodes</div>
          <div class="value">{{ tree_viz.current_frontier_count }}</div>
        </div>
        <div class="tree-meta-item">
          <div class="label">Blocked projected nodes</div>
          <div class="value">{{ tree_viz.blocked_count }}</div>
        </div>
        <div class="tree-meta-item">
          <div class="label">Removed frontier (last puncture)</div>
          <div class="value">{{ tree_viz.removed_count }}</div>
        </div>
      </div>
      <div class="tree-shell">{{ tree_viz.svg | safe }}</div>
      <div class="tree-legend">
        <span class="tree-chip frontier">Current frontier</span>
        <span class="tree-chip possible">Future derivable</span>
        <span class="tree-chip derived">Already derived branch</span>
        <span class="tree-chip blocked">Now impossible</span>
        <span class="tree-chip removed">Deleted frontier (last puncture)</span>
      </div>
      {% if tree_viz.last_puncture %}
        <p class="footer-note">
          Last puncture ({{ tree_viz.last_puncture.time }}): {{ tree_viz.last_puncture.target_kind }}
          {{ tree_viz.last_puncture.target }}
        </p>
      {% else %}
        <p class="footer-note">No puncture yet. Root frontier covers the full derivation space.</p>
      {% endif %}
    </section>

    <section class="card reveal">
      <h2>Quick Start Walkthrough</h2>
      <ol class="quickstart">
        <li class="{{ 'done' if progress.derived_once else '' }}">Derive a key for any Provider ID + File/Time ID.</li>
        <li class="{{ 'done' if progress.punctured_once else '' }}">Puncture that same pair to revoke future access.</li>
        <li class="{{ 'done' if progress.verified_void else '' }}">Derive again and confirm the key is now inaccessible.</li>
      </ol>
      <div class="progress"><span></span></div>
      <p class="footer-note">Tip: click "Run Scenario A Automatically" if you just want to see the full flow once.</p>
    </section>

    <section class="grid">
      <article class="card reveal">
        <h2>Step 1 and 2: Key Workbench</h2>
        <p class="muted">Range: provider `0..127`, file/time `0..33,554,431`.</p>

        <div class="button-row">
          <button class="btn-ghost" id="fill-demo" type="button">Fill Demo Values (42 / 123456)</button>
          <form method="post" action="{{ url_for('run_demo_a') }}">
            <button class="btn-ghost" type="submit">Run Scenario A Automatically</button>
          </form>
        </div>

        <form method="post" action="{{ url_for('derive') }}">
          <label for="derive-provider">Provider ID</label>
          <input id="derive-provider" name="provider_id" type="number" min="0" max="127" required value="{{ last_inputs.provider_id }}" />

          <label for="derive-file">File/Time ID</label>
          <input id="derive-file" name="file_time_id" type="number" min="0" max="33554431" required value="{{ last_inputs.file_time_id }}" />

          <label for="derive-purpose">Purpose / Description</label>
          <input id="derive-purpose" name="purpose" type="text" maxlength="120" value="{{ last_inputs.purpose }}" placeholder="Short why/how this key is used" />

          <div class="button-row">
            <button class="btn-primary" type="submit">Derive Key</button>
          </div>
        </form>

        <form method="post" action="{{ url_for('puncture') }}">
          <label for="puncture-provider">Provider ID</label>
          <input id="puncture-provider" name="provider_id" type="number" min="0" max="127" required value="{{ last_inputs.provider_id }}" />

          <label for="puncture-file">File/Time ID</label>
          <input id="puncture-file" name="file_time_id" type="number" min="0" max="33554431" required value="{{ last_inputs.file_time_id }}" />

          <div class="button-row">
            <button class="btn-warn" type="submit">Puncture This Tag</button>
          </div>
        </form>

        <div class="form-hint">
          Same values -> derive, then puncture, then derive again. The second derive should be blocked.
        </div>
      </article>
      <article class="card reveal">
        <h2>What "Root" Means Here</h2>
        <p class="muted">
          The frontier panel is structural state only:
          which prefixes currently hold active subtree roots.
        </p>
        <p class="muted">
          Before any puncture there is one active root (`ROOT`). After puncture you will see multiple subtree prefixes.
          Any missing prefix region is permanently void.
        </p>
      </article>
    </section>

    <section class="card reveal">
      <h2>Latest Result</h2>
      <div class="status-pill tone-{{ last_action.tone }}">{{ last_action.title }}</div>
      <div class="last-result tone-{{ last_action.tone }}">
        <p>{{ last_action.body }}</p>
        {% if last_action.provider_id is not none %}
          <p class="muted">Provider {{ last_action.provider_id }}, File/Time {{ last_action.file_time_id }}</p>
        {% endif %}
        {% if last_action.path %}
          <div class="tag-view mono">
            Tag bits:
            <span>{{ last_action.path_provider }}</span>
            <span class="split">|</span>
            <span>{{ last_action.path_resource }}</span>
            <div class="muted">(7 bits provider | 25 bits file/time)</div>
          </div>
        {% endif %}
        {% if last_action.key_hex %}
          {% if last_action.key_description %}
            <p class="muted">Purpose: {{ last_action.key_description }}</p>
          {% endif %}
          <label for="latest-key">Derived key (hex)</label>
          <textarea id="latest-key" class="mono" readonly>{{ last_action.key_hex }}</textarea>
          <div class="button-row">
            <button class="btn-ghost" type="button" data-copy-target="latest-key">Copy Key</button>
          </div>
        {% endif %}
      </div>
    </section>

    <section class="grid">
      <article class="card reveal">
        <h2>Puncture Log (Audit)</h2>
        <p class="muted">Audit list of punctured bit-strings applied in this singleton system.</p>
        <textarea id="puncture-log" class="mono" readonly>{{ puncture_log_json }}</textarea>
        <div class="button-row">
          <button class="btn-ghost" type="button" data-copy-target="puncture-log">Copy Puncture Log</button>
        </div>
      </article>

      <article class="card reveal">
        <h2>Activity Timeline</h2>
        <ul class="history">
          {% if history %}
            {% for item in history %}
              <li>
                <div class="history-meta">{{ item.time }} | {{ item.action }} | {{ item.status }}</div>
                <div>{{ item.summary }}</div>
                {% if item.path %}
                  <div class="mono muted">{{ item.path }}</div>
                {% endif %}
              </li>
            {% endfor %}
          {% else %}
            <li class="muted">No actions yet. Start with "Derive Key".</li>
          {% endif %}
        </ul>
      </article>
    </section>

    <section class="card reveal">
      <h2>Before You Leave This Page</h2>
      <div class="callout">
        This interface is a local demonstration tool. It is intentionally educational and does not include user auth,
        encrypted persistence, or hardened production deployment controls.
      </div>
      <form method="post" action="{{ url_for('reset') }}">
        <div class="button-row">
          <button class="btn-danger" type="submit">Reset Entire Lab (fresh root state)</button>
        </div>
      </form>
    </section>
  </main>

  <script>
    const demoProvider = 42;
    const demoFile = 123456;

    function setAllInputs(provider, fileTime) {
      const pairs = [
        ["derive-provider", provider],
        ["puncture-provider", provider],
        ["derive-file", fileTime],
        ["puncture-file", fileTime]
      ];
      pairs.forEach(([id, val]) => {
        const el = document.getElementById(id);
        if (el) {
          el.value = val;
        }
      });
      const purpose = document.getElementById("derive-purpose");
      if (purpose && !purpose.value.trim()) {
        purpose.value = "Scenario demo key";
      }
    }

    const demoBtn = document.getElementById("fill-demo");
    if (demoBtn) {
      demoBtn.addEventListener("click", () => setAllInputs(demoProvider, demoFile));
    }

    async function copyText(raw) {
      try {
        await navigator.clipboard.writeText(raw);
        return true;
      } catch (_err) {
        return false;
      }
    }

    document.querySelectorAll("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const value = btn.getAttribute("data-copy") || "";
        const ok = await copyText(value);
        btn.textContent = ok ? "Copied" : "Copy failed";
      });
    });

    document.querySelectorAll("[data-copy-target]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const targetId = btn.getAttribute("data-copy-target");
        const target = targetId ? document.getElementById(targetId) : null;
        const value = target ? target.value : "";
        const ok = await copyText(value);
        btn.textContent = ok ? "Copied" : "Copy failed";
      });
    });
  </script>
</body>
</html>
"""


PROVIDERS_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Provider Manager</title>
  <style>
    :root {
      --bg: #f4f0e6;
      --card: #fffdf8;
      --ink: #172126;
      --muted: #5e6b70;
      --line: #d9d1c0;
      --teal: #0f766e;
      --orange: #c2410c;
      --danger: #8b1d1d;
      --radius: 14px;
      --sans: "Avenir Next", "Trebuchet MS", "Lucida Grande", sans-serif;
      --mono: Menlo, Consolas, Monaco, "Liberation Mono", monospace;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(900px 420px at -8% -12%, #d8ece8 0%, transparent 60%),
        radial-gradient(680px 340px at 110% 0%, #f8dcc7 0%, transparent 55%),
        var(--bg);
    }

    .wrap {
      max-width: 980px;
      margin: 0 auto;
      padding: 16px 14px 36px;
    }

    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 14px;
      margin-bottom: 12px;
    }

    h1 { margin: 4px 0 10px; font-size: clamp(1.45rem, 4vw, 2rem); }
    h2 { margin: 0 0 8px; font-size: 1.1rem; }
    p { margin: 0 0 8px; }
    .muted { color: var(--muted); }
    .mono { font-family: var(--mono); font-size: 0.84rem; word-break: break-all; }

    .stats {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .stat {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 9px;
      background: #fff;
    }

    .stat .label { color: var(--muted); font-size: 0.8rem; }
    .stat .value { font-size: 1.35rem; font-weight: 700; }

    .row {
      display: grid;
      gap: 10px;
      grid-template-columns: 1fr 1fr;
    }

    label {
      display: block;
      margin: 8px 0 4px;
      font-weight: 700;
      font-size: 0.84rem;
    }

    input, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 9px 10px;
      font: inherit;
      background: #fff;
      color: var(--ink);
    }

    textarea { min-height: 88px; resize: vertical; }

    .button-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }

    .btn {
      appearance: none;
      border: 0;
      border-radius: 10px;
      padding: 10px 12px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-block;
    }

    .btn-primary { background: var(--teal); color: #fff; }
    .btn-ghost { background: #fff; border: 1px solid var(--line); color: var(--ink); }
    .btn-danger { background: #f8dcdc; border: 1px solid #e7bcbc; color: var(--danger); }

    .provider-card {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      margin-bottom: 10px;
      background: #fff;
    }

    .provider-description {
      margin: 6px 0 8px;
      font-size: 0.9rem;
      color: var(--muted);
    }

    .key-panel {
      margin-top: 10px;
      border-top: 1px dashed #ddd3bf;
      padding-top: 10px;
    }

    .key-summary {
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin: 8px 0;
    }

    .mini-stat {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px;
      background: #fffdfa;
    }

    .mini-stat .label {
      font-size: 0.72rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }

    .mini-stat .value {
      font-size: 1.08rem;
      font-weight: 700;
    }

    .chip-row {
      margin: 7px 0;
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      align-items: center;
    }

    .chip {
      display: inline-block;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 0.76rem;
      border: 1px solid var(--line);
      background: #fff;
    }

    .chip-tag { background: #f7f3e8; color: #625331; border-color: #e0d5bf; }
    .chip-derived { background: #e2f5f1; color: #0c514b; border-color: #bde4dc; }
    .chip-punctured { background: #ffe9e0; color: #7c2d11; border-color: #efcab7; }

    .key-item {
      border: 1px solid #ece3d1;
      border-radius: 10px;
      padding: 9px;
      margin-top: 8px;
      background: #fffefb;
    }

    .key-head {
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 6px;
    }

    .key-title {
      font-weight: 700;
    }

    .status-badge {
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 0.73rem;
      font-weight: 700;
    }

    .status-derived { background: #daf1ec; color: #0b4f49; }
    .status-punctured { background: #ffe7dd; color: #74250e; }

    .key-meta {
      margin-top: 4px;
      color: var(--muted);
      font-size: 0.78rem;
    }

    .provider-head {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: baseline;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }

    .provider-id {
      font-family: var(--mono);
      font-size: 0.8rem;
      color: #7a4e26;
      padding: 4px 8px;
      border: 1px dashed #d8b893;
      border-radius: 999px;
      background: #fff5eb;
    }

    .notice {
      border-radius: 10px;
      padding: 10px;
      border: 1px solid var(--line);
      margin-bottom: 10px;
      font-weight: 600;
    }

    .notice.success { background: #dcf4ef; color: #0c4f49; border-color: #b7e5dc; }
    .notice.warn { background: #ffeede; color: #6f2d13; border-color: #f0d2bb; }
    .notice.danger { background: #ffe7e7; color: #7f1717; border-color: #efc3c3; }

    .deleted-entry {
      border-bottom: 1px solid #ece5d5;
      padding: 8px 0;
    }
    .deleted-entry:last-child { border-bottom: 0; }

    @media (max-width: 800px) {
      .stats { grid-template-columns: 1fr; }
      .row { grid-template-columns: 1fr; }
      .key-summary { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <div class="button-row">
        <a class="btn btn-ghost" href="{{ url_for('index') }}">Back to Lab</a>
      </div>
      <h1>Provider Manager</h1>
      <p class="muted">
        Add, edit, and delete cloud providers. Deleting a provider revokes access to its entire 7-bit subtree by prefix puncture.
      </p>
      <div class="stats">
        <div class="stat">
          <div class="label">Active providers</div>
          <div class="value">{{ active_count }}</div>
        </div>
        <div class="stat">
          <div class="label">Deleted providers</div>
          <div class="value">{{ deleted_count }}</div>
        </div>
      </div>
    </section>

    {% if notice %}
      <div class="notice {{ notice.tone }}">{{ notice.message }}</div>
    {% endif %}

    <section class="card">
      <h2>Add Provider</h2>
      <form method="post" action="{{ url_for('provider_add') }}">
        <div class="row">
          <div>
            <label for="provider_id">Provider ID (0..127)</label>
            <input id="provider_id" name="provider_id" type="number" min="0" max="127" required />
          </div>
          <div>
            <label for="provider_name">Display Name</label>
            <input id="provider_name" name="name" type="text" maxlength="80" required />
          </div>
        </div>
        <label for="provider_desc">Description</label>
        <input id="provider_desc" name="description" type="text" maxlength="120" placeholder="Short provider description (optional)" />
        <div class="button-row">
          <button class="btn btn-primary" type="submit">Add Provider</button>
        </div>
      </form>
    </section>

    <section class="card">
      <h2>Edit Or Delete Providers</h2>
      <p class="muted">Editing changes metadata only. Provider ID is immutable to preserve key mapping.</p>
      {% if providers %}
        {% for provider in providers %}
          <article class="provider-card">
            <div class="provider-head">
              <strong>{{ provider.name }}</strong>
              <span class="provider-id">ID {{ provider.provider_id }} | Prefix {{ provider.prefix }}</span>
            </div>

            <form method="post" action="{{ url_for('provider_edit') }}">
              <input type="hidden" name="provider_id" value="{{ provider.provider_id }}" />
              <label for="name-{{ provider.provider_id }}">Display Name</label>
              <input id="name-{{ provider.provider_id }}" name="name" type="text" maxlength="80" value="{{ provider.name }}" required />
              <label for="desc-{{ provider.provider_id }}">Description</label>
              <input id="desc-{{ provider.provider_id }}" name="description" type="text" maxlength="120" value="{{ provider.description }}" />
              <div class="button-row">
                <button class="btn btn-ghost" type="submit">Save Changes</button>
              </div>
            </form>

            <div class="key-panel">
              <h3>Key ID Journal</h3>
              <p class="muted">Visualization of key IDs seen for this provider. Only keys used in this lab appear.</p>
              <div class="key-summary">
                <div class="mini-stat">
                  <div class="label">Tracked IDs</div>
                  <div class="value">{{ provider.key_count }}</div>
                </div>
                <div class="mini-stat">
                  <div class="label">Ever Derived</div>
                  <div class="value">{{ provider.derived_count }}</div>
                </div>
                <div class="mini-stat">
                  <div class="label">Ever Punctured</div>
                  <div class="value">{{ provider.punctured_count }}</div>
                </div>
              </div>

              <div class="chip-row">
                <span class="chip chip-tag">Derived IDs</span>
                {% if provider.derived_ids %}
                  {% for file_id in provider.derived_ids %}
                    <span class="chip chip-derived">{{ file_id }}</span>
                  {% endfor %}
                {% else %}
                  <span class="muted">none</span>
                {% endif %}
              </div>

              <div class="chip-row">
                <span class="chip chip-tag">Punctured IDs</span>
                {% if provider.punctured_ids %}
                  {% for file_id in provider.punctured_ids %}
                    <span class="chip chip-punctured">{{ file_id }}</span>
                  {% endfor %}
                {% else %}
                  <span class="muted">none</span>
                {% endif %}
              </div>

              {% if provider.key_rows %}
                {% for key in provider.key_rows %}
                  <article class="key-item">
                    <div class="key-head">
                      <div class="key-title">File/Time ID {{ key.file_time_id }}</div>
                      <div>
                        {% if key.ever_derived %}<span class="status-badge status-derived">Derived</span>{% endif %}
                        {% if key.ever_punctured %}<span class="status-badge status-punctured">Punctured</span>{% endif %}
                      </div>
                    </div>
                    <div class="mono">{{ key.path_provider }} | {{ key.path_resource }}</div>
                    <div class="key-meta">Derived count: {{ key.derive_count }} | Puncture count: {{ key.puncture_count }}</div>
                    <div class="key-meta">Last derived: {{ key.last_derived_at or 'never' }} | Last punctured: {{ key.last_punctured_at or 'never' }}</div>
                    <form method="post" action="{{ url_for('provider_key_note_update') }}">
                      <input type="hidden" name="provider_id" value="{{ provider.provider_id }}" />
                      <input type="hidden" name="file_time_id" value="{{ key.file_time_id }}" />
                      <label for="kdesc-{{ provider.provider_id }}-{{ key.file_time_id }}">Purpose / Description</label>
                      <input id="kdesc-{{ provider.provider_id }}-{{ key.file_time_id }}" name="description" type="text" maxlength="120" value="{{ key.description }}" placeholder="Short purpose for this key ID" />
                      <div class="button-row">
                        <button class="btn btn-ghost" type="submit">Save Key Purpose</button>
                      </div>
                    </form>
                  </article>
                {% endfor %}
              {% else %}
                <p class="muted">No key IDs tracked for this provider yet.</p>
              {% endif %}
            </div>

            <form method="post" action="{{ url_for('provider_delete') }}" onsubmit="return confirm('Delete provider {{ provider.provider_id }}? This will puncture all keys for this provider.');">
              <input type="hidden" name="provider_id" value="{{ provider.provider_id }}" />
              <div class="button-row">
                <button class="btn btn-danger" type="submit">Delete Provider And Puncture All Its Keys</button>
              </div>
            </form>
          </article>
        {% endfor %}
      {% else %}
        <p class="muted">No active providers. Add one above.</p>
      {% endif %}
    </section>

    <section class="card">
      <h2>Deleted Providers (Audit)</h2>
      {% if deleted_providers %}
        {% for item in deleted_providers %}
          <div class="deleted-entry">
            <div><strong>ID {{ item.provider_id }}</strong> - {{ item.name }} at {{ item.deleted_at }}</div>
            <div class="muted">Prefix puncture: {{ item.prefix }} | Structural change: {{ 'yes' if item.applied else 'no' }}</div>
          </div>
        {% endfor %}
      {% else %}
        <p class="muted">No providers deleted yet.</p>
      {% endif %}
    </section>
  </main>
  <script>
    function toggleAssetChecks(value) {
      document.querySelectorAll('.asset-check').forEach((node) => {
        node.checked = value;
      });
    }
  </script>
</body>
</html>
"""


ASSETS_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Asset Workflow</title>
  <style>
    :root {
      --bg: #f6f2e8;
      --card: #fffdf8;
      --ink: #172126;
      --muted: #5e6b70;
      --line: #ddd3c0;
      --teal: #0f766e;
      --teal-soft: #daf2ec;
      --danger: #9b1c1c;
      --danger-soft: #ffe8e8;
      --warn: #7c3f12;
      --warn-soft: #ffefde;
      --ok-soft: #dcf4ef;
      --info-soft: #eef4ff;
      --radius: 14px;
      --sans: "Avenir Next", "Trebuchet MS", "Lucida Grande", sans-serif;
      --mono: Menlo, Consolas, Monaco, "Liberation Mono", monospace;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--ink);
      background:
        radial-gradient(920px 460px at -10% -12%, #d8ece8 0%, transparent 60%),
        radial-gradient(700px 360px at 110% 0%, #f7ddc7 0%, transparent 56%),
        var(--bg);
    }

    .wrap { max-width: 1040px; margin: 0 auto; padding: 12px 12px 24px; }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 12px;
      margin-bottom: 10px;
    }

    h1 { margin: 0 0 8px; font-size: clamp(1.25rem, 4.5vw, 1.9rem); }
    h2 { margin: 0 0 8px; font-size: 1.03rem; }
    h3 { margin: 0 0 6px; font-size: 0.95rem; }
    p { margin: 0 0 8px; }
    .muted { color: var(--muted); }
    .mono { font-family: var(--mono); font-size: 0.8rem; word-break: break-all; }
    .tiny { color: var(--muted); font-size: 0.76rem; }

    .button-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .btn {
      appearance: none;
      border: 0;
      border-radius: 10px;
      padding: 9px 11px;
      font: inherit;
      font-weight: 700;
      text-decoration: none;
      cursor: pointer;
      display: inline-block;
    }
    .btn-primary { background: var(--teal); color: #fff; }
    .btn-ghost { background: #fff; color: var(--ink); border: 1px solid var(--line); }

    .stats { display: grid; gap: 8px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 8px; }
    .stat {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 7px;
      background: #fff;
    }
    .stat .label { color: var(--muted); font-size: 0.74rem; }
    .stat .value { font-size: 1.08rem; font-weight: 800; }

    .notice {
      border-radius: 10px;
      border: 1px solid var(--line);
      padding: 9px;
      font-weight: 700;
      margin-bottom: 10px;
    }
    .notice.hidden { display: none; }
    .notice.success { background: var(--ok-soft); color: #0c4f49; border-color: #b7e5dc; }
    .notice.warn { background: var(--warn-soft); color: #6f2d13; border-color: #f0d2bb; }
    .notice.danger { background: var(--danger-soft); color: #7f1717; border-color: #efc3c3; }
    .notice.info { background: var(--info-soft); color: #1f4f7a; border-color: #c9dbf4; }

    .grid { display: grid; gap: 10px; grid-template-columns: 1.15fr 1fr; }
    .grid-bottom { display: grid; gap: 10px; grid-template-columns: 1fr 1fr; }

    .panel {
      border: 1px solid var(--line);
      border-radius: 11px;
      padding: 10px;
      background: #fff;
    }

    label {
      display: block;
      margin: 8px 0 4px;
      font-size: 0.82rem;
      font-weight: 700;
    }

    input:not([type="checkbox"]), select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px 9px;
      font: inherit;
      color: var(--ink);
      background: #fff;
    }

    input[type="checkbox"] {
      width: 18px;
      height: 18px;
      margin: 0;
      accent-color: var(--teal);
      flex: 0 0 18px;
    }

    .file-list {
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 10px;
      max-height: 280px;
      overflow: auto;
      background: #fff;
    }

    .file-row {
      display: grid;
      grid-template-columns: auto 1fr auto auto;
      gap: 8px;
      align-items: center;
      padding: 8px;
      border-bottom: 1px dashed #ece3d2;
    }
    .file-row:last-child { border-bottom: 0; }

    .badge {
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 0.72rem;
      font-weight: 800;
      border: 1px solid var(--line);
      background: #fff;
      color: var(--muted);
      white-space: nowrap;
    }
    .state-eligible { background: #eef5ff; color: #1e4f7a; border-color: #cadef2; }
    .state-encrypted_live { background: #ddf6ee; color: #0f544d; border-color: #b6e9dc; }
    .state-encrypted_partial { background: #fff1df; color: #734217; border-color: #eed2b3; }
    .state-encrypted_blocked { background: #ffe7e7; color: #7c1d1d; border-color: #efc3c3; }

    .mapping {
      border: 1px solid #ece3d2;
      border-radius: 10px;
      padding: 8px;
      margin-top: 7px;
      background: #fffefb;
    }
    .mapping.blocked { background: #ffe7e7; border-color: #eec2c2; color: #7b1c1c; }
    .mapping.glow { border-color: #96dccc; background: #e9fffa; box-shadow: 0 0 0 2px rgba(30,154,132,0.18); }

    .mapping-head { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; flex-wrap: wrap; }

    @media (max-width: 940px) {
      .stats { grid-template-columns: 1fr 1fr; }
      .grid, .grid-bottom { grid-template-columns: 1fr; }
      .file-row { grid-template-columns: auto 1fr; }
      .file-row .tiny { grid-column: 1 / -1; margin-left: 26px; }
    }

    @media (max-width: 560px) {
      .stats { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <div class="button-row">
        <a class="btn btn-ghost" href="{{ url_for('index') }}">Back to Lab</a>
        <a class="btn btn-ghost" href="{{ url_for('providers_page') }}">Providers</a>
      </div>
      <h1>Asset Workflow</h1>
      <p class="muted">State machine lifecycle: upload -> eligible -> encrypted (live/partial/blocked). Deselect anytime before encryption.</p>
      <p class="muted">Each ciphertext mapping now includes direct decryption to filesystem when its key is still accessible.</p>
      <p id="asset_root" class="mono"></p>
      <div class="stats">
        <div class="stat"><div class="label">Cleartext Files</div><div id="stat_cleartext" class="value">0</div></div>
        <div class="stat"><div class="label">Ciphertext Mappings</div><div id="stat_mapping" class="value">0</div></div>
        <div class="stat"><div class="label">Blocked Mappings</div><div id="stat_blocked" class="value">0</div></div>
        <div class="stat"><div class="label">Glow Mappings</div><div id="stat_glow" class="value">0</div></div>
      </div>
    </section>

    <div id="notice_box" class="notice {% if initial_notice %}{{ initial_notice.tone }}{% else %}hidden info{% endif %}">{% if initial_notice %}{{ initial_notice.message }}{% endif %}</div>

    <section class="card">
      <h2>Single Lifecycle Flow</h2>
      <div class="grid">
        <div class="panel">
          <h3>1) Choose Files</h3>
          <label for="upload_files">Pick new file(s) to upload</label>
          <input id="upload_files" name="files" type="file" multiple />
          <label for="target_subdir">Upload subfolder (optional)</label>
          <input id="target_subdir" type="text" placeholder="example: docs/2026" />
          <div class="button-row" style="margin-top:8px;">
            <button id="upload_btn" class="btn btn-primary" type="button" hidden>Upload Files</button>
            <span id="upload_hint" class="tiny">Choose files to enable upload.</span>
          </div>

          <h3 style="margin-top:12px;">2) Eligible Files</h3>
          <div class="button-row" style="margin-bottom:8px;">
            <button id="select_all_btn" class="btn btn-ghost" type="button">Select all</button>
            <button id="deselect_all_btn" class="btn btn-ghost" type="button">De-select all</button>
          </div>
          <div id="eligible_list" class="file-list"></div>
          <div class="button-row" style="margin-top:8px; justify-content:space-between;">
            <span id="selected_count" class="tiny">0 selected</span>
            <span id="eligible_count" class="tiny">0 eligible</span>
          </div>
        </div>

        <div class="panel">
          <h3>3) Encrypt Selection</h3>
          <label for="provider_id">Provider</label>
          <select id="provider_id"></select>

          <label for="file_time_id">Key ID (File/Time ID)</label>
          <input id="file_time_id" type="number" min="0" max="33554431" />

          <label for="purpose">Purpose</label>
          <input id="purpose" type="text" maxlength="120" placeholder="why this key for these files" />

          <label for="combo_quick">Quick key combo</label>
          <select id="combo_quick">
            <option value="">Manual selection</option>
          </select>

          <div class="button-row" style="margin-top:10px;">
            <button id="encrypt_btn" class="btn btn-primary" type="button">Encrypt Selected Files</button>
            <button id="wipe_btn" class="btn btn-ghost" type="button">Wipe Old Decisions</button>
          </div>
          <p class="tiny">Ciphertexts are saved to filesystem immediately after encryption.</p>
        </div>
      </div>
    </section>

    <section class="card">
      <h2>Asset Lifecycle States</h2>
      <div id="lifecycle_list"></div>
    </section>

    <section class="grid-bottom">
      <article class="card">
        <h2>Asset-Centric Mappings</h2>
        <div id="asset_mappings"></div>
      </article>
      <article class="card">
        <h2>Key-Centric Usage</h2>
        <div id="key_cards"></div>
      </article>
    </section>
  </main>

  <script>
    const INITIAL_STATE = {{ snapshot | tojson }};
    let workflowState = INITIAL_STATE;
    let selected = new Set();

    function node(id) {
      return document.getElementById(id);
    }

    function clearChildren(container) {
      while (container.firstChild) container.removeChild(container.firstChild);
    }

    function showNotice(tone, message) {
      const box = node('notice_box');
      if (!box) return;
      box.className = 'notice ' + tone;
      box.textContent = message;
    }

    function uploadCount() {
      const input = node('upload_files');
      if (!input || !input.files) return 0;
      return input.files.length;
    }

    function updateUploadControls() {
      const count = uploadCount();
      const btn = node('upload_btn');
      const hint = node('upload_hint');
      if (btn) btn.hidden = count === 0;
      if (hint) hint.textContent = count > 0 ? count + ' file(s) ready to upload.' : 'Choose files to enable upload.';
    }

    function stateClass(state) {
      return 'state-' + state;
    }

    function renderStats() {
      node('asset_root').textContent = 'Asset root: ' + workflowState.asset_root;
      node('stat_cleartext').textContent = String(workflowState.stats.cleartext_count);
      node('stat_mapping').textContent = String(workflowState.stats.mapping_count);
      node('stat_blocked').textContent = String(workflowState.stats.blocked_count);
      node('stat_glow').textContent = String(workflowState.stats.glow_count);
    }

    function renderProviderOptions() {
      const providerSelect = node('provider_id');
      const comboSelect = node('combo_quick');
      clearChildren(providerSelect);
      clearChildren(comboSelect);

      const manual = document.createElement('option');
      manual.value = '';
      manual.textContent = 'Manual selection';
      comboSelect.appendChild(manual);

      workflowState.providers.forEach((provider) => {
        const option = document.createElement('option');
        option.value = String(provider.provider_id);
        option.textContent = 'ID ' + provider.provider_id + ' - ' + provider.name;
        providerSelect.appendChild(option);
      });

      workflowState.key_combo_options.forEach((combo) => {
        const option = document.createElement('option');
        option.value = String(combo.provider_id) + '|' + String(combo.file_time_id);
        option.textContent = combo.label;
        comboSelect.appendChild(option);
      });

      const last = workflowState.last_inputs || {};
      if (last.provider_id !== undefined) providerSelect.value = String(last.provider_id);
      if (last.file_time_id !== undefined) node('file_time_id').value = String(last.file_time_id);
      if (last.purpose !== undefined) node('purpose').value = String(last.purpose || '');
    }

    function renderEligibleFiles() {
      const container = node('eligible_list');
      clearChildren(container);
      const relpaths = new Set(workflowState.files.map((f) => f.relpath));
      selected = new Set([...selected].filter((path) => relpaths.has(path)));

      workflowState.files.forEach((file) => {
        const row = document.createElement('div');
        row.className = 'file-row';

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = selected.has(file.relpath);
        checkbox.addEventListener('change', () => {
          if (checkbox.checked) {
            selected.add(file.relpath);
          } else {
            selected.delete(file.relpath);
          }
          updateSelectionMeta();
        });

        const name = document.createElement('span');
        name.className = 'mono';
        name.textContent = file.relpath;

        const meta = document.createElement('span');
        meta.className = 'tiny';
        meta.textContent = file.size_label + ' · ' + file.modified_at;

        const badge = document.createElement('span');
        badge.className = 'badge ' + stateClass(file.lifecycle_state);
        badge.textContent = file.lifecycle_label;

        row.appendChild(checkbox);
        row.appendChild(name);
        row.appendChild(meta);
        row.appendChild(badge);
        container.appendChild(row);
      });

      updateSelectionMeta();
    }

    function updateSelectionMeta() {
      node('selected_count').textContent = selected.size + ' selected';
      node('eligible_count').textContent = workflowState.files.length + ' eligible';
    }

    function renderLifecycle() {
      const container = node('lifecycle_list');
      clearChildren(container);
      if (workflowState.files.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'No cleartext files uploaded yet.';
        container.appendChild(empty);
        return;
      }

      workflowState.files.forEach((file) => {
        const box = document.createElement('div');
        box.className = 'mapping';

        const head = document.createElement('div');
        head.className = 'mapping-head';
        const left = document.createElement('strong');
        left.textContent = file.relpath;
        const right = document.createElement('span');
        right.className = 'badge ' + stateClass(file.lifecycle_state);
        right.textContent = file.lifecycle_label;
        head.appendChild(left);
        head.appendChild(right);

        const info = document.createElement('div');
        info.className = 'tiny';
        info.textContent = 'Mappings: ' + file.mapping_count + ' | Blocked: ' + file.blocked_count;

        box.appendChild(head);
        box.appendChild(info);
        container.appendChild(box);
      });
    }

    function renderAssetMappings() {
      const container = node('asset_mappings');
      clearChildren(container);
      if (workflowState.asset_files.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'No ciphertext mappings yet.';
        container.appendChild(empty);
        return;
      }

      workflowState.asset_files.forEach((file) => {
        const box = document.createElement('div');
        box.className = 'mapping';
        const head = document.createElement('div');
        head.className = 'mapping-head';
        const title = document.createElement('strong');
        title.textContent = file.plaintext_relpath;
        const meta = document.createElement('span');
        meta.className = 'tiny';
        meta.textContent = 'Mappings: ' + file.mapping_count + ' | Blocked: ' + file.blocked_count;
        head.appendChild(title);
        head.appendChild(meta);
        box.appendChild(head);

        file.mappings.forEach((row) => {
          const map = document.createElement('div');
          map.className = 'mapping' + (row.show_red ? ' blocked' : '') + (row.show_glow ? ' glow' : '');
          const mHead = document.createElement('div');
          mHead.className = 'mapping-head';
          const text = document.createElement('span');
          text.textContent = 'Provider ' + row.provider_id + ' | Key ' + row.file_time_id;
          const st = document.createElement('span');
          st.className = 'tiny';
          st.textContent = row.is_accessible ? 'decryptable' : 'blocked';
          mHead.appendChild(text);
          mHead.appendChild(st);

          const c = document.createElement('div');
          c.className = 'mono';
          c.textContent = 'cipher: ' + row.ciphertext_relpath;
          const d = document.createElement('div');
          d.className = 'tiny';
          if (row.last_decrypted_relpath) {
            d.textContent = 'last decrypted: ' + row.last_decrypted_relpath + ' (' + (row.last_decrypted_at || 'time unknown') + ')';
          } else {
            d.textContent = 'not decrypted yet';
          }

          const controls = document.createElement('div');
          controls.className = 'button-row';
          const decBtn = document.createElement('button');
          decBtn.type = 'button';
          decBtn.className = 'btn btn-ghost';
          decBtn.textContent = row.is_accessible ? 'Decrypt To Filesystem' : 'Blocked (punctured key)';
          decBtn.disabled = !row.is_accessible;
          decBtn.addEventListener('click', () => decryptMappings([Number(row.record_id)]));
          controls.appendChild(decBtn);

          map.appendChild(mHead);
          map.appendChild(c);
          map.appendChild(d);
          map.appendChild(controls);
          box.appendChild(map);
        });
        container.appendChild(box);
      });
    }

    function renderKeyCards() {
      const container = node('key_cards');
      clearChildren(container);
      if (workflowState.key_cards.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'No key usage yet.';
        container.appendChild(empty);
        return;
      }

      workflowState.key_cards.forEach((key) => {
        const box = document.createElement('div');
        box.className = 'mapping';

        const title = document.createElement('strong');
        title.textContent = 'Provider ' + key.provider_id + ' | Key ' + key.file_time_id;
        const meta = document.createElement('div');
        meta.className = 'tiny';
        meta.textContent = 'Files mapped: ' + key.file_count + ' | Status: ' + (key.is_accessible ? 'decryptable' : 'blocked');

        box.appendChild(title);
        box.appendChild(meta);
        key.files.forEach((path) => {
          const line = document.createElement('div');
          line.className = 'mono';
          line.textContent = '- ' + path;
          box.appendChild(line);
        });
        container.appendChild(box);
      });
    }

    function renderAll() {
      renderStats();
      renderProviderOptions();
      renderEligibleFiles();
      renderLifecycle();
      renderAssetMappings();
      renderKeyCards();
      updateUploadControls();
    }

    async function refreshState() {
      const resp = await fetch('/api/assets/workflow');
      const data = await resp.json();
      if (!data.ok) throw new Error(data.error || 'state fetch failed');
      workflowState = data.state;
      renderAll();
    }

    async function uploadFiles() {
      const input = node('upload_files');
      if (!input.files || input.files.length === 0) {
        showNotice('warn', 'Choose at least one file to upload.');
        return;
      }

      const form = new FormData();
      for (const file of input.files) {
        form.append('files', file);
      }
      form.append('target_subdir', node('target_subdir').value || '');

      const resp = await fetch('/api/assets/workflow/upload', { method: 'POST', body: form });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        showNotice('danger', data.error || 'Upload failed.');
        return;
      }

      workflowState = data.state;
      (data.uploaded || []).forEach((path) => selected.add(path));
      input.value = '';
      showNotice('success', data.message || 'Upload complete.');
      renderAll();
    }

    async function encryptSelected() {
      if (selected.size === 0) {
        showNotice('warn', 'Select at least one eligible file before encrypting.');
        return;
      }

      const payload = {
        plaintext_relpaths: Array.from(selected),
        provider_id: Number(node('provider_id').value),
        file_time_id: Number(node('file_time_id').value),
        purpose: node('purpose').value || '',
      };

      const resp = await fetch('/api/assets/workflow/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        showNotice('danger', data.error || 'Encryption failed.');
        return;
      }

      workflowState = data.state;
      selected.clear();
      showNotice(data.errors && data.errors.length ? 'warn' : 'success', data.message || 'Encryption complete.');
      renderAll();
    }

    async function decryptMappings(recordIds) {
      if (!recordIds || recordIds.length === 0) {
        showNotice('warn', 'Select at least one ciphertext mapping to decrypt.');
        return;
      }

      const resp = await fetch('/api/assets/workflow/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record_ids: recordIds }),
      });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        showNotice('danger', data.error || 'Decryption failed.');
        return;
      }

      workflowState = data.state;
      showNotice(data.errors && data.errors.length ? 'warn' : 'success', data.message || 'Decryption complete.');
      renderAll();
    }

    async function wipeDecisions() {
      const resp = await fetch('/api/assets/workflow/clear', { method: 'POST' });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        showNotice('danger', data.error || 'Could not clear decisions.');
        return;
      }

      selected.clear();
      node('upload_files').value = '';
      node('target_subdir').value = '';
      workflowState = data.state;
      showNotice('info', data.message || 'Decisions cleared.');
      renderAll();
    }

    function applyQuickCombo() {
      const combo = node('combo_quick').value;
      if (!combo) return;
      const parts = combo.split('|');
      if (parts.length !== 2) return;
      node('provider_id').value = parts[0];
      node('file_time_id').value = parts[1];
    }

    function selectAll() {
      workflowState.files.forEach((file) => selected.add(file.relpath));
      renderEligibleFiles();
    }

    function deselectAll() {
      selected.clear();
      renderEligibleFiles();
    }

    function wireEvents() {
      node('upload_files').addEventListener('change', updateUploadControls);
      node('upload_btn').addEventListener('click', uploadFiles);
      node('encrypt_btn').addEventListener('click', encryptSelected);
      node('wipe_btn').addEventListener('click', wipeDecisions);
      node('combo_quick').addEventListener('change', applyQuickCombo);
      node('select_all_btn').addEventListener('click', selectAll);
      node('deselect_all_btn').addEventListener('click', deselectAll);
    }

    document.addEventListener('DOMContentLoaded', () => {
      wireEvents();
      renderAll();
    });
  </script>
</body>
</html>
"""


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["system"] = _new_system()

    def _system() -> Dict[str, Any]:
        return app.config["system"]

    def _compute_progress(system: Dict[str, Any]) -> Dict[str, Any]:
        history = system["history"]
        derived_once = any(item["action"] == "derive" and item["status"] == "derived" for item in history)
        punctured_once = any(item["action"] == "puncture" and item["status"] == "applied" for item in history)
        verified_void = any(item["action"] == "derive" and item["status"] == "void" for item in history)

        done = sum([derived_once, punctured_once, verified_void])
        return {
            "derived_once": derived_once,
            "punctured_once": punctured_once,
            "verified_void": verified_void,
            "done": done,
            "percent": int((done / 3) * 100),
        }

    def _provider_rows(system: Dict[str, Any]) -> list[Dict[str, Any]]:
        rows = []
        journal = system["key_journal"]
        for provider_id in sorted(system["providers"].keys()):
            row = dict(system["providers"][provider_id])
            row["prefix"] = provider_id_to_prefix(provider_id)

            keys = []
            for entry in journal.values():
                if entry["provider_id"] == provider_id:
                    keys.append(dict(entry))
            keys.sort(key=lambda item: item["file_time_id"])

            row["key_rows"] = keys
            row["keys"] = keys
            row["key_count"] = len(keys)
            row["derived_count"] = sum(1 for item in keys if item["ever_derived"])
            row["punctured_count"] = sum(1 for item in keys if item["ever_punctured"])
            row["derived_ids"] = [item["file_time_id"] for item in keys if item["ever_derived"]]
            row["punctured_ids"] = [item["file_time_id"] for item in keys if item["ever_punctured"]]
            rows.append(row)
        return rows

    def _set_provider_notice(system: Dict[str, Any], tone: str, message: str) -> None:
        system["providers_notice"] = {"tone": tone, "message": message}

    def _set_asset_notice(system: Dict[str, Any], tone: str, message: str) -> None:
        system["asset_notice"] = {"tone": tone, "message": message}

    def _normalize_unique_relpaths(raw_relpaths: list[str]) -> list[str]:
        normalized = [_normalize_relpath(path) for path in raw_relpaths if str(path).strip()]
        if not normalized:
            raise ValueError("select existing files or upload files before encrypting")
        # de-duplicate while preserving order
        return list(dict.fromkeys(normalized))

    def _persist_uploaded_files(system: Dict[str, Any]) -> list[str]:
        target_subdir = request.form.get("target_subdir", "").strip()
        target_prefix = ""
        if target_subdir:
            target_prefix = _normalize_relpath(target_subdir).strip("/")

        files = request.files.getlist("files")
        saved: list[str] = []
        for item in files:
            filename = secure_filename(item.filename or "")
            if not filename:
                continue
            desired_rel = os.path.join(target_prefix, filename) if target_prefix else filename
            final_rel = _next_plaintext_relpath(system["asset_root"], desired_rel)
            final_abs = _asset_abs_path(system["asset_root"], final_rel)
            os.makedirs(os.path.dirname(final_abs), exist_ok=True)
            item.save(final_abs)
            saved.append(final_rel)
        return saved

    def _encrypt_plaintext_relpaths(
        system: Dict[str, Any],
        *,
        plaintext_relpaths: list[str],
        provider_id: int,
        file_time_id: int,
        purpose: str,
    ) -> Dict[str, Any]:
        manager: PuncturableKeyManager = system["manager"]
        path = tag_to_binary_path(provider_id, file_time_id)
        key = manager.get_key_for_tag(path)
        if key is None:
            raise ValueError("selected key is punctured/inaccessible")

        _touch_key_derive(
            system,
            provider_id=provider_id,
            file_time_id=file_time_id,
            path=path,
            description=purpose,
        )

        saved: list[tuple[str, str]] = []
        errors: list[str] = []
        for plaintext_relpath in plaintext_relpaths:
            try:
                plaintext_abs = _asset_abs_path(system["asset_root"], plaintext_relpath)
                if not os.path.isfile(plaintext_abs):
                    raise ValueError("cleartext file does not exist")

                with open(plaintext_abs, "rb") as in_file:
                    plaintext = in_file.read()

                encrypted_blob = _encrypt_blob(key, plaintext)
                ciphertext_relpath = _next_ciphertext_relpath(
                    system["asset_root"],
                    plaintext_relpath,
                    provider_id,
                    file_time_id,
                )
                ciphertext_abs = _asset_abs_path(system["asset_root"], ciphertext_relpath)
                os.makedirs(os.path.dirname(ciphertext_abs), exist_ok=True)
                with open(ciphertext_abs, "wb") as out_file:
                    out_file.write(encrypted_blob)

                system["asset_records"].append(
                    {
                        "record_id": len(system["asset_records"]) + 1,
                        "plaintext_relpath": plaintext_relpath,
                        "ciphertext_relpath": ciphertext_relpath,
                        "provider_id": provider_id,
                        "file_time_id": file_time_id,
                        "path": path,
                        "purpose": purpose,
                        "created_at": _utc_now_label(),
                        "plaintext_size": len(plaintext),
                        "ciphertext_size": len(encrypted_blob),
                        "decrypt_count": 0,
                        "last_decrypted_at": None,
                        "last_decrypted_relpath": None,
                    }
                )
                saved.append((plaintext_relpath, ciphertext_relpath))
            except Exception as item_exc:
                errors.append(f"{plaintext_relpath}: {item_exc}")

        if not saved:
            raise ValueError("; ".join(errors[:3]) or "no file could be encrypted")

        return {"path": path, "saved": saved, "errors": errors}

    def _decrypt_asset_records(system: Dict[str, Any], *, record_ids: list[int]) -> Dict[str, Any]:
        manager: PuncturableKeyManager = system["manager"]
        index: Dict[int, Dict[str, Any]] = {
            int(item["record_id"]): item for item in system["asset_records"] if "record_id" in item
        }

        restored: list[tuple[int, str, str]] = []
        errors: list[str] = []
        for record_id in record_ids:
            row = index.get(record_id)
            if row is None:
                errors.append(f"record {record_id}: not found")
                continue

            try:
                key = manager.get_key_for_tag(str(row["path"]))
                if key is None:
                    raise ValueError("key is punctured/inaccessible")

                ciphertext_abs = _asset_abs_path(system["asset_root"], str(row["ciphertext_relpath"]))
                if not os.path.isfile(ciphertext_abs):
                    raise ValueError("ciphertext file missing from filesystem")

                with open(ciphertext_abs, "rb") as in_file:
                    blob = in_file.read()

                plaintext = _decrypt_blob(key, blob)
                decrypted_relpath = _next_decrypted_relpath(
                    system["asset_root"],
                    str(row["plaintext_relpath"]),
                    int(row["provider_id"]),
                    int(row["file_time_id"]),
                )
                decrypted_abs = _asset_abs_path(system["asset_root"], decrypted_relpath)
                os.makedirs(os.path.dirname(decrypted_abs), exist_ok=True)
                with open(decrypted_abs, "wb") as out_file:
                    out_file.write(plaintext)

                row["decrypt_count"] = int(row.get("decrypt_count", 0)) + 1
                row["last_decrypted_at"] = _utc_now_label()
                row["last_decrypted_relpath"] = decrypted_relpath

                restored.append((record_id, str(row["ciphertext_relpath"]), decrypted_relpath))
            except Exception as item_exc:
                errors.append(f"record {record_id}: {item_exc}")

        if not restored:
            raise ValueError("; ".join(errors[:3]) or "no ciphertext could be decrypted")
        return {"restored": restored, "errors": errors}

    def _key_combo_options(system: Dict[str, Any]) -> list[Dict[str, Any]]:
        options: list[Dict[str, Any]] = []
        for row in sorted(
            [dict(item) for item in system["key_journal"].values()],
            key=lambda item: (item["provider_id"], item["file_time_id"]),
        ):
            status = "blocked" if row["ever_punctured"] else "active"
            options.append(
                {
                    "provider_id": row["provider_id"],
                    "file_time_id": row["file_time_id"],
                    "status": status,
                    "label": f"Provider {row['provider_id']} | Key {row['file_time_id']} | {status}",
                }
            )
        return options

    def _asset_workflow_snapshot(system: Dict[str, Any]) -> Dict[str, Any]:
        dashboard = _asset_dashboard(system)
        plain_rows = _list_plaintext_rows(system["asset_root"])
        providers = [
            {"provider_id": item["provider_id"], "name": item["name"]}
            for item in _provider_rows(system)
        ]

        mapped_by_relpath = {item["plaintext_relpath"]: item for item in dashboard["asset_files"]}
        files = []
        for row in plain_rows:
            mapped = mapped_by_relpath.get(row["relpath"])
            mapping_count = int(mapped["mapping_count"]) if mapped else 0
            blocked_count = int(mapped["blocked_count"]) if mapped else 0
            lifecycle_state = _asset_lifecycle_state(mapping_count, blocked_count)
            files.append(
                {
                    **row,
                    "mapping_count": mapping_count,
                    "blocked_count": blocked_count,
                    "lifecycle_state": lifecycle_state,
                    "lifecycle_label": _asset_lifecycle_label(lifecycle_state),
                }
            )

        return {
            "generated_at": _utc_now_label(),
            "asset_root": system["asset_root"],
            "stats": {
                "cleartext_count": len(files),
                "mapping_count": int(dashboard["mapping_count"]),
                "blocked_count": int(dashboard["blocked_count"]),
                "glow_count": int(dashboard["glow_count"]),
            },
            "files": files,
            "providers": providers,
            "key_combo_options": _key_combo_options(system),
            "last_inputs": dict(system["last_inputs"]),
            "asset_files": dashboard["asset_files"],
            "key_cards": dashboard["key_cards"],
        }

    def _mark_known_provider_keys_punctured(system: Dict[str, Any], provider_id: int) -> int:
        touched = 0
        stamp = _utc_now_label()
        for entry in system["key_journal"].values():
            if int(entry["provider_id"]) != provider_id:
                continue
            if not entry["ever_punctured"]:
                entry["puncture_count"] += 1
            entry["ever_punctured"] = True
            entry["last_punctured_at"] = stamp
            touched += 1
        return touched

    def _asset_dashboard(system: Dict[str, Any]) -> Dict[str, Any]:
        manager: PuncturableKeyManager = system["manager"]
        records = [dict(item) for item in system["asset_records"]]

        file_map: Dict[str, list[Dict[str, Any]]] = {}
        key_map: Dict[str, Dict[str, Any]] = {}
        blocked_total = 0
        glow_total = 0

        for row in records:
            path = row["path"]
            row["is_accessible"] = manager.get_key_for_tag(path) is not None
            row["path_provider"], row["path_resource"] = _split_path_bits(path)
            if not row["is_accessible"]:
                blocked_total += 1

            file_map.setdefault(row["plaintext_relpath"], []).append(row)

            key_id = f"{row['provider_id']}:{row['file_time_id']}:{path}"
            bucket = key_map.get(key_id)
            if bucket is None:
                bucket = {
                    "provider_id": row["provider_id"],
                    "file_time_id": row["file_time_id"],
                    "path": path,
                    "path_provider": row["path_provider"],
                    "path_resource": row["path_resource"],
                    "files": set(),
                    "is_accessible": row["is_accessible"],
                }
                key_map[key_id] = bucket
            bucket["files"].add(row["plaintext_relpath"])
            bucket["is_accessible"] = bucket["is_accessible"] and row["is_accessible"]

        file_cards: list[Dict[str, Any]] = []
        for plaintext_relpath in sorted(file_map.keys()):
            mappings = file_map[plaintext_relpath]
            mappings.sort(key=lambda item: item["created_at"])
            blocked_count = sum(1 for item in mappings if not item["is_accessible"])
            for item in mappings:
                item["show_red"] = not item["is_accessible"]
                item["show_glow"] = item["is_accessible"] and blocked_count > 0
                if item["show_glow"]:
                    glow_total += 1

            file_cards.append(
                {
                    "plaintext_relpath": plaintext_relpath,
                    "mapping_count": len(mappings),
                    "blocked_count": blocked_count,
                    "mappings": mappings,
                }
            )

        key_cards: list[Dict[str, Any]] = []
        for bucket in key_map.values():
            key_cards.append(
                {
                    "provider_id": bucket["provider_id"],
                    "file_time_id": bucket["file_time_id"],
                    "path": bucket["path"],
                    "path_provider": bucket["path_provider"],
                    "path_resource": bucket["path_resource"],
                    "file_count": len(bucket["files"]),
                    "files": sorted(bucket["files"]),
                    "is_accessible": bucket["is_accessible"],
                }
            )
        key_cards.sort(key=lambda item: (item["provider_id"], item["file_time_id"]))

        return {
            "asset_files": file_cards,
            "key_cards": key_cards,
            "mapping_count": len(records),
            "blocked_count": blocked_total,
            "glow_count": glow_total,
        }

    def _remote_token_valid() -> bool:
        configured = os.getenv("PUNCTURE_REMOTE_TOKEN", "").strip()
        if not configured:
            return True
        supplied = request.headers.get("X-Puncture-Token", "")
        return hmac.compare_digest(supplied, configured)

    @app.get("/")
    def index() -> str:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        return render_template_string(
            HTML,
            tree_viz=_tree_visualization_bundle(sys, manager),
            active_nodes=manager.active_node_count,
            active_frontier=_active_frontier_rows(manager),
            puncture_count=len(manager.puncture_log()),
            puncture_log_json=manager.export_puncture_log_json(),
            history=sys["history"],
            progress=_compute_progress(sys),
            last_action=sys["last_action"],
            last_inputs=sys["last_inputs"],
        )

    @app.get("/assets")
    def assets_page() -> str:
        sys = _system()
        snapshot = _asset_workflow_snapshot(sys)
        return render_template_string(
            ASSETS_HTML,
            snapshot=snapshot,
            initial_notice=sys["asset_notice"],
        )

    @app.get("/api/assets/workflow")
    def api_assets_workflow() -> Dict[str, Any]:
        sys = _system()
        return {"ok": True, "state": _asset_workflow_snapshot(sys)}

    @app.post("/api/assets/workflow/upload")
    def api_assets_workflow_upload() -> Dict[str, Any]:
        sys = _system()
        try:
            saved = _persist_uploaded_files(sys)
            if not saved:
                raise ValueError("choose at least one file to upload")

            preview = ", ".join(saved[:3])
            extra = "" if len(saved) <= 3 else f" and {len(saved) - 3} more"
            message = f"Uploaded {len(saved)} file(s): {preview}{extra}."
            _set_asset_notice(sys, "success", message)
            _record_history(
                sys,
                action="asset-upload",
                status="uploaded",
                summary=f"Uploaded {len(saved)} cleartext file(s) into asset root.",
            )
            return {
                "ok": True,
                "uploaded": saved,
                "message": message,
                "state": _asset_workflow_snapshot(sys),
            }
        except Exception as exc:
            message = f"Upload failed: {exc}"
            _set_asset_notice(sys, "danger", message)
            _record_history(sys, action="asset-upload", status="error", summary=message)
            return {"ok": False, "error": str(exc), "state": _asset_workflow_snapshot(sys)}, 400

    @app.post("/api/assets/workflow/clear")
    def api_assets_workflow_clear() -> Dict[str, Any]:
        sys = _system()
        sys["last_inputs"] = {"provider_id": 42, "file_time_id": 123456, "purpose": ""}
        message = "Cleared saved encryption decisions."
        _set_asset_notice(sys, "info", message)
        _record_history(
            sys,
            action="asset-decisions",
            status="cleared",
            summary="User cleared saved asset form decisions.",
        )
        return {"ok": True, "message": message, "state": _asset_workflow_snapshot(sys)}

    @app.post("/api/assets/workflow/encrypt")
    def api_assets_workflow_encrypt() -> Dict[str, Any]:
        sys = _system()
        payload = request.get_json(silent=True) or {}
        try:
            raw_relpaths = payload.get("plaintext_relpaths", [])
            if not isinstance(raw_relpaths, list):
                raise ValueError("plaintext_relpaths must be a list")
            plaintext_relpaths = _normalize_unique_relpaths([str(item) for item in raw_relpaths])

            provider_id = int(payload.get("provider_id"))
            file_time_id = int(payload.get("file_time_id"))
            purpose = str(payload.get("purpose", "")).strip()
            sys["last_inputs"] = {
                "provider_id": provider_id,
                "file_time_id": file_time_id,
                "purpose": purpose,
            }

            result = _encrypt_plaintext_relpaths(
                sys,
                plaintext_relpaths=plaintext_relpaths,
                provider_id=provider_id,
                file_time_id=file_time_id,
                purpose=purpose,
            )
            saved = result["saved"]
            errors = result["errors"]
            preview = ", ".join(f"{plain} -> {cipher}" for plain, cipher in saved[:2])
            extra = "" if len(saved) <= 2 else f" and {len(saved) - 2} more"

            if errors:
                message = (
                    f"Encrypted {len(saved)} file(s) with provider={provider_id}, key_id={file_time_id}: "
                    f"{preview}{extra}. Failed: {len(errors)}."
                )
                _set_asset_notice(sys, "warn", message)
            else:
                message = (
                    f"Encrypted {len(saved)} file(s) with provider={provider_id}, key_id={file_time_id}: "
                    f"{preview}{extra}."
                )
                _set_asset_notice(sys, "success", message)

            _record_history(
                sys,
                action="asset-encrypt",
                status="encrypted",
                summary=(
                    f"Encrypted {len(saved)} file(s) with provider={provider_id}, file_time={file_time_id}. "
                    + (f"Failures: {len(errors)}." if errors else "")
                ),
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=result["path"],
            )
            return {
                "ok": True,
                "saved": [{"plaintext_relpath": p, "ciphertext_relpath": c} for p, c in saved],
                "errors": errors,
                "message": message,
                "state": _asset_workflow_snapshot(sys),
            }
        except Exception as exc:
            message = f"Encryption failed: {exc}"
            _set_asset_notice(sys, "danger", message)
            _record_history(sys, action="asset-encrypt", status="error", summary=message)
            return {"ok": False, "error": str(exc), "state": _asset_workflow_snapshot(sys)}, 400

    @app.post("/api/assets/workflow/decrypt")
    def api_assets_workflow_decrypt() -> Dict[str, Any]:
        sys = _system()
        payload = request.get_json(silent=True) or {}
        try:
            raw_ids = payload.get("record_ids", [])
            if not isinstance(raw_ids, list):
                raise ValueError("record_ids must be a list")
            if not raw_ids:
                raise ValueError("select at least one ciphertext mapping to decrypt")

            record_ids: list[int] = []
            for value in raw_ids:
                record_ids.append(int(value))
            record_ids = list(dict.fromkeys(record_ids))

            result = _decrypt_asset_records(sys, record_ids=record_ids)
            restored = result["restored"]
            errors = result["errors"]
            preview = ", ".join(f"{src} -> {dst}" for _, src, dst in restored[:2])
            extra = "" if len(restored) <= 2 else f" and {len(restored) - 2} more"

            if errors:
                message = f"Decrypted {len(restored)} mapping(s): {preview}{extra}. Failed: {len(errors)}."
                _set_asset_notice(sys, "warn", message)
            else:
                message = f"Decrypted {len(restored)} mapping(s): {preview}{extra}."
                _set_asset_notice(sys, "success", message)

            _record_history(
                sys,
                action="asset-decrypt",
                status="decrypted",
                summary=f"Decrypted {len(restored)} mapping(s)." + (f" Failures: {len(errors)}." if errors else ""),
            )
            return {
                "ok": True,
                "restored": [
                    {"record_id": record_id, "ciphertext_relpath": src, "decrypted_relpath": dst}
                    for record_id, src, dst in restored
                ],
                "errors": errors,
                "message": message,
                "state": _asset_workflow_snapshot(sys),
            }
        except Exception as exc:
            message = f"Decryption failed: {exc}"
            _set_asset_notice(sys, "danger", message)
            _record_history(sys, action="asset-decrypt", status="error", summary=message)
            return {"ok": False, "error": str(exc), "state": _asset_workflow_snapshot(sys)}, 400

    @app.post("/assets/upload")
    def asset_upload() -> Any:
        sys = _system()
        try:
            saved = _persist_uploaded_files(sys)
            if not saved:
                raise ValueError("no files were selected")

            preview = ", ".join(saved[:3])
            extra = "" if len(saved) <= 3 else f" and {len(saved) - 3} more"
            _set_asset_notice(
                sys,
                "success",
                f"Uploaded {len(saved)} cleartext file(s): {preview}{extra}.",
            )
            _record_history(
                sys,
                action="asset-upload",
                status="uploaded",
                summary=f"Uploaded {len(saved)} cleartext file(s) into asset root.",
            )
        except Exception as exc:
            _set_asset_notice(sys, "danger", f"Upload failed: {exc}")
            _record_history(sys, action="asset-upload", status="error", summary=f"Upload failed: {exc}")
        return redirect(url_for("assets_page"))

    @app.post("/assets/encrypt")
    def asset_encrypt() -> Any:
        sys = _system()
        try:
            operation = request.form.get("operation", "encrypt").strip().lower()
            if operation == "wipe":
                sys["last_inputs"] = {
                    "provider_id": 42,
                    "file_time_id": 123456,
                    "purpose": "",
                }
                _set_asset_notice(sys, "info", "Cleared saved form decisions for asset encryption.")
                _record_history(
                    sys,
                    action="asset-decisions",
                    status="cleared",
                    summary="User cleared saved asset form decisions.",
                )
                return redirect(url_for("assets_page"))

            uploaded_relpaths = _persist_uploaded_files(sys)
            include_uploads = request.form.get("include_uploads") == "1"

            raw_relpaths = request.form.getlist("plaintext_relpaths")
            if not raw_relpaths:
                fallback = request.form.get("plaintext_relpath", "").strip()
                if fallback:
                    raw_relpaths = [fallback]
            if include_uploads:
                raw_relpaths.extend(uploaded_relpaths)
            plaintext_relpaths = _normalize_unique_relpaths(raw_relpaths)
            provider_id = int(request.form["provider_id"])
            file_time_id = int(request.form["file_time_id"])
            purpose = request.form.get("purpose", "").strip()
            sys["last_inputs"] = {
                "provider_id": provider_id,
                "file_time_id": file_time_id,
                "purpose": purpose,
            }

            result = _encrypt_plaintext_relpaths(
                sys,
                plaintext_relpaths=plaintext_relpaths,
                provider_id=provider_id,
                file_time_id=file_time_id,
                purpose=purpose,
            )
            saved = result["saved"]
            errors = result["errors"]

            preview = ", ".join(f"{plain} -> {cipher}" for plain, cipher in saved[:2])
            extra = "" if len(saved) <= 2 else f" and {len(saved) - 2} more"
            if errors:
                _set_asset_notice(
                    sys,
                    "warn",
                    (
                        f"Encrypted {len(saved)} file(s) with provider={provider_id}, key_id={file_time_id}: "
                        f"{preview}{extra}. Uploads saved: {len(uploaded_relpaths)}. Failed: {len(errors)}."
                    ),
                )
            else:
                _set_asset_notice(
                    sys,
                    "success",
                    (
                        f"Encrypted {len(saved)} file(s) with provider={provider_id}, key_id={file_time_id}: "
                        f"{preview}{extra}. Uploads saved: {len(uploaded_relpaths)}."
                    ),
                )
            _record_history(
                sys,
                action="asset-encrypt",
                status="encrypted",
                summary=(
                    f"Encrypted {len(saved)} file(s) with provider={provider_id}, file_time={file_time_id}. "
                    + f"Uploads saved: {len(uploaded_relpaths)}. "
                    + (f"Failures: {len(errors)}." if errors else "")
                ),
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=result["path"],
            )
        except Exception as exc:
            _set_asset_notice(sys, "danger", f"Encryption failed: {exc}")
            _record_history(sys, action="asset-encrypt", status="error", summary=f"Encryption failed: {exc}")
        return redirect(url_for("assets_page"))

    @app.get("/providers")
    def providers_page() -> str:
        sys = _system()
        return render_template_string(
            PROVIDERS_HTML,
            providers=_provider_rows(sys),
            deleted_providers=sys["deleted_providers"],
            active_count=len(sys["providers"]),
            deleted_count=len(sys["deleted_providers"]),
            notice=sys["providers_notice"],
        )

    @app.post("/providers/add")
    def provider_add() -> Any:
        sys = _system()
        try:
            provider_id = int(request.form["provider_id"])
            name = request.form["name"].strip()
            description = request.form.get("description", "").strip()

            if not name:
                raise ValueError("Display name is required.")
            if provider_id in sys["providers"]:
                raise ValueError(f"Provider ID {provider_id} already exists.")

            # Validation for provider ID bit range.
            provider_id_to_prefix(provider_id)

            sys["providers"][provider_id] = {
                "provider_id": provider_id,
                "name": name,
                "description": description,
                "created_at": _utc_now_label(),
            }
            _set_provider_notice(sys, "success", f"Added provider {provider_id}: {name}.")
            _record_history(
                sys,
                action="provider-add",
                status="added",
                summary=f"Added provider {provider_id} ({name}).",
            )
        except Exception as exc:
            _set_provider_notice(sys, "danger", f"Add failed: {exc}")
            _record_history(sys, action="provider-add", status="error", summary=f"Add failed: {exc}")
        return redirect(url_for("providers_page"))

    @app.post("/providers/edit")
    def provider_edit() -> Any:
        sys = _system()
        try:
            provider_id = int(request.form["provider_id"])
            name = request.form["name"].strip()
            description = request.form.get("description", "").strip()

            if provider_id not in sys["providers"]:
                raise ValueError(f"Provider ID {provider_id} does not exist.")
            if not name:
                raise ValueError("Display name is required.")

            sys["providers"][provider_id]["name"] = name
            sys["providers"][provider_id]["description"] = description
            _set_provider_notice(sys, "success", f"Updated provider {provider_id}.")
            _record_history(
                sys,
                action="provider-edit",
                status="updated",
                summary=f"Updated provider {provider_id}.",
            )
        except Exception as exc:
            _set_provider_notice(sys, "danger", f"Edit failed: {exc}")
            _record_history(sys, action="provider-edit", status="error", summary=f"Edit failed: {exc}")
        return redirect(url_for("providers_page"))

    @app.post("/providers/key-note")
    def provider_key_note_update() -> Any:
        sys = _system()
        try:
            provider_id = int(request.form["provider_id"])
            file_time_id = int(request.form["file_time_id"])
            description = request.form.get("description", "").strip()

            if provider_id not in sys["providers"]:
                raise ValueError(f"Provider ID {provider_id} does not exist.")

            path = tag_to_binary_path(provider_id, file_time_id)
            entry = _ensure_key_entry(sys, provider_id=provider_id, file_time_id=file_time_id, path=path)
            entry["description"] = description

            _set_provider_notice(
                sys,
                "success",
                f"Saved key purpose for provider={provider_id}, file/time={file_time_id}.",
            )
            _record_history(
                sys,
                action="key-note-edit",
                status="updated",
                summary=f"Updated key purpose for provider={provider_id}, file/time={file_time_id}.",
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
            )
        except Exception as exc:
            _set_provider_notice(sys, "danger", f"Key note update failed: {exc}")
            _record_history(sys, action="key-note-edit", status="error", summary=f"Key note update failed: {exc}")
        return redirect(url_for("providers_page"))

    @app.post("/providers/delete")
    def provider_delete() -> Any:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        try:
            provider_id = int(request.form["provider_id"])
            provider = sys["providers"].pop(provider_id, None)
            if provider is None:
                raise ValueError(f"Provider ID {provider_id} does not exist.")

            prefix = provider_id_to_prefix(provider_id)
            before_frontier = manager.active_prefixes()
            applied = manager.puncture_prefix(prefix)
            after_frontier = manager.active_prefixes()
            _set_last_puncture_diff(
                sys,
                before_frontier=before_frontier,
                after_frontier=after_frontier,
                target_bitstring=prefix,
                target_kind="provider-prefix",
            )
            touched = _mark_known_provider_keys_punctured(sys, provider_id)

            sys["deleted_providers"].insert(
                0,
                {
                    "provider_id": provider_id,
                    "name": provider["name"],
                    "prefix": prefix,
                    "deleted_at": _utc_now_label(),
                    "applied": applied,
                },
            )
            del sys["deleted_providers"][32:]

            _set_provider_notice(
                sys,
                "warn",
                (
                    f"Deleted provider {provider_id}. Prefix {prefix} punctured across its full subtree; "
                    f"structural change: {'yes' if applied else 'no'}. "
                    f"Known key IDs marked punctured: {touched}."
                ),
            )
            _set_last_action(
                sys,
                tone="warn",
                title="Provider deleted and subtree punctured",
                body=(
                    f"Provider {provider_id} was removed from registry and its 7-bit prefix was punctured. "
                    "All keys under that provider are now inaccessible."
                ),
                provider_id=provider_id,
            )
            _record_history(
                sys,
                action="provider-delete",
                status="punctured" if applied else "already-inaccessible",
                summary=f"Deleted provider {provider_id}; prefix puncture {prefix}.",
            )
        except Exception as exc:
            _set_provider_notice(sys, "danger", f"Delete failed: {exc}")
            _record_history(sys, action="provider-delete", status="error", summary=f"Delete failed: {exc}")
        return redirect(url_for("providers_page"))

    @app.post("/derive")
    def derive() -> Any:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        try:
            provider_id = int(request.form["provider_id"])
            file_time_id = int(request.form["file_time_id"])
            purpose = request.form.get("purpose", "").strip()
            sys["last_inputs"] = {"provider_id": provider_id, "file_time_id": file_time_id, "purpose": purpose}

            path = tag_to_binary_path(provider_id, file_time_id)
            key = manager.get_key_for_tag(path)

            if key is None:
                body = (
                    "No key is derivable for this tag. It was punctured earlier or excluded by previous punctures. "
                    "This is the expected forward-secrecy behavior."
                )
                _set_last_action(
                    sys,
                    tone="warn",
                    title="Derive blocked: key is inaccessible",
                    body=body,
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                )
                _record_history(
                    sys,
                    action="derive",
                    status="void",
                    summary=f"Derive blocked for provider={provider_id}, file={file_time_id}.",
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                )
            else:
                key_hex = key.hex()
                entry = _touch_key_derive(
                    sys,
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                    description=purpose,
                )
                body = (
                    "Key derivation succeeded. Keep in mind this demo shows the key directly for learning. "
                    "In production, this should feed cryptographic operations without UI exposure."
                )
                _set_last_action(
                    sys,
                    tone="success",
                    title="Derive succeeded",
                    body=body,
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                    key_hex=key_hex,
                    key_description=entry["description"] or None,
                )
                _record_history(
                    sys,
                    action="derive",
                    status="derived",
                    summary=(
                        f"Derived key for provider={provider_id}, file={file_time_id}."
                        + (f" Purpose: {entry['description']}." if entry["description"] else "")
                    ),
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                )

        except Exception as exc:
            _set_last_action(
                sys,
                tone="danger",
                title="Input error",
                body=str(exc),
            )
            _record_history(sys, action="derive", status="error", summary=f"Derive failed: {exc}")
        return redirect(url_for("index"))

    @app.post("/puncture")
    def puncture() -> Any:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        try:
            provider_id = int(request.form["provider_id"])
            file_time_id = int(request.form["file_time_id"])
            sys["last_inputs"] = {
                "provider_id": provider_id,
                "file_time_id": file_time_id,
                "purpose": sys["last_inputs"].get("purpose", ""),
            }

            path = tag_to_binary_path(provider_id, file_time_id)
            before_frontier = manager.active_prefixes()
            applied = manager.puncture(path)
            after_frontier = manager.active_prefixes()
            _set_last_puncture_diff(
                sys,
                before_frontier=before_frontier,
                after_frontier=after_frontier,
                target_bitstring=path,
                target_kind="tag",
            )
            entry = _touch_key_puncture(
                sys,
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
                applied=applied,
            )

            if applied:
                body = (
                    "Puncture applied. This exact tag can no longer derive a key. "
                    "Other tags remain derivable through the co-path node set."
                )
                _set_last_action(
                    sys,
                    tone="success",
                    title="Puncture succeeded",
                    body=body,
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                    key_description=entry["description"] or None,
                )
                _record_history(
                    sys,
                    action="puncture",
                    status="applied",
                    summary=f"Punctured provider={provider_id}, file={file_time_id}.",
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                )
            else:
                body = (
                    "No change was needed. This tag was already inaccessible, likely due to an earlier puncture."
                )
                _set_last_action(
                    sys,
                    tone="warn",
                    title="Puncture no-op",
                    body=body,
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                    key_description=entry["description"] or None,
                )
                _record_history(
                    sys,
                    action="puncture",
                    status="noop",
                    summary=f"No-op puncture for provider={provider_id}, file={file_time_id}.",
                    provider_id=provider_id,
                    file_time_id=file_time_id,
                    path=path,
                )

        except Exception as exc:
            _set_last_action(
                sys,
                tone="danger",
                title="Input error",
                body=str(exc),
            )
            _record_history(sys, action="puncture", status="error", summary=f"Puncture failed: {exc}")
        return redirect(url_for("index"))

    @app.post("/demo/scenario-a")
    def run_demo_a() -> Any:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        provider_id = 42
        file_time_id = 123456
        path = tag_to_binary_path(provider_id, file_time_id)
        sys["last_inputs"] = {
            "provider_id": provider_id,
            "file_time_id": file_time_id,
            "purpose": "Scenario A demonstration key",
        }

        key_before = manager.get_key_for_tag(path)
        if key_before is not None:
            _touch_key_derive(
                sys,
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
                description="Scenario A demonstration key",
            )
        before_frontier = manager.active_prefixes()
        punctured = manager.puncture(path)
        after_frontier = manager.active_prefixes()
        _set_last_puncture_diff(
            sys,
            before_frontier=before_frontier,
            after_frontier=after_frontier,
            target_bitstring=path,
            target_kind="tag",
        )
        _touch_key_puncture(
            sys,
            provider_id=provider_id,
            file_time_id=file_time_id,
            path=path,
            applied=punctured,
        )
        key_after = manager.get_key_for_tag(path)

        passed = key_before is not None and punctured and key_after is None
        if passed:
            _set_last_action(
                sys,
                tone="success",
                title="Scenario A passed",
                body=(
                    "Demo complete: key existed before puncture, puncture was applied, and the same key is now inaccessible."
                ),
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
            )
            _record_history(
                sys,
                action="scenario-a",
                status="passed",
                summary="Auto-ran Scenario A successfully.",
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
            )
        else:
            _set_last_action(
                sys,
                tone="danger",
                title="Scenario A failed",
                body="Unexpected result; check activity timeline and state consistency.",
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
            )
            _record_history(
                sys,
                action="scenario-a",
                status="failed",
                summary="Auto-ran Scenario A and it failed.",
                provider_id=provider_id,
                file_time_id=file_time_id,
                path=path,
            )

        return redirect(url_for("index"))

    @app.post("/reset")
    def reset() -> Any:
        app.config["system"] = _new_system()
        sys = _system()
        _record_history(sys, action="system", status="reset", summary="Lab was reset with a fresh root state.")
        return redirect(url_for("index"))

    @app.get("/api/state")
    def api_state() -> Dict[str, Any]:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        dashboard = _asset_dashboard(sys)
        key_journal_rows = sorted(
            [dict(item) for item in sys["key_journal"].values()],
            key=lambda row: (row["provider_id"], row["file_time_id"]),
        )
        return {
            "active_nodes": manager.active_node_count,
            "active_prefixes": manager.active_prefixes(),
            "active_frontier": _active_frontier_rows(manager),
            "last_puncture_diff": sys["last_puncture_diff"],
            "puncture_log": manager.puncture_log(),
            "last_action": sys["last_action"],
            "history": sys["history"],
            "providers": list(_provider_rows(sys)),
            "deleted_providers": sys["deleted_providers"],
            "key_journal": key_journal_rows,
            "asset_root": sys["asset_root"],
            "assets": dashboard,
        }

    @app.get("/api/export")
    def api_export() -> Dict[str, Any]:
        manager: PuncturableKeyManager = _system()["manager"]
        return manager.export_state()

    @app.get("/api/view-bundle")
    def api_view_bundle() -> Dict[str, Any]:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        payload = build_view_payload(sys, manager.puncture_log())
        sync_key = os.getenv("PUNCTURE_VIEW_SYNC_KEY", "").strip() or None
        return wrap_view_bundle(payload, sync_key)

    @app.get("/api/live/state")
    def api_live_state() -> Dict[str, Any]:
        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        dashboard = _asset_dashboard(sys)
        key_journal_rows = sorted(
            [dict(item) for item in sys["key_journal"].values()],
            key=lambda row: (row["provider_id"], row["file_time_id"]),
        )
        return {
            "generated_at": _utc_now_label(),
            "active_nodes": manager.active_node_count,
            "active_prefixes": manager.active_prefixes(),
            "active_frontier": _active_frontier_rows(manager),
            "last_puncture_diff": sys["last_puncture_diff"],
            "providers": _provider_rows(sys),
            "key_journal": key_journal_rows,
            "assets": dashboard,
            "asset_root": sys["asset_root"],
        }

    @app.post("/api/remote/puncture-provider")
    def api_remote_puncture_provider() -> Dict[str, Any]:
        if not _remote_token_valid():
            return {"ok": False, "error": "unauthorized"}, 403

        sys = _system()
        manager: PuncturableKeyManager = sys["manager"]
        payload = request.get_json(silent=True) or {}
        try:
            raw_provider_id = payload.get("provider_id", request.form.get("provider_id"))
            provider_id = int(raw_provider_id)
            provider_id_to_prefix(provider_id)

            before_frontier = manager.active_prefixes()
            applied = manager.puncture_provider(provider_id)
            after_frontier = manager.active_prefixes()
            provider_prefix = provider_id_to_prefix(provider_id)
            _set_last_puncture_diff(
                sys,
                before_frontier=before_frontier,
                after_frontier=after_frontier,
                target_bitstring=provider_prefix,
                target_kind="provider-prefix",
            )
            touched = _mark_known_provider_keys_punctured(sys, provider_id)

            _set_last_action(
                sys,
                tone="warn",
                title="Remote kill-switch puncture",
                body=(
                    f"Remote command punctured provider {provider_id}. "
                    "All keys under this provider prefix are now blocked."
                ),
                provider_id=provider_id,
            )
            _record_history(
                sys,
                action="remote-provider-puncture",
                status="punctured" if applied else "already-inaccessible",
                summary=f"Remote puncture on provider {provider_id}.",
                provider_id=provider_id,
            )

            return {
                "ok": True,
                "provider_id": provider_id,
                "applied": applied,
                "known_key_rows_marked": touched,
                "puncture_count": len(manager.puncture_log()),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}, 400

    @app.post("/api/import")
    def api_import() -> Dict[str, Any]:
        payload = request.get_json(force=True)
        manager = PuncturableKeyManager.from_state(payload)
        sys = _system()
        sys["manager"] = manager
        _set_last_action(
            sys,
            tone="info",
            title="State imported",
            body="Imported active-node state and puncture log.",
        )
        _record_history(sys, action="system", status="imported", summary="Imported manager state via API.")
        return {"ok": True, "active_nodes": manager.active_node_count}

    @app.post("/api/puncture-log")
    def api_apply_puncture_log() -> Dict[str, Any]:
        payload = request.get_json(force=True)
        paths = payload.get("paths", [])
        if not isinstance(paths, list):
            return {"ok": False, "error": "paths must be a list"}, 400

        manager: PuncturableKeyManager = _system()["manager"]
        applied = manager.apply_puncture_log(paths)
        return {
            "ok": True,
            "applied": applied,
            "puncture_count": len(manager.puncture_log()),
            "active_nodes": manager.active_node_count,
        }

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run puncture web app")
    parser.add_argument("--host", default=os.getenv("PUNCTURE_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PUNCTURE_PORT", "9122")))
    args = parser.parse_args()

    app = create_app()
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
