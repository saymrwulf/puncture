"""GGM-tree based puncturable key manager.

This module implements a 32-bit tag space mapped as:
[7 bits provider_id] | [25 bits file/time_id]
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


PROVIDER_BITS = 7
RESOURCE_BITS = 25
PATH_BITS = PROVIDER_BITS + RESOURCE_BITS
KEY_SIZE_BYTES = 32


def _zeroize(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _derive_child(parent_key: bytes | bytearray, bit: str) -> bytearray:
    if bit not in {"0", "1"}:
        raise ValueError("bit must be '0' or '1'")
    marker = b"\x00" if bit == "0" else b"\x01"
    child = hmac.new(bytes(parent_key), b"GGM" + marker, hashlib.sha256).digest()
    return bytearray(child)


def _validate_binary_path(binary_path: str, expected_length: int = PATH_BITS) -> None:
    if len(binary_path) != expected_length:
        raise ValueError(f"binary_path must be {expected_length} bits")
    if any(c not in "01" for c in binary_path):
        raise ValueError("binary_path must contain only '0' or '1'")


def _validate_binary_prefix(binary_prefix: str, min_len: int = 1, max_len: int = PATH_BITS) -> None:
    if not (min_len <= len(binary_prefix) <= max_len):
        raise ValueError(f"binary_prefix must be between {min_len} and {max_len} bits")
    if any(c not in "01" for c in binary_prefix):
        raise ValueError("binary_prefix must contain only '0' or '1'")


@dataclass(frozen=True)
class Tag:
    provider_id: int
    file_time_id: int

    def to_binary_path(self) -> str:
        return tag_to_binary_path(self.provider_id, self.file_time_id)


def tag_to_binary_path(provider_id: int, file_time_id: int) -> str:
    if not (0 <= provider_id < (1 << PROVIDER_BITS)):
        raise ValueError(f"provider_id must be in [0, {1 << PROVIDER_BITS})")
    if not (0 <= file_time_id < (1 << RESOURCE_BITS)):
        raise ValueError(f"file_time_id must be in [0, {1 << RESOURCE_BITS})")

    value = (provider_id << RESOURCE_BITS) | file_time_id
    return f"{value:0{PATH_BITS}b}"


def provider_id_to_prefix(provider_id: int) -> str:
    if not (0 <= provider_id < (1 << PROVIDER_BITS)):
        raise ValueError(f"provider_id must be in [0, {1 << PROVIDER_BITS})")
    return f"{provider_id:0{PROVIDER_BITS}b}"


def binary_path_to_tag(binary_path: str) -> Tag:
    _validate_binary_path(binary_path)
    value = int(binary_path, 2)
    file_time_mask = (1 << RESOURCE_BITS) - 1
    provider_id = value >> RESOURCE_BITS
    file_time_id = value & file_time_mask
    return Tag(provider_id=provider_id, file_time_id=file_time_id)


class PuncturableKeyManager:
    """Forward-secret key manager based on puncturable GGM keys.

    State model:
    - The manager stores only a prefix-free set of active nodes (prefix -> seed).
    - A puncture operation removes one covering ancestor node and replaces it with the
      minimal set of sibling/co-path nodes needed to preserve all other leaves.
    """

    def __init__(self, master_seed: bytes):
        if len(master_seed) != KEY_SIZE_BYTES:
            raise ValueError(f"master_seed must be {KEY_SIZE_BYTES} bytes")
        self._active_nodes: Dict[str, bytearray] = {"": bytearray(master_seed)}
        self._puncture_log: List[str] = []
        self._punctured_paths: set[str] = set()
        self._punctured_prefixes: set[str] = set()

    @staticmethod
    def generate_master_seed() -> bytes:
        return os.urandom(KEY_SIZE_BYTES)

    @property
    def active_node_count(self) -> int:
        return len(self._active_nodes)

    def active_prefixes(self) -> List[str]:
        return sorted(self._active_nodes.keys(), key=lambda p: (len(p), p))

    def puncture_log(self) -> List[str]:
        return list(self._puncture_log)

    def export_puncture_log_json(self) -> str:
        return json.dumps(self._puncture_log)

    def export_state(self) -> dict:
        return {
            "active_nodes": {prefix: bytes(seed).hex() for prefix, seed in self._active_nodes.items()},
            "puncture_log": list(self._puncture_log),
        }

    @classmethod
    def from_state(cls, state: dict) -> "PuncturableKeyManager":
        # Seed is a placeholder; state fully replaces active nodes.
        manager = cls(master_seed=b"\x00" * KEY_SIZE_BYTES)

        active_nodes = state.get("active_nodes")
        if not isinstance(active_nodes, dict):
            raise ValueError("state['active_nodes'] must be a dict")

        rebuilt_nodes: Dict[str, bytearray] = {}
        for prefix, hex_seed in active_nodes.items():
            if any(c not in "01" for c in prefix):
                raise ValueError("active node prefixes must be binary strings")
            seed = bytes.fromhex(hex_seed)
            if len(seed) != KEY_SIZE_BYTES:
                raise ValueError("active node seed must be 32 bytes")
            rebuilt_nodes[prefix] = bytearray(seed)

        manager._active_nodes = rebuilt_nodes

        puncture_log = state.get("puncture_log", [])
        if not isinstance(puncture_log, list):
            raise ValueError("state['puncture_log'] must be a list")
        for bitstring in puncture_log:
            _validate_binary_prefix(bitstring, min_len=1, max_len=PATH_BITS)
        manager._puncture_log = list(puncture_log)
        manager._punctured_paths = {b for b in puncture_log if len(b) == PATH_BITS}
        manager._punctured_prefixes = {b for b in puncture_log if len(b) < PATH_BITS}
        return manager

    def _find_covering_prefix(self, binary_path: str) -> Optional[str]:
        for depth in range(len(binary_path), -1, -1):
            prefix = binary_path[:depth]
            if prefix in self._active_nodes:
                return prefix
        return None

    def get_key_for_tag(self, binary_path: str) -> Optional[bytes]:
        _validate_binary_path(binary_path)

        cover = self._find_covering_prefix(binary_path)
        if cover is None:
            return None

        key: bytes | bytearray = self._active_nodes[cover]
        for bit in binary_path[len(cover) :]:
            key = _derive_child(key, bit)
        return bytes(key)

    def get_key_for_provider_resource(self, provider_id: int, file_time_id: int) -> Optional[bytes]:
        return self.get_key_for_tag(tag_to_binary_path(provider_id, file_time_id))

    def puncture(self, binary_path: str) -> bool:
        """Puncture a path using minimal co-path replacement.

        Returns:
            True if a new puncture was applied.
            False if the path was already punctured / inaccessible.
        """

        _validate_binary_path(binary_path)

        if binary_path in self._punctured_paths:
            return False
        if any(binary_path.startswith(prefix) for prefix in self._punctured_prefixes):
            return False

        cover = self._find_covering_prefix(binary_path)
        if cover is None:
            # Already inaccessible due to earlier punctures.
            self._punctured_paths.add(binary_path)
            self._puncture_log.append(binary_path)
            return False

        current_key = self._active_nodes.pop(cover)

        for depth in range(len(cover), PATH_BITS):
            bit = binary_path[depth]
            sibling_bit = "1" if bit == "0" else "0"

            sibling_key = _derive_child(current_key, sibling_bit)
            sibling_prefix = binary_path[:depth] + sibling_bit
            self._active_nodes[sibling_prefix] = sibling_key

            selected_key = _derive_child(current_key, bit)
            _zeroize(current_key)
            current_key = selected_key

        # Current leaf key has been punctured; zeroize immediately.
        _zeroize(current_key)

        self._punctured_paths.add(binary_path)
        self._puncture_log.append(binary_path)
        return True

    def puncture_prefix(self, binary_prefix: str) -> bool:
        """Puncture a full subtree identified by a prefix.

        Example: 7-bit provider prefix to revoke all keys for that provider.
        """

        _validate_binary_prefix(binary_prefix, min_len=1, max_len=PATH_BITS)
        if len(binary_prefix) == PATH_BITS:
            return self.puncture(binary_prefix)

        if binary_prefix in self._punctured_prefixes:
            return False
        if any(binary_prefix.startswith(prefix) for prefix in self._punctured_prefixes):
            return False

        changed = False

        cover = self._find_covering_prefix(binary_prefix)
        if cover is not None:
            current_key = self._active_nodes.pop(cover)
            changed = True

            for depth in range(len(cover), len(binary_prefix)):
                bit = binary_prefix[depth]
                sibling_bit = "1" if bit == "0" else "0"

                sibling_key = _derive_child(current_key, sibling_bit)
                sibling_prefix = binary_prefix[:depth] + sibling_bit
                self._active_nodes[sibling_prefix] = sibling_key

                selected_key = _derive_child(current_key, bit)
                _zeroize(current_key)
                current_key = selected_key

            # Punctured subtree root key should not remain in memory.
            _zeroize(current_key)

        descendants = [node for node in self._active_nodes.keys() if node.startswith(binary_prefix)]
        if descendants:
            changed = True
        for node in descendants:
            doomed = self._active_nodes.pop(node)
            _zeroize(doomed)

        self._punctured_prefixes.add(binary_prefix)
        self._puncture_log.append(binary_prefix)
        return changed

    def puncture_provider_resource(self, provider_id: int, file_time_id: int) -> bool:
        return self.puncture(tag_to_binary_path(provider_id, file_time_id))

    def puncture_provider(self, provider_id: int) -> bool:
        return self.puncture_prefix(provider_id_to_prefix(provider_id))

    def apply_puncture_log(self, puncture_paths: Iterable[str]) -> int:
        applied = 0
        for bitstring in puncture_paths:
            _validate_binary_prefix(bitstring, min_len=1, max_len=PATH_BITS)
            if len(bitstring) == PATH_BITS:
                changed = self.puncture(bitstring)
            else:
                changed = self.puncture_prefix(bitstring)
            if changed:
                applied += 1
        return applied
