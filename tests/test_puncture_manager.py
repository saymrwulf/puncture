from puncture.key_manager import (
    PATH_BITS,
    PuncturableKeyManager,
    provider_id_to_prefix,
    tag_to_binary_path,
)


def test_mapping_and_derivation_roundtrip() -> None:
    manager = PuncturableKeyManager(master_seed=b"\x11" * 32)
    path = tag_to_binary_path(42, 123)
    key = manager.get_key_for_tag(path)
    assert key is not None
    assert len(key) == 32


def test_scenario_a_provider_42_then_puncture() -> None:
    manager = PuncturableKeyManager(master_seed=b"\x22" * 32)
    path = tag_to_binary_path(42, 999)

    key_before = manager.get_key_for_tag(path)
    assert key_before is not None

    punctured = manager.puncture(path)
    assert punctured is True
    assert manager.get_key_for_tag(path) is None


def test_non_target_paths_still_accessible_after_puncture() -> None:
    manager = PuncturableKeyManager(master_seed=b"\x33" * 32)
    target = tag_to_binary_path(42, 12345)
    other = tag_to_binary_path(42, 12346)

    other_before = manager.get_key_for_tag(other)
    manager.puncture(target)
    other_after = manager.get_key_for_tag(other)

    assert manager.get_key_for_tag(target) is None
    assert other_before == other_after


def test_minimal_copath_replacement_from_root() -> None:
    manager = PuncturableKeyManager(master_seed=b"\x44" * 32)
    path = tag_to_binary_path(1, 1)
    assert manager.active_node_count == 1

    manager.puncture(path)

    # Remove root (1) and add one sibling node per level (32).
    assert manager.active_node_count == PATH_BITS


def test_scenario_b_seized_state_cannot_recover_punctured() -> None:
    manager = PuncturableKeyManager(master_seed=b"\x55" * 32)
    punctured = tag_to_binary_path(42, 2024)
    control = tag_to_binary_path(42, 2025)

    control_before = manager.get_key_for_tag(control)
    manager.puncture(punctured)

    seized = PuncturableKeyManager.from_state(manager.export_state())
    assert seized.get_key_for_tag(punctured) is None
    assert seized.get_key_for_tag(control) == control_before


def test_provider_puncture_blocks_all_provider_keys() -> None:
    manager = PuncturableKeyManager(master_seed=b"\x66" * 32)
    p42_a = tag_to_binary_path(42, 100)
    p42_b = tag_to_binary_path(42, 101)
    p41 = tag_to_binary_path(41, 100)

    p41_before = manager.get_key_for_tag(p41)
    assert manager.puncture_provider(42) is True

    assert manager.get_key_for_tag(p42_a) is None
    assert manager.get_key_for_tag(p42_b) is None
    assert manager.get_key_for_tag(p41) == p41_before


def test_prefix_puncture_log_replay() -> None:
    seed = b"\x77" * 32
    source = PuncturableKeyManager(master_seed=seed)
    target = PuncturableKeyManager(master_seed=seed)

    provider_prefix = provider_id_to_prefix(42)
    source.puncture_prefix(provider_prefix)

    applied = target.apply_puncture_log(source.puncture_log())
    assert applied == 1
    assert target.get_key_for_tag(tag_to_binary_path(42, 1234)) is None
