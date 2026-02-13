"""Simulation scenarios for puncturable key manager."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .key_manager import PuncturableKeyManager, tag_to_binary_path


@dataclass
class ScenarioResult:
    scenario: str
    passed: bool
    details: dict


def run_scenario_a() -> ScenarioResult:
    """Scenario A: Upload file to Provider 42, then puncture its key."""

    seed = PuncturableKeyManager.generate_master_seed()
    manager = PuncturableKeyManager(seed)

    provider_id = 42
    file_time_id = 123456
    tag = tag_to_binary_path(provider_id, file_time_id)

    key_before = manager.get_key_for_tag(tag)
    punctured = manager.puncture(tag)
    key_after = manager.get_key_for_tag(tag)

    passed = key_before is not None and punctured and key_after is None
    return ScenarioResult(
        scenario="A",
        passed=passed,
        details={
            "provider_id": provider_id,
            "file_time_id": file_time_id,
            "path": tag,
            "key_before_exists": key_before is not None,
            "puncture_applied": punctured,
            "key_after_exists": key_after is not None,
            "active_nodes": manager.active_node_count,
        },
    )


def run_scenario_b() -> ScenarioResult:
    """Scenario B: seized node-set cannot derive punctured key but can derive others."""

    seed = PuncturableKeyManager.generate_master_seed()
    manager = PuncturableKeyManager(seed)

    punctured_path = tag_to_binary_path(42, 777777)
    control_path = tag_to_binary_path(42, 777778)

    control_before = manager.get_key_for_tag(control_path)
    manager.puncture(punctured_path)

    # Simulate nation-state seizure of *current* active node-set only.
    seized_state = manager.export_state()
    seized_manager = PuncturableKeyManager.from_state(seized_state)

    punctured_from_seized = seized_manager.get_key_for_tag(punctured_path)
    control_from_seized = seized_manager.get_key_for_tag(control_path)

    passed = punctured_from_seized is None and control_before == control_from_seized
    return ScenarioResult(
        scenario="B",
        passed=passed,
        details={
            "punctured_path": punctured_path,
            "control_path": control_path,
            "punctured_recoverable_from_seized": punctured_from_seized is not None,
            "control_key_still_recoverable": control_from_seized is not None,
            "control_key_matches_pre_puncture": control_before == control_from_seized,
            "active_nodes_seized": seized_manager.active_node_count,
        },
    )


def run_all() -> dict:
    scenario_a = run_scenario_a()
    scenario_b = run_scenario_b()

    return {
        "scenario_a": {"passed": scenario_a.passed, "details": scenario_a.details},
        "scenario_b": {"passed": scenario_b.passed, "details": scenario_b.details},
        "overall_passed": scenario_a.passed and scenario_b.passed,
    }


if __name__ == "__main__":
    print(json.dumps(run_all(), indent=2))
