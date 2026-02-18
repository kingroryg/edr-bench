"""Shared test fixtures for edr-bench."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from edr_bench.config.settings import Settings
from edr_bench.models.enums import (
    AttackType,
    Complexity,
    GroundTruthSource,
    Platform,
    Role,
    Severity,
)
from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent
from edr_bench.models.scenario import Scenario, SimulationStep


@pytest.fixture
def sample_step() -> SimulationStep:
    return SimulationStep(
        order=1,
        role=Role.CLI,
        command="whoami",
        description="Check current user",
        expected_artifact="whoami process",
        timeout_seconds=10,
    )


@pytest.fixture
def sample_scenario(sample_step: SimulationStep) -> Scenario:
    return Scenario(
        id="TEST-001",
        name="Test Scenario",
        description="A simple test scenario",
        platform=Platform.LINUX,
        attack_type=AttackType.DISCOVERY,
        mitre_technique_id="T1033",
        mitre_technique_name="System Owner/User Discovery",
        complexity=Complexity.LOW,
        simulation_steps=[sample_step],
        expected_detections=["user_discovery"],
        tags=["test"],
    )


@pytest.fixture
def sample_ground_truth() -> list[GroundTruthEvent]:
    base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    return [
        GroundTruthEvent(
            timestamp=base_time,
            source=GroundTruthSource.TRACEE,
            scenario_id="TEST-001",
            step_order=1,
            event_type="execve",
            process_name="whoami",
            command_line="whoami",
        ),
        GroundTruthEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 5, tzinfo=timezone.utc),
            source=GroundTruthSource.TRACEE,
            scenario_id="TEST-001",
            step_order=1,
            event_type="execve",
            process_name="cat",
            command_line="cat /etc/passwd",
            file_path="/etc/passwd",
        ),
    ]


@pytest.fixture
def sample_findings() -> list[Finding]:
    base_time = datetime(2024, 1, 15, 10, 0, 2, tzinfo=timezone.utc)
    return [
        Finding(
            id="F-001",
            timestamp=base_time,
            rule_name="User Discovery Command",
            severity=Severity.LOW,
            description="Detected user discovery command execution",
            mitre_technique_id="T1033",
            process_name="whoami",
            command_line="whoami",
        ),
        Finding(
            id="F-002",
            timestamp=datetime(2024, 1, 15, 10, 0, 7, tzinfo=timezone.utc),
            rule_name="Sensitive File Access",
            severity=Severity.MEDIUM,
            description="Access to /etc/passwd detected",
            mitre_technique_id="T1087.001",
            process_name="cat",
            file_path="/etc/passwd",
        ),
        Finding(
            id="F-003",
            timestamp=datetime(2024, 1, 15, 10, 1, 0, tzinfo=timezone.utc),
            rule_name="False Positive Alert",
            severity=Severity.INFO,
            description="Benign system activity",
        ),
    ]


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def scenarios_dir(tmp_path: Path) -> Path:
    return tmp_path / "scenarios"
