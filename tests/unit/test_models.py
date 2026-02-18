"""Tests for data models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

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
from edr_bench.models.metrics import BenchmarkReport, ScenarioResult
from edr_bench.models.scenario import Scenario, SimulationStep


@pytest.mark.unit
class TestSimulationStep:
    def test_create_cli_step(self):
        step = SimulationStep(
            order=1,
            role=Role.CLI,
            command="whoami",
            description="Check user",
        )
        assert step.order == 1
        assert step.role == Role.CLI
        assert step.command == "whoami"
        assert step.timeout_seconds == 60

    def test_create_ui_step(self):
        step = SimulationStep(
            order=2,
            role=Role.UI,
            description="Open browser",
            ui_instructions="Click the Firefox icon",
        )
        assert step.role == Role.UI
        assert step.ui_instructions == "Click the Firefox icon"
        assert step.command is None

    def test_step_order_must_be_positive(self):
        with pytest.raises(Exception):
            SimulationStep(order=0, role=Role.CLI, description="Bad step")

    def test_step_timeout_must_be_positive(self):
        with pytest.raises(Exception):
            SimulationStep(
                order=1, role=Role.CLI, description="Bad", timeout_seconds=0
            )


@pytest.mark.unit
class TestScenario:
    def test_create_scenario(self, sample_scenario: Scenario):
        assert sample_scenario.id == "TEST-001"
        assert sample_scenario.platform == Platform.LINUX
        assert len(sample_scenario.simulation_steps) == 1

    def test_is_cli_scenario(self, sample_scenario: Scenario):
        assert sample_scenario.is_cli_scenario is True
        assert sample_scenario.is_ui_scenario is False

    def test_is_ui_scenario(self):
        scenario = Scenario(
            id="UI-001",
            name="UI Test",
            description="Test",
            platform=Platform.LINUX,
            attack_type=AttackType.EXECUTION,
            mitre_technique_id="T1059",
            mitre_technique_name="Command Interpreter",
            complexity=Complexity.MEDIUM,
            simulation_steps=[
                SimulationStep(
                    order=1,
                    role=Role.UI,
                    description="Open browser",
                    ui_instructions="Click Firefox",
                )
            ],
        )
        assert scenario.is_ui_scenario is True
        assert scenario.is_cli_scenario is False

    def test_scenario_needs_at_least_one_step(self):
        with pytest.raises(Exception):
            Scenario(
                id="EMPTY",
                name="Empty",
                description="No steps",
                platform=Platform.LINUX,
                attack_type=AttackType.DISCOVERY,
                mitre_technique_id="T1082",
                mitre_technique_name="System Info",
                complexity=Complexity.LOW,
                simulation_steps=[],
            )


@pytest.mark.unit
class TestFinding:
    def test_create_finding(self):
        finding = Finding(
            id="F-001",
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            rule_name="Test Rule",
            severity=Severity.HIGH,
        )
        assert finding.id == "F-001"
        assert finding.blocked is False
        assert finding.raw == {}

    def test_finding_with_all_fields(self):
        finding = Finding(
            id="F-002",
            timestamp=datetime.now(timezone.utc),
            rule_name="Full Finding",
            severity=Severity.CRITICAL,
            description="Detailed description",
            mitre_technique_id="T1059.001",
            process_name="powershell",
            process_pid=1234,
            command_line="powershell -enc ...",
            file_path="/tmp/evil.ps1",
            network_dst="10.0.0.1",
            network_port=443,
            blocked=True,
            raw={"original": "data"},
        )
        assert finding.blocked is True
        assert finding.raw == {"original": "data"}


@pytest.mark.unit
class TestGroundTruthEvent:
    def test_create_event(self):
        event = GroundTruthEvent(
            timestamp=datetime.now(timezone.utc),
            source=GroundTruthSource.TRACEE,
            scenario_id="TEST-001",
            event_type="execve",
            process_name="whoami",
        )
        assert event.source == GroundTruthSource.TRACEE


@pytest.mark.unit
class TestScenarioResult:
    def test_create_result(self):
        result = ScenarioResult(
            scenario_id="TEST-001",
            scenario_name="Test",
            platform=Platform.LINUX,
            attack_type=AttackType.DISCOVERY,
            mitre_technique_id="T1033",
            detection_rate=0.8,
            contextual_accuracy=0.7,
            time_to_detect_seconds=2.5,
            blocking_efficacy=0.0,
            noise_ratio=0.1,
            ground_truth_count=5,
            findings_count=6,
            matched_count=4,
            false_positive_count=1,
        )
        assert result.detection_rate == 0.8

    def test_detection_rate_bounds(self):
        with pytest.raises(Exception):
            ScenarioResult(
                scenario_id="BAD",
                scenario_name="Bad",
                platform=Platform.LINUX,
                attack_type=AttackType.DISCOVERY,
                mitre_technique_id="T1033",
                detection_rate=1.5,
                contextual_accuracy=0.5,
                blocking_efficacy=0.5,
                noise_ratio=0.1,
                ground_truth_count=0,
                findings_count=0,
                matched_count=0,
                false_positive_count=0,
            )


@pytest.mark.unit
class TestEnums:
    def test_platform_values(self):
        assert Platform.LINUX == "linux"
        assert Platform.WINDOWS == "windows"

    def test_role_values(self):
        assert Role.CLI == "cli"
        assert Role.UI == "ui"

    def test_attack_type_values(self):
        assert AttackType.EXECUTION == "execution"
        assert AttackType.EXFILTRATION == "exfiltration"
