"""Tests for CSV scenario loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from edr_bench.models.enums import AttackType, Complexity, Platform, Role
from edr_bench.utils.csv_loader import CSVLoader


def _write_csv(path: Path, rows: list[dict]) -> Path:
    """Helper to write a CSV file from row dicts."""
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = rows[0].keys()
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _make_row(
    scenario_id: str = "TEST-001",
    name: str = "Test Scenario",
    platform: str = "linux",
    steps: list[dict] | None = None,
) -> dict:
    """Build a scenario CSV row."""
    if steps is None:
        steps = [
            {
                "order": 1,
                "role": "cli",
                "command": "whoami",
                "description": "Check user",
            }
        ]
    return {
        "id": scenario_id,
        "name": name,
        "description": "Test description",
        "platform": platform,
        "attack_type": "discovery",
        "mitre_technique_id": "T1033",
        "mitre_technique_name": "System Owner/User Discovery",
        "complexity": "low",
        "simulation_steps": json.dumps(steps),
        "expected_detections": json.dumps(["test_rule"]),
        "tags": json.dumps(["test"]),
    }


@pytest.mark.unit
class TestCSVLoader:
    def test_load_single_scenario(self, tmp_path: Path):
        csv_path = _write_csv(tmp_path / "test.csv", [_make_row()])
        loader = CSVLoader()
        scenarios = loader.load_scenarios(csv_path)

        assert len(scenarios) == 1
        s = scenarios[0]
        assert s.id == "TEST-001"
        assert s.platform == Platform.LINUX
        assert s.attack_type == AttackType.DISCOVERY
        assert s.complexity == Complexity.LOW
        assert len(s.simulation_steps) == 1
        assert s.simulation_steps[0].role == Role.CLI
        assert s.simulation_steps[0].command == "whoami"

    def test_load_multiple_scenarios(self, tmp_path: Path):
        rows = [
            _make_row("S-001", "First"),
            _make_row("S-002", "Second"),
            _make_row("S-003", "Third"),
        ]
        csv_path = _write_csv(tmp_path / "multi.csv", rows)
        loader = CSVLoader()
        scenarios = loader.load_scenarios(csv_path)
        assert len(scenarios) == 3

    def test_load_scenario_with_multiple_steps(self, tmp_path: Path):
        steps = [
            {"order": 1, "role": "cli", "command": "whoami", "description": "Step 1"},
            {"order": 2, "role": "cli", "command": "id", "description": "Step 2"},
            {"order": 3, "role": "ui", "description": "Step 3", "ui_instructions": "Click X"},
        ]
        csv_path = _write_csv(tmp_path / "steps.csv", [_make_row(steps=steps)])
        loader = CSVLoader()
        scenarios = loader.load_scenarios(csv_path)

        assert len(scenarios[0].simulation_steps) == 3
        assert scenarios[0].simulation_steps[2].role == Role.UI

    def test_load_directory(self, tmp_path: Path):
        _write_csv(tmp_path / "a.csv", [_make_row("A-001")])
        _write_csv(tmp_path / "b.csv", [_make_row("B-001"), _make_row("B-002")])

        loader = CSVLoader()
        scenarios = loader.load_directory(tmp_path)
        assert len(scenarios) == 3

    def test_load_directory_ignores_non_csv(self, tmp_path: Path):
        _write_csv(tmp_path / "valid.csv", [_make_row()])
        (tmp_path / "readme.txt").write_text("not a csv")

        loader = CSVLoader()
        scenarios = loader.load_directory(tmp_path)
        assert len(scenarios) == 1

    def test_validate_scenarios_no_errors(self, tmp_path: Path):
        csv_path = _write_csv(tmp_path / "ok.csv", [_make_row()])
        loader = CSVLoader()
        scenarios = loader.load_scenarios(csv_path)
        errors = loader.validate_scenarios(scenarios)
        assert errors == []

    def test_validate_catches_duplicate_ids(self, tmp_path: Path):
        rows = [_make_row("DUPE"), _make_row("DUPE")]
        csv_path = _write_csv(tmp_path / "dupes.csv", rows)
        loader = CSVLoader()
        scenarios = loader.load_scenarios(csv_path)
        errors = loader.validate_scenarios(scenarios)
        assert any("duplicate" in e.lower() for e in errors)

    def test_empty_csv_returns_empty_list(self, tmp_path: Path):
        import csv

        csv_path = tmp_path / "empty.csv"
        with open(csv_path, "w") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "name", "description", "platform", "attack_type",
                "mitre_technique_id", "mitre_technique_name", "complexity",
                "simulation_steps", "expected_detections", "tags",
            ])
        loader = CSVLoader()
        scenarios = loader.load_scenarios(csv_path)
        assert scenarios == []
