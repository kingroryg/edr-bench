"""Tests for the Typer CLI."""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from edr_bench.cli import app

runner = CliRunner()


@pytest.mark.unit
class TestCLI:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "edr-bench" in result.output

    def test_run_help(self):
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "--platform" in result.output
        assert "--edr-settle" in result.output
        assert "--verbose" in result.output

    def test_validate_nonexistent_path(self, tmp_path: Path):
        bad_path = tmp_path / "nonexistent"
        result = runner.invoke(app, ["validate", str(bad_path)])
        assert result.exit_code != 0

    def test_validate_with_valid_scenarios(self):
        result = runner.invoke(app, ["validate", "data/scenarios"])
        assert result.exit_code == 0
        assert "validated successfully" in result.output

    def test_report_nonexistent_json(self, tmp_path: Path):
        bad_file = tmp_path / "nonexistent.json"
        result = runner.invoke(app, ["report", str(bad_file)])
        assert result.exit_code != 0

    def test_edr_settle_flag_accepted(self):
        result = runner.invoke(app, ["run", "--help"])
        assert "--edr-settle" in result.output

    def test_infra_invalid_action(self):
        result = runner.invoke(app, ["infra", "invalid_action"])
        assert result.exit_code != 0
        assert "Unknown action" in result.output
