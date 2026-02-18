"""CSV loader for scenario definitions."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import structlog

from edr_bench.models.enums import AttackType, Complexity, Platform
from edr_bench.models.scenario import Scenario, SimulationStep

logger = structlog.get_logger(__name__)


class CSVLoader:
    """Load and validate Scenario definitions from CSV files.

    Expected CSV columns:
        id, name, description, platform, attack_type, mitre_technique_id,
        mitre_technique_name, complexity, simulation_steps, expected_detections, tags

    The ``simulation_steps``, ``expected_detections``, and ``tags`` columns
    contain JSON-encoded strings.
    """

    # Column names that must be present in every CSV file.
    REQUIRED_COLUMNS: frozenset[str] = frozenset(
        {
            "id",
            "name",
            "description",
            "platform",
            "attack_type",
            "mitre_technique_id",
            "mitre_technique_name",
            "complexity",
            "simulation_steps",
        }
    )

    # Columns that contain JSON-encoded strings.
    JSON_COLUMNS: frozenset[str] = frozenset(
        {
            "simulation_steps",
            "expected_detections",
            "tags",
        }
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def load_scenarios(cls, path: Path | str) -> list[Scenario]:
        """Load scenarios from a single CSV file.

        Args:
            path: Path to the CSV file.

        Returns:
            A list of parsed Scenario model instances.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If required columns are missing.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scenario CSV not found: {path}")

        scenarios: list[Scenario] = []
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                raise ValueError(f"CSV file is empty or has no header: {path}")

            columns = frozenset(reader.fieldnames)
            missing = cls.REQUIRED_COLUMNS - columns
            if missing:
                raise ValueError(
                    f"CSV {path} is missing required columns: {sorted(missing)}"
                )

            for row_idx, row in enumerate(reader, start=2):  # row 1 = header
                try:
                    scenario = cls._parse_row(row)
                    scenarios.append(scenario)
                except Exception as exc:
                    logger.error(
                        "csv_row_parse_error",
                        file=str(path),
                        row=row_idx,
                        error=str(exc),
                    )
                    raise ValueError(
                        f"Error parsing row {row_idx} in {path}: {exc}"
                    ) from exc

        logger.info(
            "scenarios_loaded",
            file=str(path),
            count=len(scenarios),
        )
        return scenarios

    @classmethod
    def load_directory(cls, dir_path: Path | str) -> list[Scenario]:
        """Load all ``.csv`` files in a directory.

        Files are sorted by name to ensure deterministic ordering.

        Args:
            dir_path: Path to the directory containing CSV files.

        Returns:
            A combined list of Scenario instances from all CSV files.

        Raises:
            FileNotFoundError: If the directory does not exist.
        """
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            raise FileNotFoundError(f"Scenario directory not found: {dir_path}")

        csv_files = sorted(dir_path.glob("*.csv"))
        if not csv_files:
            logger.warning("no_csv_files_found", directory=str(dir_path))
            return []

        all_scenarios: list[Scenario] = []
        for csv_file in csv_files:
            scenarios = cls.load_scenarios(csv_file)
            all_scenarios.extend(scenarios)

        logger.info(
            "directory_loaded",
            directory=str(dir_path),
            files=len(csv_files),
            total_scenarios=len(all_scenarios),
        )
        return all_scenarios

    @classmethod
    def validate_scenarios(cls, scenarios: list[Scenario]) -> list[str]:
        """Validate a list of scenarios and return any errors found.

        Checks performed:
        - Duplicate scenario IDs.
        - Each scenario has at least one simulation step.
        - Simulation steps have sequential ordering starting from 1.
        - Platform enum value is valid.
        - AttackType enum value is valid.
        - Complexity enum value is valid.

        Args:
            scenarios: The scenarios to validate.

        Returns:
            A list of human-readable error strings. An empty list means
            all scenarios are valid.
        """
        errors: list[str] = []
        seen_ids: dict[str, int] = {}

        for idx, scenario in enumerate(scenarios):
            label = f"Scenario[{idx}] id={scenario.id!r}"

            # Check for duplicate IDs
            if scenario.id in seen_ids:
                errors.append(
                    f"{label}: duplicate ID (first seen at index {seen_ids[scenario.id]})"
                )
            else:
                seen_ids[scenario.id] = idx

            # Validate simulation steps are present
            if not scenario.simulation_steps:
                errors.append(f"{label}: has no simulation steps")
                continue

            # Validate step ordering
            orders = [step.order for step in scenario.simulation_steps]
            expected_orders = list(range(1, len(scenario.simulation_steps) + 1))
            if sorted(orders) != expected_orders:
                errors.append(
                    f"{label}: simulation_steps orders {orders} should be "
                    f"sequential from 1..{len(scenario.simulation_steps)}"
                )

            # Validate enum values (Pydantic would have already caught these
            # during parsing, but we check again for scenarios built manually)
            try:
                Platform(scenario.platform)
            except ValueError:
                errors.append(f"{label}: invalid platform {scenario.platform!r}")

            try:
                AttackType(scenario.attack_type)
            except ValueError:
                errors.append(f"{label}: invalid attack_type {scenario.attack_type!r}")

            try:
                Complexity(scenario.complexity)
            except ValueError:
                errors.append(f"{label}: invalid complexity {scenario.complexity!r}")

        if errors:
            logger.warning("scenario_validation_errors", count=len(errors))
        else:
            logger.info("scenario_validation_passed", count=len(scenarios))

        return errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _parse_row(cls, row: dict[str, str]) -> Scenario:
        """Parse a single CSV row dict into a Scenario model.

        Args:
            row: A dictionary mapping column names to string values.

        Returns:
            A validated Scenario instance.
        """
        # Parse JSON columns
        simulation_steps_raw = cls._parse_json_field(
            row.get("simulation_steps", "[]"), "simulation_steps"
        )
        expected_detections_raw = cls._parse_json_field(
            row.get("expected_detections", "[]"), "expected_detections"
        )
        tags_raw = cls._parse_json_field(
            row.get("tags", "[]"), "tags"
        )

        # Build SimulationStep objects
        if not isinstance(simulation_steps_raw, list):
            raise ValueError(
                f"simulation_steps must be a JSON array, got {type(simulation_steps_raw).__name__}"
            )
        simulation_steps = [
            SimulationStep(**step) if isinstance(step, dict) else step
            for step in simulation_steps_raw
        ]

        # Build the Scenario
        scenario = Scenario(
            id=row["id"].strip(),
            name=row["name"].strip(),
            description=row["description"].strip(),
            platform=Platform(row["platform"].strip().lower()),
            attack_type=AttackType(row["attack_type"].strip().lower()),
            mitre_technique_id=row["mitre_technique_id"].strip(),
            mitre_technique_name=row["mitre_technique_name"].strip(),
            complexity=Complexity(row["complexity"].strip().lower()),
            simulation_steps=simulation_steps,
            expected_detections=(
                expected_detections_raw if isinstance(expected_detections_raw, list) else []
            ),
            tags=tags_raw if isinstance(tags_raw, list) else [],
        )
        return scenario

    @staticmethod
    def _parse_json_field(value: str, field_name: str) -> Any:
        """Parse a JSON-encoded string from a CSV cell.

        Args:
            value: The raw string value from the CSV cell.
            field_name: The column name (used in error messages).

        Returns:
            The parsed JSON value.

        Raises:
            ValueError: If the value is not valid JSON.
        """
        value = value.strip()
        if not value:
            return []
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Column {field_name!r} contains invalid JSON: {exc}"
            ) from exc
