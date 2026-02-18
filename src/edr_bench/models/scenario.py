"""Scenario and SimulationStep models for EDR-Bench."""

from __future__ import annotations

from pydantic import BaseModel, Field

from edr_bench.models.enums import AttackType, Complexity, Platform, Role


class SimulationStep(BaseModel):
    """A single action within a scenario."""

    order: int = Field(ge=1, description="Execution order within the scenario")
    role: Role = Field(description="Executor type for this step")
    command: str | None = Field(default=None, description="Shell command for CLI steps")
    description: str = Field(description="Human-readable description of this step")
    ui_instructions: str | None = Field(
        default=None,
        description="Natural language instructions for computer-use agent (UI steps)",
    )
    expected_artifact: str | None = Field(
        default=None,
        description="Expected file, process, or network artifact for ground truth",
    )
    timeout_seconds: int = Field(default=60, ge=1, description="Max execution time")
    atomic_test_id: str | None = Field(
        default=None,
        description="Atomic Red Team test GUID (e.g. T1059.001-1)",
    )


class Scenario(BaseModel):
    """A complete attack scenario for EDR benchmarking."""

    id: str = Field(description="Unique scenario identifier")
    name: str = Field(description="Human-readable scenario name")
    description: str = Field(description="Detailed scenario description")
    platform: Platform
    attack_type: AttackType
    mitre_technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g. T1059.001)",
    )
    mitre_technique_name: str = Field(
        description="MITRE ATT&CK technique name",
    )
    complexity: Complexity
    simulation_steps: list[SimulationStep] = Field(
        min_length=1,
        description="Ordered list of simulation steps",
    )
    expected_detections: list[str] = Field(
        default_factory=list,
        description="Expected EDR detection rule names or IDs",
    )
    tags: list[str] = Field(default_factory=list, description="Categorization tags")

    @property
    def is_ui_scenario(self) -> bool:
        return any(step.role == Role.UI for step in self.simulation_steps)

    @property
    def is_cli_scenario(self) -> bool:
        return all(step.role == Role.CLI for step in self.simulation_steps)
