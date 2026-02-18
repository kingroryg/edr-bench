"""Scoring metrics and result models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, computed_field

from edr_bench.models.enums import AttackType, Platform


class StepResult(BaseModel):
    """Result of executing a single simulation step."""

    step_order: int
    role: str
    status: str = Field(description="'success', 'failed', 'skipped', 'timeout'")
    error_message: str | None = None
    duration_seconds: float = 0.0
    ground_truth_events: int = Field(
        default=0, description="Number of ground truth events captured for this step"
    )


class ScenarioResult(BaseModel):
    """Results for a single scenario execution."""

    scenario_id: str
    scenario_name: str
    platform: Platform
    attack_type: AttackType
    mitre_technique_id: str

    detection_rate: float = Field(
        ge=0.0, le=1.0,
        description="Fraction of ground truth events detected by the EDR",
    )
    contextual_accuracy: float = Field(
        ge=0.0, le=1.0,
        description="Accuracy of EDR context (technique ID, severity) vs ground truth",
    )
    time_to_detect_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Average seconds between ground truth event and EDR finding",
    )
    blocking_efficacy: float = Field(
        ge=0.0, le=1.0,
        description="Fraction of blocking-expected events actually blocked",
    )
    noise_ratio: float = Field(
        ge=0.0,
        description="Ratio of false positive findings to total findings",
    )

    ground_truth_count: int = Field(ge=0)
    findings_count: int = Field(ge=0)
    matched_count: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)

    execution_started: datetime | None = None
    execution_finished: datetime | None = None
    errors: list[str] = Field(default_factory=list)
    step_results: list[StepResult] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_completeness(self) -> float:
        """Return the fraction of steps that succeeded."""
        if not self.step_results:
            return 0.0
        succeeded = sum(1 for s in self.step_results if s.status == "success")
        return succeeded / len(self.step_results)


class TechniqueScore(BaseModel):
    """Aggregated score for a single MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    detection_rate: float
    scenario_count: int


class BenchmarkReport(BaseModel):
    """Complete benchmark report aggregating all scenario results."""

    report_id: str
    generated_at: datetime
    edr_name: str = Field(description="Name of the EDR product under test")
    edr_version: str = Field(default="", description="EDR product version")

    scenario_results: list[ScenarioResult] = Field(default_factory=list)

    overall_detection_rate: float = Field(ge=0.0, le=1.0)
    overall_contextual_accuracy: float = Field(ge=0.0, le=1.0)
    average_time_to_detect: float | None = None
    overall_blocking_efficacy: float = Field(ge=0.0, le=1.0)
    overall_noise_ratio: float = Field(ge=0.0)

    technique_scores: list[TechniqueScore] = Field(default_factory=list)
    platform_breakdown: dict[Platform, float] = Field(default_factory=dict)
    attack_type_breakdown: dict[AttackType, float] = Field(default_factory=dict)

    total_scenarios: int = Field(ge=0)
    total_ground_truth_events: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    total_errors: int = Field(ge=0)
