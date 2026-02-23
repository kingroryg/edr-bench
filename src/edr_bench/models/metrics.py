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

    # Step context (populated from scenario definition)
    command: str | None = Field(default=None, description="Command executed in this step")
    description: str | None = Field(default=None, description="Human-readable step description")
    expected_artifact: str | None = Field(default=None, description="Expected outcome of step")

    # Per-step EDR detection attribution (populated after correlation)
    detected: bool = Field(default=False, description="Whether the EDR detected this step")
    matched_finding_count: int = Field(default=0, description="Number of EDR findings matched to this step")
    finding_summaries: list[str] = Field(
        default_factory=list,
        description="Short descriptions of EDR findings that matched this step",
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
    time_to_detect_percentiles: dict[str, float] | None = Field(
        default=None,
        description="TTD percentiles: mean, p50, p90, p95, max (in seconds)",
    )
    ttd_raw_deltas: list[float] = Field(
        default_factory=list,
        description="Raw per-event TTD deltas in seconds (for aggregate percentile computation)",
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
    coach_coverage: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraction of Coach-expected events confirmed by MockNet (attack execution success rate)",
    )

    execution_started: datetime | None = None
    execution_finished: datetime | None = None
    errors: list[str] = Field(default_factory=list)
    step_results: list[StepResult] = Field(default_factory=list)

    attack_chain_coverage: float | None = Field(
        default=None,
        description="Fraction of executed steps where the EDR detected at least one event",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_completeness(self) -> float:
        """Return the fraction of non-skipped steps that succeeded."""
        if not self.step_results:
            return 0.0
        non_skipped = [s for s in self.step_results if s.status != "skipped"]
        if not non_skipped:
            return 0.0
        succeeded = sum(1 for s in non_skipped if s.status == "success")
        return succeeded / len(non_skipped)


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
    time_to_detect_percentiles: dict[str, float] | None = Field(
        default=None,
        description="Aggregate TTD percentiles: p50, p90, p95, max (in seconds)",
    )
    overall_blocking_efficacy: float = Field(ge=0.0, le=1.0)
    overall_noise_ratio: float = Field(ge=0.0)

    technique_scores: list[TechniqueScore] = Field(default_factory=list)
    platform_breakdown: dict[Platform, float] = Field(default_factory=dict)
    attack_type_breakdown: dict[AttackType, float] = Field(default_factory=dict)

    total_scenarios: int = Field(ge=0)
    total_ground_truth_events: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    total_errors: int = Field(ge=0)
