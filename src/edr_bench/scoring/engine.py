"""Scoring engine: correlates ground truth with EDR findings and computes metrics."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from edr_bench.edr_interface.api_poller import APIPoller
from edr_bench.edr_interface.base import EDRListener
from edr_bench.edr_interface.file_tailer import FileTailer
from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.edr_interface.syslog_receiver import SyslogReceiver
from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent
from edr_bench.models.metrics import ScenarioResult
from edr_bench.models.scenario import Scenario
from edr_bench.scoring.correlator import GroundTruthCorrelator
from edr_bench.scoring.metrics import (
    calc_blocking_efficacy,
    calc_contextual_accuracy,
    calc_detection_rate,
    calc_noise_ratio,
    calc_time_to_detect,
)

logger = structlog.get_logger(__name__)


class ScoringEngine:
    """Orchestrate correlation and metric calculation for a single scenario."""

    def __init__(self, settings: Any) -> None:
        self._settings = settings
        self._correlator = GroundTruthCorrelator(
            window_seconds=settings.correlation_window_seconds,
        )
        self._normalizer = FindingNormalizer()
        self._listener: EDRListener | None = None

    async def score_scenario(
        self,
        scenario: Scenario,
        ground_truth_events: list[GroundTruthEvent],
        findings: list[Finding] | None = None,
        execution_started: datetime | None = None,
        execution_finished: datetime | None = None,
    ) -> ScenarioResult:
        """Score a single scenario execution.

        Parameters
        ----------
        scenario:
            The scenario that was executed.
        ground_truth_events:
            Collected ground truth events for this scenario.
        findings:
            Optionally provide pre-collected EDR findings.
            If ``None``, the engine will collect from the configured EDR listener.
        execution_started:
            When the scenario execution began.
        execution_finished:
            When the scenario execution ended.
        """
        started = execution_started or datetime.now(tz=timezone.utc)
        finished = execution_finished or datetime.now(tz=timezone.utc)
        errors: list[str] = []

        # Collect EDR findings if not provided
        if findings is None:
            findings = await self._collect_findings(errors)

        # Run correlation
        correlation = self._correlator.correlate(ground_truth_events, findings)

        # Calculate metrics
        matched_count = len(correlation.matched_pairs)
        gt_count = len(ground_truth_events)
        findings_count = len(findings)
        fp_count = len(correlation.false_positives)

        detection_rate = calc_detection_rate(matched_count, gt_count)
        contextual_accuracy = calc_contextual_accuracy(correlation.matched_pairs)
        time_to_detect = calc_time_to_detect(correlation.matched_pairs)
        blocking_efficacy = calc_blocking_efficacy(correlation.matched_pairs)
        noise_ratio = calc_noise_ratio(fp_count, findings_count)

        result = ScenarioResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            platform=scenario.platform,
            attack_type=scenario.attack_type,
            mitre_technique_id=scenario.mitre_technique_id,
            detection_rate=detection_rate,
            contextual_accuracy=contextual_accuracy,
            time_to_detect_seconds=time_to_detect,
            blocking_efficacy=blocking_efficacy,
            noise_ratio=noise_ratio,
            ground_truth_count=gt_count,
            findings_count=findings_count,
            matched_count=matched_count,
            false_positive_count=fp_count,
            execution_started=started,
            execution_finished=finished,
            errors=errors,
        )

        logger.info(
            "scoring_engine.scenario_scored",
            scenario_id=scenario.id,
            detection_rate=detection_rate,
            contextual_accuracy=contextual_accuracy,
            time_to_detect_seconds=time_to_detect,
            blocking_efficacy=blocking_efficacy,
            noise_ratio=noise_ratio,
            matched=matched_count,
            ground_truth=gt_count,
            findings=findings_count,
            false_positives=fp_count,
        )

        return result

    # ------------------------------------------------------------------
    # EDR listener management
    # ------------------------------------------------------------------

    def _build_listener(self) -> EDRListener | None:
        """Create the appropriate EDR listener based on settings."""
        edr = self._settings.edr

        if edr.log_path:
            return FileTailer(
                log_path=edr.log_path,
                normalizer=self._normalizer,
            )
        if edr.api_url and edr.api_key:
            return APIPoller(
                api_url=edr.api_url,
                api_key=edr.api_key,
                poll_interval=edr.poll_interval,
                normalizer=self._normalizer,
            )
        if edr.syslog_port:
            return SyslogReceiver(
                port=edr.syslog_port,
                normalizer=self._normalizer,
            )

        logger.warning("scoring_engine.no_edr_listener_configured")
        return None

    async def _collect_findings(self, errors: list[str]) -> list[Finding]:
        """Collect findings from the configured EDR listener."""
        if self._listener is None:
            self._listener = self._build_listener()

        if self._listener is None:
            errors.append("No EDR listener configured")
            return []

        try:
            findings = await self._listener.get_findings()
            return findings
        except Exception as exc:
            msg = f"Failed to collect EDR findings: {exc}"
            logger.exception("scoring_engine.collect_findings_error")
            errors.append(msg)
            return []
