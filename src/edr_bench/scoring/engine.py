"""Scoring engine: correlates ground truth with EDR findings and computes metrics."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog

from edr_bench.edr_interface.api_poller import APIPoller
from edr_bench.edr_interface.base import EDRListener
from edr_bench.edr_interface.file_tailer import FileTailer
from edr_bench.edr_interface.falco_normalizer import FalcoNormalizer
from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.edr_interface.wazuh_normalizer import WazuhNormalizer
from edr_bench.edr_interface.syslog_receiver import SyslogReceiver
from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent
from edr_bench.models.metrics import ScenarioResult
from edr_bench.models.scenario import Scenario
from edr_bench.scoring.correlator import CorrelationResult, GroundTruthCorrelator
from edr_bench.scoring.metrics import (
    calc_blocking_efficacy,
    calc_contextual_accuracy,
    calc_detection_rate,
    calc_noise_ratio,
    calc_time_to_detect,
    calc_time_to_detect_percentiles,
)

logger = structlog.get_logger(__name__)


class ScoringEngine:
    """Orchestrate correlation and metric calculation for a single scenario."""

    def __init__(self, settings: Any) -> None:
        self._settings = settings
        self._correlator = GroundTruthCorrelator(
            window_seconds=settings.correlation_window_seconds,
        )
        self._normalizer = self._select_normalizer(settings.edr.name)
        self._listener: EDRListener | None = None
        self._listener_started: bool = False
        self._last_correlation: CorrelationResult | None = None

    @staticmethod
    def _select_normalizer(edr_name: str) -> FindingNormalizer:
        """Return the appropriate normalizer for the given EDR."""
        name = edr_name.lower()
        if "wazuh" in name:
            return WazuhNormalizer()
        if "falco" in name:
            return FalcoNormalizer()
        return FindingNormalizer()

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
        self._last_correlation = correlation

        # Calculate metrics
        matched_count = len(correlation.matched_pairs)
        gt_count = len(ground_truth_events)
        findings_count = len(findings)
        fp_count = len(correlation.false_positives)

        detection_rate = calc_detection_rate(matched_count, gt_count)
        contextual_accuracy = calc_contextual_accuracy(correlation.matched_pairs)
        time_to_detect = calc_time_to_detect(correlation.matched_pairs)
        ttd_percentiles = calc_time_to_detect_percentiles(correlation.matched_pairs)
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
            time_to_detect_percentiles=ttd_percentiles,
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

    def get_step_detections(
        self,
        step_commands: dict[int, str] | None = None,
    ) -> dict[int, list[Finding]]:
        """Map matched pairs from the last correlation back to step_order.

        Parameters
        ----------
        step_commands:
            Optional dict mapping step_order -> command string.  Used for
            fallback attribution when matched GT events lack step_order.
            Findings are attributed to steps whose command text contains
            the finding's file path or shares keyword overlap.

        Returns a dict keyed by step_order containing the list of EDR
        findings that matched ground truth events for that step.
        """
        if not self._last_correlation:
            return {}
        result: dict[int, list[Finding]] = {}
        unattributed: list[Finding] = []

        for gt, finding in self._last_correlation.matched_pairs:
            if gt.step_order is not None:
                result.setdefault(gt.step_order, []).append(finding)
            else:
                unattributed.append(finding)

        # Fallback: attribute findings to steps by matching file paths
        # and keywords against step commands
        if unattributed and step_commands:
            for finding in unattributed:
                best_step: int | None = None
                best_score = 0.0
                for step_order, cmd in step_commands.items():
                    score = self._finding_step_overlap(finding, cmd)
                    if score > best_score:
                        best_score = score
                        best_step = step_order
                if best_step is not None and best_score > 0.05:
                    result.setdefault(best_step, []).append(finding)

        return result

    @staticmethod
    def _finding_step_overlap(finding: Finding, command: str) -> float:
        """Score how well a finding matches a step's command.

        Checks file path containment and keyword overlap.
        """
        score = 0.0
        cmd_lower = command.lower()

        # File path match: does the finding's file_path appear in the command?
        if finding.file_path:
            path = finding.file_path.lower()
            if path in cmd_lower:
                score += 1.0
            else:
                # Check if any path component matches
                parts = [p for p in path.split("/") if p and len(p) > 3]
                cmd_parts = set(cmd_lower.split())
                for part in parts:
                    if any(part in cp for cp in cmd_parts):
                        score += 0.3
                        break

        # Keyword overlap between finding description and command
        if finding.description or finding.rule_name:
            finding_text = " ".join(
                t for t in [finding.description, finding.rule_name] if t
            ).lower()
            finding_words = set(finding_text.split()) - {"", "the", "a", "an", "in", "of", "to", "was"}
            cmd_words = set(cmd_lower.split()) - {"", "&&", "||", "2>/dev/null"}
            if finding_words and cmd_words:
                overlap = len(finding_words & cmd_words)
                if overlap > 0:
                    score += 0.2 * overlap

        return score

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

        # Start the listener on first call (begins tailing the log file)
        if not self._listener_started:
            try:
                await self._listener.start()
                self._listener_started = True
                # Give it a moment for the initial file read
                await asyncio.sleep(1.0)
            except Exception as exc:
                msg = f"Failed to start EDR listener: {exc}"
                logger.exception("scoring_engine.listener_start_error")
                errors.append(msg)
                return []

        # Let the tailer pick up any new lines written since last check
        await asyncio.sleep(0.5)

        try:
            findings = await self._listener.get_findings()
            return findings
        except Exception as exc:
            msg = f"Failed to collect EDR findings: {exc}"
            logger.exception("scoring_engine.collect_findings_error")
            errors.append(msg)
            return []

    async def close(self) -> None:
        """Stop the EDR listener if running."""
        if self._listener is not None and self._listener_started:
            await self._listener.stop()
            self._listener_started = False
