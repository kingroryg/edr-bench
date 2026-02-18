"""Correlate ground truth events with EDR findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import structlog

from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent

logger = structlog.get_logger(__name__)


@dataclass
class CorrelationResult:
    """Result of correlating ground truth with EDR findings."""

    matched_pairs: list[tuple[GroundTruthEvent, Finding]] = field(default_factory=list)
    unmatched_gt: list[GroundTruthEvent] = field(default_factory=list)
    unmatched_findings: list[Finding] = field(default_factory=list)

    @property
    def false_positives(self) -> list[Finding]:
        """Alias for findings that did not match any ground truth event."""
        return self.unmatched_findings


class GroundTruthCorrelator:
    """Match ground truth events to EDR findings using temporal and attribute overlap.

    The correlator uses a greedy best-match algorithm:

    1. For each ``(gt, finding)`` pair within the time window, compute
       an overlap score.
    2. Sort candidate pairs by descending score.
    3. Greedily assign the best-scoring pairs first, ensuring each
       ground truth event and each finding is matched at most once.
    """

    def __init__(self, window_seconds: float = 30.0) -> None:
        self._window_seconds = window_seconds

    def correlate(
        self,
        ground_truth: Sequence[GroundTruthEvent],
        findings: Sequence[Finding],
    ) -> CorrelationResult:
        """Correlate *ground_truth* events against *findings*.

        Returns a :class:`CorrelationResult` containing matched pairs
        and the unmatched remainders on both sides.
        """
        if not ground_truth or not findings:
            return CorrelationResult(
                matched_pairs=[],
                unmatched_gt=list(ground_truth),
                unmatched_findings=list(findings),
            )

        # Build all candidate pairs with scores
        candidates: list[tuple[float, int, int]] = []  # (score, gt_idx, f_idx)

        for gi, gt in enumerate(ground_truth):
            for fi, finding in enumerate(findings):
                score = self._score_pair(gt, finding)
                if score > 0.0:
                    candidates.append((score, gi, fi))

        # Sort descending by score (greedy best-match)
        candidates.sort(key=lambda c: c[0], reverse=True)

        matched_gt_indices: set[int] = set()
        matched_f_indices: set[int] = set()
        matched_pairs: list[tuple[GroundTruthEvent, Finding]] = []

        for score, gi, fi in candidates:
            if gi in matched_gt_indices or fi in matched_f_indices:
                continue
            matched_gt_indices.add(gi)
            matched_f_indices.add(fi)
            matched_pairs.append((ground_truth[gi], findings[fi]))

        unmatched_gt = [
            gt for i, gt in enumerate(ground_truth) if i not in matched_gt_indices
        ]
        unmatched_findings = [
            f for i, f in enumerate(findings) if i not in matched_f_indices
        ]

        logger.info(
            "correlator.result",
            matched=len(matched_pairs),
            unmatched_gt=len(unmatched_gt),
            false_positives=len(unmatched_findings),
        )

        return CorrelationResult(
            matched_pairs=matched_pairs,
            unmatched_gt=unmatched_gt,
            unmatched_findings=unmatched_findings,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_pair(self, gt: GroundTruthEvent, finding: Finding) -> float:
        """Compute a match score for a (ground truth, finding) pair.

        Returns 0.0 if the pair is outside the correlation time window.
        Otherwise returns a score in ``(0, 1]`` based on attribute overlap.
        """
        # Temporal proximity check
        time_delta = abs((finding.timestamp - gt.timestamp).total_seconds())
        if time_delta > self._window_seconds:
            return 0.0

        # Temporal score: closer in time -> higher score
        temporal_score = 1.0 - (time_delta / self._window_seconds)

        # Attribute overlap score
        attr_score = self._attribute_overlap(gt, finding)

        if attr_score == 0.0:
            return 0.0

        # Combined score: weighted average
        return 0.4 * temporal_score + 0.6 * attr_score

    @staticmethod
    def _attribute_overlap(gt: GroundTruthEvent, finding: Finding) -> float:
        """Score attribute overlap between a ground truth event and finding.

        Compares: process_name, command_line, file_path, network_dst.
        Returns a value in ``[0, 1]``.
        """
        checks: list[tuple[bool, float]] = []

        # Process name match
        if gt.process_name and finding.process_name:
            match = (
                gt.process_name.lower() == finding.process_name.lower()
                or gt.process_name.lower() in finding.process_name.lower()
                or finding.process_name.lower() in gt.process_name.lower()
            )
            checks.append((match, 1.0))

        # Command line overlap
        if gt.command_line and finding.command_line:
            gt_tokens = set(gt.command_line.lower().split())
            f_tokens = set(finding.command_line.lower().split())
            if gt_tokens and f_tokens:
                overlap = len(gt_tokens & f_tokens) / max(
                    len(gt_tokens), len(f_tokens)
                )
                checks.append((overlap > 0.3, overlap))

        # File path match
        if gt.file_path and finding.file_path:
            match = (
                gt.file_path == finding.file_path
                or gt.file_path.endswith(finding.file_path)
                or finding.file_path.endswith(gt.file_path)
            )
            checks.append((match, 1.0 if match else 0.0))

        # Network destination match
        if gt.network_dst and finding.network_dst:
            match = gt.network_dst == finding.network_dst
            checks.append((match, 1.0 if match else 0.0))

        if not checks:
            # No overlapping attributes to compare; give a small base score
            # so temporal-only matches can still succeed (weakly).
            return 0.1

        total_weight = sum(weight for _, weight in checks)
        matched_weight = sum(weight for is_match, weight in checks if is_match)
        return matched_weight / total_weight if total_weight > 0 else 0.0
