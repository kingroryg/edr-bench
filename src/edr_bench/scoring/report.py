"""Aggregate scoring results for reporting."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog

from edr_bench.models.metrics import ScenarioResult

logger = structlog.get_logger(__name__)


class ReportDataAggregator:
    """Aggregate :class:`ScenarioResult` instances into report-ready structures."""

    def aggregate(self, results: list[ScenarioResult]) -> dict[str, Any]:
        """Aggregate results by MITRE technique, platform, and attack type.

        Returns
        -------
        dict
            A dictionary with keys:

            - ``technique_scores`` -- per-MITRE-technique averages
            - ``platform_breakdown`` -- per-platform averages
            - ``attack_type_breakdown`` -- per-attack-type averages
            - ``overall`` -- global averages across all results
        """
        if not results:
            return {
                "technique_scores": {},
                "platform_breakdown": {},
                "attack_type_breakdown": {},
                "overall": _empty_summary(),
            }

        technique_groups: dict[str, list[ScenarioResult]] = defaultdict(list)
        platform_groups: dict[str, list[ScenarioResult]] = defaultdict(list)
        attack_type_groups: dict[str, list[ScenarioResult]] = defaultdict(list)

        for result in results:
            technique_key = result.mitre_technique_id or "unknown"
            technique_groups[technique_key].append(result)

            platform_key = result.platform or "unknown"
            platform_groups[platform_key].append(result)

            attack_type_key = result.attack_type or "unknown"
            attack_type_groups[attack_type_key].append(result)

        technique_scores = {
            key: _summarize(group) for key, group in sorted(technique_groups.items())
        }
        platform_breakdown = {
            key: _summarize(group) for key, group in sorted(platform_groups.items())
        }
        attack_type_breakdown = {
            key: _summarize(group)
            for key, group in sorted(attack_type_groups.items())
        }
        overall = _summarize(results)

        logger.info(
            "report_aggregator.aggregated",
            scenarios=len(results),
            techniques=len(technique_scores),
            platforms=len(platform_breakdown),
            attack_types=len(attack_type_breakdown),
        )

        return {
            "technique_scores": technique_scores,
            "platform_breakdown": platform_breakdown,
            "attack_type_breakdown": attack_type_breakdown,
            "overall": overall,
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _summarize(results: list[ScenarioResult]) -> dict[str, Any]:
    """Compute average metrics for a group of results."""
    n = len(results)
    if n == 0:
        return _empty_summary()

    detection_rates = [r.detection_rate for r in results]
    contextual_accuracies = [r.contextual_accuracy for r in results]
    blocking_efficacies = [r.blocking_efficacy for r in results]
    noise_ratios = [r.noise_ratio for r in results]

    ttd_values = [
        r.time_to_detect_seconds
        for r in results
        if r.time_to_detect_seconds is not None
    ]

    total_gt = sum(r.ground_truth_count for r in results)
    total_findings = sum(r.findings_count for r in results)
    total_matched = sum(r.matched_count for r in results)
    total_fp = sum(r.false_positive_count for r in results)

    return {
        "count": n,
        "avg_detection_rate": _safe_mean(detection_rates),
        "avg_contextual_accuracy": _safe_mean(contextual_accuracies),
        "avg_time_to_detect_seconds": _safe_mean(ttd_values) if ttd_values else None,
        "avg_blocking_efficacy": _safe_mean(blocking_efficacies),
        "avg_noise_ratio": _safe_mean(noise_ratios),
        "total_ground_truth": total_gt,
        "total_findings": total_findings,
        "total_matched": total_matched,
        "total_false_positives": total_fp,
    }


def _empty_summary() -> dict[str, Any]:
    """Return a summary dict with all zeroes."""
    return {
        "count": 0,
        "avg_detection_rate": 0.0,
        "avg_contextual_accuracy": 0.0,
        "avg_time_to_detect_seconds": None,
        "avg_blocking_efficacy": 0.0,
        "avg_noise_ratio": 0.0,
        "total_ground_truth": 0,
        "total_findings": 0,
        "total_matched": 0,
        "total_false_positives": 0,
    }


def _safe_mean(values: list[float]) -> float:
    """Compute the mean, returning 0.0 for empty lists."""
    if not values:
        return 0.0
    return sum(values) / len(values)
