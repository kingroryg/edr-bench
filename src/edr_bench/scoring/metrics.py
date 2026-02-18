"""Individual metric calculator functions for EDR scoring."""
from __future__ import annotations

from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent


def calc_detection_rate(matched: int, total_gt: int) -> float:
    """Calculate the detection rate: proportion of ground truth events detected.

    Parameters
    ----------
    matched:
        Number of ground truth events that were matched to an EDR finding.
    total_gt:
        Total number of ground truth events.

    Returns
    -------
    float
        A value in ``[0.0, 1.0]``.  Returns ``1.0`` when *total_gt* is zero
        (nothing to detect means nothing was missed).
    """
    if total_gt <= 0:
        return 1.0  # Nothing to detect = nothing missed
    return min(matched / total_gt, 1.0)


def calc_contextual_accuracy(
    matched_pairs: list[tuple[GroundTruthEvent, Finding]],
) -> float:
    """Calculate the average contextual accuracy of matched findings.

    For each matched pair the accuracy is determined by:
    - Whether the finding's MITRE technique ID aligns with the ground truth
      scenario (if available).
    - Whether the severity is appropriate (non-trivial check based on event
      type).

    Returns a value in ``[0.0, 1.0]``.
    """
    if not matched_pairs:
        return 1.0  # No pairs to evaluate = no errors

    scores: list[float] = []
    for gt, finding in matched_pairs:
        pair_score = 0.0
        checks = 0

        # MITRE technique ID match
        if gt.details and gt.details.get("mitre_technique_id"):
            checks += 1
            gt_technique = str(gt.details["mitre_technique_id"]).upper()
            if finding.mitre_technique_id:
                finding_technique = finding.mitre_technique_id.upper()
                if gt_technique == finding_technique:
                    pair_score += 1.0
                elif gt_technique.split(".")[0] == finding_technique.split(".")[0]:
                    # Same parent technique (e.g. T1059.001 vs T1059.003)
                    pair_score += 0.5

        # Severity appropriateness: any non-null severity gets partial credit
        checks += 1
        if finding.severity is not None:
            pair_score += 0.8  # Having a severity at all is good
        else:
            pair_score += 0.2

        # Process / command enrichment
        if gt.process_name or gt.command_line:
            checks += 1
            if finding.process_name or finding.command_line:
                pair_score += 1.0
            else:
                pair_score += 0.0

        accuracy = pair_score / checks if checks > 0 else 0.0
        scores.append(accuracy)

    return sum(scores) / len(scores)


def calc_time_to_detect(
    matched_pairs: list[tuple[GroundTruthEvent, Finding]],
) -> float | None:
    """Calculate the average time-to-detect in seconds across matched pairs.

    Returns ``None`` when there are no matched pairs.
    """
    if not matched_pairs:
        return None

    deltas: list[float] = []
    for gt, finding in matched_pairs:
        delta = abs((finding.timestamp - gt.timestamp).total_seconds())
        deltas.append(delta)

    return sum(deltas) / len(deltas)


def calc_blocking_efficacy(
    matched_pairs: list[tuple[GroundTruthEvent, Finding]],
) -> float:
    """Calculate the fraction of matched findings that resulted in blocking.

    Returns a value in ``[0.0, 1.0]``.
    """
    if not matched_pairs:
        return 0.0

    blocked_count = sum(1 for _, finding in matched_pairs if finding.blocked)
    return blocked_count / len(matched_pairs)


def calc_noise_ratio(false_positives: int, total_findings: int) -> float:
    """Calculate the noise ratio: proportion of findings that are false positives.

    Parameters
    ----------
    false_positives:
        Number of findings that did not match any ground truth event.
    total_findings:
        Total number of EDR findings received.

    Returns
    -------
    float
        A value in ``[0.0, 1.0]``.  Returns ``0.0`` when *total_findings* is zero.
    """
    if total_findings <= 0:
        return 0.0
    return min(false_positives / total_findings, 1.0)
