"""Tests for scoring metric calculators."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from edr_bench.models.finding import Finding
from edr_bench.models.enums import Severity
from edr_bench.models.ground_truth import GroundTruthEvent
from edr_bench.scoring.metrics import (
    calc_blocking_efficacy,
    calc_contextual_accuracy,
    calc_detection_rate,
    calc_noise_ratio,
    calc_time_to_detect,
)


@pytest.mark.unit
class TestDetectionRate:
    def test_perfect_detection(self):
        assert calc_detection_rate(5, 5) == 1.0

    def test_no_detection(self):
        assert calc_detection_rate(0, 5) == 0.0

    def test_partial_detection(self):
        assert calc_detection_rate(3, 10) == pytest.approx(0.3)

    def test_zero_ground_truth(self):
        # If there's nothing to detect, rate should be 1.0 (nothing was missed)
        assert calc_detection_rate(0, 0) == 1.0


@pytest.mark.unit
class TestContextualAccuracy:
    def test_perfect_accuracy(self, sample_ground_truth, sample_findings):
        pairs = list(zip(sample_ground_truth[:1], sample_findings[:1]))
        # Both have matching technique ID T1033 -> whoami
        score = calc_contextual_accuracy(pairs)
        assert 0.0 <= score <= 1.0

    def test_empty_pairs(self):
        assert calc_contextual_accuracy([]) == 1.0

    def test_mismatched_technique(self):
        gt = GroundTruthEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            source="tracee",
            scenario_id="T1",
            event_type="execve",
            process_name="whoami",
        )
        finding = Finding(
            id="F1",
            timestamp=datetime(2024, 1, 15, 10, 0, 1, tzinfo=timezone.utc),
            rule_name="Wrong Rule",
            severity=Severity.LOW,
            mitre_technique_id="T9999",
            process_name="whoami",
        )
        score = calc_contextual_accuracy([(gt, finding)])
        # Should be lower since technique doesn't match
        assert score < 1.0


@pytest.mark.unit
class TestTimeToDetect:
    def test_calculates_average(self, sample_ground_truth, sample_findings):
        pairs = list(zip(sample_ground_truth[:2], sample_findings[:2]))
        ttd = calc_time_to_detect(pairs)
        assert ttd is not None
        assert ttd > 0.0

    def test_empty_pairs(self):
        assert calc_time_to_detect([]) is None


@pytest.mark.unit
class TestBlockingEfficacy:
    def test_all_blocked(self):
        pairs = [
            (None, Finding(
                id="F1",
                timestamp=datetime.now(timezone.utc),
                rule_name="R",
                severity=Severity.HIGH,
                blocked=True,
            )),
        ]
        assert calc_blocking_efficacy(pairs) == 1.0

    def test_none_blocked(self):
        pairs = [
            (None, Finding(
                id="F1",
                timestamp=datetime.now(timezone.utc),
                rule_name="R",
                severity=Severity.HIGH,
                blocked=False,
            )),
        ]
        assert calc_blocking_efficacy(pairs) == 0.0

    def test_empty_pairs(self):
        assert calc_blocking_efficacy([]) == 0.0


@pytest.mark.unit
class TestNoiseRatio:
    def test_no_noise(self):
        assert calc_noise_ratio(0, 10) == 0.0

    def test_all_noise(self):
        assert calc_noise_ratio(10, 10) == 1.0

    def test_zero_findings(self):
        assert calc_noise_ratio(0, 0) == 0.0

    def test_partial_noise(self):
        assert calc_noise_ratio(2, 10) == pytest.approx(0.2)
