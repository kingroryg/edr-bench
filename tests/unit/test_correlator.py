"""Tests for ground truth <-> EDR finding correlator."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from edr_bench.models.enums import GroundTruthSource, Severity
from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent
from edr_bench.scoring.correlator import GroundTruthCorrelator


def _gt(ts_offset: int = 0, process: str = "whoami", cmd: str = "whoami") -> GroundTruthEvent:
    """Quick helper to build a ground truth event."""
    return GroundTruthEvent(
        timestamp=datetime(2024, 1, 15, 10, 0, ts_offset, tzinfo=timezone.utc),
        source=GroundTruthSource.TRACEE,
        scenario_id="TEST-001",
        event_type="execve",
        process_name=process,
        command_line=cmd,
    )


def _finding(ts_offset: int = 2, process: str = "whoami", cmd: str = "whoami") -> Finding:
    """Quick helper to build a finding."""
    return Finding(
        id=f"F-{ts_offset}",
        timestamp=datetime(2024, 1, 15, 10, 0, ts_offset, tzinfo=timezone.utc),
        rule_name="Test Rule",
        severity=Severity.MEDIUM,
        process_name=process,
        command_line=cmd,
    )


@pytest.mark.unit
class TestCorrelator:
    def test_exact_match(self):
        correlator = GroundTruthCorrelator(window_seconds=30.0)
        gt_events = [_gt(0)]
        findings = [_finding(2)]

        result = correlator.correlate(gt_events, findings)
        assert len(result.matched_pairs) == 1
        assert len(result.unmatched_gt) == 0
        assert len(result.unmatched_findings) == 0

    def test_no_match_outside_window(self):
        correlator = GroundTruthCorrelator(window_seconds=5.0)
        gt_events = [_gt(0)]
        # Finding happened 10 seconds later, outside 5s window
        findings = [_finding(10)]

        result = correlator.correlate(gt_events, findings)
        assert len(result.matched_pairs) == 0
        assert len(result.unmatched_gt) == 1
        assert len(result.unmatched_findings) == 1

    def test_no_match_different_process(self):
        correlator = GroundTruthCorrelator(window_seconds=30.0)
        gt_events = [_gt(0, process="whoami")]
        findings = [_finding(2, process="completely_different")]

        result = correlator.correlate(gt_events, findings)
        assert len(result.matched_pairs) == 0

    def test_multiple_matches(self):
        correlator = GroundTruthCorrelator(window_seconds=30.0)
        gt_events = [_gt(0, process="whoami"), _gt(5, process="cat", cmd="cat /etc/passwd")]
        findings = [
            _finding(2, process="whoami"),
            _finding(7, process="cat", cmd="cat /etc/passwd"),
        ]

        result = correlator.correlate(gt_events, findings)
        assert len(result.matched_pairs) == 2
        assert len(result.unmatched_gt) == 0
        assert len(result.unmatched_findings) == 0

    def test_false_positives(self):
        correlator = GroundTruthCorrelator(window_seconds=30.0)
        gt_events = [_gt(0)]
        findings = [_finding(2), _finding(3, process="suspicious", cmd="something_else")]

        result = correlator.correlate(gt_events, findings)
        assert len(result.matched_pairs) == 1
        # The second finding doesn't match any ground truth
        assert len(result.unmatched_findings) == 1

    def test_missed_detections(self):
        correlator = GroundTruthCorrelator(window_seconds=30.0)
        gt_events = [_gt(0), _gt(5, process="cat", cmd="cat /etc/shadow")]
        findings = [_finding(2)]  # Only one finding for two GT events

        result = correlator.correlate(gt_events, findings)
        assert len(result.matched_pairs) == 1
        assert len(result.unmatched_gt) == 1

    def test_empty_inputs(self):
        correlator = GroundTruthCorrelator()
        result = correlator.correlate([], [])
        assert len(result.matched_pairs) == 0
        assert len(result.unmatched_gt) == 0
        assert len(result.unmatched_findings) == 0

    def test_gt_only_no_findings(self):
        correlator = GroundTruthCorrelator()
        result = correlator.correlate([_gt(0)], [])
        assert len(result.matched_pairs) == 0
        assert len(result.unmatched_gt) == 1

    def test_findings_only_no_gt(self):
        correlator = GroundTruthCorrelator()
        result = correlator.correlate([], [_finding(0)])
        assert len(result.matched_pairs) == 0
        assert len(result.unmatched_findings) == 1
