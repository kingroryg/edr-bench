"""Tests for FindingNormalizer."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.models.enums import Severity


@pytest.fixture
def normalizer() -> FindingNormalizer:
    return FindingNormalizer()


@pytest.mark.unit
class TestNormalizeJson:
    def test_crowdstrike_style_json(self, normalizer: FindingNormalizer):
        raw = {
            "DetectName": "Credential Theft",
            "SeverityName": "high",
            "Description": "Credential dumping detected",
            "MitreTechniqueId": "T1003",
            "ImageFileName": "mimikatz.exe",
            "ProcessId": "1234",
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
            "RemoteAddressIP4": "10.0.0.5",
            "RemotePort": "443",
            "PatternDispositionFlags": {"Kill": True},
            "Timestamp": "2024-06-15T12:00:00+00:00",
        }
        finding = normalizer.normalize_json(raw)
        assert finding.rule_name == "Credential Theft"
        assert finding.severity == Severity.HIGH
        assert finding.mitre_technique_id == "T1003"
        assert finding.process_name == "mimikatz.exe"
        assert finding.process_pid == 1234
        assert finding.command_line == "mimikatz.exe sekurlsa::logonpasswords"
        assert finding.network_dst == "10.0.0.5"
        assert finding.network_port == 443
        assert finding.blocked is True

    def test_minimal_dict(self, normalizer: FindingNormalizer):
        raw = {"rule_name": "Simple Alert"}
        finding = normalizer.normalize_json(raw)
        assert finding.rule_name == "Simple Alert"
        assert finding.severity == Severity.MEDIUM  # default
        assert finding.blocked is False

    def test_empty_dict(self, normalizer: FindingNormalizer):
        finding = normalizer.normalize_json({})
        assert finding.rule_name == "unknown"
        assert finding.severity == Severity.MEDIUM
        assert finding.blocked is False
        assert finding.id  # Should have a UUID


@pytest.mark.unit
class TestNormalizeCef:
    def test_valid_cef_line(self, normalizer: FindingNormalizer):
        cef = "CEF:0|Acme|EDR|1.0|100|Suspicious Process|high|src=10.0.0.1 dst=10.0.0.2"
        finding = normalizer.normalize_cef(cef)
        assert finding.rule_name == "Suspicious Process"
        assert finding.severity == Severity.HIGH

    def test_malformed_cef_too_few_fields(self, normalizer: FindingNormalizer):
        cef = "CEF:0|Acme|EDR|1.0"
        finding = normalizer.normalize_cef(cef)
        # Should not crash; returns an unknown finding
        assert finding.rule_name == "unknown"


@pytest.mark.unit
class TestMapSeverity:
    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            ("info", Severity.INFO),
            ("low", Severity.LOW),
            ("medium", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("INFO", Severity.INFO),
            ("HIGH", Severity.HIGH),
        ],
    )
    def test_string_levels(self, input_val: str, expected: Severity):
        assert FindingNormalizer._map_severity(input_val) == expected

    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            ("1", Severity.INFO),
            ("2", Severity.LOW),
            ("3", Severity.MEDIUM),
            ("4", Severity.HIGH),
            ("5", Severity.CRITICAL),
        ],
    )
    def test_numeric_string_values(self, input_val: str, expected: Severity):
        assert FindingNormalizer._map_severity(input_val) == expected

    def test_out_of_range_high_numeric(self):
        result = FindingNormalizer._map_severity(10)
        assert result == Severity.CRITICAL

    def test_out_of_range_low_numeric(self):
        result = FindingNormalizer._map_severity(0)
        assert result == Severity.LOW

    def test_none_returns_medium(self):
        assert FindingNormalizer._map_severity(None) == Severity.MEDIUM


@pytest.mark.unit
class TestParseTimestamp:
    def test_iso_string(self):
        ts = FindingNormalizer._parse_timestamp("2024-06-15T12:00:00+00:00")
        assert ts.year == 2024
        assert ts.month == 6

    def test_epoch_seconds(self):
        ts = FindingNormalizer._parse_timestamp(1718452800)
        assert isinstance(ts, datetime)
        assert ts.tzinfo is not None

    def test_epoch_milliseconds(self):
        ts = FindingNormalizer._parse_timestamp(1718452800000)
        assert isinstance(ts, datetime)
        # Should be same as seconds after conversion
        expected = FindingNormalizer._parse_timestamp(1718452800)
        assert abs((ts - expected).total_seconds()) < 1.0

    def test_epoch_nanoseconds(self):
        ts = FindingNormalizer._parse_timestamp(1718452800000000000)
        assert isinstance(ts, datetime)
        expected = FindingNormalizer._parse_timestamp(1718452800)
        assert abs((ts - expected).total_seconds()) < 1.0

    def test_none_returns_now(self):
        before = datetime.now(tz=timezone.utc)
        ts = FindingNormalizer._parse_timestamp(None)
        after = datetime.now(tz=timezone.utc)
        assert before <= ts <= after


@pytest.mark.unit
class TestParseBlocked:
    def test_bool_true(self):
        assert FindingNormalizer._parse_blocked(True) is True

    def test_bool_false(self):
        assert FindingNormalizer._parse_blocked(False) is False

    @pytest.mark.parametrize("val", ["blocked", "quarantined", "dropped"])
    def test_string_variants(self, val: str):
        assert FindingNormalizer._parse_blocked(val) is True

    def test_crowdstrike_dict(self):
        assert FindingNormalizer._parse_blocked({"Kill": True}) is True
        assert FindingNormalizer._parse_blocked({"Kill": False, "Quarantine": False}) is False

    def test_int_zero_is_false(self):
        assert FindingNormalizer._parse_blocked(0) is False

    def test_int_one_is_true(self):
        assert FindingNormalizer._parse_blocked(1) is True


@pytest.mark.unit
class TestFieldExtraction:
    def test_mitre_technique_from_various_fields(self, normalizer: FindingNormalizer):
        for field in ["mitre_technique_id", "technique_id", "MitreTechniqueId", "rule.mitre.id"]:
            raw = {field: "T1059.001"}
            finding = normalizer.normalize_json(raw)
            assert finding.mitre_technique_id == "T1059.001"

    def test_network_dst_extraction(self, normalizer: FindingNormalizer):
        raw = {"RemoteAddressIP4": "192.168.1.100"}
        finding = normalizer.normalize_json(raw)
        assert finding.network_dst == "192.168.1.100"

    def test_process_pid_string_to_int(self, normalizer: FindingNormalizer):
        raw = {"pid": "42"}
        finding = normalizer.normalize_json(raw)
        assert finding.process_pid == 42
