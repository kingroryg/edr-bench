"""Normalize raw EDR output into the canonical Finding model."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from edr_bench.models.finding import Finding, Severity

logger = structlog.get_logger(__name__)

# Mapping from common vendor severity strings to our Severity enum.
_SEVERITY_MAP: dict[str, Severity] = {
    # Generic
    "info": Severity.INFO if hasattr(Severity, "INFO") else Severity("info"),
    "informational": Severity.INFO if hasattr(Severity, "INFO") else Severity("info"),
    "low": Severity.LOW if hasattr(Severity, "LOW") else Severity("low"),
    "medium": Severity.MEDIUM if hasattr(Severity, "MEDIUM") else Severity("medium"),
    "high": Severity.HIGH if hasattr(Severity, "HIGH") else Severity("high"),
    "critical": Severity.CRITICAL if hasattr(Severity, "CRITICAL") else Severity("critical"),
    # CrowdStrike numeric-ish
    "1": Severity.INFO if hasattr(Severity, "INFO") else Severity("info"),
    "2": Severity.LOW if hasattr(Severity, "LOW") else Severity("low"),
    "3": Severity.MEDIUM if hasattr(Severity, "MEDIUM") else Severity("medium"),
    "4": Severity.HIGH if hasattr(Severity, "HIGH") else Severity("high"),
    "5": Severity.CRITICAL if hasattr(Severity, "CRITICAL") else Severity("critical"),
    # Falco priorities
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
    "debug": Severity.INFO,
}

# Common field name aliases across EDR vendors.
_FIELD_ALIASES: dict[str, list[str]] = {
    "rule_name": [
        "rule_name", "ruleName", "detection_name", "DetectName",
        "title", "alert_name", "threatName", "ThreatName",
        "rule.description",  # Wazuh
        "rule",  # Falco
    ],
    "severity": [
        "severity", "Severity", "priority", "risk_level",
        "SeverityName", "alert_severity",
        "rule.level",  # Wazuh (0-15 numeric)
    ],
    "description": [
        "description", "Description", "message", "summary",
        "DetectDescription", "alert_description",
        "output",  # Falco
    ],
    "mitre_technique_id": [
        "mitre_technique_id", "technique_id", "MitreTechniqueId",
        "tactic_id", "Tactic", "attack_technique",
        "rule.mitre.id",  # Wazuh
    ],
    "process_name": [
        "process_name", "processName", "ImageFileName",
        "ParentImageFileName", "process", "comm",
        "proc.name",  # Falco
    ],
    "process_pid": [
        "process_pid", "pid", "ProcessId", "TargetProcessId",
    ],
    "command_line": [
        "command_line", "commandLine", "CommandLine", "cmdline",
        "process_command_line",
        "data.command",  # Wazuh
        "proc.cmdline",  # Falco
    ],
    "file_path": [
        "file_path", "filePath", "FilePath", "TargetFilename",
        "file_name", "path",
        "syscheck.path",  # Wazuh
        "fd.name",  # Falco
    ],
    "network_dst": [
        "network_dst", "RemoteAddressIP4", "dst_ip", "dest_ip",
        "remote_ip", "RemoteIP",
        "data.dstip",  # Wazuh
    ],
    "network_port": [
        "network_port", "RemotePort", "dst_port", "dest_port",
        "remote_port",
    ],
    "blocked": [
        "blocked", "Blocked", "action_taken", "preventionStatus",
        "PatternDispositionFlags",
    ],
    "timestamp": [
        "timestamp", "Timestamp", "created_at", "detectionTime",
        "ProcessStartTime", "event_time",
    ],
    "source_container": [
        "source_container", "container_id", "ContainerId",
        "container_name",
        "container.id",  # Falco
    ],
}


class FindingNormalizer:
    """Convert raw EDR data into canonical :class:`Finding` instances."""

    def normalize_json(self, raw: dict[str, Any]) -> Finding:
        """Normalize a JSON dict (e.g. from an EDR log file or API)."""
        return self._build_finding(raw)

    def normalize_cef(self, cef_line: str) -> Finding:
        """Normalize a CEF-formatted syslog line.

        Expected format::

            CEF:0|vendor|product|version|sig_id|name|severity|extensions
        """
        raw = self._parse_cef(cef_line)
        return self._build_finding(raw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_finding(self, raw: dict[str, Any]) -> Finding:
        """Build a :class:`Finding` from a flattened dict using alias lookup."""
        def _get(field: str) -> Any:
            for alias in _FIELD_ALIASES.get(field, [field]):
                if alias in raw:
                    return raw[alias]
            return None

        severity_raw = _get("severity")
        severity = self._map_severity(severity_raw)

        timestamp_raw = _get("timestamp")
        timestamp = self._parse_timestamp(timestamp_raw)

        blocked_raw = _get("blocked")
        blocked = self._parse_blocked(blocked_raw)

        pid_raw = _get("process_pid")
        process_pid: int | None = None
        if pid_raw is not None:
            try:
                process_pid = int(pid_raw)
            except (ValueError, TypeError):
                pass

        port_raw = _get("network_port")
        network_port: int | None = None
        if port_raw is not None:
            try:
                network_port = int(port_raw)
            except (ValueError, TypeError):
                pass

        return Finding(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            rule_name=str(_get("rule_name") or "unknown"),
            severity=severity,
            description=str(_get("description") or ""),
            mitre_technique_id=_get("mitre_technique_id"),
            source_container=_get("source_container"),
            process_name=_get("process_name"),
            process_pid=process_pid,
            command_line=_get("command_line"),
            file_path=_get("file_path"),
            network_dst=_get("network_dst"),
            network_port=network_port,
            blocked=blocked,
            raw=raw,
        )

    @staticmethod
    def _map_severity(value: Any) -> Severity:
        """Map a vendor severity value to the canonical enum."""
        if value is None:
            return Severity.MEDIUM if hasattr(Severity, "MEDIUM") else list(Severity)[0]
        key = str(value).strip().lower()
        mapped = _SEVERITY_MAP.get(key)
        if mapped is not None:
            return mapped
        # Try numeric mapping
        try:
            num = int(float(key))
            if num <= 2:
                return Severity.LOW if hasattr(Severity, "LOW") else list(Severity)[0]
            if num <= 5:
                return Severity.MEDIUM if hasattr(Severity, "MEDIUM") else list(Severity)[0]
            if num <= 8:
                return Severity.HIGH if hasattr(Severity, "HIGH") else list(Severity)[0]
            return Severity.CRITICAL if hasattr(Severity, "CRITICAL") else list(Severity)[0]
        except (ValueError, TypeError):
            pass
        return Severity.MEDIUM if hasattr(Severity, "MEDIUM") else list(Severity)[0]

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            if value > 1e15:
                # Nanosecond epoch (e.g. Falco, some cloud APIs)
                value = value / 1e9
            elif value > 1e12:
                # Millisecond epoch (e.g. CrowdStrike, Wazuh)
                value = value / 1e3
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
        return datetime.now(tz=timezone.utc)

    @staticmethod
    def _parse_blocked(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {
                "true", "1", "yes", "blocked", "prevented",
                "dropped", "denied", "quarantined", "killed",
            }
        if isinstance(value, (int, float)):
            return bool(value)
        # CrowdStrike PatternDispositionFlags
        if isinstance(value, dict):
            return bool(
                value.get("Kill") or value.get("Quarantine")
                or value.get("ProcessBlocked") or value.get("OperationBlocked")
            )
        return False

    @staticmethod
    def _parse_cef(cef_line: str) -> dict[str, Any]:
        """Parse a CEF syslog line into a flat dict.

        Format: ``CEF:0|vendor|product|version|sig_id|name|severity|extensions``
        """
        raw: dict[str, Any] = {}
        line = cef_line.strip()
        if not line.startswith("CEF:"):
            logger.warning("normalizer.invalid_cef_prefix", line=line[:120])
            raw["_raw_line"] = line
            return raw

        # Strip the "CEF:" prefix and split header fields
        body = line[4:]  # Remove "CEF:"
        parts = body.split("|", 7)
        if len(parts) < 8:
            logger.warning("normalizer.cef_too_few_fields", count=len(parts))
            raw["_raw_line"] = line
            return raw

        raw["cef_version"] = parts[0]
        raw["vendor"] = parts[1]
        raw["product"] = parts[2]
        raw["device_version"] = parts[3]
        raw["sig_id"] = parts[4]
        raw["rule_name"] = parts[5]
        raw["severity"] = parts[6]

        # Parse extension key=value pairs
        extensions = parts[7]
        raw.update(_parse_cef_extensions(extensions))

        return raw


def _parse_cef_extensions(ext_string: str) -> dict[str, str]:
    """Parse CEF extension ``key=value`` pairs.

    Values may contain ``=`` if they are the last value, and keys
    are always single tokens.  We use a simple split approach.
    """
    result: dict[str, str] = {}
    if not ext_string:
        return result

    # CEF extensions are space-separated key=value; values can contain spaces
    # but keys cannot.  We split on " key=" boundaries.
    tokens = ext_string.split(" ")
    current_key: str | None = None
    current_value_parts: list[str] = []

    for token in tokens:
        if "=" in token:
            eq_idx = token.index("=")
            candidate_key = token[:eq_idx]
            # Heuristic: CEF keys are short alphanumeric identifiers
            if candidate_key.isidentifier() and len(candidate_key) < 40:
                # Flush previous pair
                if current_key is not None:
                    result[current_key] = " ".join(current_value_parts)
                current_key = candidate_key
                current_value_parts = [token[eq_idx + 1 :]]
                continue
        current_value_parts.append(token)

    if current_key is not None:
        result[current_key] = " ".join(current_value_parts)

    return result
