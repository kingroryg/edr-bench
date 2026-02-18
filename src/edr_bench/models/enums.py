"""Enumerations for EDR-Bench scenario and finding classification."""

from enum import StrEnum


class Platform(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    CLOUD = "cloud"


class Complexity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Role(StrEnum):
    """Role of the simulation step executor."""

    CLI = "cli"
    UI = "ui"
    PHISHING = "phishing"
    CLOUD = "cloud"
    USB = "usb"


class AttackType(StrEnum):
    """MITRE ATT&CK-aligned attack type classification."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class Severity(StrEnum):
    """EDR finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GroundTruthSource(StrEnum):
    """Source of a ground truth event."""

    TRACEE = "tracee"
    MITMPROXY = "mitmproxy"
    DOCKER_EVENTS = "docker_events"
    SCENARIO_DEFINITION = "scenario_definition"
