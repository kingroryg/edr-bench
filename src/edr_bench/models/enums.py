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


class CoachCategory(StrEnum):
    """Categories specific to Coach security intervention scenarios."""

    AI_DATA_LEAK = "ai_data_leak"
    FILE_SHARING = "file_sharing"
    EXFIL_VECTORS = "exfil_vectors"
    SECRET_EXPOSURE = "secret_exposure"
    UNTRUSTED_SOFTWARE = "untrusted_software"
    ACCESS_MANAGEMENT = "access_management"
    AUTH_PHISHING = "auth_phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    AI_AGENT_MCP = "ai_agent_mcp"
    CONFIG_POSTURE = "config_posture"
    NETWORK = "network"
    INSIDER_THREAT = "insider_threat"


class DeploySurface(StrEnum):
    """Where the Coach intervention gets deployed."""

    BROWSER_EXTENSION = "browser_extension"
    DESKTOP_AGENT = "desktop_agent"
    IDE_PLUGIN = "ide_plugin"
    CLI_HOOK = "cli_hook"
    EMAIL_PLUGIN = "email_plugin"
    SLACK_BOT = "slack_bot"
    MOBILE_AGENT = "mobile_agent"


class Priority(StrEnum):
    """Scenario test priority."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class RiskLevel(StrEnum):
    """Risk level for a scenario."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


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
    MOCKNET = "mocknet"
    SCENARIO_DEFINITION = "scenario_definition"
