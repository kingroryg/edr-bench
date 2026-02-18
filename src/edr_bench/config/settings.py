"""Pydantic Settings for EDR-Bench configuration."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DockerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOCKER_")

    host: str = "unix:///var/run/docker.sock"
    compose_project: str = "edr-bench"
    network_subnet: str = "172.28.0.0/16"
    network_name: str = "edr-bench-net"


class VNCSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VNC_")

    password: str = "edrbench"
    display: str = ":1"
    port: int = 5900
    novnc_port: int = 6080
    screenshot_interval: float = 1.0


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENT_")

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5-20250514"
    openai_api_key: str = ""
    openai_model: str = "computer-use-preview"
    max_agent_steps: int = 50
    screenshot_timeout: float = 5.0


class TraceeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACEE_")

    enabled: bool = True
    output_format: str = "json"
    container_filter: str = ""
    image: str = "aquasec/tracee:latest"


class EDRSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EDR_")

    log_path: str = "/var/log/edr/alerts.json"
    api_url: str = ""
    api_key: str = ""
    syslog_port: int = 1514
    poll_interval: float = 5.0
    name: str = "Unknown EDR"
    version: str = ""


class GoPhishSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GOPHISH_")

    api_key: str = ""
    admin_url: str = "https://localhost:3333"


class LocalStackSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOCALSTACK_")

    url: str = "http://localstack:4566"
    region: str = "us-east-1"


class Settings(BaseSettings):
    """Root settings aggregating all sub-configurations."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    docker: DockerSettings = Field(default_factory=DockerSettings)
    vnc: VNCSettings = Field(default_factory=VNCSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    tracee: TraceeSettings = Field(default_factory=TraceeSettings)
    edr: EDRSettings = Field(default_factory=EDRSettings)
    gophish: GoPhishSettings = Field(default_factory=GoPhishSettings)
    localstack: LocalStackSettings = Field(default_factory=LocalStackSettings)

    scenarios_dir: Path = Path("data/scenarios")
    report_output_dir: Path = Path("reports")
    correlation_window_seconds: float = 30.0
    dry_run: bool = False
    log_level: str = "INFO"
