"""Configuration schema validation utilities."""

from __future__ import annotations

from pathlib import Path

import yaml

from edr_bench.config.settings import Settings


def load_config(config_path: Path | None = None) -> Settings:
    """Load settings, optionally merging from a YAML config file."""
    if config_path and config_path.exists():
        with open(config_path) as f:
            overrides = yaml.safe_load(f) or {}
        return Settings(**overrides)
    return Settings()


def validate_config(settings: Settings) -> list[str]:
    """Validate configuration and return list of warnings."""
    warnings: list[str] = []

    if not settings.scenarios_dir.exists():
        warnings.append(f"Scenarios directory not found: {settings.scenarios_dir}")

    if settings.agent.anthropic_api_key == "" and settings.agent.openai_api_key == "":
        warnings.append("No AI agent API key configured; UI scenarios will not execute")

    if settings.edr.api_url == "" and settings.edr.log_path == "":
        warnings.append("No EDR data source configured")

    return warnings
