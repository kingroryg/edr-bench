"""Normalized EDR Finding model."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from edr_bench.models.enums import Severity


class Finding(BaseModel):
    """A normalized EDR detection finding."""

    id: str = Field(description="Unique finding identifier")
    timestamp: datetime = Field(description="When the EDR generated this finding")
    rule_name: str = Field(description="EDR detection rule or signature name")
    severity: Severity
    description: str = Field(default="", description="Finding description text")
    mitre_technique_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK technique if reported by EDR",
    )
    source_container: str | None = Field(
        default=None,
        description="Container ID or name where the event originated",
    )
    process_name: str | None = Field(default=None)
    process_pid: int | None = Field(default=None)
    command_line: str | None = Field(default=None)
    file_path: str | None = Field(default=None)
    network_dst: str | None = Field(default=None)
    network_port: int | None = Field(default=None)
    blocked: bool = Field(
        default=False,
        description="Whether the EDR blocked/prevented the action",
    )
    raw: dict = Field(
        default_factory=dict,
        description="Original raw finding from the EDR",
    )
