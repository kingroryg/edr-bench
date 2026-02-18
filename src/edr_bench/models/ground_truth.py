"""Ground truth event model captured via eBPF, mitmproxy, and Docker events."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from edr_bench.models.enums import GroundTruthSource


class GroundTruthEvent(BaseModel):
    """A verified ground truth event observed during scenario execution."""

    timestamp: datetime = Field(description="When the event was observed")
    source: GroundTruthSource = Field(description="Collection source")
    scenario_id: str = Field(description="Associated scenario ID")
    step_order: int | None = Field(default=None, description="Associated step order")
    container_id: str | None = Field(default=None)
    event_type: str = Field(description="Event type (e.g. execve, network_connect, file_write)")
    process_name: str | None = Field(default=None)
    process_pid: int | None = Field(default=None)
    command_line: str | None = Field(default=None)
    file_path: str | None = Field(default=None)
    network_dst: str | None = Field(default=None)
    network_port: int | None = Field(default=None)
    http_method: str | None = Field(default=None)
    http_url: str | None = Field(default=None)
    http_status: int | None = Field(default=None)
    details: dict = Field(
        default_factory=dict,
        description="Additional event-specific details",
    )
