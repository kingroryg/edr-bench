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
    content_summary: str | None = Field(default=None, description="Summary of the content involved (e.g. 'customer PII', 'API keys')")
    data_classification: str | None = Field(default=None, description="Classification of the data (e.g. 'pii', 'credentials', 'financial', 'proprietary_code')")
    data_volume_bytes: int | None = Field(default=None, description="Size of data transferred")
    source_app: str | None = Field(default=None, description="Application that originated the action (e.g. 'firefox', 'scp', 'git')")
    destination_type: str | None = Field(default=None, description="Type of destination (e.g. 'personal_cloud', 'external_ip', 'ai_service', 'social_media')")
    destination_site: str | None = Field(default=None, description="Specific destination (e.g. 'chatgpt.com', 'drive.google.com')")
    action_type: str | None = Field(default=None, description="Semantic action (e.g. 'paste_text', 'upload_file', 'send_message', 'share_link')")
    details: dict = Field(
        default_factory=dict,
        description="Additional event-specific details",
    )
