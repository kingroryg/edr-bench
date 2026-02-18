"""Parse mitmproxy JSONL flow files into ground truth events."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from edr_bench.models.ground_truth import GroundTruthEvent, GroundTruthSource

logger = structlog.get_logger(__name__)


class MitmproxyParser:
    """Parse JSONL flow files produced by the mitmproxy addon."""

    def parse_flow_file(self, flow_path: Path) -> list[GroundTruthEvent]:
        """Parse every line in *flow_path* and return GroundTruthEvent instances.

        Each line is expected to be a JSON object with fields:
        timestamp, method, url, request_headers, request_body,
        status_code, response_content_type, response_size.
        """
        events: list[GroundTruthEvent] = []
        path = Path(flow_path)

        if not path.exists():
            logger.warning("mitmproxy_parser.file_not_found", path=str(path))
            return events

        with path.open("r") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug(
                        "mitmproxy_parser.invalid_json",
                        path=str(path),
                        line_no=line_no,
                    )
                    continue

                event = self._flow_to_event(data)
                if event is not None:
                    events.append(event)

        logger.info(
            "mitmproxy_parser.parsed",
            path=str(path),
            events=len(events),
        )
        return events

    def parse_flows_for_scenario(
        self,
        flow_path: Path,
        scenario_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[GroundTruthEvent]:
        """Parse flows and keep only those within *[start_time, end_time]*."""
        all_events = self.parse_flow_file(flow_path)
        filtered: list[GroundTruthEvent] = []
        for event in all_events:
            if start_time <= event.timestamp <= end_time:
                event.scenario_id = scenario_id
                filtered.append(event)
        logger.info(
            "mitmproxy_parser.filtered",
            scenario_id=scenario_id,
            total=len(all_events),
            kept=len(filtered),
        )
        return filtered

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _flow_to_event(data: dict[str, Any]) -> GroundTruthEvent | None:
        """Convert a single mitmproxy flow JSON object to a GroundTruthEvent."""
        try:
            timestamp = _parse_timestamp(data.get("timestamp"))
            method: str = data.get("method", "GET")
            url: str = data.get("url", "")
            status_code = data.get("status_code")

            # Extract host / port from URL for network fields
            network_dst: str | None = None
            network_port: int | None = None
            if url:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                network_dst = parsed.hostname
                network_port = parsed.port

            return GroundTruthEvent(
                timestamp=timestamp,
                source=GroundTruthSource.MITMPROXY,
                scenario_id="",
                step_order=0,
                container_id="",
                event_type="http_request",
                http_method=method,
                http_url=url,
                http_status=int(status_code) if status_code is not None else None,
                network_dst=network_dst,
                network_port=network_port,
                details=data,
            )
        except Exception:
            logger.exception("mitmproxy_parser.event_conversion_error")
            return None


def _parse_timestamp(value: Any) -> datetime:
    """Best-effort timestamp parsing."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)
