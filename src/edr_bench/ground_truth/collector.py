"""Unified ground truth collector that merges all sources."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from edr_bench.config.settings import Settings
from edr_bench.ground_truth.docker_events import DockerEventCollector
from edr_bench.ground_truth.mitmproxy_parser import MitmproxyParser
from edr_bench.ground_truth.mocknet_parser import MockNetParser
from edr_bench.ground_truth.tracee_monitor import TraceeMonitor
from edr_bench.models.ground_truth import GroundTruthEvent

logger = structlog.get_logger(__name__)


class GroundTruthCollector:
    """Aggregate ground truth from Tracee, mitmproxy, and Docker events."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tracee = TraceeMonitor(settings)
        self._mitmproxy = MitmproxyParser()
        self._mocknet = MockNetParser()
        self._docker = DockerEventCollector()
        self._scenario_id: str | None = None
        self._start_time: datetime | None = None
        self._container_id: str | None = None
        self._mitmproxy_flow_path: Path | None = None
        self._mocknet_traffic_path: Path | None = None

    async def collect(
        self,
        scenario_id: str,
        container_id: str = "",
        mitmproxy_flow_path: Path | None = None,
        mocknet_traffic_path: Path | None = None,
    ) -> None:
        """Start all collectors for a new scenario execution.

        Parameters
        ----------
        scenario_id:
            Identifier of the scenario being executed.
        container_id:
            Docker container to monitor.
        mitmproxy_flow_path:
            Optional path to mitmproxy JSONL flow file.
        mocknet_traffic_path:
            Optional path to MockNet traffic.jsonl log file.
        """
        self._scenario_id = scenario_id
        self._start_time = datetime.now().astimezone()
        self._container_id = container_id
        self._mitmproxy_flow_path = mitmproxy_flow_path
        self._mocknet_traffic_path = mocknet_traffic_path

        # Start Tracee monitor
        try:
            await self._tracee.start(container_id)
        except Exception:
            logger.exception(
                "ground_truth_collector.tracee_start_failed",
                scenario_id=scenario_id,
            )

        # Start Docker event collector
        try:
            await self._docker.start(container_id)
        except Exception:
            logger.exception(
                "ground_truth_collector.docker_start_failed",
                scenario_id=scenario_id,
            )

        logger.info(
            "ground_truth_collector.started",
            scenario_id=scenario_id,
            container_id=container_id,
        )

    async def stop_and_collect(
        self,
        mitmproxy_flow_path: Path | None = None,
    ) -> list[GroundTruthEvent]:
        """Stop all collectors, merge, sort, deduplicate, and return events."""
        scenario_id = self._scenario_id or ""
        end_time = datetime.now().astimezone()
        all_events: list[GroundTruthEvent] = []

        # Collect from Tracee
        try:
            await self._tracee.stop()
            tracee_events = await self._tracee.get_events(scenario_id)
            all_events.extend(tracee_events)
            logger.info(
                "ground_truth_collector.tracee_events",
                count=len(tracee_events),
            )
        except Exception:
            logger.exception("ground_truth_collector.tracee_collect_failed")

        # Collect from Docker
        try:
            docker_events = await self._docker.stop()
            for evt in docker_events:
                evt.scenario_id = scenario_id
            all_events.extend(docker_events)
            logger.info(
                "ground_truth_collector.docker_events",
                count=len(docker_events),
            )
        except Exception:
            logger.exception("ground_truth_collector.docker_collect_failed")

        # Parse mitmproxy flows (use param if given, else fall back to stored path)
        effective_mitmproxy_path = mitmproxy_flow_path or self._mitmproxy_flow_path
        if effective_mitmproxy_path is not None and self._start_time is not None:
            try:
                mitmproxy_events = self._mitmproxy.parse_flows_for_scenario(
                    flow_path=effective_mitmproxy_path,
                    scenario_id=scenario_id,
                    start_time=self._start_time,
                    end_time=end_time,
                )
                all_events.extend(mitmproxy_events)
                logger.info(
                    "ground_truth_collector.mitmproxy_events",
                    count=len(mitmproxy_events),
                )
            except Exception:
                logger.exception("ground_truth_collector.mitmproxy_collect_failed")

        # Parse MockNet traffic log
        if self._mocknet_traffic_path is not None and self._start_time is not None:
            try:
                mocknet_events = self._mocknet.parse_for_scenario(
                    traffic_log_path=self._mocknet_traffic_path,
                    scenario_id=scenario_id,
                    start_time=self._start_time,
                    end_time=end_time,
                )
                all_events.extend(mocknet_events)
                logger.info(
                    "ground_truth_collector.mocknet_events",
                    count=len(mocknet_events),
                )
            except Exception:
                logger.exception("ground_truth_collector.mocknet_collect_failed")

        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)

        # Deduplicate by (timestamp, event_type, source, container_id)
        deduped = _deduplicate(all_events)

        logger.info(
            "ground_truth_collector.collected",
            scenario_id=scenario_id,
            total_raw=len(all_events),
            total_deduped=len(deduped),
        )
        return deduped


def _deduplicate(events: list[GroundTruthEvent]) -> list[GroundTruthEvent]:
    """Remove duplicate events based on key attributes."""
    seen: set[tuple[str, ...]] = set()
    result: list[GroundTruthEvent] = []
    for evt in events:
        key = (
            evt.timestamp.isoformat(),
            evt.event_type or "",
            evt.source.value if evt.source else "",
            evt.container_id or "",
            evt.process_name or "",
            evt.command_line or "",
            evt.file_path or "",
            evt.http_url or "",
        )
        if key not in seen:
            seen.add(key)
            result.append(evt)
    return result
