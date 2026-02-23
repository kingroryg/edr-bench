"""Monitor Tracee runtime security events for ground truth collection."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from edr_bench.config.settings import Settings
from edr_bench.models.ground_truth import GroundTruthEvent, GroundTruthSource

logger = structlog.get_logger(__name__)

_DEFAULT_TRACEE_OUTPUT = Path("/tmp/tracee/out/events.json")

# Tracee event type -> field mapping helpers
_PROCESS_EVENTS = frozenset({"execve", "execveat", "sched_process_exec"})
_FILE_EVENTS = frozenset({"open", "openat", "openat2", "creat", "unlink", "rename"})
_NETWORK_EVENTS = frozenset({"connect", "accept", "bind", "listen"})


class TraceeMonitor:
    """Consumes Tracee JSON output and converts events to GroundTruthEvent."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tracee_cfg = settings.tracee
        self._container_id: str | None = None
        self._events: list[GroundTruthEvent] = []
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._output_path = getattr(
            settings, "tracee_output_path", _DEFAULT_TRACEE_OUTPUT
        )

    async def start(self, container_id: str) -> None:
        """Start consuming Tracee JSON output, filtering for *container_id*."""
        self._container_id = container_id
        self._events.clear()
        self._running = True

        if not self._tracee_cfg.enabled:
            logger.warning("tracee.enabled is False; TraceeMonitor will not collect")
            return

        self._task = asyncio.create_task(self._consume_loop())
        logger.info(
            "tracee_monitor.started",
            container_id=container_id,
            output_path=str(self._output_path),
        )

    async def stop(self) -> None:
        """Stop the monitoring loop."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("tracee_monitor.stopped", events_collected=len(self._events))

    async def get_events(self, scenario_id: str) -> list[GroundTruthEvent]:
        """Return collected events tagged with *scenario_id*."""
        for evt in self._events:
            evt.scenario_id = scenario_id
        return list(self._events)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _consume_loop(self) -> None:
        """Read the Tracee JSON output file line-by-line."""
        try:
            await self._wait_for_file()
            async for raw in self._tail_file():
                if not self._running:
                    break
                event = self._parse_line(raw)
                if event is not None:
                    self._events.append(event)
        except asyncio.CancelledError:
            raise
        except FileNotFoundError:
            logger.warning(
                "tracee_monitor.file_not_found",
                path=str(self._output_path),
            )
        except Exception:
            logger.exception("tracee_monitor.consume_error")

    async def _wait_for_file(self, timeout: float = 30.0) -> None:
        """Wait until the Tracee output file exists."""
        deadline = asyncio.get_running_loop().time() + timeout
        while not self._output_path.exists():
            if asyncio.get_running_loop().time() > deadline:
                raise FileNotFoundError(
                    f"Tracee output not found after {timeout}s: {self._output_path}"
                )
            await asyncio.sleep(0.5)

    async def _tail_file(self):  # noqa: ANN201 – async generator
        """Yield new JSON lines as they are appended to the file."""
        loop = asyncio.get_running_loop()
        with self._output_path.open("r") as fh:
            while self._running:
                line = await loop.run_in_executor(None, fh.readline)
                if line:
                    line = line.strip()
                    if line:
                        yield line
                else:
                    await asyncio.sleep(0.25)

    def _parse_line(self, raw_line: str) -> GroundTruthEvent | None:
        """Parse a single Tracee JSON line into a GroundTruthEvent."""
        try:
            data: dict[str, Any] = json.loads(raw_line)
        except json.JSONDecodeError:
            logger.debug("tracee_monitor.invalid_json", line=raw_line[:200])
            return None

        # Filter by container ID when available
        container_id = data.get("containerId", data.get("container", {}).get("id", ""))
        if self._container_id and not container_id.startswith(self._container_id[:12]):
            return None

        event_name: str = data.get("eventName", data.get("event_name", ""))
        args: list[dict[str, Any]] = data.get("args", [])
        args_map = {a.get("name", ""): a.get("value") for a in args}

        timestamp = self._extract_timestamp(data)
        process_name = data.get("processName", data.get("comm", ""))
        process_pid = data.get("processId", data.get("pid"))
        command_line: str | None = None
        file_path: str | None = None
        network_dst: str | None = None
        network_port: int | None = None
        event_type = event_name

        if event_name in _PROCESS_EVENTS:
            event_type = "process_execution"
            argv = args_map.get("argv")
            if isinstance(argv, list):
                command_line = " ".join(str(a) for a in argv)
            elif isinstance(argv, str):
                command_line = argv
            pathname = args_map.get("pathname", args_map.get("path"))
            if pathname:
                process_name = process_name or str(pathname).rsplit("/", 1)[-1]

        elif event_name in _FILE_EVENTS:
            event_type = "file_access"
            file_path = args_map.get("pathname", args_map.get("path"))

        elif event_name in _NETWORK_EVENTS:
            event_type = "network_connection"
            sockaddr = args_map.get("addr", args_map.get("sockaddr", {}))
            if isinstance(sockaddr, dict):
                network_dst = sockaddr.get("ip", sockaddr.get("addr"))
                port = sockaddr.get("port")
                if port is not None:
                    network_port = int(port)

        return GroundTruthEvent(
            timestamp=timestamp,
            source=GroundTruthSource.TRACEE,
            scenario_id="",
            step_order=0,
            container_id=container_id,
            event_type=event_type,
            process_name=process_name or None,
            process_pid=process_pid,
            command_line=command_line,
            file_path=file_path,
            network_dst=network_dst,
            network_port=network_port,
            details=data,
        )

    @staticmethod
    def _extract_timestamp(data: dict[str, Any]) -> datetime:
        """Best-effort timestamp extraction from a Tracee event."""
        ts = data.get("timestamp")
        if isinstance(ts, (int, float)):
            # Tracee may report nanoseconds since epoch
            if ts > 1e15:
                ts = ts / 1e9
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                pass
        return datetime.now(tz=timezone.utc)
