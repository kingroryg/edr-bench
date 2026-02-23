"""Collect Docker daemon events as ground truth."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog

from edr_bench.models.ground_truth import GroundTruthEvent, GroundTruthSource

logger = structlog.get_logger(__name__)

_RELEVANT_ACTIONS = frozenset({
    "exec_create",
    "exec_start",
    "exec_die",
    "die",
    "kill",
    "start",
    "stop",
    "pause",
    "unpause",
    "oom",
})


class DockerEventCollector:
    """Stream Docker daemon events for a specific container."""

    def __init__(self, docker_host: str | None = None) -> None:
        self._docker_host = docker_host
        self._client: Any | None = None
        self._container_id: str | None = None
        self._events: list[GroundTruthEvent] = []
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def start(self, container_id: str) -> None:
        """Start streaming Docker events for *container_id*."""
        self._container_id = container_id
        self._events.clear()
        self._running = True

        try:
            import docker  # type: ignore[import-untyped]

            kwargs: dict[str, Any] = {}
            if self._docker_host:
                kwargs["base_url"] = self._docker_host
            self._client = docker.DockerClient(**kwargs)
        except Exception:
            logger.warning(
                "docker_event_collector.client_init_failed",
                docker_host=self._docker_host,
            )
            self._client = None
            return

        self._task = asyncio.create_task(self._stream_loop())
        logger.info(
            "docker_event_collector.started",
            container_id=container_id,
        )

    async def stop(self) -> list[GroundTruthEvent]:
        """Stop streaming and return the collected events."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                logger.debug("docker_event_collector.close_error", exc_info=True)
            self._client = None

        logger.info(
            "docker_event_collector.stopped",
            events_collected=len(self._events),
        )
        return list(self._events)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _stream_loop(self) -> None:
        """Read Docker events in a background executor."""
        if self._client is None:
            return

        loop = asyncio.get_running_loop()
        try:
            events_gen = self._client.events(
                decode=True,
                filters={
                    "container": [self._container_id],
                    "type": ["container"],
                },
            )
            while self._running:
                raw = await loop.run_in_executor(None, self._next_event, events_gen)
                if raw is None:
                    await asyncio.sleep(0.1)
                    continue
                event = self._map_event(raw)
                if event is not None:
                    self._events.append(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("docker_event_collector.stream_error")

    @staticmethod
    def _next_event(gen: Any) -> dict[str, Any] | None:
        """Pull the next event from the blocking generator (runs in executor)."""
        try:
            return next(gen)
        except StopIteration:
            return None
        except Exception:
            logger.debug("docker_event_collector.next_event_error", exc_info=True)
            return None

    def _map_event(self, raw: dict[str, Any]) -> GroundTruthEvent | None:
        """Convert a raw Docker event dict into a GroundTruthEvent."""
        action: str = raw.get("Action", raw.get("action", ""))
        status: str = raw.get("status", action)

        if status not in _RELEVANT_ACTIONS:
            return None

        timestamp = self._extract_timestamp(raw)
        actor: dict[str, Any] = raw.get("Actor", raw.get("actor", {}))
        attributes: dict[str, str] = actor.get("Attributes", actor.get("attributes", {}))

        container_id = actor.get("ID", self._container_id or "")
        process_name = attributes.get("execID") or attributes.get("name")
        command_line: str | None = None

        # exec_create often contains the command
        if "execCreate" in raw.get("Action", ""):
            command_line = attributes.get("execID")

        event_type = f"docker_{status}"

        return GroundTruthEvent(
            timestamp=timestamp,
            source=GroundTruthSource.DOCKER_EVENTS,
            scenario_id="",
            step_order=None,
            container_id=str(container_id),
            event_type=event_type,
            process_name=process_name,
            command_line=command_line,
            details=raw,
        )

    @staticmethod
    def _extract_timestamp(raw: dict[str, Any]) -> datetime:
        ts = raw.get("time") or raw.get("timeNano")
        if isinstance(ts, int):
            # Docker may report seconds or nanoseconds
            if ts > 1e15:
                ts = ts / 1e9
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        return datetime.now(tz=timezone.utc)
