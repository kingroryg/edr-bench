"""Async timing utilities: context manager and Timer class."""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def timed_operation(name: str, **extra: Any) -> AsyncGenerator[Timer, None]:
    """Async context manager that logs start, end, and duration of an operation.

    Args:
        name: A human-readable name for the operation being timed.
        **extra: Additional key-value pairs to include in log messages.

    Yields:
        A Timer instance that tracks elapsed time.

    Example::

        async with timed_operation("fetch_alerts", source="crowdstrike") as t:
            alerts = await client.get_alerts()
        print(t.elapsed)
    """
    timer = Timer(name=name)
    log = logger.bind(operation=name, **extra)
    log.info("operation_started")
    timer.start()
    try:
        yield timer
    except Exception:
        timer.stop()
        log.error(
            "operation_failed",
            duration_seconds=timer.elapsed,
        )
        raise
    else:
        timer.stop()
        log.info(
            "operation_completed",
            duration_seconds=timer.elapsed,
        )


@dataclass
class Timer:
    """A simple timer that tracks elapsed wall-clock time.

    Attributes:
        name: A label for this timer.
        start_time: The monotonic timestamp when the timer was started.
        end_time: The monotonic timestamp when the timer was stopped, or None.
        laps: A list of (lap_name, duration) tuples recorded via ``lap()``.
    """

    name: str = ""
    start_time: float | None = None
    end_time: float | None = None
    laps: list[tuple[str, float]] = field(default_factory=list)

    def start(self) -> Timer:
        """Start (or restart) the timer.

        Returns:
            self for method chaining.
        """
        self.start_time = time.monotonic()
        self.end_time = None
        self.laps.clear()
        return self

    def stop(self) -> float:
        """Stop the timer.

        Returns:
            The total elapsed time in seconds.

        Raises:
            RuntimeError: If the timer was never started.
        """
        if self.start_time is None:
            raise RuntimeError("Timer was never started.")
        self.end_time = time.monotonic()
        return self.elapsed

    @property
    def elapsed(self) -> float:
        """Return elapsed time in seconds.

        If the timer is still running, returns time since start.
        If the timer has been stopped, returns the total duration.

        Raises:
            RuntimeError: If the timer was never started.
        """
        if self.start_time is None:
            raise RuntimeError("Timer was never started.")
        end = self.end_time if self.end_time is not None else time.monotonic()
        return end - self.start_time

    @property
    def is_running(self) -> bool:
        """Return True if the timer is currently running."""
        return self.start_time is not None and self.end_time is None

    def lap(self, name: str = "") -> float:
        """Record a lap time without stopping the timer.

        Args:
            name: Optional label for this lap.

        Returns:
            The elapsed time at this lap in seconds.

        Raises:
            RuntimeError: If the timer was never started.
        """
        elapsed = self.elapsed
        self.laps.append((name, elapsed))
        return elapsed

    def __repr__(self) -> str:
        if self.start_time is None:
            status = "not started"
        elif self.end_time is None:
            status = f"running, elapsed={self.elapsed:.4f}s"
        else:
            status = f"stopped, elapsed={self.elapsed:.4f}s"
        return f"Timer(name={self.name!r}, {status})"
