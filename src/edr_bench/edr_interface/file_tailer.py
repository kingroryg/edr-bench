"""Tail a JSON log file to collect EDR findings."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

from edr_bench.edr_interface.base import EDRListener
from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.models.finding import Finding

logger = structlog.get_logger(__name__)


class FileTailer(EDRListener):
    """Watch a JSON log file and normalize each line into a Finding.

    Uses a poll-based approach: periodically checks for new content
    appended to the file (works on all platforms without inotify).
    """

    def __init__(
        self,
        log_path: str | Path,
        normalizer: FindingNormalizer | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        self._log_path = Path(log_path)
        self._normalizer = normalizer or FindingNormalizer()
        self._poll_interval = poll_interval
        self._findings: list[Finding] = []
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._file_position: int = 0

    async def start(self) -> None:
        """Begin tailing the log file."""
        self._findings.clear()
        self._file_position = 0
        self._running = True
        self._task = asyncio.create_task(self._tail_loop())
        logger.info("file_tailer.started", path=str(self._log_path))

    async def stop(self) -> None:
        """Stop tailing."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info(
            "file_tailer.stopped",
            path=str(self._log_path),
            findings=len(self._findings),
        )

    async def get_findings(self) -> list[Finding]:
        """Return all findings collected so far."""
        return list(self._findings)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _tail_loop(self) -> None:
        """Poll the log file for new lines."""
        loop = asyncio.get_event_loop()
        try:
            # Wait for the file to appear
            while self._running and not self._log_path.exists():
                logger.debug("file_tailer.waiting_for_file", path=str(self._log_path))
                await asyncio.sleep(self._poll_interval)

            while self._running:
                new_lines = await loop.run_in_executor(None, self._read_new_lines)
                for line in new_lines:
                    self._process_line(line)
                await asyncio.sleep(self._poll_interval)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("file_tailer.tail_error", path=str(self._log_path))

    def _read_new_lines(self) -> list[str]:
        """Read any lines appended since last read (blocking, runs in executor)."""
        lines: list[str] = []
        if not self._log_path.exists():
            return lines

        try:
            with self._log_path.open("r") as fh:
                fh.seek(self._file_position)
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
                self._file_position = fh.tell()
        except OSError:
            logger.debug("file_tailer.read_error", path=str(self._log_path))
        return lines

    def _process_line(self, line: str) -> None:
        """Parse a single JSON line and normalize it."""
        try:
            raw: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("file_tailer.invalid_json", line=line[:200])
            return

        try:
            finding = self._normalizer.normalize_json(raw)
            self._findings.append(finding)
        except Exception:
            logger.exception("file_tailer.normalize_error")
