"""Receive CEF/LEEF syslog messages over UDP and convert them to Findings."""
from __future__ import annotations

import asyncio

import structlog

from edr_bench.edr_interface.base import EDRListener
from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.models.finding import Finding

logger = structlog.get_logger(__name__)


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that collects raw syslog datagrams."""

    def __init__(self, callback: asyncio.Queue[str]) -> None:
        self._queue = callback

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # noqa: ARG002
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            message = data.decode("utf-8", errors="replace").strip()
            if message:
                self._queue.put_nowait(message)
        except Exception:
            logger.debug("syslog_receiver.decode_error", addr=addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("syslog_receiver.protocol_error", error=str(exc))


class SyslogReceiver(EDRListener):
    """Asyncio UDP server that receives CEF/LEEF syslog messages.

    Each incoming datagram is expected to contain a single CEF- or
    LEEF-formatted line.  The receiver parses CEF (Common Event Format)::

        CEF:0|vendor|product|version|sig_id|name|severity|extensions

    Parsed data is passed through the :class:`FindingNormalizer`.
    """

    def __init__(
        self,
        port: int = 514,
        normalizer: FindingNormalizer | None = None,
        bind_address: str = "0.0.0.0",
    ) -> None:
        self._port = port
        self._bind_address = bind_address
        self._normalizer = normalizer or FindingNormalizer()
        self._findings: list[Finding] = []
        self._running = False
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._transport: asyncio.DatagramTransport | None = None
        self._consumer_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Bind the UDP socket and start receiving syslog messages."""
        self._findings.clear()
        self._running = True

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self._queue),
            local_addr=(self._bind_address, self._port),
        )
        self._transport = transport  # type: ignore[assignment]
        self._consumer_task = asyncio.create_task(self._consume_loop())

        logger.info(
            "syslog_receiver.started",
            bind=self._bind_address,
            port=self._port,
        )

    async def stop(self) -> None:
        """Close the UDP socket and stop processing."""
        self._running = False
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._consumer_task is not None:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None

        logger.info(
            "syslog_receiver.stopped",
            findings=len(self._findings),
        )

    async def get_findings(self) -> list[Finding]:
        """Return all findings collected so far."""
        return list(self._findings)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _consume_loop(self) -> None:
        """Drain the message queue and normalize each syslog line."""
        while self._running:
            try:
                message = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                raise

            try:
                finding = self._parse_syslog_message(message)
                if finding is not None:
                    self._findings.append(finding)
            except Exception:
                logger.exception("syslog_receiver.parse_error", message=message[:200])

    def _parse_syslog_message(self, message: str) -> Finding | None:
        """Parse a syslog message, handling optional syslog header.

        Syslog messages may have a BSD-style header before the CEF payload::

            <priority>timestamp hostname CEF:0|...

        We strip everything before the ``CEF:`` prefix.
        """
        # Locate CEF payload
        cef_idx = message.find("CEF:")
        if cef_idx >= 0:
            cef_line = message[cef_idx:]
            return self._normalizer.normalize_cef(cef_line)

        # Locate LEEF payload (basic support: treat as raw JSON-ish)
        leef_idx = message.find("LEEF:")
        if leef_idx >= 0:
            logger.debug("syslog_receiver.leef_not_fully_supported")
            return None

        # Attempt JSON parse as a fallback
        try:
            import json

            raw = json.loads(message)
            if isinstance(raw, dict):
                return self._normalizer.normalize_json(raw)
        except (json.JSONDecodeError, ValueError):
            pass

        logger.debug("syslog_receiver.unrecognised_format", message=message[:200])
        return None
