"""Poll an EDR REST API for alert findings."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog

from edr_bench.edr_interface.base import EDRListener
from edr_bench.utils.retry import retry_async
from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.models.finding import Finding

logger = structlog.get_logger(__name__)


class APIPoller(EDRListener):
    """Periodically poll an EDR REST API ``GET /alerts`` endpoint."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        poll_interval: float = 10.0,
        normalizer: FindingNormalizer | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._poll_interval = poll_interval
        self._normalizer = normalizer or FindingNormalizer()
        self._findings: list[Finding] = []
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._last_seen: datetime = datetime.now(tz=timezone.utc)
        self._seen_ids: set[str] = set()

    async def start(self) -> None:
        """Start polling the EDR API."""
        self._findings.clear()
        self._seen_ids.clear()
        self._last_seen = datetime.now(tz=timezone.utc)
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("api_poller.started", url=self._api_url)

    async def stop(self) -> None:
        """Stop polling."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info(
            "api_poller.stopped",
            url=self._api_url,
            findings=len(self._findings),
        )

    async def get_findings(self) -> list[Finding]:
        """Return all findings collected so far."""
        return list(self._findings)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        """Periodically fetch alerts from the EDR API."""
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError:
            logger.error("api_poller.httpx_not_installed")
            return

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(30.0),
        ) as client:
            while self._running:
                try:
                    await self._fetch_alerts(client)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("api_poller.fetch_error", url=self._api_url)
                await asyncio.sleep(self._poll_interval)

    @retry_async(max_attempts=3, min_delay=2.0, max_delay=15.0, retry_on=(ConnectionError, OSError))
    async def _fetch_alerts(self, client: Any) -> None:
        """Perform a single GET /alerts request and process results."""
        params: dict[str, str] = {
            "since": self._last_seen.isoformat(),
        }
        url = f"{self._api_url}/alerts"

        response = await client.get(url, params=params)

        if response.status_code != 200:
            logger.warning(
                "api_poller.bad_status",
                url=url,
                status=response.status_code,
            )
            return

        body = response.json()
        alerts: list[dict[str, Any]] = []

        # Handle both { "alerts": [...] } and bare [...] responses
        if isinstance(body, list):
            alerts = body
        elif isinstance(body, dict):
            alerts = body.get("alerts", body.get("data", body.get("items", [])))

        new_count = 0
        for alert in alerts:
            alert_id = str(
                alert.get("id", alert.get("alert_id", alert.get("detection_id", "")))
            )
            if alert_id and alert_id in self._seen_ids:
                continue
            if alert_id:
                self._seen_ids.add(alert_id)

            try:
                finding = self._normalizer.normalize_json(alert)
                self._findings.append(finding)
                new_count += 1
                # Advance the watermark
                if finding.timestamp > self._last_seen:
                    self._last_seen = finding.timestamp
            except Exception:
                logger.exception("api_poller.normalize_error")

        if new_count:
            logger.info(
                "api_poller.new_findings",
                count=new_count,
                total=len(self._findings),
            )
