"""MITRE Caldera executor for running adversary operations via the Caldera REST API."""

from __future__ import annotations

import asyncio

import httpx
import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models import Scenario, SimulationStep

logger = structlog.get_logger(__name__)

_POLL_INTERVAL_SECONDS = 5
_TERMINAL_STATES = frozenset({"finished", "cleanup", "failed"})


class CalderaExecutor(AttackExecutor):
    """Integrates with the MITRE Caldera REST API to create and monitor
    adversary operations."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.caldera_url: str = getattr(settings, "caldera_url", "")
        self.api_key: str = getattr(settings, "caldera_api_key", "")

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        ability_id = step.command
        log = logger.bind(
            ability_id=ability_id,
            step_order=step.order,
            scenario_id=scenario.id,
        )
        log.info("caldera_creating_operation")

        base_url = self.caldera_url.rstrip("/")
        headers = {
            "KEY": self.api_key,
            "Content-Type": "application/json",
        }

        operation_payload = {
            "name": f"edr-bench-{scenario.id}-step-{step.order}",
            "adversary": {
                "atomic_ordering": [ability_id],
            },
            "auto_close": True,
            "state": "running",
        }

        async with httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=httpx.Timeout(30.0),
        ) as client:
            response = await client.post(
                "/api/v2/operations",
                json=operation_payload,
            )
            response.raise_for_status()
            operation = response.json()
            operation_id: str = operation["id"]
            log = log.bind(operation_id=operation_id)
            log.info("caldera_operation_created")

            elapsed = 0.0
            timeout = float(step.timeout_seconds) if step.timeout_seconds else 300.0

            while elapsed < timeout:
                await asyncio.sleep(_POLL_INTERVAL_SECONDS)
                elapsed += _POLL_INTERVAL_SECONDS

                status_response = await client.get(
                    f"/api/v2/operations/{operation_id}",
                )
                status_response.raise_for_status()
                op_data = status_response.json()
                state: str = op_data.get("state", "unknown")

                log.debug("caldera_poll_status", state=state, elapsed=elapsed)

                if state in _TERMINAL_STATES:
                    if state == "failed":
                        log.error("caldera_operation_failed", operation=op_data)
                        raise RuntimeError(
                            f"Caldera operation {operation_id} failed."
                        )
                    log.info("caldera_operation_complete", state=state)
                    return

            log.error("caldera_operation_timeout", elapsed=elapsed, timeout=timeout)
            raise asyncio.TimeoutError(
                f"Caldera operation {operation_id} did not complete within "
                f"{timeout} seconds."
            )

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []

        if not self.caldera_url:
            errors.append("Caldera URL is not configured.")
        if not self.api_key:
            errors.append("Caldera API key is not configured.")
        if not step.command:
            errors.append(
                "Step command must contain a Caldera ability_id."
            )

        return errors
