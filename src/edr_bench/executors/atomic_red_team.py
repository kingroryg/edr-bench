"""Atomic Red Team executor for running ATT&CK-based atomic tests."""

from __future__ import annotations

import asyncio
import re

import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models import Scenario, SimulationStep
from edr_bench.utils.docker_client import DockerClientWrapper

logger = structlog.get_logger(__name__)

_ATOMIC_TEST_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?-\d+$")


class AtomicRedTeamExecutor(AttackExecutor):
    """Wraps Invoke-AtomicTest PowerShell commands and executes them inside a
    victim Docker container via ``pwsh``."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._docker = DockerClientWrapper(settings.docker)

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        container_name = f"edr-bench-victim-{scenario.platform.value}-1"

        if step.atomic_test_id is not None:
            command = (
                f'pwsh -Command "Invoke-AtomicTest {step.atomic_test_id} '
                f'-Confirm:\\$false"'
            )
        else:
            command = step.command

        log = logger.bind(
            container=container_name,
            atomic_test_id=step.atomic_test_id,
            step_order=step.order,
        )
        log.info("executing_atomic_red_team_step", command=command)

        try:
            exit_code, output = await self._docker.exec_in_container(
                container_name=container_name,
                command=command,
                timeout=step.timeout_seconds,
            )
        except asyncio.TimeoutError:
            log.error(
                "atomic_red_team_timeout",
                timeout_seconds=step.timeout_seconds,
            )
            raise

        if exit_code != 0:
            log.error(
                "atomic_red_team_nonzero_exit",
                exit_code=exit_code,
                output=output,
            )
            raise RuntimeError(
                f"Atomic Red Team test exited with code {exit_code}: {output}"
            )

        log.info("atomic_red_team_step_complete", exit_code=exit_code)

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []

        if step.atomic_test_id is not None:
            if not _ATOMIC_TEST_ID_PATTERN.match(step.atomic_test_id):
                errors.append(
                    f"Invalid atomic_test_id format: '{step.atomic_test_id}'. "
                    f"Expected pattern like T1059.001-1 or T1059-1."
                )
        elif not step.command:
            errors.append(
                "Step must have either a valid atomic_test_id or a non-empty command."
            )

        return errors
