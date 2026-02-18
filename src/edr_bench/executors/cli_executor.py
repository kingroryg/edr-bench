"""CLI executor -- runs shell commands via Docker exec."""

from __future__ import annotations

import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models.scenario import Scenario, SimulationStep
from edr_bench.utils.docker_client import DockerClientWrapper

logger = structlog.get_logger()


class CLIExecutor(AttackExecutor):
    """Execute CLI commands inside victim containers via docker exec."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.docker = DockerClientWrapper(settings.docker.host)

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        if not step.command:
            raise ValueError(f"CLI step {step.order} has no command")

        container_name = f"edr-bench-victim-{scenario.platform.value}-1"
        logger.info(
            "cli_exec",
            scenario=scenario.id,
            step=step.order,
            container=container_name,
            command=step.command[:100],
        )

        if self.settings.dry_run:
            logger.info("dry_run_skip", step=step.order)
            return

        result = await self.docker.exec_in_container(
            container_name,
            step.command,
            timeout=step.timeout_seconds,
        )

        if result.exit_code != 0:
            logger.warning(
                "cli_nonzero_exit",
                scenario=scenario.id,
                step=step.order,
                exit_code=result.exit_code,
                stderr=result.stderr[:500] if result.stderr else "",
            )
            if not step.allow_nonzero_exit:
                raise RuntimeError(
                    f"CLI step {step.order} exited with code {result.exit_code}: "
                    f"{(result.stderr or '')[:200]}"
                )

        logger.info(
            "cli_exec_complete",
            scenario=scenario.id,
            step=step.order,
            exit_code=result.exit_code,
        )

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []
        if not step.command:
            errors.append(f"Step {step.order}: CLI step requires a command")
        return errors
