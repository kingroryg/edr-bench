"""Terraform executor for provisioning infrastructure against LocalStack."""

from __future__ import annotations

import asyncio
import uuid

import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models import Scenario, SimulationStep
from edr_bench.utils.docker_client import DockerClientWrapper

logger = structlog.get_logger(__name__)

_CONTROLLER_CONTAINER = "edr-bench-controller-1"
_TF_WORK_DIR_BASE = "/tmp/terraform"


class TerraformExecutor(AttackExecutor):
    """Runs Terraform configurations against a LocalStack instance by writing
    HCL to the controller container and executing ``terraform init`` followed
    by ``terraform apply``."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._docker = DockerClientWrapper(settings.docker)
        self._aws_region: str = getattr(
            settings.localstack, "region", "us-east-1"
        )

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        run_id = uuid.uuid4().hex[:8]
        tf_work_dir = f"{_TF_WORK_DIR_BASE}/{scenario.id}-{step.order}-{run_id}"
        tf_file = f"{tf_work_dir}/main.tf"

        log = logger.bind(
            step_order=step.order,
            scenario_id=scenario.id,
            tf_work_dir=tf_work_dir,
        )
        log.info("terraform_executor_starting")

        env_vars = (
            f"AWS_ACCESS_KEY_ID=test "
            f"AWS_SECRET_ACCESS_KEY=test "
            f"AWS_DEFAULT_REGION={self._aws_region}"
        )

        # Step 1: Create the working directory.
        await self._exec(
            f"mkdir -p {tf_work_dir}",
            step.timeout_seconds,
            log,
            description="create terraform work directory",
        )

        # Step 2: Write the Terraform configuration from step.command.
        import base64

        encoded_config = base64.b64encode(step.command.encode()).decode()
        write_command = (
            f"sh -c 'echo {encoded_config} | base64 -d > {tf_file}'"
        )
        await self._exec(
            write_command,
            step.timeout_seconds,
            log,
            description="write terraform config",
        )

        # Step 3: Run terraform init.
        init_command = (
            f"sh -c 'cd {tf_work_dir} && {env_vars} terraform init -no-color'"
        )
        await self._exec(
            init_command,
            step.timeout_seconds,
            log,
            description="terraform init",
        )

        # Step 4: Run terraform apply.
        apply_command = (
            f"sh -c 'cd {tf_work_dir} && {env_vars} "
            f"terraform apply -auto-approve -no-color'"
        )
        await self._exec(
            apply_command,
            step.timeout_seconds,
            log,
            description="terraform apply",
        )

        log.info("terraform_executor_complete")

    async def _exec(
        self,
        command: str,
        timeout: int | None,
        log: structlog.stdlib.BoundLogger,
        *,
        description: str,
    ) -> tuple[int, str]:
        """Execute a command inside the controller container."""
        log.debug("terraform_exec", description=description, command=command)

        try:
            exit_code, output = await self._docker.exec_in_container(
                container_name=_CONTROLLER_CONTAINER,
                command=command,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            log.error("terraform_exec_timeout", description=description)
            raise

        if exit_code != 0:
            log.error(
                "terraform_exec_failed",
                description=description,
                exit_code=exit_code,
                output=output,
            )
            raise RuntimeError(
                f"Terraform step '{description}' failed with exit code "
                f"{exit_code}: {output}"
            )

        return exit_code, output

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []

        if not step.command:
            errors.append(
                "Step command must contain the Terraform HCL configuration."
            )

        return errors
