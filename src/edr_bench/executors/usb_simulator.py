"""USB device insertion simulator executor."""

from __future__ import annotations

import asyncio
import shlex
import textwrap

import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models import Scenario, SimulationStep
from edr_bench.utils.docker_client import DockerClientWrapper

logger = structlog.get_logger(__name__)

_USB_MOUNT_PATH = "/media/usb0"
_PAYLOAD_FILENAME = "payload.sh"


class USBSimulatorExecutor(AttackExecutor):
    """Simulates USB device insertion by creating a mount point inside a
    Docker container, writing a payload file, and triggering a synthetic
    udev-style notification."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._docker = DockerClientWrapper(settings.docker)

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        container_name = f"edr-bench-victim-{scenario.platform.value}-1"
        payload_content = step.command

        log = logger.bind(
            container=container_name,
            step_order=step.order,
            scenario_id=scenario.id,
        )
        log.info("usb_simulator_starting")

        # Step 1: Create the USB mount point directory inside the container.
        await self._exec(
            container_name,
            f"mkdir -p {_USB_MOUNT_PATH}",
            step.timeout_seconds,
            log,
            description="create mount point",
        )

        # Step 2: Write the payload file to the simulated USB mount.
        payload_path = f"{_USB_MOUNT_PATH}/{_PAYLOAD_FILENAME}"
        escaped_content = shlex.quote(payload_content)
        write_command = f"sh -c 'cat > {payload_path} << '\"'\"'EOFPAYLOAD'\"'\"'\n{payload_content}\nEOFPAYLOAD'"

        # Use a safer approach: base64 encode the content and decode inside the
        # container to avoid shell-escaping pitfalls.
        import base64

        encoded = base64.b64encode(payload_content.encode()).decode()
        write_command = (
            f"sh -c 'echo {encoded} | base64 -d > {payload_path} && "
            f"chmod +x {payload_path}'"
        )

        await self._exec(
            container_name,
            write_command,
            step.timeout_seconds,
            log,
            description="write payload file",
        )

        # Step 3: Simulate a udev event notification for USB insertion.
        udev_notify_command = textwrap.dedent(f"""\
            sh -c 'if command -v udevadm >/dev/null 2>&1; then
                udevadm trigger --action=add --subsystem-match=block
            else
                echo "USB device inserted at {_USB_MOUNT_PATH}" | logger -t usb-simulator 2>/dev/null || true
            fi'
        """).strip()

        await self._exec(
            container_name,
            udev_notify_command,
            step.timeout_seconds,
            log,
            description="simulate udev event",
        )

        log.info("usb_simulator_complete", payload_path=payload_path)

    async def _exec(
        self,
        container_name: str,
        command: str,
        timeout: int | None,
        log: structlog.stdlib.BoundLogger,
        *,
        description: str,
    ) -> tuple[int, str]:
        """Run a command inside the container, logging and raising on failure."""
        log.debug("usb_simulator_exec", description=description, command=command)

        try:
            exit_code, output = await self._docker.exec_in_container(
                container_name=container_name,
                command=command,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            log.error("usb_simulator_timeout", description=description)
            raise

        if exit_code != 0:
            log.error(
                "usb_simulator_exec_failed",
                description=description,
                exit_code=exit_code,
                output=output,
            )
            raise RuntimeError(
                f"USB simulator step '{description}' failed with exit code "
                f"{exit_code}: {output}"
            )

        return exit_code, output

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []

        if not step.command:
            errors.append(
                "Step command must contain the payload content/script for USB simulation."
            )

        return errors
