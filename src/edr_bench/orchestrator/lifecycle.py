"""Docker container lifecycle management."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import structlog

from edr_bench.config.settings import Settings
from edr_bench.utils.docker_client import DockerClientWrapper
from edr_bench.utils.retry import retry_async

logger = structlog.get_logger()


def _running_inside_docker() -> bool:
    """Return True when executing inside a Docker container."""
    return Path("/.dockerenv").exists() or os.environ.get("DOCKER_CONTAINER") == "1"


class DockerLifecycleManager:
    """Manages Docker Compose service lifecycle for benchmark runs."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = DockerClientWrapper(settings.docker.host)
        self._running_containers: list[str] = []

    @retry_async(max_attempts=2, min_delay=5.0, max_delay=30.0, retry_on=RuntimeError)
    async def start_services(self, profile: str) -> None:
        """Start Docker Compose services for the given profile.

        When running inside a Docker container (e.g. the controller), skip
        ``docker compose up`` since services are managed externally.
        """
        if _running_inside_docker():
            logger.info("skip_start_services_inside_docker", profile=profile)
            return

        logger.info("starting_services", profile=profile)
        cmd = [
            "docker", "compose",
            "-f", "docker/docker-compose.yml",
            "--profile", profile,
            "up", "-d",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            stderr_text = stderr.decode()
            logger.warning(
                "compose_up_nonzero_exit",
                profile=profile,
                returncode=proc.returncode,
                stderr=stderr_text[-500:],
            )
            # Verify victim container comes up healthy despite non-zero exit
            victim_running = await self.wait_for_health(
                f"docker-victim-{profile}-1", timeout=90.0
            )
            if not victim_running:
                raise RuntimeError(
                    f"Failed to start services: {stderr_text}"
                )
        logger.info("services_started", profile=profile)

    async def stop_services(self, profile: str) -> None:
        """Stop Docker Compose services for the given profile.

        When running inside a Docker container, skip teardown to avoid
        self-destructing the controller.
        """
        if _running_inside_docker():
            logger.info("skip_stop_services_inside_docker", profile=profile)
            return

        logger.info("stopping_services", profile=profile)
        cmd = [
            "docker", "compose",
            "-f", "docker/docker-compose.yml",
            "--profile", profile,
            "down", "-v",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        logger.info("services_stopped", profile=profile)

    async def _is_container_healthy(self, container_name: str) -> bool:
        """Check if a container is running and healthy via docker inspect."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format",
            "{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
            container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            return False
        output = stdout.decode().strip()
        status, health = output.split(":", 1) if ":" in output else (output, "none")
        return status == "running" and health in ("healthy", "none")

    async def wait_for_health(self, container_name: str, timeout: float = 60.0) -> bool:
        """Wait for a container to become healthy."""
        logger.info("waiting_for_health", container=container_name)
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if await self._is_container_healthy(container_name):
                logger.info("container_healthy", container=container_name)
                return True
            await asyncio.sleep(2.0)
        logger.warning("health_timeout", container=container_name)
        return False

    async def get_victim_container_id(self, platform: str) -> str:
        """Get the container ID for the victim container of a given platform."""
        suffix = f"victim-{platform}-1"
        containers = await asyncio.to_thread(self.client._client.containers.list)
        for container in containers:
            if container.name.endswith(suffix):
                return container.id
        raise RuntimeError(f"No victim container found matching *{suffix}")
