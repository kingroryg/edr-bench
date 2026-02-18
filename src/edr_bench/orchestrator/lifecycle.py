"""Docker container lifecycle management."""

from __future__ import annotations

import asyncio

import structlog

from edr_bench.config.settings import Settings
from edr_bench.utils.docker_client import DockerClientWrapper

logger = structlog.get_logger()


class DockerLifecycleManager:
    """Manages Docker Compose service lifecycle for benchmark runs."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = DockerClientWrapper(settings.docker.host)
        self._running_containers: list[str] = []

    async def start_services(self, profile: str) -> None:
        """Start Docker Compose services for the given profile."""
        logger.info("starting_services", profile=profile)
        cmd = [
            "docker", "compose",
            "-f", "docker/docker-compose.yml",
            "--profile", profile,
            "up", "-d", "--wait",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"Failed to start services: {stderr.decode()}"
            )
        logger.info("services_started", profile=profile)

    async def stop_services(self, profile: str) -> None:
        """Stop Docker Compose services for the given profile."""
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

    async def wait_for_health(self, container_name: str, timeout: float = 60.0) -> bool:
        """Wait for a container to become healthy."""
        logger.info("waiting_for_health", container=container_name)
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                container = await asyncio.to_thread(
                    self.client.docker.containers.get, container_name
                )
                health = container.attrs.get("State", {}).get("Health", {})
                status = health.get("Status", "none")
                if status == "healthy":
                    logger.info("container_healthy", container=container_name)
                    return True
                if container.status == "running" and status == "none":
                    # No healthcheck defined, consider running as healthy
                    return True
            except Exception:
                pass
            await asyncio.sleep(2.0)
        logger.warning("health_timeout", container=container_name)
        return False

    async def get_victim_container_id(self, platform: str) -> str:
        """Get the container ID for the victim container of a given platform."""
        name = f"edr-bench-victim-{platform}-1"
        container = await asyncio.to_thread(
            self.client.docker.containers.get, name
        )
        return container.id
