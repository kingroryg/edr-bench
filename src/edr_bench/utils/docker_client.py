"""Docker client wrapper providing async access to the docker-py SDK."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any

import docker
import docker.errors
import docker.models.containers
import structlog

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ExecResult:
    """Result of executing a command inside a Docker container.

    Attributes:
        exit_code: The process exit code.
        stdout: Standard output as a decoded string.
        stderr: Standard error as a decoded string.
    """

    exit_code: int
    stdout: str
    stderr: str


class DockerClientWrapper:
    """Async-friendly wrapper around the docker-py SDK.

    All blocking docker SDK calls are dispatched to a thread via
    ``asyncio.to_thread`` so they can be safely awaited from async code.

    Args:
        host: Docker daemon URL. If ``None``, uses the default socket
            (``unix:///var/run/docker.sock`` on Linux/macOS).
    """

    def __init__(self, host: str | None = None) -> None:
        kwargs: dict[str, Any] = {}
        if host is not None:
            kwargs["base_url"] = host
        self._client: docker.DockerClient = docker.DockerClient(**kwargs)
        logger.info("docker_client_initialized", host=host or "default")

    # ------------------------------------------------------------------
    # Container helpers
    # ------------------------------------------------------------------

    def get_container(
        self, name: str
    ) -> docker.models.containers.Container:
        """Get a container by name or ID (synchronous).

        Args:
            name: The container name or ID.

        Returns:
            The Docker container object.

        Raises:
            docker.errors.NotFound: If no container with that name exists.
        """
        return self._client.containers.get(name)

    async def get_container_async(
        self, name: str
    ) -> docker.models.containers.Container:
        """Get a container by name or ID (async).

        Args:
            name: The container name or ID.

        Returns:
            The Docker container object.
        """
        return await asyncio.to_thread(self.get_container, name)

    def get_container_ip(self, name: str) -> str:
        """Return the IPv4 address of a container on its first network.

        Args:
            name: The container name or ID.

        Returns:
            The container's IP address as a string.

        Raises:
            docker.errors.NotFound: If the container is not found.
            RuntimeError: If the container has no network settings or IP.
        """
        container = self.get_container(name)
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        if not networks:
            raise RuntimeError(
                f"Container {name!r} has no network settings."
            )
        # Return the IP from the first available network
        first_network = next(iter(networks.values()))
        ip_address: str | None = first_network.get("IPAddress")
        if not ip_address:
            raise RuntimeError(
                f"Container {name!r} has no IP address assigned."
            )
        return ip_address

    async def get_container_ip_async(self, name: str) -> str:
        """Return the IPv4 address of a container (async).

        Args:
            name: The container name or ID.

        Returns:
            The container's IP address as a string.
        """
        return await asyncio.to_thread(self.get_container_ip, name)

    def is_container_running(self, name: str) -> bool:
        """Check whether a container is in the 'running' state.

        Args:
            name: The container name or ID.

        Returns:
            True if the container exists and is running, False otherwise.
        """
        try:
            container = self.get_container(name)
            return container.status == "running"
        except docker.errors.NotFound:
            return False

    async def is_container_running_async(self, name: str) -> bool:
        """Check whether a container is in the 'running' state (async).

        Args:
            name: The container name or ID.

        Returns:
            True if the container exists and is running, False otherwise.
        """
        return await asyncio.to_thread(self.is_container_running, name)

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    async def exec_in_container(
        self,
        container_name: str,
        command: str | list[str],
        timeout: float = 30.0,
        workdir: str | None = None,
        environment: dict[str, str] | None = None,
        user: str | None = None,
    ) -> ExecResult:
        """Execute a command inside a running container.

        The blocking docker SDK call is run in a thread. An
        ``asyncio.timeout`` guard is applied to prevent indefinite hangs.

        Args:
            container_name: Name or ID of the target container.
            command: The command to execute (string or list of strings).
            timeout: Maximum seconds to wait for the command to complete.
            workdir: Optional working directory inside the container.
            environment: Optional environment variables for the command.
            user: Optional user to run the command as.

        Returns:
            An ExecResult with exit_code, stdout, and stderr.

        Raises:
            asyncio.TimeoutError: If the command exceeds the timeout.
            docker.errors.NotFound: If the container is not found.
            docker.errors.APIError: On Docker API errors.
        """

        def _exec() -> ExecResult:
            container = self.get_container(container_name)
            exec_kwargs: dict[str, Any] = {
                "cmd": command,
                "stdout": True,
                "stderr": True,
                "demux": True,
            }
            if workdir is not None:
                exec_kwargs["workdir"] = workdir
            if environment is not None:
                exec_kwargs["environment"] = environment
            if user is not None:
                exec_kwargs["user"] = user

            exit_code, (stdout_bytes, stderr_bytes) = container.exec_run(**exec_kwargs)
            return ExecResult(
                exit_code=exit_code,
                stdout=(stdout_bytes or b"").decode("utf-8", errors="replace"),
                stderr=(stderr_bytes or b"").decode("utf-8", errors="replace"),
            )

        async with asyncio.timeout(timeout):
            result = await asyncio.to_thread(_exec)

        logger.debug(
            "container_exec_completed",
            container=container_name,
            command=command,
            exit_code=result.exit_code,
        )
        return result

    # ------------------------------------------------------------------
    # Event streaming
    # ------------------------------------------------------------------

    async def stream_events(
        self,
        filters: dict[str, Any] | None = None,
        decode: bool = True,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Stream Docker daemon events as an async generator.

        Args:
            filters: Optional dictionary of event filters (e.g.
                ``{"container": ["my-ctr"], "event": ["start", "die"]}``).
            decode: Whether to decode events into dicts (default True).

        Yields:
            Individual Docker event dictionaries.
        """
        kwargs: dict[str, Any] = {"decode": decode}
        if filters is not None:
            kwargs["filters"] = filters

        # docker-py events() returns a blocking generator; we pull from it
        # in a thread one event at a time.
        event_stream = self._client.events(**kwargs)

        def _next_event() -> dict[str, Any] | None:
            try:
                return next(event_stream)  # type: ignore[arg-type]
            except StopIteration:
                return None

        try:
            while True:
                event = await asyncio.to_thread(_next_event)
                if event is None:
                    break
                yield event
        finally:
            event_stream.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying Docker client connection."""
        self._client.close()
        logger.info("docker_client_closed")

    async def close_async(self) -> None:
        """Close the underlying Docker client connection (async)."""
        await asyncio.to_thread(self.close)

    async def __aenter__(self) -> DockerClientWrapper:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close_async()
