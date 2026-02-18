"""Integration tests for Docker lifecycle management.

These tests need a working Docker daemon to run.
"""

from __future__ import annotations

import pytest

from edr_bench.config.settings import Settings
from edr_bench.orchestrator.lifecycle import DockerLifecycleManager


@pytest.mark.integration
class TestDockerLifecycle:
    @pytest.fixture
    def manager(self) -> DockerLifecycleManager:
        settings = Settings()
        return DockerLifecycleManager(settings)

    async def test_lifecycle_manager_creates(self, manager: DockerLifecycleManager):
        """Just check the manager can be set up without crashing."""
        assert manager.client is not None

    async def test_start_and_stop_services(self, manager: DockerLifecycleManager):
        """Bring up and tear down services for the linux profile.

        This is a slow test that actually starts Docker containers.
        Only run when you have Docker available.
        """
        try:
            await manager.start_services("linux")
            # Give the containers a moment to stabilize
            import asyncio
            await asyncio.sleep(5)
            assert await manager.client.is_container_running("edr-bench-victim-linux-1")
        finally:
            await manager.stop_services("linux")
