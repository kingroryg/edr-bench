"""Abstract base for computer-use agents."""

from __future__ import annotations

from abc import ABC, abstractmethod

from edr_bench.config.settings import Settings


class ComputerUseAgent(ABC):
    """Base class for computer-use AI agents that interact with VNC desktops."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.max_steps = settings.agent.max_agent_steps

    @abstractmethod
    async def execute_task(self, prompt: str, timeout: float = 120.0) -> str:
        """Execute a task described by the prompt via computer use.

        Returns a summary of actions taken.
        """

    @abstractmethod
    async def take_screenshot(self) -> bytes:
        """Capture the current screen state as PNG bytes."""
