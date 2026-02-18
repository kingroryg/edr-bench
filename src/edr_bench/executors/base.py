"""Abstract base for attack executors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from edr_bench.config.settings import Settings
from edr_bench.models.scenario import Scenario, SimulationStep


class AttackExecutor(ABC):
    """Base class for all attack executors."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @abstractmethod
    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        """Execute a single simulation step."""

    @abstractmethod
    async def validate(self, step: SimulationStep) -> list[str]:
        """Validate that a step can be executed. Returns list of error messages."""
