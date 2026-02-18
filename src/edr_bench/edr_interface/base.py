"""Abstract base class for EDR listeners."""
from __future__ import annotations

import abc

from edr_bench.models.finding import Finding


class EDRListener(abc.ABC):
    """Abstract interface for receiving findings from an EDR product."""

    @abc.abstractmethod
    async def start(self) -> None:
        """Begin listening for EDR findings."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Stop listening and release resources."""

    @abc.abstractmethod
    async def get_findings(self) -> list[Finding]:
        """Return all findings collected since the last call to *start*."""
