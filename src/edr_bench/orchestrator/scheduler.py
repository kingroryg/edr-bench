"""Scenario scheduling and ordering."""

from __future__ import annotations

from collections import defaultdict

import structlog

from edr_bench.models.enums import Platform, Role
from edr_bench.models.scenario import Scenario

logger = structlog.get_logger()


class ScenarioScheduler:
    """Groups and orders scenarios for efficient execution."""

    def group_by_platform(self, scenarios: list[Scenario]) -> dict[Platform, list[Scenario]]:
        """Group scenarios by target platform."""
        groups: dict[Platform, list[Scenario]] = defaultdict(list)
        for scenario in scenarios:
            groups[scenario.platform].append(scenario)
        return dict(groups)

    def order_scenarios(self, scenarios: list[Scenario]) -> list[Scenario]:
        """Order scenarios: CLI-only first (parallelizable), then UI scenarios (sequential)."""
        cli_scenarios = [s for s in scenarios if s.is_cli_scenario]
        ui_scenarios = [s for s in scenarios if s.is_ui_scenario]
        mixed = [s for s in scenarios if not s.is_cli_scenario and not s.is_ui_scenario]
        return cli_scenarios + mixed + ui_scenarios

    def get_execution_plan(
        self, scenarios: list[Scenario], platform_filter: Platform | None = None
    ) -> list[Scenario]:
        """Build an ordered execution plan, optionally filtered by platform."""
        filtered = scenarios
        if platform_filter:
            filtered = [s for s in scenarios if s.platform == platform_filter]

        if not filtered:
            logger.warning("no_scenarios_matched", platform=platform_filter)
            return []

        ordered = self.order_scenarios(filtered)
        logger.info(
            "execution_plan_built",
            total=len(ordered),
            cli_count=sum(1 for s in ordered if s.is_cli_scenario),
            ui_count=sum(1 for s in ordered if s.is_ui_scenario),
        )
        return ordered

    def get_parallel_batches(self, scenarios: list[Scenario]) -> list[list[Scenario]]:
        """Split CLI scenarios into parallel batches and UI scenarios into sequential list."""
        batches: list[list[Scenario]] = []
        cli_batch = [s for s in scenarios if s.is_cli_scenario]
        if cli_batch:
            batches.append(cli_batch)
        for s in scenarios:
            if not s.is_cli_scenario:
                batches.append([s])
        return batches
