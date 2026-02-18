"""UI executor -- dispatches actions to computer-use agents."""

from __future__ import annotations

import structlog

from edr_bench.agents.action_translator import ActionTranslator
from edr_bench.agents.base import ComputerUseAgent
from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models.scenario import Scenario, SimulationStep

logger = structlog.get_logger()


class UIExecutor(AttackExecutor):
    """Execute UI-based attack steps via computer-use agent."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._agent: ComputerUseAgent | None = None
        self.translator = ActionTranslator()

    def _get_agent(self) -> ComputerUseAgent:
        if self._agent:
            return self._agent

        if self.settings.agent.anthropic_api_key:
            from edr_bench.agents.anthropic_agent import AnthropicComputerAgent

            self._agent = AnthropicComputerAgent(self.settings)
        elif self.settings.agent.openai_api_key:
            from edr_bench.agents.openai_agent import OpenAIComputerAgent

            self._agent = OpenAIComputerAgent(self.settings)
        else:
            raise RuntimeError("No AI agent API key configured for UI execution")
        return self._agent

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        if not step.ui_instructions:
            raise ValueError(f"UI step {step.order} has no ui_instructions")

        logger.info(
            "ui_exec",
            scenario=scenario.id,
            step=step.order,
            instructions=step.ui_instructions[:100],
        )

        if self.settings.dry_run:
            logger.info("dry_run_skip", step=step.order)
            return

        prompt = self.translator.translate(step, scenario)
        agent = self._get_agent()
        await agent.execute_task(prompt, timeout=step.timeout_seconds)

        logger.info("ui_exec_complete", scenario=scenario.id, step=step.order)

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []
        if not step.ui_instructions:
            errors.append(f"Step {step.order}: UI step requires ui_instructions")
        if not self.settings.agent.anthropic_api_key and not self.settings.agent.openai_api_key:
            errors.append(f"Step {step.order}: No AI agent API key configured")
        return errors
