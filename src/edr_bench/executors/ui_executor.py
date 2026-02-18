"""UI executor -- dispatches actions to computer-use agents."""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

from edr_bench.agents.action_translator import ActionTranslator
from edr_bench.agents.base import ComputerUseAgent
from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models.scenario import Scenario, SimulationStep

logger = structlog.get_logger()

_FAILURE_INDICATORS = (
    "reached max steps",
    "unable to",
    "could not",
    "failed to",
    "error:",
    "timed out",
    "i cannot",
    "not possible",
)

_MAX_RETRIES = 2
_RETRY_DELAY = 5.0


class UIExecutor(AttackExecutor):
    """Execute UI-based attack steps via computer-use agent."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._agent: ComputerUseAgent | None = None
        self.translator = ActionTranslator()
        self._screenshot_dir = Path(
            settings.report_output_dir / "screenshots"
        )

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

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            if attempt > 0:
                logger.warning(
                    "ui_exec_retry",
                    scenario=scenario.id,
                    step=step.order,
                    attempt=attempt + 1,
                )
                await asyncio.sleep(_RETRY_DELAY)

            try:
                summary = await agent.execute_task(prompt, timeout=step.timeout_seconds)

                # Check for failure indicators in agent summary
                if summary and any(
                    indicator in summary.lower() for indicator in _FAILURE_INDICATORS
                ):
                    raise RuntimeError(
                        f"UI agent reported failure for step {step.order}: "
                        f"{summary[:200]}"
                    )

                # Save screenshot on success
                await self._save_screenshot(agent, scenario.id, step.order)

                logger.info("ui_exec_complete", scenario=scenario.id, step=step.order)
                return

            except Exception as e:
                last_error = e
                logger.warning(
                    "ui_exec_attempt_failed",
                    scenario=scenario.id,
                    step=step.order,
                    attempt=attempt + 1,
                    error=str(e),
                )

        # All retries exhausted
        raise RuntimeError(
            f"UI step {step.order} failed after {_MAX_RETRIES + 1} attempts: {last_error}"
        )

    async def _save_screenshot(
        self, agent: ComputerUseAgent, scenario_id: str, step_order: int
    ) -> None:
        """Save a screenshot after a UI step."""
        try:
            screenshot_bytes = await agent.take_screenshot()
            out_dir = self._screenshot_dir / scenario_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"step_{step_order}.png"
            out_path.write_bytes(screenshot_bytes)
            logger.info(
                "screenshot_saved",
                scenario=scenario_id,
                step=step_order,
                path=str(out_path),
            )
        except Exception:
            logger.warning(
                "screenshot_save_failed",
                scenario=scenario_id,
                step=step_order,
            )

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []
        if not step.ui_instructions:
            errors.append(f"Step {step.order}: UI step requires ui_instructions")
        if not self.settings.agent.anthropic_api_key and not self.settings.agent.openai_api_key:
            errors.append(f"Step {step.order}: No AI agent API key configured")
        return errors
