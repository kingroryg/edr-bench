"""Translate SimulationSteps into natural language prompts for computer-use agents."""

from __future__ import annotations

from edr_bench.models.scenario import Scenario, SimulationStep


class ActionTranslator:
    """Converts simulation steps into natural language prompts for AI agents."""

    def translate(self, step: SimulationStep, scenario: Scenario) -> str:
        """Convert a simulation step into a natural language prompt."""
        parts = [
            f"You are executing step {step.order} of security test scenario '{scenario.name}'.",
            "",
            f"Task: {step.description}",
        ]

        if step.ui_instructions:
            parts.append("")
            parts.append(f"Instructions: {step.ui_instructions}")

        if step.expected_artifact:
            parts.append("")
            parts.append(
                f"After completing this action, verify that the following artifact exists "
                f"or was created: {step.expected_artifact}"
            )

        parts.append("")
        parts.append(
            "Execute these actions carefully and precisely. "
            "Take a screenshot after each significant action to verify success. "
            "If an action fails, try an alternative approach."
        )

        return "\n".join(parts)

    def translate_multi_step(self, steps: list[SimulationStep], scenario: Scenario) -> str:
        """Translate multiple steps into a single compound prompt."""
        parts = [
            f"You are executing security test scenario '{scenario.name}'.",
            f"Description: {scenario.description}",
            "",
            "Execute the following steps in order:",
        ]

        for step in steps:
            parts.append(f"")
            parts.append(f"Step {step.order}: {step.description}")
            if step.ui_instructions:
                parts.append(f"  Instructions: {step.ui_instructions}")
            if step.expected_artifact:
                parts.append(f"  Verify: {step.expected_artifact}")

        parts.append("")
        parts.append(
            "Execute each step carefully. Take screenshots to verify success "
            "before moving to the next step."
        )

        return "\n".join(parts)
