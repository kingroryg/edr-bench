"""Anthropic Claude computer-use agent (primary agent)."""

from __future__ import annotations

import asyncio
import base64

import structlog
from anthropic import Anthropic

from edr_bench.agents.base import ComputerUseAgent
from edr_bench.agents.vnc_client import VNCClient
from edr_bench.config.settings import Settings

logger = structlog.get_logger()

COMPUTER_TOOL = {
    "type": "computer_20250124",
    "name": "computer",
    "display_width_px": 1920,
    "display_height_px": 1080,
    "display_number": 1,
}

SYSTEM_PROMPT = (
    "You are an automated security testing agent operating inside a sandboxed Linux desktop. "
    "Execute the requested actions precisely using the computer tool. "
    "Take screenshots to verify your actions succeeded before proceeding to the next step."
)


class AnthropicComputerAgent(ComputerUseAgent):
    """Claude computer_20250124 tool agent for UI-based attack simulation."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.client = Anthropic(api_key=settings.agent.anthropic_api_key)
        self.model = settings.agent.anthropic_model
        self.vnc = VNCClient(
            host=settings.vnc.host,
            port=settings.vnc.port,
            password=settings.vnc.password,
            container_name=settings.vnc.container_name,
        )

    async def take_screenshot(self) -> bytes:
        return await self.vnc.screenshot()

    async def execute_task(self, prompt: str, timeout: float = 120.0) -> str:
        """Execute a task via the Claude computer-use agent loop."""
        logger.info("anthropic_agent_start", prompt=prompt[:100])

        async with self.vnc.session():
            screenshot = await self.take_screenshot()
            screenshot_b64 = base64.standard_b64encode(screenshot).decode()

            messages = [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": screenshot_b64,
                            },
                        },
                    ],
                }
            ]

            actions_taken: list[str] = []

            for step in range(self.max_steps):
                response = await asyncio.to_thread(
                    self.client.beta.messages.create,
                    model=self.model,
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    tools=[COMPUTER_TOOL],
                    messages=messages,
                    betas=["computer-use-2025-01-24"],
                )

                # Process response content blocks
                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                tool_use_blocks = [b for b in assistant_content if b.type == "tool_use"]

                if not tool_use_blocks:
                    # Agent is done -- extract text response
                    text_blocks = [b for b in assistant_content if b.type == "text"]
                    summary = " ".join(b.text for b in text_blocks) if text_blocks else "Done"
                    logger.info("anthropic_agent_done", steps=step + 1)
                    return summary

                # Execute each tool use
                tool_results = []
                for tool_block in tool_use_blocks:
                    action = tool_block.input.get("action", "unknown")
                    actions_taken.append(action)
                    logger.info("agent_action", step=step, action=action)

                    result = await self._execute_computer_action(tool_block.input)
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_block.id,
                            "content": result,
                        }
                    )

                messages.append({"role": "user", "content": tool_results})

            logger.warning("anthropic_agent_max_steps", max_steps=self.max_steps)
            return f"Reached max steps ({self.max_steps}). Actions: {', '.join(actions_taken)}"

    async def _execute_computer_action(self, action_input: dict) -> list[dict]:
        """Execute a computer tool action and return screenshot result."""
        action = action_input.get("action", "")
        coordinate = action_input.get("coordinate")
        text = action_input.get("text")

        if action == "screenshot":
            pass  # Just take screenshot below
        elif action == "mouse_move" and coordinate:
            await self.vnc.mouse_move(coordinate[0], coordinate[1])
        elif action == "left_click" and coordinate:
            await self.vnc.mouse_click(coordinate[0], coordinate[1])
        elif action == "right_click" and coordinate:
            await self.vnc.mouse_click(coordinate[0], coordinate[1], button=3)
        elif action == "double_click" and coordinate:
            await self.vnc.mouse_double_click(coordinate[0], coordinate[1])
        elif action == "left_click_drag":
            start = action_input.get("start_coordinate", [0, 0])
            await self.vnc.mouse_drag(start[0], start[1], coordinate[0], coordinate[1])
        elif action == "type" and text:
            await self.vnc.type_text(text)
        elif action == "key" and text:
            await self.vnc.key_press(text)
        elif action == "scroll" and coordinate:
            direction = action_input.get("direction", "down")
            amount = action_input.get("amount", 3)
            clicks = amount if direction == "up" else -amount
            await self.vnc.scroll(coordinate[0], coordinate[1], clicks)
        elif action == "wait":
            # Claude sometimes requests explicit wait for UI to update
            duration = action_input.get("duration", 3)
            await asyncio.sleep(min(duration, 10))

        # Small delay for UI to update
        await asyncio.sleep(0.3)

        screenshot = await self.take_screenshot()
        screenshot_b64 = base64.standard_b64encode(screenshot).decode()

        return [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": screenshot_b64,
                },
            }
        ]
