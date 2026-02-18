"""OpenAI computer-use agent (secondary agent)."""

from __future__ import annotations

import asyncio
import base64

import structlog
from openai import OpenAI

from edr_bench.agents.base import ComputerUseAgent
from edr_bench.agents.vnc_client import VNCClient
from edr_bench.config.settings import Settings

logger = structlog.get_logger()

SYSTEM_PROMPT = (
    "You are an automated security testing agent operating inside a sandboxed Linux desktop. "
    "Execute the requested actions precisely. "
    "Take screenshots to verify your actions succeeded before proceeding."
)


class OpenAIComputerAgent(ComputerUseAgent):
    """OpenAI Responses API computer-use-preview agent."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.client = OpenAI(api_key=settings.agent.openai_api_key)
        self.model = settings.agent.openai_model
        self.vnc = VNCClient(
            host="172.28.1.10",
            port=settings.vnc.port,
            password=settings.vnc.password,
        )

    async def take_screenshot(self) -> bytes:
        return await self.vnc.screenshot()

    async def execute_task(self, prompt: str, timeout: float = 120.0) -> str:
        """Execute a task via the OpenAI computer-use agent loop."""
        logger.info("openai_agent_start", prompt=prompt[:100])

        async with self.vnc.session():
            screenshot = await self.take_screenshot()
            screenshot_b64 = base64.standard_b64encode(screenshot).decode()

            tools = [
                {
                    "type": "computer_use_preview",
                    "display_width": 1920,
                    "display_height": 1080,
                    "environment": "linux",
                }
            ]

            input_content = [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/png;base64,{screenshot_b64}",
                    },
                },
            ]

            actions_taken: list[str] = []
            previous_response_id = None

            for step in range(self.max_steps):
                kwargs = {
                    "model": self.model,
                    "tools": tools,
                    "instructions": SYSTEM_PROMPT,
                    "input": input_content,
                    "truncation": "auto",
                }
                if previous_response_id:
                    kwargs["previous_response_id"] = previous_response_id

                response = await asyncio.to_thread(
                    self.client.responses.create, **kwargs
                )
                previous_response_id = response.id

                # Find computer_call items in output
                computer_calls = [
                    item for item in response.output
                    if item.type == "computer_call"
                ]

                if not computer_calls:
                    text_items = [
                        item for item in response.output
                        if item.type == "message"
                    ]
                    summary = ""
                    for item in text_items:
                        for content in item.content:
                            if hasattr(content, "text"):
                                summary += content.text
                    logger.info("openai_agent_done", steps=step + 1)
                    return summary or "Done"

                for call in computer_calls:
                    action_type = call.action.type
                    actions_taken.append(action_type)
                    logger.info("agent_action", step=step, action=action_type)

                    await self._execute_action(call.action)
                    await asyncio.sleep(0.3)

                    screenshot = await self.take_screenshot()
                    screenshot_b64 = base64.standard_b64encode(screenshot).decode()

                    input_content = [
                        {
                            "type": "computer_call_output",
                            "call_id": call.call_id,
                            "output": {
                                "type": "computer_screenshot",
                                "image_url": f"data:image/png;base64,{screenshot_b64}",
                            },
                        }
                    ]

            logger.warning("openai_agent_max_steps", max_steps=self.max_steps)
            return f"Reached max steps ({self.max_steps})"

    async def _execute_action(self, action) -> None:
        """Execute a computer action from OpenAI response."""
        action_type = action.type

        if action_type == "click":
            await self.vnc.mouse_click(action.x, action.y)
        elif action_type == "double_click":
            await self.vnc.mouse_double_click(action.x, action.y)
        elif action_type == "type":
            await self.vnc.type_text(action.text)
        elif action_type == "key":
            await self.vnc.key_press(action.key)
        elif action_type == "scroll":
            clicks = action.scroll_y if hasattr(action, "scroll_y") else -3
            await self.vnc.scroll(action.x, action.y, clicks)
        elif action_type == "drag":
            path = action.path
            if len(path) >= 2:
                await self.vnc.mouse_drag(
                    path[0]["x"], path[0]["y"],
                    path[-1]["x"], path[-1]["y"],
                )
        elif action_type == "move":
            await self.vnc.mouse_move(action.x, action.y)
        elif action_type == "screenshot":
            pass  # Will take screenshot after
