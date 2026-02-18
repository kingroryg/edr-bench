"""VNC client for screenshot capture and action execution."""

from __future__ import annotations

import asyncio
import io
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from PIL import Image

logger = structlog.get_logger()


class VNCClient:
    """Async VNC client wrapping asyncvnc for screenshot and input."""

    def __init__(self, host: str, port: int = 5900, password: str = "") -> None:
        self.host = host
        self.port = port
        self.password = password
        self._connection = None

    async def connect(self) -> None:
        """Establish VNC connection."""
        import asyncvnc

        self._connection = await asyncvnc.connect(
            self.host, port=self.port, password=self.password
        )
        logger.info("vnc_connected", host=self.host, port=self.port)

    async def disconnect(self) -> None:
        """Close VNC connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("vnc_disconnected")

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[VNCClient, None]:
        """Context manager for VNC session."""
        await self.connect()
        try:
            yield self
        finally:
            await self.disconnect()

    async def screenshot(self) -> bytes:
        """Capture screenshot as PNG bytes."""
        if not self._connection:
            raise RuntimeError("VNC not connected")

        pixels = self._connection.screenshot()
        image = Image.fromarray(pixels)
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return buf.getvalue()

    async def mouse_move(self, x: int, y: int) -> None:
        """Move mouse to coordinates."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        self._connection.mouse.move(x, y)

    async def mouse_click(self, x: int, y: int, button: int = 1) -> None:
        """Click at coordinates."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        self._connection.mouse.move(x, y)
        self._connection.mouse.click(button)

    async def mouse_double_click(self, x: int, y: int) -> None:
        """Double-click at coordinates."""
        await self.mouse_click(x, y)
        await asyncio.sleep(0.05)
        await self.mouse_click(x, y)

    async def key_press(self, key: str) -> None:
        """Press a key."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        self._connection.keyboard.press(key)

    async def type_text(self, text: str, delay: float = 0.02) -> None:
        """Type text character by character."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        for char in text:
            self._connection.keyboard.press(char)
            await asyncio.sleep(delay)

    async def mouse_drag(self, x1: int, y1: int, x2: int, y2: int) -> None:
        """Drag from (x1,y1) to (x2,y2)."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        self._connection.mouse.move(x1, y1)
        self._connection.mouse.press(1)
        self._connection.mouse.move(x2, y2)
        self._connection.mouse.release(1)

    async def scroll(self, x: int, y: int, clicks: int) -> None:
        """Scroll at position. Positive clicks = scroll up."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        self._connection.mouse.move(x, y)
        button = 4 if clicks > 0 else 5
        for _ in range(abs(clicks)):
            self._connection.mouse.click(button)
