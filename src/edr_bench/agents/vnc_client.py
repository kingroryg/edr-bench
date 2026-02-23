"""VNC client for screenshot capture and action execution."""

from __future__ import annotations

import asyncio
import io
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from PIL import Image

logger = structlog.get_logger()

# Map key names from Claude CU / common formats to asyncvnc keysymdef names
_KEY_ALIASES: dict[str, str] = {
    "alt": "Alt",
    "ctrl": "Ctrl",
    "control": "Ctrl",
    "shift": "Shift",
    "super": "Super",
    "meta": "Super",
    "cmd": "Cmd",
    "enter": "Return",
    "return": "Return",
    "esc": "Esc",
    "escape": "Esc",
    "backspace": "Backspace",
    "delete": "Del",
    "del": "Del",
    "tab": "Tab",
    "space": "space",
    "up": "Up",
    "down": "Down",
    "left": "Left",
    "right": "Right",
    "home": "Home",
    "end": "End",
    "pageup": "Page_Up",
    "page_up": "Page_Up",
    "pagedown": "Page_Down",
    "page_down": "Page_Down",
    "insert": "Insert",
    # Multi-word modifier names that Claude CU agent sometimes sends
    "left shift": "Shift",
    "right shift": "Shift",
    "left ctrl": "Ctrl",
    "right ctrl": "Ctrl",
    "left alt": "Alt",
    "right alt": "Alt",
    "left super": "Super",
    "right super": "Super",
    "left meta": "Super",
    "right meta": "Super",
    "caps lock": "Caps_Lock",
    "num lock": "Num_Lock",
    "scroll lock": "Scroll_Lock",
    "print screen": "Print",
}

# Characters that asyncvnc can't handle as single-char keysyms.
# Map them to the correct X11 key name.
_CHAR_ALIASES: dict[str, str] = {
    "\n": "Return",
    "\r": "Return",
    "\t": "Tab",
    "\x1b": "Esc",
    "\x7f": "Backspace",
}


def _map_key_name(key: str) -> str:
    """Map a key name to an asyncvnc-compatible name."""
    # Check special characters first (\n, \t, etc.)
    if key in _CHAR_ALIASES:
        return _CHAR_ALIASES[key]
    # Check case-insensitive alias first
    lower = key.lower()
    if lower in _KEY_ALIASES:
        return _KEY_ALIASES[lower]
    # F-keys: f1-f12 -> F1-F12
    if lower.startswith("f") and lower[1:].isdigit():
        return f"F{lower[1:]}"
    # Already a valid asyncvnc key name (single char, or exact keysymdef name)
    return key


class VNCClient:
    """Async VNC client wrapping asyncvnc for screenshot and input."""

    def __init__(
        self,
        host: str,
        port: int = 5900,
        password: str = "",
        container_name: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        self._container_name = container_name
        self._connection = None
        self._ctx = None

    async def connect(self) -> None:
        """Establish VNC connection."""
        import asyncvnc

        self._ctx = asyncvnc.connect(
            self.host, port=self.port, password=self.password
        )
        self._connection = await self._ctx.__aenter__()
        logger.info("vnc_connected", host=self.host, port=self.port)

    async def disconnect(self) -> None:
        """Close VNC connection."""
        if self._ctx:
            await self._ctx.__aexit__(None, None, None)
            self._ctx = None
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
        """Capture screenshot as PNG bytes.

        Uses ImageMagick ``import`` inside the container via docker exec,
        which is more reliable than asyncvnc's screenshot() (that method
        can hang on static screens or crash on unsupported VNC encodings).
        Falls back to asyncvnc if docker exec is unavailable.
        """
        # Docker exec screenshots work even after VNC disconnect
        if self._container_name:
            return await self._screenshot_via_docker()

        if not self._connection:
            raise RuntimeError("VNC not connected")

        # Fallback: direct VNC screenshot (may hang or fail with some servers)
        pixels = await self._connection.screenshot()
        image = Image.fromarray(pixels)
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        return buf.getvalue()

    async def _screenshot_via_docker(self) -> bytes:
        """Capture screenshot using ImageMagick inside the container."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self._container_name,
            "bash", "-c", "DISPLAY=:1 import -window root png:-",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        if proc.returncode != 0:
            raise RuntimeError(f"Screenshot failed: {stderr.decode()[:200]}")
        return stdout

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
        """Press a key or key combination (e.g., 'alt+F2', 'ctrl+c').

        Handles several Claude CU agent patterns:
        - Compound combos: "alt+F2", "ctrl+shift+c"
        - Multi-word key names: "Left shift" (mapped to Shift)
        - Repeated keys with spaces: "Tab Tab Tab" (pressed sequentially)
        """
        if not self._connection:
            raise RuntimeError("VNC not connected")

        # Split compound key combos on '+' (e.g., "alt+F2" -> ["alt", "F2"])
        parts = [k.strip() for k in key.split("+")]
        mapped: list[str] = []
        for p in parts:
            m = _map_key_name(p)
            # If mapping returned unchanged AND contains spaces, it might be
            # repeated keys like "Tab Tab Tab" -- split and press sequentially.
            if m == p and " " in p:
                sub_keys = [_map_key_name(s) for s in p.split()]
                for sk in sub_keys:
                    self._connection.keyboard.press(sk)
            else:
                mapped.append(m)
        if mapped:
            self._connection.keyboard.press(*mapped)

    async def type_text(self, text: str, delay: float = 0.02) -> None:
        """Type text character by character."""
        if not self._connection:
            raise RuntimeError("VNC not connected")
        for char in text:
            # Map special characters (newline, tab, etc.) to X11 key names
            key = _CHAR_ALIASES.get(char, char)
            self._connection.keyboard.press(key)
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
