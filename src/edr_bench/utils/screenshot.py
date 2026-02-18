"""Screenshot utilities: save and encode screenshots using Pillow."""
from __future__ import annotations

import base64
import io
from pathlib import Path

from PIL import Image

import structlog

logger = structlog.get_logger(__name__)


def save_screenshot(
    image_bytes: bytes,
    path: Path | str,
    format: str | None = None,
    optimize: bool = True,
) -> Path:
    """Save raw image bytes to a file on disk.

    Args:
        image_bytes: Raw image data (e.g. PNG or JPEG bytes).
        path: Destination file path.
        format: Image format to save as (e.g. "PNG", "JPEG"). If None, inferred
            from the file extension.
        optimize: Whether to apply Pillow's optimize flag when saving.

    Returns:
        The resolved Path where the image was saved.

    Raises:
        ValueError: If image_bytes is empty.
        OSError: If the file cannot be written.
    """
    if not image_bytes:
        raise ValueError("image_bytes must not be empty.")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    image = Image.open(io.BytesIO(image_bytes))
    save_kwargs: dict[str, object] = {}
    if format is not None:
        save_kwargs["format"] = format
    if optimize:
        save_kwargs["optimize"] = True

    image.save(str(path), **save_kwargs)
    logger.info(
        "screenshot_saved",
        path=str(path),
        size_bytes=len(image_bytes),
        dimensions=image.size,
    )
    return path.resolve()


def encode_screenshot_base64(
    image_bytes: bytes,
    output_format: str = "PNG",
) -> str:
    """Encode raw image bytes as a base64 string.

    The image is decoded and re-encoded in the specified format before
    base64 encoding. This normalises the image data regardless of the
    original format.

    Args:
        image_bytes: Raw image data.
        output_format: The image format to encode to before base64 conversion.
            Defaults to "PNG".

    Returns:
        A base64-encoded string of the image data.

    Raises:
        ValueError: If image_bytes is empty.
    """
    if not image_bytes:
        raise ValueError("image_bytes must not be empty.")

    image = Image.open(io.BytesIO(image_bytes))
    buffer = io.BytesIO()
    image.save(buffer, format=output_format)
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    logger.debug(
        "screenshot_encoded",
        original_size_bytes=len(image_bytes),
        encoded_length=len(encoded),
        output_format=output_format,
    )
    return encoded


def decode_screenshot_base64(
    encoded: str,
) -> bytes:
    """Decode a base64-encoded image string back to raw bytes.

    Args:
        encoded: A base64-encoded string of image data.

    Returns:
        The decoded raw image bytes.

    Raises:
        ValueError: If the encoded string is empty.
    """
    if not encoded:
        raise ValueError("encoded string must not be empty.")
    return base64.b64decode(encoded)
