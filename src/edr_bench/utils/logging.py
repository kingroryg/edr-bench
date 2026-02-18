"""Structured logging setup using structlog with rich console and JSON file output."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import structlog


def configure_logging(
    level: int | str = logging.INFO,
    log_file: Path | str | None = None,
    json_log_file: Path | str | None = None,
) -> None:
    """Configure structlog with rich console output and optional JSON file output.

    Args:
        level: The logging level (e.g. logging.DEBUG, "INFO").
        log_file: Optional path for a human-readable log file.
        json_log_file: Optional path for a JSON-formatted log file.
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Shared processors applied before final rendering
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure the standard library root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    # Remove any existing handlers to avoid duplicates on reconfiguration
    root_logger.handlers.clear()

    # Console handler with rich/colored output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        foreign_pre_chain=shared_processors,
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Optional human-readable file handler
    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setLevel(level)
        file_formatter = structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.dev.ConsoleRenderer(colors=False),
            ],
            foreign_pre_chain=shared_processors,
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Optional JSON file handler
    if json_log_file is not None:
        json_log_file = Path(json_log_file)
        json_log_file.parent.mkdir(parents=True, exist_ok=True)
        json_handler = logging.FileHandler(str(json_log_file), encoding="utf-8")
        json_handler.setLevel(level)
        json_formatter = structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
            foreign_pre_chain=shared_processors,
        )
        json_handler.setFormatter(json_formatter)
        root_logger.addHandler(json_handler)

    # Configure structlog itself
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None, **initial_values: Any) -> structlog.stdlib.BoundLogger:
    """Get a structlog bound logger.

    Args:
        name: Optional logger name. Defaults to the caller's module name.
        **initial_values: Key-value pairs to bind to the logger.

    Returns:
        A configured structlog BoundLogger instance.
    """
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name, **initial_values)
    return logger
