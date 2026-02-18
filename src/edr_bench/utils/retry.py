"""Async retry decorator using tenacity with exponential backoff."""
from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import structlog
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
    after_log,
)

logger = structlog.get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def retry_async(
    max_attempts: int = 3,
    max_delay: float = 60.0,
    min_delay: float = 1.0,
    multiplier: float = 2.0,
    retry_on: type[Exception] | tuple[type[Exception], ...] = Exception,
    reraise: bool = True,
) -> Callable[[F], F]:
    """Async retry decorator with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts (including the first call).
        max_delay: Maximum delay in seconds between retries.
        min_delay: Minimum (initial) delay in seconds between retries.
        multiplier: Multiplier for exponential backoff.
        retry_on: Exception type(s) that should trigger a retry.
        reraise: Whether to reraise the last exception on failure.

    Returns:
        A decorator that wraps an async function with retry logic.

    Example::

        @retry_async(max_attempts=5, max_delay=30.0)
        async def fetch_data(url: str) -> dict:
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            attempt = 0
            async for attempt_ctx in AsyncRetrying(
                stop=stop_after_attempt(max_attempts),
                wait=wait_exponential(
                    multiplier=multiplier,
                    min=min_delay,
                    max=max_delay,
                ),
                retry=retry_if_exception_type(retry_on),
                reraise=reraise,
            ):
                with attempt_ctx:
                    attempt += 1
                    if attempt > 1:
                        logger.warning(
                            "retrying_operation",
                            function=func.__qualname__,
                            attempt=attempt,
                            max_attempts=max_attempts,
                        )
                    return await func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


async def retry_call(
    func: Callable[..., Awaitable[Any]],
    *args: Any,
    max_attempts: int = 3,
    max_delay: float = 60.0,
    min_delay: float = 1.0,
    multiplier: float = 2.0,
    retry_on: type[Exception] | tuple[type[Exception], ...] = Exception,
    **kwargs: Any,
) -> Any:
    """Execute an async callable with retry logic (functional style).

    Args:
        func: The async callable to execute.
        *args: Positional arguments for the callable.
        max_attempts: Maximum number of retry attempts.
        max_delay: Maximum delay in seconds between retries.
        min_delay: Minimum (initial) delay in seconds between retries.
        multiplier: Multiplier for exponential backoff.
        retry_on: Exception type(s) that should trigger a retry.
        **kwargs: Keyword arguments for the callable.

    Returns:
        The return value of the callable.
    """
    attempt = 0
    async for attempt_ctx in AsyncRetrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(
            multiplier=multiplier,
            min=min_delay,
            max=max_delay,
        ),
        retry=retry_if_exception_type(retry_on),
        reraise=True,
    ):
        with attempt_ctx:
            attempt += 1
            if attempt > 1:
                logger.warning(
                    "retrying_operation",
                    function=func.__qualname__,
                    attempt=attempt,
                    max_attempts=max_attempts,
                )
            return await func(*args, **kwargs)
