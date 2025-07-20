"""Async rate limiting and circuit breaker utilities with monitoring."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, Optional

from .exceptions import SecurityError
from monitoring.security_monitor import SecurityEventMonitor


class RateLimiter:
    """Simple async rate limiter."""

    def __init__(self, rate: int, period: float, monitor: Optional[SecurityEventMonitor] = None) -> None:
        self.rate = rate
        self.period = period
        self.monitor = monitor
        self.calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self.calls = [t for t in self.calls if now - t < self.period]
            if len(self.calls) >= self.rate:
                wait = self.period - (now - self.calls[0])
                await asyncio.sleep(wait)
                if self.monitor:
                    self.monitor.log_rate_limit_event(wait)
            self.calls.append(time.monotonic())


class CircuitBreaker:
    """Async circuit breaker."""

    def __init__(self, threshold: int, reset_timeout: float, monitor: Optional[SecurityEventMonitor] = None) -> None:
        self.threshold = threshold
        self.reset_timeout = reset_timeout
        self.monitor = monitor
        self.failures = 0
        self.open_until = 0.0

    async def call(self, func: Callable[[], Awaitable[Any]]) -> Any:
        now = time.monotonic()
        if self.open_until > now:
            if self.monitor:
                self.monitor.log_circuit_breaker_event("open_block")
            raise SecurityError("Circuit breaker open")
        try:
            result = await func()
        except Exception:
            self.failures += 1
            if self.failures >= self.threshold:
                self.open_until = now + self.reset_timeout
                if self.monitor:
                    self.monitor.log_circuit_breaker_event("opened")
            raise
        else:
            if self.failures and now >= self.open_until:
                self.failures = 0
                if self.monitor and self.open_until:
                    self.monitor.log_circuit_breaker_event("closed")
            return result
