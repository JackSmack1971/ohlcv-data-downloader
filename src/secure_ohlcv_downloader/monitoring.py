"""Security monitoring utilities."""

from typing import Any

class SecurityMonitor:
    """Placeholder security monitoring component."""

    def __init__(self) -> None:
        """Initialize monitor."""
        self.events: list[Any] = []

    def log_event(self, event: str) -> None:
        """Log a security event."""
        self.events.append(event)
