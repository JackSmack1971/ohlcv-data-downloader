from __future__ import annotations

"""Security event monitoring and alerting utilities."""

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import json
import logging
import threading
from typing import Any, Callable, Dict, List, Optional

import psutil


class SecurityEventLevel(Enum):
    """Security event severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class SecurityEvent:
    """Structured security event."""

    event_id: str
    timestamp: datetime
    level: SecurityEventLevel
    category: str
    description: str
    source_component: str
    metadata: Dict[str, Any]
    resolved: bool = False
    resolution_timestamp: Optional[datetime] = None


class SecurityEventMonitor:
    """Comprehensive security event monitoring and alerting."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or self._get_default_config()
        self.events: List[SecurityEvent] = []
        self.event_handlers: Dict[str, List[Callable[[SecurityEvent], None]]] = {}
        self.metrics: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._setup_logging()
        self._setup_metrics()

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "max_events": 10000,
            "alert_thresholds": {
                "critical_events_per_hour": 5,
                "failed_validations_per_hour": 20,
                "certificate_errors_per_hour": 3,
            },
            "notification": {
                "email_enabled": False,
                "webhook_enabled": False,
                "log_file": "logs/security_events.log",
            },
        }

    def _setup_logging(self) -> None:
        self.security_logger = logging.getLogger("security_monitor")
        self.security_logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(self.config["notification"]["log_file"])
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        self.security_logger.addHandler(file_handler)

    def _setup_metrics(self) -> None:
        self.metrics = {
            "total_events": 0,
            "events_by_level": {level.value: 0 for level in SecurityEventLevel},
            "events_by_category": {},
            "certificate_validations": 0,
            "certificate_failures": 0,
            "rate_limit_hits": 0,
            "circuit_breaker_trips": 0,
            "memory_alerts": 0,
            "last_reset": datetime.now(),
        }

    def log_security_event(
        self,
        category: str,
        description: str,
        level: SecurityEventLevel = SecurityEventLevel.INFO,
        source_component: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        event_id = self._generate_event_id()
        event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            level=level,
            category=category,
            description=description,
            source_component=source_component,
            metadata=metadata or {},
        )
        with self._lock:
            self.events.append(event)
            if len(self.events) > self.config["max_events"]:
                self.events = self.events[-self.config["max_events"] :]
            self._update_metrics(event)
            self._log_event_to_file(event)
            self._check_alert_thresholds(event)
            self._trigger_event_handlers(event)
        return event_id

    def start_operation(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        return self.log_security_event(
            "operation_start",
            f"Started {name}",
            SecurityEventLevel.INFO,
            "operation_tracker",
            {"operation": name, **(metadata or {})},
        )

    def complete_operation(self, operation_id: str, status: str, details: str | None = None) -> None:
        self.log_security_event(
            "operation_complete",
            f"Operation completed with status: {status}",
            SecurityEventLevel.WARNING if status == "failure" else SecurityEventLevel.INFO,
            "operation_tracker",
            {"operation_id": operation_id, "status": status, "details": details},
        )

    def log_certificate_event(self, hostname: str, event_type: str, details: Dict[str, Any]) -> None:
        level = (
            SecurityEventLevel.CRITICAL
            if event_type in {"rotation_detected", "validation_failed"}
            else SecurityEventLevel.INFO
        )
        self.log_security_event(
            "certificate",
            f"Certificate {event_type} for {hostname}",
            level,
            "certificate_manager",
            {"hostname": hostname, **details},
        )
        with self._lock:
            if event_type == "validation_success":
                self.metrics["certificate_validations"] += 1
            elif event_type == "validation_failed":
                self.metrics["certificate_failures"] += 1

    def log_rate_limit_event(self, waited: float) -> None:
        self.log_security_event(
            "rate_limit",
            f"Rate limit enforced: waited {waited:.2f}s",
            SecurityEventLevel.WARNING,
            "rate_limiter",
        )
        with self._lock:
            self.metrics["rate_limit_hits"] += 1

    def log_circuit_breaker_event(self, state: str) -> None:
        self.log_security_event(
            "circuit_breaker",
            f"Circuit breaker {state}",
            SecurityEventLevel.CRITICAL if state == "opened" else SecurityEventLevel.INFO,
            "circuit_breaker",
        )
        if state == "opened":
            with self._lock:
                self.metrics["circuit_breaker_trips"] += 1

    def monitor_memory(self, threshold_mb: int) -> Callable[[], None]:
        start = psutil.Process().memory_info().rss / (1024 * 1024)

        def _finish() -> None:
            end = psutil.Process().memory_info().rss / (1024 * 1024)
            if end - start > threshold_mb:
                self.log_security_event(
                    "memory",
                    f"Memory usage increased by {end - start:.2f}MB",
                    SecurityEventLevel.WARNING,
                    "memory_monitor",
                    {"delta_mb": end - start},
                )
                with self._lock:
                    self.metrics["memory_alerts"] += 1

        return _finish

    def get_security_metrics(self) -> Dict[str, Any]:
        with self._lock:
            recent = datetime.now() - timedelta(hours=1)
            return {
                **self.metrics,
                "critical_events_last_hour": len(
                    [e for e in self.events if e.level == SecurityEventLevel.CRITICAL and e.timestamp > recent]
                ),
            }

    def register_event_handler(
        self, category: str, handler: Callable[[SecurityEvent], None]
    ) -> None:
        if category not in self.event_handlers:
            self.event_handlers[category] = []
        self.event_handlers[category].append(handler)

    def _generate_event_id(self) -> str:
        import uuid

        return f"SEC-{uuid.uuid4().hex[:8].upper()}"

    def _update_metrics(self, event: SecurityEvent) -> None:
        self.metrics["total_events"] += 1
        self.metrics["events_by_level"][event.level.value] += 1
        self.metrics["events_by_category"].setdefault(event.category, 0)
        self.metrics["events_by_category"][event.category] += 1

    def _log_event_to_file(self, event: SecurityEvent) -> None:
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        self.security_logger.info(json.dumps(data))

    def _check_alert_thresholds(self, event: SecurityEvent) -> None:
        recent = datetime.now() - timedelta(hours=1)
        crit = len(
            [e for e in self.events if e.level == SecurityEventLevel.CRITICAL and e.timestamp > recent]
        )
        if crit >= self.config["alert_thresholds"]["critical_events_per_hour"]:
            self._send_alert("critical_threshold", f"Critical events: {crit}")

    def _send_alert(self, alert_type: str, message: str) -> None:
        self.security_logger.critical(f"ALERT {alert_type}: {message}")

    def _trigger_event_handlers(self, event: SecurityEvent) -> None:
        for handler in self.event_handlers.get(event.category, []):
            try:
                handler(event)
            except Exception as exc:  # pragma: no cover
                self.security_logger.error(f"Handler error: {exc}")
