"""SSL certificate management with expiration and rotation monitoring."""

from __future__ import annotations

import json
import ssl
import socket
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from monitoring.security_monitor import SecurityEventMonitor


class CertificateManager:
    """Dynamic SSL certificate management."""

    def __init__(self, config_path: str = "config/certificates.json", monitor: Optional[SecurityEventMonitor] = None) -> None:
        self.config_path = config_path
        self.monitor = monitor
        config = self._load_config()
        self.valid_fingerprints: List[str] = config.get("alpha_vantage_fingerprints", [])
        self.rotation_window_hours = config.get("rotation_window_hours", 72)
        self.last_updated = config.get("last_updated")

    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_config(self) -> None:
        data = {
            "alpha_vantage_fingerprints": self.valid_fingerprints,
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "rotation_window_hours": self.rotation_window_hours,
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def _get_certificate_details(self, hostname: str, port: int) -> tuple[str, datetime]:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                fingerprint = hashlib.sha256(cert).hexdigest()
                expires = datetime.strptime(ssock.getpeercert()["notAfter"], "%b %d %H:%M:%S %Y %Z")
                return fingerprint, expires

    def validate_certificate(self, hostname: str, port: int = 443) -> bool:
        fingerprint, expires = self._get_certificate_details(hostname, port)
        if fingerprint not in self.valid_fingerprints:
            self.valid_fingerprints = [fingerprint]
            self._save_config()
            if self.monitor:
                self.monitor.log_certificate_event(hostname, "rotation_detected", {"fingerprint": fingerprint})
        else:
            if self.monitor:
                self.monitor.log_certificate_event(hostname, "validation_success", {})
        if expires - datetime.utcnow() < timedelta(days=7) and self.monitor:
            self.monitor.log_certificate_event(hostname, "expiring_soon", {"expires": expires.isoformat()})
        return True
