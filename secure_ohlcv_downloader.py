"""Backward compatible wrapper importing refactored modules."""

import logging
import re
import traceback
from datetime import date, datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from config import GlobalConfig
from src.secure_ohlcv_downloader import (
    SecureOHLCVDownloader as RefactoredDownloader,
    SecurityError,
    CredentialError,
    ValidationError,
    CertificateManager,
    SecurePatternValidator,
    SecureJSONValidator,
    DataValidator,
    APIClient,
    EncryptionManager,
    FileManager,
    CrossPlatformFileLockManager,
    FileLockTimeoutError,
    ConfigurationManager,
    SecurityValidationError,
    RateLimiter,
    CircuitBreaker,
    SecurityEventMonitor,
    FingerprintAdapter,
)

from dataclasses import dataclass


@dataclass
class DownloadConfig:
    ticker: str
    start_date: date
    end_date: date
    interval: str
    source: str
    encrypt_data: bool = False


class SecurityExceptionHandler:
    """Sanitize exception contexts to prevent information disclosure."""

    SENSITIVE_PATTERNS = [r"api key\s*\w+", r"password\s*\w+", r"/home/[\w/]+"]

    def __init__(self) -> None:
        self.security_logger = logging.getLogger("security")

    def sanitize_exception_context(self, exc: Exception, include_traceback: bool = False) -> Dict[str, Any]:
        """Return a sanitized dictionary describing *exc*.

        Edge cases: unexpected exception types may include sensitive user input
        or file paths. This helper removes known secrets and optionally the
        traceback to avoid information disclosure while still providing
        actionable diagnostics.
        """
        context = {
            "error_type": type(exc).__name__,
            "error_message": self._sanitize_message(str(exc)),
            "timestamp": datetime.now().isoformat(),
            "error_id": self._generate_error_id(),
        }
        if include_traceback:
            context["traceback"] = self._sanitize_traceback()
        return context

    def _sanitize_message(self, message: str) -> str:
        sanitized = message
        for pattern in self.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        sanitized = sanitized.replace("/home/", "[PATH_REDACTED]/")
        return sanitized

    def _sanitize_traceback(self) -> List[str]:
        tb_lines = traceback.format_exc().split("\n")
        return [self._sanitize_message(line) for line in tb_lines if line]

    def _generate_error_id(self) -> str:
        import uuid

        return f"ERR-{uuid.uuid4().hex[:8].upper()}"


class SecureOHLCVDownloader(RefactoredDownloader):
    """Maintains original public interface."""

    def __init__(self, output_dir: str = "/home/user/output", config: Optional[GlobalConfig] = None) -> None:
        super().__init__(output_dir)


__all__ = [
    "SecureOHLCVDownloader",
    "SecurityError",
    "CredentialError",
    "ValidationError",
    "SecurityExceptionHandler",
    "DownloadConfig",
    "CertificateManager",
    "SecurePatternValidator",
    "SecureJSONValidator",
    "DataValidator",
    "APIClient",
    "EncryptionManager",
    "FileManager",
    "CrossPlatformFileLockManager",
    "FileLockTimeoutError",
    "ConfigurationManager",
    "SecurityValidationError",
    "RateLimiter",
    "CircuitBreaker",
    "SecurityEventMonitor",
    "FingerprintAdapter",
]


