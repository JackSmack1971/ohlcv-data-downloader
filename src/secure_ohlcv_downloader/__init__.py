"""Secure OHLCV downloader package with comprehensive security controls."""

from .downloader import SecureOHLCVDownloader
from .certificate_manager import CertificateManager
from .validation import (
    SecurePatternValidator,
    SecureJSONValidator,
    DataValidator,
)
from .api_client import APIClient
from .api_client import FingerprintAdapter
from .encryption import EncryptionManager
from .file_manager import FileManager
from .file_lock import CrossPlatformFileLockManager
from .exceptions import FileLockTimeoutError
from .monitoring import RateLimiter, CircuitBreaker
from monitoring.security_monitor import SecurityEventMonitor
from .configuration import ConfigurationManager
from .exceptions import (
    SecurityError,
    ValidationError,
    SecurityValidationError,
    CredentialError,
)

__version__ = "1.0.0"
__all__ = [
    "SecureOHLCVDownloader",
    "CertificateManager",
    "SecurePatternValidator",
    "SecureJSONValidator",
    "DataValidator",
    "APIClient",
    "EncryptionManager",
    "FileManager",
    "CrossPlatformFileLockManager",
    "ConfigurationManager",
    "SecurityError",
    "ValidationError",
    "CredentialError",
    "SecurityValidationError",
    "FileLockTimeoutError",
    "RateLimiter",
    "CircuitBreaker",
    "SecurityEventMonitor",
    "FingerprintAdapter",
]
