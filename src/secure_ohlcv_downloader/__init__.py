"""Secure OHLCV downloader package with comprehensive security controls."""

from .downloader import SecureOHLCVDownloader
from .certificate_manager import CertificateManager
from .validation import SecurePatternValidator, SecureJSONValidator
from .exceptions import SecurityError, ValidationError, SecurityValidationError

__version__ = "1.0.0"
__all__ = [
    "SecureOHLCVDownloader",
    "CertificateManager",
    "SecurePatternValidator",
    "SecureJSONValidator",
    "SecurityError",
    "ValidationError",
    "SecurityValidationError",
]
