#!/usr/bin/env python3
"""
Secure OHLCV Data Downloader - Core Module
Addresses critical security vulnerabilities from audit SEC-2025-001 through SEC-2025-006
"""

import os
import re
import regex
from utils import sanitize_error
import sys
import traceback
from typing import List
import json
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Awaitable, TypeVar, Tuple
from datetime import datetime, date, timedelta
import getpass
from dataclasses import dataclass
import pandas as pd
import yfinance as yf
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from jsonschema import validate, exceptions as jsonschema_exceptions
from cryptography.fernet import Fernet, InvalidToken
from io import BytesIO
from keyring import errors as keyring_errors
import keyring
from keyrings.alt.file import PlaintextKeyring
from dotenv import load_dotenv
from config import GlobalConfig, load_global_config
from audit import AuditLogger, AuditError
import tempfile
import shutil
import asyncio
import time
import psutil
import ssl
import socket

if os.name == "posix":
    import fcntl
else:
    import msvcrt

# Load environment variables
load_dotenv()

DEFAULT_RETENTION_DAYS = 2555


@dataclass
class DownloadConfig:
    """Configuration class for OHLCV downloads"""

    ticker: str
    start_date: date
    end_date: date
    interval: str
    source: str
    encrypt_data: bool = False


class SecurityError(Exception):
    """Custom exception for security-related errors"""

    pass


class CredentialError(SecurityError):
    """Exception raised for credential storage or retrieval issues."""

    pass


class ValidationError(Exception):
    """Custom exception for validation errors"""

    pass


class SecurityExceptionHandler:
    """Sanitize exception contexts to prevent information disclosure."""

    SENSITIVE_PATTERNS = [
        r"/home/[^/\s]+",
        r"/Users/[^/\s]+",
        r"C:\\Users\\[^\\]+",
        r"api\s*key[\'\"\s]*[:=]?[\'\"\s]*[^\s\'\"]+",
        r"password[\'\"\s]*[:=][\'\"\s]*[^\s\'\"]+",
        r"secret[\'\"\s]*[:=][\'\"\s]*[^\s\'\"]+",
        r"token[\'\"\s]*[:=][\'\"\s]*[^\s\'\"]+",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ]

    def __init__(self) -> None:
        self.security_logger = self._setup_security_logger()

    def _setup_security_logger(self) -> logging.Logger:
        logger = logging.getLogger("security")
        if not logger.handlers:
            handler = logging.FileHandler("logs/security_exceptions.log")
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.ERROR)
        return logger

    def sanitize_exception_context(
        self, exc: Exception, include_traceback: bool = False
    ) -> Dict[str, Any]:
        context = {
            "error_type": type(exc).__name__,
            "error_message": self._sanitize_message(str(exc)),
            "timestamp": datetime.now().isoformat(),
            "error_id": self._generate_error_id(),
        }
        if include_traceback:
            context["traceback"] = self._sanitize_traceback()
        self._log_full_exception_securely(exc, context["error_id"])
        return context

    def _sanitize_message(self, message: str) -> str:
        sanitized = message
        for pattern in self.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"/[^/\s]+/[^/\s]+/", "[PATH]/", sanitized)
        sanitized = re.sub(r"[A-Z]:\\\\[^\\\\]+(?:\\\\[^\\\\]+)*", "[PATH]", sanitized)
        return sanitized

    def _sanitize_traceback(self) -> List[str]:
        tb_lines = traceback.format_exc().split("\n")
        sanitized_lines: List[str] = []
        for line in tb_lines:
            if 'File "' in line:
                match = re.search(r'File "([^"]+)", line (\d+), in (.+)', line)
                if match:
                    filename = os.path.basename(match.group(1))
                    line_num = match.group(2)
                    func_name = match.group(3)
                    sanitized_lines.append(
                        f'File "{filename}", line {line_num}, in {func_name}'
                    )
                else:
                    sanitized_lines.append("[TRACEBACK LINE REDACTED]")
            else:
                sanitized_lines.append(self._sanitize_message(line))
        return sanitized_lines

    def _generate_error_id(self) -> str:
        import uuid
        return f"ERR-{uuid.uuid4().hex[:8].upper()}"

    def _log_full_exception_securely(self, exc: Exception, error_id: str) -> None:
        secure_log = {
            "error_id": error_id,
            "exception_type": type(exc).__name__,
            "exception_args": exc.args,
            "full_traceback": traceback.format_exc(),
            "local_variables": self._extract_safe_local_variables(),
            "timestamp": datetime.now().isoformat(),
        }
        self.security_logger.error("Security exception logged", extra={"secure_data": secure_log})

    def _extract_safe_local_variables(self) -> Dict[str, str]:
        frame = sys.exc_info()[2].tb_frame if sys.exc_info()[2] else None
        safe_vars: Dict[str, str] = {}
        if frame:
            for name, value in frame.f_locals.items():
                if name.startswith("_"):
                    continue
                safe_vars[name] = self._sanitize_variable_value(name, value)
        return safe_vars

    def _sanitize_variable_value(self, name: str, value: Any) -> str:
        sensitive_names = ["password", "api_key", "secret", "token", "key"]
        if any(s in name.lower() for s in sensitive_names):
            return "[SENSITIVE_VARIABLE_REDACTED]"
        try:
            return self._sanitize_message(str(value))
        except Exception:
            return "[VARIABLE_CONVERSION_FAILED]"

class FingerprintAdapter(HTTPAdapter):
    """HTTPAdapter that validates server certificate fingerprint."""

    def __init__(self, fingerprint: str, *args: Any, **kwargs: Any) -> None:
        self.fingerprint = fingerprint.lower().replace(":", "")
        super().__init__(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert) -> None:  # type: ignore[override]
        super().cert_verify(conn, url, verify, cert)
        der_cert = conn.sock.getpeercert(True)
        digest = hashlib.sha256(der_cert).hexdigest()
        if digest != self.fingerprint:
            raise SecurityError("Certificate fingerprint mismatch")


class CertificateAlertManager:
    """Handle certificate-related security alerts."""

    def send_certificate_alert(self, host: str, fingerprint: Optional[str], msg: str) -> None:
        logging.error("CERT ALERT %s: %s %s", host, msg, fingerprint or "")


class CertificateRotationDetector:
    """Detect and control certificate rotations."""

    def __init__(self) -> None:
        self.rotation_history: Dict[str, datetime] = {}

    def is_legitimate_rotation(self, new_fingerprint: str, host: str) -> bool:
        last = self.rotation_history.get(host)
        now = datetime.now()
        if last and (now - last) < timedelta(hours=1):
            return False
        self.rotation_history[host] = now
        return True


class CertificateManager:
    """Manage trusted SSL certificate fingerprints dynamically."""

    def __init__(self, config_path: str = "config/certificates.json") -> None:
        self.config_path = config_path
        self.config = self._load_config()
        self.valid_fingerprints = self.config.get("alpha_vantage_fingerprints", [])
        self.rotation_detector = CertificateRotationDetector()
        self.alert_manager = CertificateAlertManager()

    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            default_fp = os.getenv(
                "ALPHA_VANTAGE_FINGERPRINT",
                "626ab34fbac6f21bd70928a741b93d7c5edda6af032dca527d17bffb8d34e523",
            )
            default = {
                "alpha_vantage_fingerprints": [default_fp],
                "last_updated": datetime.now().isoformat(),
                "rotation_window_hours": 72,
            }
            self._save_config(default)
            return default

    def _save_config(self, data: Dict[str, Any]) -> None:
        Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(data, f, indent=2)

    def get_preferred_fingerprint(self) -> Optional[str]:
        return self.valid_fingerprints[0] if self.valid_fingerprints else None

    def validate_certificate(self, hostname: str, port: int = 443) -> bool:
        try:
            fingerprint, expires = self._get_certificate_details(hostname, port)
            self._check_expiration(expires, hostname)
            if fingerprint in self.valid_fingerprints:
                return True
            if self.rotation_detector.is_legitimate_rotation(fingerprint, hostname):
                self.valid_fingerprints.insert(0, fingerprint)
                self.config["alpha_vantage_fingerprints"] = self.valid_fingerprints
                self.config["last_updated"] = datetime.now().isoformat()
                self._save_config(self.config)
                return True
            self.alert_manager.send_certificate_alert(hostname, fingerprint, "Unknown certificate")
            return False
        except Exception as e:
            self.alert_manager.send_certificate_alert(hostname, None, f"Validation failed: {str(e)}")
            return False

    def _get_certificate_details(self, hostname: str, port: int) -> Tuple[str, datetime]:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                info = ssock.getpeercert()
                fp = hashlib.sha256(der).hexdigest()
                exp = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z")
                return fp, exp

    def _check_expiration(self, expires: datetime, host: str) -> None:
        if expires - datetime.utcnow() < timedelta(days=7):
            self.alert_manager.send_certificate_alert(host, None, "Certificate expiring soon")

class RateLimiter:
    """Simple async token bucket rate limiter."""

    def __init__(self, rate: int, per: float) -> None:
        self._rate = rate
        self._per = per
        self._allowance = rate
        self._last_check = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_check
            self._last_check = now
            self._allowance += elapsed * (self._rate / self._per)
            if self._allowance > self._rate:
                self._allowance = self._rate
            if self._allowance < 1:
                wait = (1 - self._allowance) * (self._per / self._rate)
                await asyncio.sleep(wait)
                self._allowance = 0
            else:
                self._allowance -= 1


T = TypeVar("T")


class CircuitBreaker:
    """Async circuit breaker for external calls."""

    def __init__(self, max_failures: int, reset_timeout: float) -> None:
        self._max_failures = max_failures
        self._reset_timeout = reset_timeout
        self._failures = 0
        self._state = "closed"
        self._opened = 0.0

    async def call(self, func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        if self._state == "open":
            if time.monotonic() - self._opened >= self._reset_timeout:
                self._state = "half"
            else:
                raise SecurityError("Circuit breaker open")
        try:
            result = await func(*args, **kwargs)
        except (
            SecurityError,
            ValidationError,
            CredentialError,
            requests.RequestException,
            OSError,
            ValueError,
            KeyError,
        ) as exc:
            self._failures += 1
            if self._failures >= self._max_failures:
                self._state = "open"
                self._opened = time.monotonic()
            raise exc
        else:
            if self._state == "half":
                self._state = "closed"
            self._failures = 0
            return result


class APICache:
    """Simple in-memory async cache with TTL."""

    def __init__(self, ttl: int) -> None:
        self._ttl = ttl
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            timestamp, value = entry
            if time.monotonic() - timestamp > self._ttl:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            self._store[key] = (time.monotonic(), value)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


class SecureOHLCVDownloader:
    """
    Secure OHLCV data downloader with comprehensive input validation,
    path sanitization, and JSON schema validation
    """

    # Valid ticker symbol pattern (alphanumeric, dots, hyphens, underscores)
    try:
        TICKER_PATTERN = regex.compile(r"^[A-Z0-9._-]{1,10}$", timeout=0.1)
    except Exception:
        TICKER_PATTERN = regex.compile(r"^[A-Z0-9._-]{1,10}$")

    # Pre-compiled date pattern with timeout to mitigate ReDoS
    try:
        DATE_PATTERN = regex.compile(r"^\d{4}-\d{2}-\d{2}$", timeout=0.1)
    except Exception:
        DATE_PATTERN = regex.compile(r"^\d{4}-\d{2}-\d{2}$")


    # Valid intervals
    VALID_INTERVALS = {
        "1d",
        "1wk",
        "1mo",
        "3mo",
        "6mo",
        "1y",
        "2y",
        "5y",
        "10y",
        "ytd",
        "max",
    }

    # Valid data sources
    VALID_SOURCES = {"yahoo", "alpha_vantage"}



    # JSON schema for Alpha Vantage API response validation
    ALPHA_VANTAGE_SCHEMA = {
        "type": "object",
        "properties": {
            "Time Series (Daily)": {
                "type": "object",
                "patternProperties": {
                    r"^\d{4}-\d{2}-\d{2}$": {
                        "type": "object",
                        "properties": {
                            "1. open": {"type": "string"},
                            "2. high": {"type": "string"},
                            "3. low": {"type": "string"},
                            "4. close": {"type": "string"},
                            "5. volume": {"type": "string"},
                        },
                        "required": [
                            "1. open",
                            "2. high",
                            "3. low",
                            "4. close",
                            "5. volume",
                        ],
                    }
                },
            },
            "Meta Data": {
                "type": "object",
                "properties": {"2. Symbol": {"type": "string"}},
            },
        },
    }

    def __init__(self, output_dir: str = "/home/user/output", config: Optional[GlobalConfig] = None):
        """
        Initialize secure OHLCV downloader

        Args:
            output_dir: Base directory for output files
        """
        self.output_dir = Path(output_dir).resolve()
        self.config = config or load_global_config(os.getenv("OHLCV_CONFIG_FILE"))
        self.certificate_manager = CertificateManager()
        self.rate_limiter = RateLimiter(int(os.getenv("API_RATE", "5")), 60.0)
        self.circuit_breaker = CircuitBreaker(3, 60.0)
        self.cache = APICache(self.config.cache_ttl)
        self.exception_handler = SecurityExceptionHandler()
        self._setup_logging()
        self._validate_output_directory()
        self.audit = AuditLogger(
            self.output_dir / "audit.log",
            os.getenv("AUDIT_LOG_HMAC_KEY"),
        )
        self._setup_encryption()

    def _setup_logging(self) -> None:
        """Setup secure logging with sanitized messages"""
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(self.output_dir / "secure_downloader.log"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)
        self.security_logger = self.exception_handler.security_logger

    def _setup_encryption(self) -> None:
        """Setup encryption for sensitive data storage with key persistence."""
        try:
            backend = keyring.get_keyring()
            if isinstance(backend, keyring.backends.fail.Keyring):
                keyring.set_keyring(PlaintextKeyring())

            key = os.getenv("OHLCV_ENCRYPTION_KEY")
            if not key:
                key = keyring.get_password("ohlcv_downloader", "encryption_key")
            if not key:
                key = Fernet.generate_key().decode()
                keyring.set_password(
                    "ohlcv_downloader",
                    "encryption_key",
                    key,
                )
                self.logger.warning("Generated new encryption key and stored securely")

            self.cipher = Fernet(key.encode())
        except keyring_errors.KeyringError as e:
            raise SecurityError(f"Keyring failure: {self._sanitize_error(str(e))}")

    def _validate_output_directory(self) -> None:
        """Validate and create output directory with proper permissions"""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.output_dir, self.config.dir_permissions)
        except OSError as e:
            sanitized = self._sanitize_error(str(e))
            raise SecurityError(
                f"Failed to create secure output directory: {sanitized}"
            )

    def rotate_encryption_key(self) -> None:
        """Rotate encryption key while keeping old key for backward compatibility."""
        try:
            old_key = keyring.get_password("ohlcv_downloader", "encryption_key")
            if not old_key:
                raise SecurityError("No existing encryption key to rotate")

            keyring.set_password("ohlcv_downloader", "encryption_key_prev", old_key)
            new_key = Fernet.generate_key().decode()
            keyring.set_password("ohlcv_downloader", "encryption_key", new_key)
            self.cipher = Fernet(new_key.encode())
            self.logger.info("Encryption key rotated successfully")
        except (keyring_errors.KeyringError, SecurityError) as e:
            raise SecurityError(f"Key rotation failed: {self._sanitize_error(str(e))}")

    def decrypt_file(self, file_path: Path) -> pd.DataFrame:
        """Decrypt an encrypted CSV file using current or previous key."""
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            try:
                decrypted = self.cipher.decrypt(encrypted_data)
            except InvalidToken:
                prev_key = keyring.get_password(
                    "ohlcv_downloader", "encryption_key_prev"
                )
                if not prev_key:
                    raise
                prev_cipher = Fernet(prev_key.encode())
                decrypted = prev_cipher.decrypt(encrypted_data)

            df = pd.read_csv(BytesIO(decrypted), index_col=0)
            self._audit_event("decrypt", {"file": str(file_path)})
            return df
        except (OSError, InvalidToken, keyring_errors.KeyringError) as e:
            raise SecurityError(f"Decryption failed: {self._sanitize_error(str(e))}")

    def _sanitize_error(self, error_message: str) -> str:
        """
        Sanitize error messages to prevent information disclosure

        Args:
            error_message: Raw error message

        Returns:
            Sanitized error message
        """
        exc = sys.exc_info()[1] or Exception(error_message)
        context = self.exception_handler.sanitize_exception_context(exc)
        return context["error_message"]

    def _handle_security_exception(self, exc: Exception, operation: str) -> Dict[str, Any]:
        sanitized = self.exception_handler.sanitize_exception_context(exc, include_traceback=True)
        self.security_logger.warning(
            f"Security exception in {operation}",
            extra={
                "operation": operation,
                "error_id": sanitized["error_id"],
                "error_type": sanitized["error_type"],
            },
        )
        return sanitized

    def _audit_event(self, action: str, details: Dict[str, Any]) -> None:
        """Log audit event and handle failures silently."""
        user = os.getenv("OHLCV_USER", getpass.getuser())
        try:
            self.audit.log(user, action, details)
        except AuditError as exc:
            self.logger.error(
                f"Audit log failure: {self._sanitize_error(str(exc))}"
            )

    def _check_memory(self) -> None:
        """Raise SecurityError if available memory is below threshold."""
        available_mb = psutil.virtual_memory().available / (1024 * 1024)
        if available_mb < self.config.max_memory_mb:
            raise SecurityError("Available memory below configured limit")

    def _validate_ticker(self, ticker: str) -> str:
        """Validate and sanitize ticker symbol."""
        if not ticker:
            raise ValidationError("Ticker symbol cannot be empty")

        # Convert to uppercase and strip whitespace
        ticker = ticker.upper().strip()

        # Validate against pattern with timeout protection
        try:
            if not self.TICKER_PATTERN.match(ticker):
                raise ValidationError(
                    "Invalid ticker symbol format. Use only alphanumeric characters, dots, hyphens, and underscores"
                )
        except regex.TimeoutError as exc:
            raise SecurityError("Ticker validation timed out") from exc

        # Additional security check for path traversal attempts
        if ".." in ticker or "/" in ticker or "\\" in ticker:
            raise SecurityError("Potential path traversal attempt detected")

        return ticker

    def _validate_date_range(self, start_date: date, end_date: date) -> None:
        """
        Validate date range parameters

        Args:
            start_date: Start date for data download
            end_date: End date for data download

        Raises:
            ValidationError: If date range is invalid
        """
        if start_date > end_date:
            raise ValidationError("Start date must be before end date")

        if end_date > date.today():
            raise ValidationError("End date cannot be in the future")

        # Reasonable date range limits (prevent excessive API calls)
        max_days = self.config.max_date_range_days
        if (end_date - start_date).days > max_days:
            raise ValidationError(
                f"Date range too large. Maximum {max_days} days allowed"
            )

    def _validate_interval(self, interval: str) -> str:
        """
        Validate interval parameter

        Args:
            interval: Time interval for data

        Returns:
            Validated interval

        Raises:
            ValidationError: If interval is invalid
        """
        if interval not in self.VALID_INTERVALS:
            raise ValidationError(
                f"Invalid interval. Must be one of: {', '.join(self.VALID_INTERVALS)}"
            )
        return interval

    def _validate_source(self, source: str) -> str:
        """
        Validate data source parameter

        Args:
            source: Data source name

        Returns:
            Validated source

        Raises:
            ValidationError: If source is invalid
        """
        if source not in self.VALID_SOURCES:
            raise ValidationError(
                f"Invalid source. Must be one of: {', '.join(self.VALID_SOURCES)}"
            )
        return source

    def _create_secure_path(self, ticker: str, date_range: str) -> Path:
        """
        Create secure file path with validation

        Args:
            ticker: Validated ticker symbol
            date_range: Date range string

        Returns:
            Secure path within output directory

        Raises:
            SecurityError: If path is outside allowed directory
        """
        # Build target path and validate
        output_root = self.output_dir.resolve()
        target_dir = output_root / "data" / ticker / date_range
        resolved_target = target_dir.resolve()

        if not str(resolved_target).startswith(str(output_root)):
            raise SecurityError("Path traversal attempt detected before creation")

        tmp_dir = Path(tempfile.mkdtemp(dir=str(output_root)))
        lock_path = output_root / ".dirlock"

        lock_file = open(lock_path, "w")
        try:
            if os.name == "posix":
                fcntl.flock(lock_file, fcntl.LOCK_EX)
            else:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)

            target_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp_dir, target_dir)

            final_resolved = target_dir.resolve()
            if not str(final_resolved).startswith(str(output_root)):
                raise SecurityError("Path traversal attempt detected after creation")

            os.chmod(target_dir, self.config.dir_permissions)
            self._audit_event(
                "path_created",
                {"path": str(target_dir)},
            )
        finally:
            if os.name == "posix":
                fcntl.flock(lock_file, fcntl.LOCK_UN)
            else:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            lock_file.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return target_dir

    def _validate_date_key(self, key: str) -> None:
        """Validate date keys to mitigate ReDoS attacks."""
        if len(key) > 10:
            raise ValidationError("Date key length exceeds limit")
        if not self.DATE_PATTERN.fullmatch(key):
            raise ValidationError("Invalid date key format")

    def _validate_json_response(
        self, response_data: Dict[Any, Any], schema: Dict[Any, Any]
    ) -> None:
        """Validate JSON response with ReDoS protections.

        Args:
            response_data: JSON response data
            schema: JSON schema for validation

        Raises:
            ValidationError: If validation fails
        """
        try:
            time_series = response_data.get("Time Series (Daily)", {})
            if len(time_series) > 10000:
                raise ValidationError("Time series too large")
            for key in time_series.keys():
                self._validate_date_key(str(key))

            validate(instance=response_data, schema=schema)
        except (
            ValidationError,
            jsonschema_exceptions.ValidationError,
            TypeError,
        ) as e:
            raise ValidationError(
                f"API response validation failed: {self._sanitize_error(str(e))}"
            )

    def _get_api_key(self, service: str) -> Optional[str]:
        """Retrieve API key from environment or keyring securely."""

        key_name = f"{service.upper()}_API_KEY"
        api_key = os.getenv(key_name)

        if not api_key:
            try:
                api_key = keyring.get_password("ohlcv_downloader", key_name.lower())
            except keyring_errors.KeyringError as e:
                raise CredentialError(
                    f"Keyring access failure: {self._sanitize_error(str(e))}"
                )

        if api_key:
            self.logger.info(f"API key retrieved for {service}")
        else:
            self.logger.warning(f"No API key available for {service}")

        return api_key

    def download_data(self, config: DownloadConfig) -> Path:
        """
        Download OHLCV data with comprehensive security validation

        Args:
            config: Download configuration

        Returns:
            Path to downloaded data file

        Raises:
            ValidationError: If input validation fails
            SecurityError: If security check fails
        """
        try:
            # Validate all inputs
            ticker = self._validate_ticker(config.ticker)
            self._validate_date_range(config.start_date, config.end_date)
            interval = self._validate_interval(config.interval)
            source = self._validate_source(config.source)

            # Create secure file path
            date_range = f"{config.start_date}_{config.end_date}"
            output_path = self._create_secure_path(ticker, date_range)

            # Log download attempt (with sanitized info)
            self.logger.info(
                f"Starting secure download: ticker={ticker}, source={source}, interval={interval}"
            )

            # Download data based on source
            filename = f"{ticker}_{source}.csv"
            file_path = output_path / filename
            record_count = 0

            if source == "yahoo":
                if (config.end_date - config.start_date).days > self.config.chunk_size_days:
                    record_count = self._download_yahoo_stream(
                        ticker, config.start_date, config.end_date, interval, file_path
                    )
                    data = None
                else:
                    data = self._download_yahoo_secure(
                        ticker, config.start_date, config.end_date, interval
                    )
                    record_count = len(data)
            elif source == "alpha_vantage":
                data = self._download_alpha_vantage_secure(ticker)
                record_count = len(data)
            else:
                raise ValidationError(f"Unsupported source: {source}")

            if config.encrypt_data:
                if record_count and data is not None:
                    self._save_encrypted_data(data, file_path)
                else:
                    self._encrypt_existing_file(file_path)
                file_path = Path(f"{file_path}.encrypted")
            else:
                if data is not None:
                    data.to_csv(file_path, index=True)

            os.chmod(file_path, self.config.file_permissions)

            self._audit_event(
                "download",
                {
                    "ticker": ticker,
                    "source": source,
                    "file": str(file_path),
                    "records": record_count,
                },
            )

            self._create_metadata(config, output_path, record_count)

            self.logger.info(f"Download completed successfully: {record_count} records")
            asyncio.run(self.cleanup_expired_data(self.config.retention_days))
            return file_path

        except (
            ValidationError,
            SecurityError,
            CredentialError,
            requests.RequestException,
            OSError,
            ValueError,
            KeyError,
        ) as e:
            sanitized = self._handle_security_exception(e, "download")
            self.logger.error(f"Download failed: {sanitized['error_message']}")
            raise

    def _download_yahoo_secure(
        self, ticker: str, start_date: date, end_date: date, interval: str
    ) -> pd.DataFrame:
        """
        Securely download data from Yahoo Finance

        Args:
            ticker: Validated ticker symbol
            start_date: Start date
            end_date: End date
            interval: Time interval

        Returns:
            Downloaded data as DataFrame
        """
        try:
            data = asyncio.run(
                self._yahoo_history(ticker, start_date, end_date, interval)
            )

            if data.empty:
                raise ValidationError("No data returned from Yahoo Finance")

            # Validate data structure
            expected_columns = {"Open", "High", "Low", "Close", "Volume"}
            if not expected_columns.issubset(data.columns):
                raise ValidationError("Invalid data structure from Yahoo Finance")

            return data

        except (
            requests.RequestException,
            ValueError,
            KeyError,
        ) as e:
            raise ValidationError(
                f"Yahoo Finance download failed: {self._sanitize_error(str(e))}"
            )

    def _download_yahoo_stream(
        self,
        ticker: str,
        start_date: date,
        end_date: date,
        interval: str,
        file_path: Path,
    ) -> int:
        """Download Yahoo data in chunks and stream to CSV."""
        total = 0
        header = True
        current = start_date
        while current <= end_date:
            self._check_memory()
            chunk_end = min(
                current + timedelta(days=self.config.chunk_size_days - 1), end_date
            )
            df = asyncio.run(
                self._yahoo_history(ticker, current, chunk_end, interval)
            )
            if not df.empty:
                total += len(df)
                df.to_csv(file_path, mode="a", header=header)
                header = False
            current = chunk_end + timedelta(days=1)
        return total

    def _create_pinned_session(self, host: str, fingerprint: str) -> requests.Session:
        """Create a requests session with certificate pinning and retries."""
        session = requests.Session()
        retries = Retry(
            total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504]
        )
        adapter = FingerprintAdapter(fingerprint, max_retries=retries)
        session.mount(host, adapter)
        session.verify = True
        return session

    async def _fetch_with_limit(
        self, session: requests.Session, url: str, **kwargs: Any
    ) -> requests.Response:
        async def _request() -> requests.Response:
            return await asyncio.to_thread(session.get, url, **kwargs)

        await self.rate_limiter.acquire()
        return await self.circuit_breaker.call(_request)

    async def _yahoo_history(
        self, ticker: str, start_date: date, end_date: date, interval: str
    ) -> pd.DataFrame:
        """Retrieve historical data from Yahoo Finance with caching."""
        key = f"yahoo:{ticker}:{start_date}:{end_date}:{interval}"
        cached = await self.cache.get(key)
        if cached is not None:
            self.logger.info("Cache hit for Yahoo data")
            return cached
        async def _call() -> pd.DataFrame:
            stock = yf.Ticker(ticker)
            return await asyncio.to_thread(
                stock.history,
                start=start_date,
                end=end_date,
                interval=interval,
            )

        await self.rate_limiter.acquire()
        data = await self.circuit_breaker.call(_call)
        await self.cache.set(key, data)
        return data

    def _download_alpha_vantage_secure(self, ticker: str) -> pd.DataFrame:
        """
        Securely download data from Alpha Vantage with JSON validation,
        certificate pinning, and response caching

        Args:
            ticker: Validated ticker symbol

        Returns:
            Downloaded data as DataFrame
        """
        api_key = self._get_api_key("alpha_vantage")
        if not api_key:
            raise ValidationError(
                "Alpha Vantage API key not found in environment variables"
            )

        cache_key = f"alpha_vantage:{ticker}"
        cached = asyncio.run(self.cache.get(cache_key))
        if cached is not None:
            self.logger.info("Cache hit for Alpha Vantage data")
            return cached

        url = "https://www.alphavantage.co/query"
        params = {
            "function": "TIME_SERIES_DAILY",
            "symbol": ticker,
            "apikey": api_key,
            "outputsize": "compact",
        }

        try:
            host = "www.alphavantage.co"
            if not self.certificate_manager.validate_certificate(host):
                raise SecurityError("Certificate validation failed")
            fingerprint = self.certificate_manager.get_preferred_fingerprint()
            session = self._create_pinned_session(
                "https://www.alphavantage.co", fingerprint or ""
            )
            response = asyncio.run(
                self._fetch_with_limit(
                    session, url, params=params, timeout=self.config.request_timeout
                )
            )
            response.raise_for_status()

            # Validate response size (prevent memory exhaustion)
            if len(response.content) > self.config.max_api_response_size:
                raise ValidationError("API response too large")

            data = response.json()

            # Validate JSON structure
            self._validate_json_response(data, self.ALPHA_VANTAGE_SCHEMA)

            # Check for API errors
            if "Error Message" in data:
                raise ValidationError("Invalid ticker symbol or API limit reached")

            if "Note" in data:
                raise ValidationError("API call frequency limit reached")

            # Convert to DataFrame
            time_series = data.get("Time Series (Daily)", {})
            if not time_series:
                raise ValidationError("No time series data in response")

            df_data = []
            for date_str, values in time_series.items():
                df_data.append(
                    {
                        "Date": pd.to_datetime(date_str),
                        "Open": float(values["1. open"]),
                        "High": float(values["2. high"]),
                        "Low": float(values["3. low"]),
                        "Close": float(values["4. close"]),
                        "Volume": int(values["5. volume"]),
                    }
                )

            df = pd.DataFrame(df_data)
            df.set_index("Date", inplace=True)
            df.sort_index(inplace=True)

            asyncio.run(self.cache.set(cache_key, df))
            return df

        except requests.RequestException as e:
            raise ValidationError(f"Network error: {self._sanitize_error(str(e))}")
        except SecurityError as e:
            raise ValidationError(
                f"SSL validation failed: {self._sanitize_error(str(e))}"
            )
        except (ValueError, KeyError) as e:
            raise ValidationError(f"Data parsing error: {self._sanitize_error(str(e))}")

    def _save_encrypted_data(self, data: pd.DataFrame, file_path: Path) -> None:
        """
        Save data with encryption

        Args:
            data: DataFrame to save
            file_path: Output file path
        """
        # Convert DataFrame to CSV string
        csv_data = data.to_csv(index=True)

        # Encrypt the data
        encrypted_data = self.cipher.encrypt(csv_data.encode())

        # Save encrypted data
        with open(f"{file_path}.encrypted", "wb") as f:
            f.write(encrypted_data)

        self.logger.info("Data saved with encryption")
        self._audit_event("save_encrypted", {"file": f"{file_path}.encrypted"})

    def _encrypt_existing_file(self, file_path: Path) -> None:
        """Encrypt an existing CSV file in place."""
        self._check_memory()
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = self.cipher.encrypt(data)
        with open(f"{file_path}.encrypted", "wb") as f:
            f.write(encrypted)
        os.remove(file_path)
        self.logger.info("Data saved with encryption")
        self._audit_event("save_encrypted", {"file": f"{file_path}.encrypted"})

    def _create_metadata(
        self, config: DownloadConfig, output_path: Path, record_count: int
    ) -> None:
        """
        Create metadata file with download information

        Args:
            config: Download configuration
            output_path: Output directory path
            record_count: Number of records downloaded
        """
        metadata = {
            "ticker": config.ticker,
            "source": config.source,
            "interval": config.interval,
            "start_date": config.start_date.isoformat(),
            "end_date": config.end_date.isoformat(),
            "download_timestamp": datetime.now().isoformat(),
            "record_count": record_count,
            "encrypted": config.encrypt_data,
            "checksum": self._calculate_checksum(output_path),
        }

        metadata_path = output_path / f"{config.ticker}_{config.source}_metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # Set secure permissions
        os.chmod(metadata_path, self.config.file_permissions)
        self._audit_event(
            "metadata_created",
            {"file": str(metadata_path), "records": record_count},
        )

    def _calculate_checksum(self, file_path: Path) -> str:
        """
        Calculate SHA-256 checksum for data integrity

        Args:
            file_path: Path to file

        Returns:
            SHA-256 checksum
        """
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except FileNotFoundError:
            return "file_not_found"

    async def _remove_path(self, path: Path) -> None:
        try:
            if path.is_dir():
                await asyncio.to_thread(shutil.rmtree, path)
            else:
                await asyncio.to_thread(path.unlink)
            self._audit_event("data_cleanup", {"path": str(path)})
        except OSError as e:
            self.logger.error(
                f"Cleanup failed: {self._sanitize_error(str(e))}"
            )

    async def cleanup_expired_data(
        self, retention_days: int = DEFAULT_RETENTION_DAYS
    ) -> None:
        cutoff = datetime.now() - timedelta(days=retention_days)
        data_root = self.output_dir / "data"
        if not data_root.exists():
            return
        for path in data_root.rglob("*"):
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime)
            except OSError as e:
                self.logger.error(
                    f"Retention stat failed: {self._sanitize_error(str(e))}"
                )
                continue
            if mtime < cutoff:
                await self._remove_path(path)
        for dir_path in sorted(data_root.rglob("*"), reverse=True):
            if dir_path.is_dir():
                try:
                    dir_path.rmdir()
                except OSError:
                    pass
