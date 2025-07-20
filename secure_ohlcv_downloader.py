#!/usr/bin/env python3
"""
Secure OHLCV Data Downloader - Core Module
Addresses critical security vulnerabilities from audit SEC-2025-001 through SEC-2025-006
"""

import os
import re
import regex
import json
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Awaitable, TypeVar
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


class SecureOHLCVDownloader:
    """
    Secure OHLCV data downloader with comprehensive input validation,
    path sanitization, and JSON schema validation
    """

    # Valid ticker symbol pattern (alphanumeric, dots, hyphens, underscores)
    TICKER_PATTERN = re.compile(r"^[A-Z0-9._-]{1,10}$")

    # Pre-compiled date pattern with timeout to mitigate ReDoS
    try:
        DATE_PATTERN = regex.compile(r"^\d{4}-\d{2}-\d{2}$", timeout=0.1)
    except Exception:
        DATE_PATTERN = regex.compile(r"^\d{4}-\d{2}-\d{2}$")

    # Pre-compiled pattern for error sanitization with timeout
    try:
        SANITIZE_PATTERN = regex.compile(
            r"(?P<path>/\S+)|(?P<key>key[=:]\s*\S+)|(?P<token>token[=:]\s*\S+)|(?P<password>password[=:]\s*\S+)",
            regex.IGNORECASE,
            timeout=0.05,
        )
    except Exception:
        SANITIZE_PATTERN = regex.compile(
            r"(?P<path>/\S+)|(?P<key>key[=:]\s*\S+)|(?P<token>token[=:]\s*\S+)|(?P<password>password[=:]\s*\S+)",
            regex.IGNORECASE,
        )

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

    # SHA256 fingerprint for Alpha Vantage SSL certificate (example value)
    ALPHA_VANTAGE_FINGERPRINT = os.getenv(
        "ALPHA_VANTAGE_FINGERPRINT",
        "626ab34fbac6f21bd70928a741b93d7c5edda6af032dca527d17bffb8d34e523",
    )

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
        self.rate_limiter = RateLimiter(int(os.getenv("API_RATE", "5")), 60.0)
        self.circuit_breaker = CircuitBreaker(3, 60.0)
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
        def replacer(match: regex.Match[str]) -> str:
            if match.group("path"):
                return "[PATH_REDACTED]"
            if match.group("key"):
                return "key=[REDACTED]"
            if match.group("token"):
                return "token=[REDACTED]"
            if match.group("password"):
                return "password=[REDACTED]"
            return ""

        return self.SANITIZE_PATTERN.sub(replacer, error_message, timeout=0.05)

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
        """
        Validate and sanitize ticker symbol to prevent path traversal

        Args:
            ticker: Raw ticker symbol

        Returns:
            Validated ticker symbol

        Raises:
            ValidationError: If ticker is invalid
        """
        if not ticker:
            raise ValidationError("Ticker symbol cannot be empty")

        # Convert to uppercase and strip whitespace
        ticker = ticker.upper().strip()

        # Validate against pattern
        if not self.TICKER_PATTERN.match(ticker):
            raise ValidationError(
                "Invalid ticker symbol format. Use only alphanumeric characters, dots, hyphens, and underscores"
            )

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
            error_msg = self._sanitize_error(str(e))
            self.logger.error(f"Download failed: {error_msg}")
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
        async def _call() -> pd.DataFrame:
            stock = yf.Ticker(ticker)
            return await asyncio.to_thread(
                stock.history,
                start=start_date,
                end=end_date,
                interval=interval,
            )

        await self.rate_limiter.acquire()
        return await self.circuit_breaker.call(_call)

    def _download_alpha_vantage_secure(self, ticker: str) -> pd.DataFrame:
        """
        Securely download data from Alpha Vantage with JSON validation and
        certificate pinning

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

        url = "https://www.alphavantage.co/query"
        params = {
            "function": "TIME_SERIES_DAILY",
            "symbol": ticker,
            "apikey": api_key,
            "outputsize": "compact",
        }

        try:
            session = self._create_pinned_session(
                "https://www.alphavantage.co", self.ALPHA_VANTAGE_FINGERPRINT
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
