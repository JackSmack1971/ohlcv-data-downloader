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
from typing import Optional, Dict, Any
from datetime import datetime, date
from dataclasses import dataclass
import pandas as pd
import yfinance as yf
import requests
from jsonschema import validate
from cryptography.fernet import Fernet, InvalidToken
from io import BytesIO
from keyring import errors as keyring_errors
import keyring
from keyrings.alt.file import PlaintextKeyring
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


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


class ValidationError(Exception):
    """Custom exception for validation errors"""

    pass


class SecureOHLCVDownloader:
    """
    Secure OHLCV data downloader with comprehensive input validation,
    path sanitization, and JSON schema validation
    """

    # Valid ticker symbol pattern (alphanumeric, dots, hyphens, underscores)
    TICKER_PATTERN = re.compile(r"^[A-Z0-9._-]{1,10}$")

    # Pre-compiled date pattern with timeout to mitigate ReDoS
    DATE_PATTERN = regex.compile(r"^\d{4}-\d{2}-\d{2}$", timeout=0.1)

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

    def __init__(self, output_dir: str = "/home/user/output"):
        """
        Initialize secure OHLCV downloader

        Args:
            output_dir: Base directory for output files
        """
        self.output_dir = Path(output_dir).resolve()
        self._setup_logging()
        self._setup_encryption()
        self._validate_output_directory()

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
            # Set restrictive permissions (owner read/write/execute only)
            os.chmod(self.output_dir, 0o700)
        except Exception as e:
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

            return pd.read_csv(BytesIO(decrypted), index_col=0)
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
        # Remove file paths, API keys, and other sensitive information
        sanitized = re.sub(r"/[^\s]*", "[PATH_REDACTED]", error_message)
        sanitized = re.sub(
            r"key[=:]\s*[^\s]+", "key=[REDACTED]", sanitized, flags=re.IGNORECASE
        )
        sanitized = re.sub(
            r"token[=:]\s*[^\s]+", "token=[REDACTED]", sanitized, flags=re.IGNORECASE
        )
        sanitized = re.sub(
            r"password[=:]\s*[^\s]+",
            "password=[REDACTED]",
            sanitized,
            flags=re.IGNORECASE,
        )

        return sanitized

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
        max_days = 3650  # 10 years
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
        # Create path components
        ticker_dir = self.output_dir / "data" / ticker / date_range

        # Resolve path and validate it's within output directory
        resolved_path = ticker_dir.resolve()

        if not str(resolved_path).startswith(str(self.output_dir.resolve())):
            raise SecurityError("Path traversal attempt detected")

        # Create directory with secure permissions
        resolved_path.mkdir(parents=True, exist_ok=True)
        os.chmod(resolved_path, 0o700)

        return resolved_path

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
        except Exception as e:
            raise ValidationError(
                f"API response validation failed: {self._sanitize_error(str(e))}"
            )

    def _get_api_key(self, service: str) -> Optional[str]:
        """
        Securely retrieve API key from environment variables

        Args:
            service: Service name (alpha_vantage, polygon)

        Returns:
            API key if available, None otherwise
        """
        key_name = f"{service.upper()}_API_KEY"
        api_key = os.getenv(key_name)

        if api_key:
            self.logger.info(f"API key found for {service}")
        else:
            self.logger.warning(
                f"No API key found for {service} in environment variable {key_name}"
            )

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
            if source == "yahoo":
                data = self._download_yahoo_secure(
                    ticker, config.start_date, config.end_date, interval
                )
            elif source == "alpha_vantage":
                data = self._download_alpha_vantage_secure(ticker)
            else:
                raise ValidationError(f"Unsupported source: {source}")

            # Save data securely
            filename = f"{ticker}_{source}.csv"
            file_path = output_path / filename

            if config.encrypt_data:
                self._save_encrypted_data(data, file_path)
            else:
                data.to_csv(file_path, index=True)

            # Set secure file permissions
            os.chmod(file_path, 0o600)

            # Create metadata
            self._create_metadata(config, output_path, len(data))

            self.logger.info(f"Download completed successfully: {len(data)} records")
            return file_path

        except Exception as e:
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
            stock = yf.Ticker(ticker)
            data = stock.history(start=start_date, end=end_date, interval=interval)

            if data.empty:
                raise ValidationError("No data returned from Yahoo Finance")

            # Validate data structure
            expected_columns = {"Open", "High", "Low", "Close", "Volume"}
            if not expected_columns.issubset(data.columns):
                raise ValidationError("Invalid data structure from Yahoo Finance")

            return data

        except Exception as e:
            raise ValidationError(
                f"Yahoo Finance download failed: {self._sanitize_error(str(e))}"
            )

    def _download_alpha_vantage_secure(self, ticker: str) -> pd.DataFrame:
        """
        Securely download data from Alpha Vantage with JSON validation

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
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()

            # Validate response size (prevent memory exhaustion)
            if len(response.content) > 10 * 1024 * 1024:  # 10MB limit
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
        os.chmod(metadata_path, 0o600)

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
