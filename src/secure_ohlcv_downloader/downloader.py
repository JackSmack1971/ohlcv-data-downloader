"""Main secure OHLCV downloader implementation."""

import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from config import GlobalConfig
from .api_client import APIClient
from .configuration import ConfigurationManager
from .encryption import EncryptionManager
from .exceptions import CredentialError, SecurityError, ValidationError
from .file_manager import FileManager
from .validation import DataValidator


class SecureOHLCVDownloader:
    """Main downloader class orchestrating components."""

    def __init__(self, output_dir: str) -> None:
        self.config_manager = ConfigurationManager()
        self.config: GlobalConfig = self.config_manager.config
        self.output_dir = Path(output_dir)
        self.encryption = EncryptionManager()
        self.validator = DataValidator(self.config)
        self.file_manager = FileManager(self.config, self.encryption)
        self.api_client = APIClient(cert_manager=None)  # certificate manager placeholder

    def _create_pinned_session(self, host: str, fingerprint: str):
        return self.api_client.create_pinned_session(host, fingerprint)

    def _validate_interval(self, interval: str) -> str:
        return self.validator.validate_interval(interval)

    def _validate_source(self, source: str) -> str:
        return self.validator.validate_source(source)

    def _validate_date_key(self, key: str) -> None:
        self.validator.validate_date_key(key)

    def _create_secure_path(self, ticker: str, date_range: str) -> Path:
        return self.file_manager.create_secure_path(ticker, date_range, self.output_dir)

    def _get_api_key(self, service: str):
        return self.config_manager.get_api_key(service)

    def _validate_date_range(self, start_date, end_date) -> None:
        self.validator.validate_date_range(start_date, end_date)

    def _sanitize_error(self, msg: str) -> str:  # simplified from original
        return msg.replace("/", "[PATH_REDACTED]")

    async def cleanup_expired_data(self, days: int) -> None:
        """Remove files older than *days* from the output directory."""
        root = (self.output_dir / "data").resolve()
        logger = logging.getLogger(__name__)
        if not root.exists():
            return

        cutoff = (datetime.now() - timedelta(days=days)).timestamp()
        removed = 0
        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                if file_path.stat().st_mtime < cutoff:
                    await self.file_manager.remove_path(file_path)
                    removed += 1
            except OSError as exc:
                logger.warning("Failed to remove %s: %s", file_path, self._sanitize_error(str(exc)))

        for directory in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
            try:
                if not any(directory.iterdir()):
                    await self.file_manager.remove_path(directory)
            except OSError as exc:
                logger.warning("Failed to clean directory %s: %s", directory, self._sanitize_error(str(exc)))

        logger.info("Cleanup removed %d expired files", removed)


