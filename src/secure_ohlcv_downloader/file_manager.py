"""Secure file system operations."""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import aiofiles

from config import GlobalConfig
from .encryption import EncryptionManager
from .exceptions import SecurityError, FileLockTimeoutError
from .file_lock import CrossPlatformFileLockManager


class FileManager:
    """Handle secure file storage."""

    def __init__(self, config: GlobalConfig, enc: EncryptionManager) -> None:
        self.config = config
        self.encryption = enc
        self.lock_manager = CrossPlatformFileLockManager()

    def create_secure_path(self, ticker: str, date_range: str, output_dir: Path) -> Path:
        """Create a sanitized directory for downloaded data.

        The path is validated to prevent directory traversal by confirming
        the resolved path remains under ``output_dir`` both before and after
        creation. A temporary directory and file lock are used to mitigate
        race conditions during directory setup.
        """
        output_root = output_dir.resolve()
        target_dir = output_root / "data" / ticker / date_range
        resolved = target_dir.resolve() if target_dir.exists() else target_dir
        if not str(resolved).startswith(str(output_root)):
            raise SecurityError("Path traversal attempt detected before creation")

        tmp_dir = Path(tempfile.mkdtemp(dir=str(output_root)))
        lock_file = str(target_dir) + ".lock"
        try:
            with self.lock_manager.secure_file_lock(lock_file, timeout=5.0):
                target_dir.parent.mkdir(parents=True, exist_ok=True)
                os.replace(tmp_dir, target_dir)
                os.chmod(target_dir, self.config.dir_permissions)
                final_resolved = target_dir.resolve()
                if not str(final_resolved).startswith(str(output_root)):
                    raise SecurityError("Path traversal attempt detected after creation")
                return target_dir
        except FileLockTimeoutError as exc:
            raise SecurityError(f"Unable to acquire lock for {target_dir}") from exc
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def save_encrypted(self, data: bytes, file_path: Path) -> None:
        """Encrypt and persist data asynchronously.

        Attack scenario: writing unencrypted sensitive data to disk. Data is
        encrypted in a background thread prior to being written. File
        permissions are hardened after writing to reduce exposure.
        """
        encrypted = await asyncio.to_thread(self.encryption.encrypt, data)
        async with asyncio.Lock():
            async with aiofiles.open(file_path, "wb") as f:
                await f.write(encrypted)
        await asyncio.to_thread(os.chmod, file_path, self.config.file_permissions)

    async def calculate_checksum(self, path: Path) -> str:
        """Return a SHA-256 checksum for *path* without loading entire file."""
        import hashlib

        h = hashlib.sha256()
        async with aiofiles.open(path, "rb") as f:
            while True:
                chunk = await f.read(4096)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    async def remove_path(self, path: Path) -> None:
        """Remove a file or directory securely.

        Uses background threads to avoid blocking the event loop and ensures
        both files and directories are handled correctly.
        """
        if path.is_dir():
            await asyncio.to_thread(shutil.rmtree, path)
        else:
            await asyncio.to_thread(path.unlink)

