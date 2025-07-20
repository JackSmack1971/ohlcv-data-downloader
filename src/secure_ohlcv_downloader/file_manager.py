"""Secure file system operations."""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from config import GlobalConfig
from .encryption import EncryptionManager
from .exceptions import SecurityError


class FileManager:
    """Handle secure file storage."""

    def __init__(self, config: GlobalConfig, enc: EncryptionManager) -> None:
        self.config = config
        self.encryption = enc

    def create_secure_path(self, ticker: str, date_range: str, output_dir: Path) -> Path:
        output_root = output_dir.resolve()
        target_dir = output_root / "data" / ticker / date_range
        resolved = target_dir.resolve() if target_dir.exists() else target_dir
        if not str(resolved).startswith(str(output_root)):
            raise SecurityError("Path traversal attempt detected before creation")
        tmp_dir = Path(tempfile.mkdtemp(dir=str(output_root)))
        try:
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp_dir, target_dir)
            os.chmod(target_dir, self.config.dir_permissions)
            final_resolved = target_dir.resolve()
            if not str(final_resolved).startswith(str(output_root)):
                raise SecurityError("Path traversal attempt detected after creation")
            return target_dir
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def save_encrypted(self, data: bytes, file_path: Path) -> None:
        encrypted = await asyncio.to_thread(self.encryption.encrypt, data)
        async with asyncio.Lock():
            with open(file_path, "wb") as f:
                f.write(encrypted)
        os.chmod(file_path, self.config.file_permissions)

    def calculate_checksum(self, path: Path) -> str:
        import hashlib

        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    async def remove_path(self, path: Path) -> None:
        if path.is_dir():
            await asyncio.to_thread(shutil.rmtree, path)
        else:
            await asyncio.to_thread(path.unlink)

