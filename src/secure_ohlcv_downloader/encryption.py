"""Encryption utilities using Fernet symmetric encryption."""

import os
from cryptography.fernet import Fernet, InvalidToken

from .exceptions import SecurityError


class EncryptionManager:
    """Encrypt and decrypt byte strings securely."""

    def __init__(self) -> None:
        key = os.getenv("OHLCV_ENCRYPTION_KEY")
        if not key:
            key = Fernet.generate_key().decode()
        self.cipher = Fernet(key.encode())

    def encrypt(self, data: bytes) -> bytes:
        try:
            return self.cipher.encrypt(data)
        except Exception as exc:  # pragma: no cover - library errors
            raise SecurityError(str(exc))

    def decrypt(self, data: bytes) -> bytes:
        try:
            return self.cipher.decrypt(data)
        except InvalidToken as exc:
            raise SecurityError("Decryption failed") from exc
