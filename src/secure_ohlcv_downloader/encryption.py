"""Encryption utilities using Fernet symmetric encryption."""

import os
from cryptography.fernet import Fernet, InvalidToken

from .exceptions import SecurityError


class EncryptionManager:
    """Encrypt and decrypt byte strings securely."""

    def __init__(self) -> None:
        """Initialize the encryption context.

        Security assumption: the symmetric key is provided via the
        ``OHLCV_ENCRYPTION_KEY`` environment variable. If absent, a new key
        is generated at runtime which limits decryption to the current
        session only.
        """
        key = os.getenv("OHLCV_ENCRYPTION_KEY")
        if not key:
            key = Fernet.generate_key().decode()
        self.cipher = Fernet(key.encode())

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt *data* using Fernet.

        Attack scenario: encryption failures may leak plaintext if not
        handled. Exceptions are trapped and re-raised as
        :class:`SecurityError` to avoid exposing implementation details.
        """
        try:
            return self.cipher.encrypt(data)
        except Exception as exc:  # pragma: no cover - library errors
            raise SecurityError(str(exc))

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt *data* using Fernet.

        Invalid or tampered ciphertext raises :class:`SecurityError` to
        prevent attackers from gleaning information through error messages.
        """
        try:
            return self.cipher.decrypt(data)
        except InvalidToken as exc:
            raise SecurityError("Decryption failed") from exc
