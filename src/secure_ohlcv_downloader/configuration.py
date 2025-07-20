"""Access configuration and credentials securely."""

import os
from typing import Optional

import keyring
from keyring import errors as keyring_errors

from config import GlobalConfig, load_global_config
from .exceptions import CredentialError


class ConfigurationManager:
    """Provide configuration and credential retrieval."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config = load_global_config(config_path)

    def get_api_key(self, service: str) -> Optional[str]:
        key_name = f"{service.upper()}_API_KEY"
        api_key = os.getenv(key_name)
        if not api_key:
            try:
                api_key = keyring.get_password("ohlcv_downloader", key_name.lower())
            except keyring_errors.KeyringError as exc:
                raise CredentialError(str(exc))
        return api_key

