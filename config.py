from __future__ import annotations
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _parse_oct(value: str, default: int) -> int:
    try:
        return int(value, 8)
    except ValueError:
        return default


@dataclass
class GlobalConfig:
    max_api_response_size: int
    max_date_range_days: int
    request_timeout: int
    chunk_size_days: int
    max_memory_mb: int
    dir_permissions: int
    file_permissions: int
    retention_days: int
    cache_ttl: int


def load_global_config(path: Optional[str] = None) -> GlobalConfig:
    """Load configuration from JSON file and environment variables."""
    data = {}
    if path:
        config_path = Path(path)
        if config_path.is_file():
            try:
                data = json.loads(config_path.read_text())
            except (OSError, json.JSONDecodeError):
                data = {}
    env = os.getenv
    return GlobalConfig(
        max_api_response_size=int(
            data.get("max_api_response_size", env("MAX_API_RESPONSE_SIZE", "10485760"))
        ),
        max_date_range_days=int(
            data.get("max_date_range_days", env("MAX_DATE_RANGE_DAYS", "3650"))
        ),
        request_timeout=int(
            data.get("request_timeout", env("REQUEST_TIMEOUT", "30"))
        ),
        chunk_size_days=int(
            data.get("chunk_size_days", env("CHUNK_SIZE_DAYS", "365"))
        ),
        max_memory_mb=int(
            data.get("max_memory_mb", env("MAX_MEMORY_MB", "512"))
        ),
        dir_permissions=_parse_oct(
            str(data.get("dir_permissions", env("DIR_PERMISSIONS", "0o700"))),
            0o700,
        ),
        file_permissions=_parse_oct(
            str(data.get("file_permissions", env("FILE_PERMISSIONS", "0o600"))),
            0o600,
        ),
        retention_days=int(
            data.get("retention_days", env("RETENTION_DAYS", "2555"))
        ),
        cache_ttl=int(
            data.get("cache_ttl", env("CACHE_TTL", "3600"))
        ),
    )

