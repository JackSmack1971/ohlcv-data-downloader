import json
import os
from datetime import date, timedelta
import pytest

from secure_ohlcv_downloader import SecureOHLCVDownloader, ValidationError
from config import load_global_config


def test_env_config_override(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_DATE_RANGE_DAYS", "1")
    dl = SecureOHLCVDownloader(str(tmp_path))
    start = date.today() - timedelta(days=2)
    end = date.today()
    with pytest.raises(ValidationError):
        dl._validate_date_range(start, end)


def test_file_config_loading(tmp_path, monkeypatch):
    config_data = {
        "max_api_response_size": 1,
        "max_date_range_days": 2,
        "request_timeout": 5,
        "dir_permissions": "0700",
        "file_permissions": "0600",
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config_data))
    monkeypatch.setenv("OHLCV_CONFIG_FILE", str(config_path))
    cfg = load_global_config(str(config_path))
    assert cfg.max_date_range_days == 2
    dl = SecureOHLCVDownloader(str(tmp_path))
    assert dl.config.max_date_range_days == 2

