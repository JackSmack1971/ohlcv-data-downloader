import pytest
from secure_ohlcv_downloader import SecureOHLCVDownloader, ValidationError, SecurityError


def create_downloader(tmp_path):
    return SecureOHLCVDownloader(str(tmp_path))


def test_sanitize_error(tmp_path):
    dl = create_downloader(tmp_path)
    error = dl._sanitize_error("/tmp/secret.txt key=abcdef token=123")
    assert "[PATH_REDACTED]" in error
    assert "abcdef" not in error
    assert "token=[REDACTED]" in error


def test_validate_interval_invalid(tmp_path):
    dl = create_downloader(tmp_path)
    with pytest.raises(ValidationError):
        dl._validate_interval("bad")


def test_validate_source_invalid(tmp_path):
    dl = create_downloader(tmp_path)
    with pytest.raises(ValidationError):
        dl._validate_source("badsource")


def test_validate_date_key_length(tmp_path):
    dl = create_downloader(tmp_path)
    with pytest.raises(ValidationError):
        dl._validate_date_key("2024-01-011")


def test_validate_date_key_format(tmp_path):
    dl = create_downloader(tmp_path)
    with pytest.raises(ValidationError):
        dl._validate_date_key("2024/01/01")

