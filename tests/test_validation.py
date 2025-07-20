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


def test_sanitize_error_password(tmp_path):
    dl = create_downloader(tmp_path)
    error = dl._sanitize_error("/tmp/secret.txt password=supersecret")
    assert "password=[REDACTED]" in error
    assert "supersecret" not in error


def test_sanitize_error_function():
    from utils import sanitize_error

    msg = "/home/user/data key=mykey token=abc password=secret"
    sanitized = sanitize_error(msg)
    assert "[PATH_REDACTED]" in sanitized
    assert "key=[REDACTED]" in sanitized
    assert "token=[REDACTED]" in sanitized
    assert "password=[REDACTED]" in sanitized


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

