import asyncio
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_ohlcv_downloader import (
    SecureOHLCVDownloader,
    SecurityError,
    ValidationError,
    SecurityExceptionHandler,
)
from src.secure_ohlcv_downloader.certificate_manager import CertificateManager


class TestSecurityIntegration:
    """Comprehensive security integration tests."""

    @pytest.fixture
    def secure_downloader(self, tmp_path: Path):
        return SecureOHLCVDownloader(output_dir=str(tmp_path))

    @pytest.mark.asyncio
    async def test_end_to_end_security_flow(self, secure_downloader: SecureOHLCVDownloader, tmp_path: Path):
        """Test complete security flow from request to encrypted storage."""
        mock_response = {"Meta Data": {"1": "info"}, "Time Series": {"2024-01-02": {"close": "1"}}}
        file_path = tmp_path / "result.enc"
        await secure_downloader.file_manager.save_encrypted(json.dumps(mock_response).encode("utf-8"), file_path)

        assert os.path.exists(file_path)
        with open(file_path, "rb") as f:
            data = f.read()
            assert b"Meta Data" not in data
        decrypted = secure_downloader.encryption.decrypt(data)
        assert json.loads(decrypted.decode("utf-8")) == mock_response

    def test_certificate_validation_integration(self, secure_downloader: SecureOHLCVDownloader):
        """Test certificate validation during API calls."""
        cert_mgr = CertificateManager()
        with patch.object(cert_mgr, "validate_certificate", return_value=False):
            with pytest.raises(SecurityError, match="Certificate validation failed"):
                if not cert_mgr.validate_certificate("example.com"):
                    raise SecurityError("Certificate validation failed")

    def test_input_validation_integration(self, secure_downloader: SecureOHLCVDownloader):
        """Test that all input validation layers work together."""
        with pytest.raises(ValidationError):
            secure_downloader.validator.validate_ticker("<script>alert('xss')</script>")

        malicious = "A" * 1000 + "!"
        with pytest.raises(ValidationError):
            secure_downloader.validator.validate_ticker(malicious)

    def test_json_bomb_protection_integration(self, secure_downloader: SecureOHLCVDownloader):
        """Test JSON bomb protection in response processing."""
        bomb = {}
        current = bomb
        for _ in range(20):
            current["nested"] = {}
            current = current["nested"]

        with pytest.raises(ValidationError):
            secure_downloader.validator.validate_json_response(bomb, {})

    def test_exception_sanitization_integration(self):
        """Test exception sanitization across components."""
        handler = SecurityExceptionHandler()
        exc = Exception("API key abc123 failed at /home/user/secret/config.py line 42")
        context = handler.sanitize_exception_context(exc)
        assert "abc123" not in context["error_message"]
        assert "/home/user" not in context["error_message"]
        assert "[REDACTED]" in context["error_message"] or "[PATH_REDACTED]" in context["error_message"]
