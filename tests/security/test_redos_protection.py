import pytest
import time
from secure_ohlcv_downloader import SecurePatternValidator, SecurityValidationError


class TestReDoSProtection:
    """Security tests for ReDoS protection mechanisms."""

    def test_ticker_validation_timeout(self):
        """Ticker validation should timeout on malicious input."""
        malicious_input = "A" * 1000 + "!" * 1000
        start_time = time.time()
        with pytest.raises(SecurityValidationError):
            SecurePatternValidator.validate_with_timeout(
                SecurePatternValidator.TICKER_PATTERN,
                malicious_input,
            )
        elapsed = time.time() - start_time
        assert elapsed < 1.0, "Validation should timeout quickly"

    def test_pattern_consistency(self):
        """All patterns must have a timeout set."""
        patterns = [
            SecurePatternValidator.TICKER_PATTERN,
            SecurePatternValidator.DATE_PATTERN,
        ]
        for pattern in patterns:
            assert hasattr(pattern, "timeout")
            assert pattern.timeout == 0.1
