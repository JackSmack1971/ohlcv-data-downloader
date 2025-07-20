import pytest
from secure_ohlcv_downloader import SecurityExceptionHandler

class TestExceptionSanitization:
    """Security tests for exception context sanitization."""

    def test_sensitive_data_removal(self):
        handler = SecurityExceptionHandler()
        sensitive_message = "API key abc123 failed at /home/user/secret/file.py"
        exc = ValueError(sensitive_message)
        sanitized = handler.sanitize_exception_context(exc)
        assert 'abc123' not in sanitized['error_message']
        assert '/home/user' not in sanitized['error_message']
        assert '[REDACTED]' in sanitized['error_message']

    def test_stack_trace_sanitization(self):
        handler = SecurityExceptionHandler()
        try:
            raise ValueError("Test exception")
        except Exception as e:
            sanitized = handler.sanitize_exception_context(e, include_traceback=True)
            for line in sanitized['traceback']:
                assert '/home/' not in line
                assert 'C:\\Users\\' not in line

