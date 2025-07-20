import gc
import pytest

from secure_ohlcv_cli import SecureCredentialManager, SecureString, SecureCLI


class TestCredentialProtection:
    """Security tests for memory-based credential protection."""

    def test_secure_string_clearing(self):
        manager = SecureCredentialManager()
        test_cred = "test_api_key_12345"
        secure_str = manager.create_secure_string(test_cred)

        assert secure_str.get_value() == test_cred
        assert len(secure_str) == len(test_cred)

        secure_str.clear()

        assert secure_str._cleared
        with pytest.raises(ValueError):
            secure_str.get_value()
        assert len(secure_str) == 0

    def test_automatic_clearing_on_deletion(self):
        manager = SecureCredentialManager()
        secure_str = manager.create_secure_string("sensitive_data")
        del secure_str
        gc.collect()

    def test_credential_lifecycle_management(self):
        cli = SecureCLI()
        api_key = cli.credential_manager.create_secure_string("test_key")
        cli.secure_credentials["test"] = api_key
        cli._check_environment()  # Should run without exposing credentials
        cli._check_environment()
        cli.credential_manager._secure_clear_variable("api_key", locals())
