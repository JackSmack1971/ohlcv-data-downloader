"""Pytest configuration with security fixtures."""

from pathlib import Path
import tempfile
import pytest

@pytest.fixture(scope="session")
def secure_tmp_path() -> Path:
    """Provide a temporary directory for security-related tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)
