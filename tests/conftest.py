import pytest
import tempfile
import asyncio
from pathlib import Path

@pytest.fixture
def temp_directory():
    """Provide temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)

@pytest.fixture
def mock_config():
    """Provide mock configuration for testing."""
    return {
        'security': {
            'certificate_validation': True,
            'input_validation': True,
            'memory_protection': True
        }
    }

@pytest.fixture
async def async_client():
    """Provide async client for testing."""
    # Mock async client implementation
    yield None

@pytest.fixture(scope="session")
def secure_tmp_path() -> Path:
    """Provide a temporary directory for security-related tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)

# Add more fixtures as needed for security testing
