import json
import pytest
from secure_ohlcv_downloader import SecureJSONValidator, SecurityValidationError


class TestJSONValidationLimits:
    """Tests for SecureJSONValidator resource limits."""

    def test_depth_limit_exceeded(self) -> None:
        validator = SecureJSONValidator()
        data: dict = {}
        current = data
        for _ in range(11):
            current["a"] = {}
            current = current["a"]
        with pytest.raises(SecurityValidationError):
            validator.validate_json_with_limits(json.dumps(data), {"type": "object"})

    def test_size_limit_exceeded(self) -> None:
        validator = SecureJSONValidator()
        payload = {f"k{i}": i for i in range(1001)}
        with pytest.raises(SecurityValidationError):
            validator.validate_json_with_limits(json.dumps(payload), {"type": "object"})
