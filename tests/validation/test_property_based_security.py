import json

from hypothesis import given, strategies as st

from secure_ohlcv_downloader import SecureJSONValidator
from src.secure_ohlcv_downloader.validation import DataValidator, ValidationError
from config import load_global_config


class TestPropertyBasedSecurity:
    """Property-based security tests using Hypothesis."""

    @given(ticker=st.text(min_size=1, max_size=50))
    def test_ticker_validation_properties(self, ticker: str):
        """Test ticker validation with random inputs."""
        validator = DataValidator(load_global_config())

        try:
            result = validator.validate_ticker(ticker)
            if result:
                assert len(result) <= 10
                assert result.isupper()
                assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in result)
        except ValidationError:
            pass

    @given(
        json_data=st.recursive(
            st.one_of(
                st.booleans(),
                st.integers(),
                st.floats(allow_nan=False, allow_infinity=False),
                st.text(max_size=100),
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=10),
                st.dictionaries(st.text(max_size=20), children, max_size=10),
            ),
            max_leaves=50,
        )
    )
    def test_json_validation_properties(self, json_data):
        """Test JSON validation with random nested structures."""
        validator = SecureJSONValidator()
        json_string = json.dumps(json_data)

        try:
            result = validator.validate_json_with_limits(json_string, {})
            if result:
                self._verify_json_structure_limits(result)
        except ValidationError:
            pass

    def _verify_json_structure_limits(self, data, depth: int = 0):
        assert depth <= 10
        if isinstance(data, dict):
            assert len(data) <= 1000
            for key, value in data.items():
                assert len(str(key)) <= 10000
                self._verify_json_structure_limits(value, depth + 1)
        elif isinstance(data, list):
            assert len(data) <= 10000
            for item in data:
                self._verify_json_structure_limits(item, depth + 1)
        elif isinstance(data, str):
            assert len(data) <= 10000
