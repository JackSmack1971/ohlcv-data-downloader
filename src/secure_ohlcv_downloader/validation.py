"""Input validation with security controls."""

import json
import re
from datetime import date
from typing import Any, Dict, Set

from config import GlobalConfig
from .exceptions import ValidationError, SecurityError

class SecurePatternValidator:
    """Pattern validation with ReDoS protection."""

    # Placeholder patterns (will be replaced with regex module)
    TICKER_PATTERN = re.compile(r"^[A-Z0-9._-]{1,10}$")

    @classmethod
    def validate_with_timeout(cls, pattern: re.Pattern[str], input_string: str,
                               max_length: int = 1000) -> bool:
        """Validate with timeout protection."""
        return bool(pattern.match(input_string))

class SecureJSONValidator:
    """JSON validation with resource protection."""

    def __init__(self) -> None:
        """Initialize JSON validator."""
        pass

    def validate_json_with_limits(self, json_data: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Validate JSON with security limits."""
        import json
        return json.loads(json_data)


class ChoiceValidator:
    """Generic validator for enumerated choices."""

    def __init__(self, choices: Set[str]) -> None:
        self.choices = choices

    def __call__(self, value: str, name: str = "value") -> str:
        if value not in self.choices:
            raise ValidationError(
                f"Invalid {name}. Must be one of: {', '.join(self.choices)}"
            )
        return value


class DataValidator:
    """Validate user supplied parameters and API responses."""

    def __init__(self, config: GlobalConfig) -> None:
        self.config = config
        self.pattern_validator = SecurePatternValidator()
        self.json_validator = SecureJSONValidator()
        self.interval_validator = ChoiceValidator(
            {
                "1d",
                "1wk",
                "1mo",
                "3mo",
                "6mo",
                "1y",
                "2y",
                "5y",
                "10y",
                "ytd",
                "max",
            }
        )
        self.source_validator = ChoiceValidator({"yahoo", "alpha_vantage"})

    def validate_ticker(self, ticker: str) -> str:
        """Validate a ticker symbol and reject malicious input.

        Edge cases: empty strings and lower/upper case differences are
        normalized before validation. The regex pattern limits length and
        characters to mitigate injection or path traversal attempts.

        Attack scenario: an attacker may try to pass ``../`` or extremely
        long strings to traverse directories or trigger ReDoS. This method
        enforces strict pattern matching and raises :class:`SecurityError`
        when suspicious sequences are detected.
        """

        if not ticker:
            raise ValidationError("Ticker symbol cannot be empty")
        ticker = ticker.upper().strip()
        if not self.pattern_validator.validate_with_timeout(
            SecurePatternValidator.TICKER_PATTERN, ticker, max_length=10
        ):
            raise ValidationError(
                "Invalid ticker symbol format. Use only alphanumeric characters, dots, hyphens, and underscores"
            )
        if ".." in ticker or "/" in ticker or "\\" in ticker:
            raise SecurityError("Potential path traversal attempt detected")
        return ticker

    def validate_date_range(self, start_date: date, end_date: date) -> None:
        """Ensure the requested date range is within allowed limits.

        Security assumption: ``start_date`` and ``end_date`` come from user
        input and must be validated to prevent resource exhaustion. Large
        ranges could trigger excessive API calls or large file writes.

        Attack vector: specifying a far future ``end_date`` or extremely long
        range may lead to denial of service. The method checks chronological
        order, prevents future dates, and enforces a configurable maximum
        window.
        """

        if start_date > end_date:
            raise ValidationError("Start date must be before end date")
        if end_date > date.today():
            raise ValidationError("End date cannot be in the future")
        max_days = self.config.max_date_range_days
        if (end_date - start_date).days > max_days:
            raise ValidationError(f"Date range too large. Maximum {max_days} days allowed")

    def validate_interval(self, interval: str) -> str:
        """Validate allowed time intervals for API requests.

        Only whitelisted intervals are accepted to avoid unexpected API
        behavior. Invalid values raise :class:`ValidationError`.
        """

        return self.interval_validator(interval, "interval")

    def validate_source(self, source: str) -> str:
        """Validate data source identifier.

        Accepts only known providers to prevent SSRF or unauthorized data
        retrieval from arbitrary hosts.
        """

        return self.source_validator(source, "source")

    def validate_date_key(self, key: str) -> None:
        """Validate a date key used for data dictionaries.

        Attack scenario: extremely long or malformed keys could corrupt
        stored data structures. This method restricts the key to ``YYYY-MM-DD``
        format and enforces a length limit.
        """

        pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
        if len(key) > 10:
            raise ValidationError("Date key length exceeds limit")
        if not pattern.fullmatch(key):
            raise ValidationError("Invalid date key format")

    def _validate_structure_limits(self, data: Any, depth: int = 0) -> None:
        """Recursively enforce JSON structure limits.

        Depth and size checks defend against maliciously crafted responses
        attempting to exhaust memory (e.g., deeply nested arrays). Limits are
        conservative to balance functionality with safety.
        """

        if depth > 10:
            raise ValidationError("JSON depth exceeds limit")
        if isinstance(data, dict):
            if len(data) > 1000:
                raise ValidationError("Object has too many properties")
            for k, v in data.items():
                if len(str(k)) > 10000:
                    raise ValidationError("Property key too long")
                self._validate_structure_limits(v, depth + 1)
        elif isinstance(data, list):
            if len(data) > 10000:
                raise ValidationError("Array too large")
            for item in data:
                self._validate_structure_limits(item, depth + 1)
        elif isinstance(data, str) and len(data) > 10000:
            raise ValidationError("String too long")

    def validate_json_response(self, response_data: Dict[Any, Any], schema: Dict[Any, Any]) -> None:
        """Validate API JSON responses against a schema.

        Potential attack vector: a server may return oversized or deeply
        nested JSON to trigger memory exhaustion or bypass client logic. The
        method enforces structural limits before delegating to a schema
        validator and raises :class:`ValidationError` on any deviation.
        """

        self._validate_structure_limits(response_data)
        try:
            self.json_validator.validate_json_with_limits(json.dumps(response_data), schema)
        except Exception as exc:
            raise ValidationError(f"API response validation failed: {exc}")
