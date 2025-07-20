import regex
from typing import Match

try:
    SANITIZE_PATTERN = regex.compile(
        r"(?P<path>/\S+)|(?P<key>key[=:]\s*\S+)|(?P<token>token[=:]\s*\S+)|(?P<password>password[=:]\s*\S+)",
        regex.IGNORECASE,
        timeout=0.05,
    )
except Exception:
    SANITIZE_PATTERN = regex.compile(
        r"(?P<path>/\S+)|(?P<key>key[=:]\s*\S+)|(?P<token>token[=:]\s*\S+)|(?P<password>password[=:]\s*\S+)",
        regex.IGNORECASE,
    )


def sanitize_error(error_message: str) -> str:
    """Sanitize error messages to prevent information disclosure."""

    def replacer(match: Match[str]) -> str:
        if match.group("path"):
            return "[PATH_REDACTED]"
        if match.group("key"):
            return "key=[REDACTED]"
        if match.group("token"):
            return "token=[REDACTED]"
        if match.group("password"):
            return "password=[REDACTED]"
        return ""

    try:
        return SANITIZE_PATTERN.sub(replacer, error_message, timeout=0.05)
    except regex.TimeoutError:
        return "[SANITIZE_TIMEOUT]"
