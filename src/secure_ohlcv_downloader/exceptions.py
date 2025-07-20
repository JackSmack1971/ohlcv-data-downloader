"""Security-focused exception classes."""

class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass

class ValidationError(SecurityError):
    """Exception for validation failures."""
    pass

class SecurityValidationError(ValidationError):
    """Exception for security validation failures."""
    pass

class JSONValidationError(ValidationError):
    """Exception for JSON validation failures."""
    pass

class FileLockError(SecurityError):
    """Exception for file locking errors."""
    pass

class FileLockTimeoutError(FileLockError):
    """Exception for file lock timeouts."""
    pass
