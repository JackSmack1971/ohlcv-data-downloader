# AGENTS.md - Security Audit Remediation Guide

## Project Overview

This is a financial data security application that downloads and processes OHLCV (Open, High, Low, Close, Volume) market data with enterprise-grade security controls. The recent security audit (2025-007 through PERF-2025-003) identified **17 findings** requiring immediate attention, with **2 CRITICAL** and **5 HIGH** severity issues.

### Repository Structure
```
├── secure_ohlcv_downloader.py  # Core security-focused downloader
├── secure_ohlcv_cli.py         # Command-line interface
├── security_test_demo.py       # Security validation tests
├── AGENTS.md                   # This file - agent guidance
└── requirements.txt            # Dependencies
```

## Critical Security Context

### Immediate Priority Issues (Fix First)
1. **SEC-2025-007 (CRITICAL)**: Encryption key persistence failure - data becomes permanently unrecoverable
2. **SEC-2025-008 (CRITICAL)**: ReDoS vulnerability in JSON schema validation
3. **SEC-2025-009 (HIGH)**: API keys exposed in process environment
4. **SEC-2025-010 (HIGH)**: TOCTOU race condition in path validation
5. **SEC-2025-011 (HIGH)**: Missing SSL certificate verification

### Financial Data Compliance Requirements
- **SOX Compliance**: Data integrity, access controls, audit trails
- **GDPR**: Data minimization, processing records, availability
- **PCI-DSS**: Credential protection, secure transmission, logging

## Development Guidelines

### Security-First Approach
- **Fail Secure**: All security controls must fail to a secure state
- **Defense in Depth**: Multiple layers of protection for each vulnerability
- **Least Privilege**: Minimal necessary permissions and access
- **Zero Trust**: Validate all inputs, encrypt all data, verify all operations

### Code Quality Standards
- **Type Hints**: All functions must include complete type annotations
- **Error Handling**: Use specific custom exceptions, never catch generic `Exception`
- **Input Validation**: Validate and sanitize all external data sources
- **Logging**: Comprehensive audit trails for all security-relevant operations

### Performance Considerations
- **Memory Management**: Stream large datasets, don't load entirely into memory
- **API Efficiency**: Implement rate limiting, caching, and circuit breakers
- **Regex Safety**: Use compiled patterns, implement timeouts for regex operations

## Implementation Instructions

### 1. Encryption Key Management (SEC-2025-007)
**Location**: `secure_ohlcv_downloader.py:119-126` - `_setup_encryption` method

**Current Problem**: 
```python
# BROKEN: Key generated but never persisted
self.cipher = Fernet(Fernet.generate_key())
logger.warning("Generated new encryption key")
```

**Required Implementation**:
- Use `keyring` library for secure OS-level key storage
- Implement key recovery mechanism for operational continuity
- Add key rotation capabilities with backward compatibility
- Fail fast if key cannot be securely stored or retrieved

**Test Validation**: 
- Verify encrypted data remains accessible after process restart
- Test key recovery mechanisms
- Validate key rotation preserves existing data access

### 2. ReDoS Protection (SEC-2025-008)
**Location**: `secure_ohlcv_downloader.py:61-77` - `ALPHA_VANTAGE_SCHEMA`

**Current Problem**: 
```python
# VULNERABLE: Could allow ReDoS attacks
"pattern": r'^\\d{4}-\\d{2}-\\d{2}$'
```

**Required Implementation**:
- Add regex timeout limits using `signal` module or `regex` library
- Pre-compile all regex patterns for performance
- Implement input size limits before validation
- Consider alternative validation approaches (datetime parsing)

### 3. Secure Credential Management (SEC-2025-009)
**Location**: `secure_ohlcv_cli.py:117-125` - `_prompt_for_api_keys`

**Current Problem**:
```python
# INSECURE: Credentials stored in process environment
os.environ['ALPHA_VANTAGE_API_KEY'] = api_key
```

**Required Implementation**:
- Use `keyring` library for credential storage
- Implement memory-only credential handling during execution
- Clear any temporary credential storage immediately after use
- Add secure credential validation without exposure

### 4. Race Condition Prevention (SEC-2025-010)
**Location**: `secure_ohlcv_downloader.py:229-239` - `_create_secure_path`

**Current Problem**:
```python
# TOCTOU: Gap between validation and creation
if not resolved_path.is_relative_to(output_dir):
    # ... time gap here ...
resolved_path.mkdir(parents=True, exist_ok=True)
```

**Required Implementation**:
- Use atomic operations with `tempfile.mkdtemp`
- Implement filesystem locks using `fcntl` (Unix) or `msvcrt` (Windows)
- Re-validate path after creation
- Use context managers for safe resource handling

### 5. SSL Certificate Verification (SEC-2025-011)
**Location**: `secure_ohlcv_downloader.py:336` - `_download_alpha_vantage_secure`

**Current Problem**:
```python
# INSECURE: No explicit SSL verification
response = requests.get(url, timeout=30)
```

**Required Implementation**:
- Add explicit SSL verification: `verify=True`
- Implement certificate pinning for known APIs
- Configure custom SSL context with security parameters
- Add certificate validation error handling

## Configuration Management Strategy

### Externalize All Hardcoded Values
Replace these hardcoded values with configuration:
```python
# Current hardcoded values to externalize:
MAX_API_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_DATE_RANGE_DAYS = 3650  # 10 years
DEFAULT_TIMEOUT = 30  # seconds
SECURE_DIR_PERMISSIONS = 0o700
SECURE_FILE_PERMISSIONS = 0o600
MIN_DATE = datetime(1900, 1, 1)
```

**Implementation**: Create `config.yaml` with environment-specific overrides and validation.

### Environment Variables Strategy
```python
# Secure environment variable handling
REQUIRED_VARS = ['OHLCV_ENCRYPTION_KEY', 'ALPHA_VANTAGE_API_KEY']
OPTIONAL_VARS = ['OHLCV_LOG_LEVEL', 'OHLCV_CACHE_DIR']
```

## Testing Requirements

### Security Test Expansion
**Location**: Expand `security_test_demo.py`

**Required Test Categories**:
1. **Encryption Tests**: Key persistence, data recovery, rotation
2. **Input Validation**: ReDoS protection, malformed data handling
3. **Credential Security**: Memory exposure, storage security
4. **Path Traversal**: TOCTOU prevention, symlink attacks
5. **SSL/TLS**: Certificate validation, MITM protection

### Test Implementation Pattern
```python
def test_encryption_key_persistence():
    """Verify encryption keys persist across process restarts"""
    # Test implementation with actual process restart simulation
    
def test_redos_protection():
    """Verify regex timeout and input size limits"""
    # Test with malicious regex inputs
    
def test_credential_memory_safety():
    """Verify credentials don't leak to process environment"""
    # Test memory dumps and process inspection
```

## Error Handling Standards

### Exception Hierarchy
```python
class SecurityError(Exception):
    """Base security-related exception"""
    
class ValidationError(SecurityError):
    """Input validation failures"""
    
class EncryptionError(SecurityError):
    """Encryption/decryption failures"""
    
class AuthenticationError(SecurityError):
    """API authentication failures"""
```

### Logging Requirements
- **Security Events**: All authentication, authorization, and validation events
- **Audit Trail**: Data access, modification, deletion with user context
- **Error Context**: Sanitized error details without sensitive data exposure
- **Performance Metrics**: API usage, memory consumption, processing times

## Performance Optimization Guidelines

### Memory Management
- Use `pandas.read_csv(chunksize=N)` for large datasets
- Implement streaming JSON parsing for API responses
- Add memory monitoring with `psutil`
- Clear DataFrames explicitly after processing

### API Efficiency
- Implement exponential backoff for retry logic
- Add request caching with TTL for repeated data requests
- Use connection pooling for multiple API calls
- Monitor and respect API rate limits

## Compliance Implementation

### Audit Trail Requirements
Every security-relevant operation must log:
```python
audit_logger.info("encryption_key_access", extra={
    "user": get_current_user(),
    "operation": "key_retrieval",
    "timestamp": datetime.utcnow().isoformat(),
    "resource": "encryption_key",
    "result": "success"
})
```

### Data Retention Policy
```python
# Implement configurable retention
DEFAULT_RETENTION_DAYS = 2555  # 7 years for financial data
def cleanup_expired_data(retention_days: int = DEFAULT_RETENTION_DAYS):
    """Remove data older than retention period"""
```

## Work Validation Instructions

### Pre-commit Checklist
1. **Security**: Run expanded security test suite
2. **Linting**: `black`, `flake8`, `mypy` with strict settings
3. **Dependencies**: `safety check` for known vulnerabilities
4. **Documentation**: Update docstrings for all modified functions

### Integration Testing
```bash
# Run complete test suite
python -m pytest security_test_demo.py -v
python -m pytest tests/ --cov=. --cov-report=html

# Security-specific validation
python -c "from security_test_demo import run_comprehensive_security_tests; run_comprehensive_security_tests()"

# Performance validation with sample data
python secure_ohlcv_cli.py --symbol AAPL --start-date 2023-01-01 --end-date 2024-01-01 --test-mode
```

## Pull Request Guidelines

### Title Format
`[SECURITY] Fix [Finding-ID]: [Brief Description]`

Examples:
- `[SECURITY] Fix SEC-2025-007: Implement secure encryption key persistence`
- `[SECURITY] Fix SEC-2025-009: Replace environment variable credential storage`

### PR Description Template
```markdown
## Security Audit Remediation

**Finding ID**: SEC-2025-XXX
**Severity**: CRITICAL/HIGH/MEDIUM/LOW
**Category**: Security/Quality/Performance/Compliance

### Problem Summary
Brief description of the security issue and its impact.

### Solution Implemented
Detailed explanation of the fix, including:
- Security controls added
- Libraries/approaches used
- Backward compatibility considerations

### Testing Performed
- [ ] Security tests pass
- [ ] Integration tests pass
- [ ] Manual verification completed
- [ ] Performance impact assessed

### Compliance Impact
How this fix addresses SOX/GDPR/PCI-DSS requirements.

### Breaking Changes
Any changes that might affect existing usage.
```

## Dependencies and Libraries

### Required Security Libraries
```python
# Add to requirements.txt
keyring>=24.0.0          # Secure credential storage
cryptography>=41.0.0     # Enhanced crypto operations
requests[security]>=2.31.0  # SSL/TLS improvements
regex>=2023.0.0          # ReDoS protection with timeouts
psutil>=5.9.0           # Memory monitoring
pydantic>=2.0.0         # Enhanced input validation
```

### Development Dependencies
```python
# Add to requirements-dev.txt
safety>=2.3.0           # Vulnerability scanning
bandit>=1.7.0           # Security linting
pytest-cov>=4.0.0      # Coverage reporting
mypy>=1.0.0             # Type checking
black>=23.0.0           # Code formatting
```

## Security Contact Information

For security-related questions during implementation:
- Escalate any uncertainty about security implementations
- Never compromise security for convenience
- Document all security design decisions
- Review all cryptographic implementations carefully

## Implementation Priority Order

1. **CRITICAL** (Immediate - Start Here):
   - SEC-2025-007: Encryption key persistence
   - SEC-2025-008: ReDoS protection

2. **HIGH** (Next Priority):
   - SEC-2025-009: Credential security
   - SEC-2025-010: Race condition prevention
   - SEC-2025-011: SSL verification

3. **MEDIUM** (Following Week):
   - Configuration externalization
   - Audit trail implementation
   - Test coverage expansion

4. **LOW** (Ongoing Improvements):
   - Code refactoring
   - Documentation updates
   - Performance optimizations

Remember: Security fixes should be implemented incrementally with thorough testing at each step. Do not attempt to fix all issues in a single massive change.
