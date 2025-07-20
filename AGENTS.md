Execution Guidelines
For Each task:

Always check for AGENTS.md files in current directory and follow their guidelines
Use git to commit changes with clean commit messages
Never create new branches - work on current branch only
Check git status after each change to ensure clean worktree
Cite all code modifications using F:file_path†L<line> format
Include terminal output citations using chunk_id format when running tests
Do not modify or amend existing commits - create new commits only

Priority Order:

Execute Phase 1 (Critical) immediately
Complete Phase 2 (High) before other phases
Phases 3-5 can be executed in parallel or sequentially based on resources

Validation:

Run all programmatic checks specified in AGENTS.md after each phase
Ensure each commit follows AGENTS.md commit message format
Validate that security fixes address the specific finding IDs mentioned
Confirm all citations use proper F: and chunk_id formats as required
# Security Audit Remediation Guide

## Project Overview
This codebase is a secure financial data downloader with strict security requirements. This AGENTS.md provides specific guidance for addressing findings from security audit SEC-2025-012 through DOC-2025-001.

## Critical Security Priorities

### 1. SSL Certificate Management (SEC-2025-012) - CRITICAL
**Current Issue**: Hardcoded SSL certificate fingerprint creates operational and security risks.

**Implementation Requirements**:
- Replace hardcoded fingerprint with dynamic certificate management
- Support multiple valid fingerprints for certificate rotation
- Implement graceful fallback mechanisms
- Add certificate rotation detection and alerting

**Code Location**: `secure_ohlcv_downloader.py:87-90`

**Required Changes**:
```python
# Replace this pattern:
ALPHA_VANTAGE_FINGERPRINT = os.getenv(..., "hardcoded_value")

# With dynamic certificate store:
class CertificateManager:
    def __init__(self):
        self.valid_fingerprints = self._load_valid_fingerprints()
        self.rotation_detector = CertificateRotationDetector()
    
    def validate_certificate(self, cert_fingerprint: str) -> bool:
        # Implement multi-fingerprint validation with rotation detection
```

### 2. ReDoS Protection (SEC-2025-013) - CRITICAL  
**Current Issue**: Ticker pattern validation lacks timeout protection, inconsistent with other patterns.

**Implementation Requirements**:
- Replace `re.compile` with `regex.compile` for TICKER_PATTERN
- Add timeout parameter (0.1 seconds)
- Ensure consistency with existing DATE_PATTERN implementation

**Code Location**: `secure_ohlcv_downloader.py:78`

**Required Changes**:
```python
# Replace:
TICKER_PATTERN = re.compile(r"^[A-Z0-9._-]{1,10}$")

# With:
TICKER_PATTERN = regex.compile(r"^[A-Z0-9._-]{1,10}$", timeout=0.1)
```

## High Priority Security Fixes

### 3. Exception Context Sanitization (SEC-2025-014)
**Focus Areas**:
- Implement structured exception logging with context sanitization
- Ensure stack traces are never exposed to end users
- Sanitize local variables and file paths in exception context

**Implementation Pattern**:
```python
class SecureExceptionHandler:
    @staticmethod
    def sanitize_exception_context(exc: Exception) -> Dict[str, Any]:
        # Remove sensitive context, file paths, local variables
        # Return safe error information for logging
```

### 4. JSON Schema Validation Hardening (SEC-2025-015)
**Enhancement Requirements**:
- Add JSON depth limits (max 10 levels)
- Implement object size limits (max 1000 properties)
- Add string length limits (max 10000 characters)
- Include resource monitoring during JSON processing

**Code Location**: `secure_ohlcv_downloader.py:395-407`

### 5. Memory-based Credential Protection (SEC-2025-016)
**Security Requirements**:
- Implement secure string handling for credentials
- Use character arrays that can be explicitly cleared
- Minimize credential lifetime in memory

## Architecture Improvements

### Class Refactoring (ARCH-2025-001)
**Refactoring Strategy**: Break down the monolithic `SecureOHLCVDownloader` class into focused components:

1. **DataValidator**: Input validation and sanitization
2. **APIClient**: External API communication
3. **EncryptionManager**: Encryption/decryption operations  
4. **FileManager**: File operations and secure storage
5. **ConfigurationManager**: Configuration and credential management

**Implementation Approach**:
- Create interfaces for each component
- Implement dependency injection for testing
- Maintain backward compatibility during refactoring

## Code Quality Standards

### Validation Logic (QUAL-2025-001)
**Pattern**: Extract common validation into reusable components:
```python
class ValidationDecorator:
    @staticmethod
    def validate_input(validator_func):
        def decorator(func):
            # Common validation wrapper
```

### Cross-Platform Compatibility (ARCH-2025-002)
**Approach**: Replace platform-specific file locking with abstraction:
- Use `filelock` library for cross-platform file locking
- Remove conditional Windows/POSIX code paths
- Ensure consistent behavior across platforms

## Testing Requirements

### Security Testing (TEST-2025-001)
**Required Test Categories**:
1. **Integration Tests**: Multi-component security validation
2. **End-to-End Security Tests**: Real attack scenario simulation
3. **Property-Based Testing**: Input validation edge cases
4. **Performance Security Tests**: ReDoS and DoS resistance

**Test Implementation Pattern**:
```python
class SecurityIntegrationTests:
    def test_certificate_rotation_handling(self):
        # Test certificate updates without service disruption
    
    def test_redos_protection(self):
        # Test regex timeout under malicious inputs
    
    def test_json_bomb_protection(self):
        # Test deeply nested JSON rejection
```

## Performance Considerations

### Async I/O Implementation (PERF-2025-001)
**Required Changes**:
- Wrap file operations with `asyncio.to_thread()`
- Use `aiofiles` library for async file operations
- Implement proper async context managers

**Implementation Pattern**:
```python
import aiofiles
import asyncio

async def secure_file_operation(file_path: str, data: bytes):
    async with aiofiles.open(file_path, 'wb') as f:
        await f.write(data)
```

## Implementation Sequence

### Phase 1: Critical Security Fixes (Week 1)
1. Implement dynamic certificate management (SEC-2025-012)
2. Add ReDoS protection to ticker validation (SEC-2025-013)
3. Comprehensive testing of critical fixes

### Phase 2: High Priority Security (Week 2)  
1. Exception context sanitization (SEC-2025-014)
2. JSON validation hardening (SEC-2025-015)
3. Memory credential protection (SEC-2025-016)

### Phase 3: Architecture Improvements (Weeks 3-4)
1. Begin class refactoring (ARCH-2025-001)
2. Implement async I/O improvements (PERF-2025-001)
3. Add comprehensive security test suite (TEST-2025-001)

### Phase 4: Quality and Documentation (Week 5)
1. Extract common validation patterns (QUAL-2025-001)
2. Cross-platform improvements (ARCH-2025-002)
3. Security documentation updates (DOC-2025-001)

## Validation and Testing

### Security Validation Checklist
Before marking any security fix complete:
- [ ] Unit tests pass with new security controls
- [ ] Integration tests validate multi-component security
- [ ] Performance impact measured and acceptable
- [ ] Security edge cases documented and tested
- [ ] Code review by security-focused team member

### Performance Validation
- Measure baseline performance before changes
- Ensure security improvements don't degrade performance >10%
- Load test async I/O improvements under concurrent usage

## Deployment and Monitoring

### Rollout Strategy
1. Deploy certificate management in staging with monitoring
2. Validate ReDoS protection with synthetic attack tests
3. Gradual rollout with feature flags for major changes
4. Monitor security metrics and performance impact

### Security Monitoring
- SSL certificate rotation events
- Regex timeout activations  
- Exception sanitization effectiveness
- JSON processing resource usage
- Memory credential handling metrics

## Documentation Requirements

### Security Documentation Updates
For each fix, update documentation to include:
- Security rationale for implementation choices
- Attack scenarios the fix prevents
- Configuration requirements for security features
- Monitoring and alerting recommendations

### Code Documentation Standards
- Include security considerations in all method docstrings
- Document security assumptions and requirements
- Provide examples of secure usage patterns
- Include references to relevant security standards (SOX, PCI-DSS, GDPR)

---

## Working with Codex

When implementing these fixes:
1. **Focus on one finding at a time** - Don't try to fix multiple security issues in a single task
2. **Test thoroughly** - Include security-focused test cases with each fix
3. **Maintain backward compatibility** - Ensure existing functionality continues to work
4. **Document security rationale** - Explain why each security choice was made
5. **Validate with tools** - Use security linters and scanners to verify fixes

Remember: Security fixes require careful implementation and thorough testing. Each change should be validated against the specific attack scenarios described in the audit findings.
