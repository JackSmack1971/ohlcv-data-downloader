#!/usr/bin/env python3
"""
Secure OHLCV Downloader - Test Demonstration
Shows the security fixes in action and validates functionality
"""

import os
import sys
from datetime import date, timedelta
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, '/home/user/output')

try:
    from secure_ohlcv_downloader import (
        SecureOHLCVDownloader,
        DownloadConfig,
        ValidationError,
        SecurityError,
        CredentialError,
    )
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure secure_ohlcv_downloader.py is in the current directory")
    sys.exit(1)

class SecurityTestSuite:
    """Test suite demonstrating security fixes"""

    def __init__(self):
        self.downloader = SecureOHLCVDownloader("/home/user/output")
        self.test_results = []

    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """Log test results"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.test_results.append((test_name, passed, message))
        print(f"{status}: {test_name}")
        if message:
            print(f"    {message}")

    def test_path_traversal_protection(self):
        """Test SEC-2025-002: Path traversal vulnerability fix"""
        print("\n🔒 Testing Path Traversal Protection (SEC-2025-002)")

        # Test 1: Valid ticker should pass
        try:
            valid_ticker = self.downloader._validate_ticker("AAPL")
            self.log_test("Valid ticker validation", valid_ticker == "AAPL")
        except (ValidationError, SecurityError) as e:
            self.log_test("Valid ticker validation", False, str(e))

        # Test 2: Path traversal attempt should fail
        try:
            self.downloader._validate_ticker("../../../etc/passwd")
            self.log_test("Path traversal detection", False, "Should have raised SecurityError")
        except SecurityError:
            self.log_test("Path traversal detection", True, "Correctly blocked path traversal")
        except ValidationError as e:
            self.log_test("Path traversal detection", False, f"Wrong exception: {e}")

        # Test 3: Invalid characters should fail
        try:
            self.downloader._validate_ticker("AAPL/../../")
            self.log_test("Invalid character detection", False, "Should have raised SecurityError")
        except SecurityError:
            self.log_test("Invalid character detection", True, "Correctly blocked invalid characters")
        except ValidationError as e:
            self.log_test("Invalid character detection", False, f"Wrong exception: {e}")

    def test_input_validation(self):
        """Test SEC-2025-005: Input validation for dates"""
        print("\n📅 Testing Input Validation (SEC-2025-005)")

        # Test 1: Valid date range
        try:
            start_date = date.today() - timedelta(days=30)
            end_date = date.today()
            self.downloader._validate_date_range(start_date, end_date)
            self.log_test("Valid date range", True)
        except ValidationError as e:
            self.log_test("Valid date range", False, str(e))

        # Test 2: Invalid date range (start > end)
        try:
            start_date = date.today()
            end_date = date.today() - timedelta(days=30)
            self.downloader._validate_date_range(start_date, end_date)
            self.log_test("Invalid date range detection", False, "Should have raised ValidationError")
        except ValidationError:
            self.log_test("Invalid date range detection", True, "Correctly detected invalid range")
        except SecurityError as e:
            self.log_test("Invalid date range detection", False, f"Wrong exception: {e}")

        # Test 3: Future date should fail
        try:
            start_date = date.today()
            end_date = date.today() + timedelta(days=30)
            self.downloader._validate_date_range(start_date, end_date)
            self.log_test("Future date detection", False, "Should have raised ValidationError")
        except ValidationError:
            self.log_test("Future date detection", True, "Correctly blocked future dates")
        except SecurityError as e:
            self.log_test("Future date detection", False, f"Wrong exception: {e}")

    def test_api_key_security(self):
        """Test SEC-2025-001: Secure API key handling"""
        print("\n🔐 Testing API Key Security (SEC-2025-001)")

        # Test 1: API key retrieval from environment
        original_key = os.getenv('ALPHA_VANTAGE_API_KEY')

        # Set a test key
        os.environ['ALPHA_VANTAGE_API_KEY'] = 'test_key_12345'

        try:
            api_key = self.downloader._get_api_key('alpha_vantage')
            self.log_test("API key retrieval", api_key == 'test_key_12345')
        except (CredentialError, ValidationError, SecurityError) as e:
            self.log_test("API key retrieval", False, str(e))

        # Test 2: Missing API key handling
        if 'ALPHA_VANTAGE_API_KEY' in os.environ:
            del os.environ['ALPHA_VANTAGE_API_KEY']

        try:
            api_key = self.downloader._get_api_key('alpha_vantage')
            self.log_test("Missing API key handling", api_key is None)
        except (CredentialError, ValidationError, SecurityError) as e:
            self.log_test("Missing API key handling", False, str(e))

        # Restore original key if it existed
        if original_key:
            os.environ['ALPHA_VANTAGE_API_KEY'] = original_key

    def test_error_sanitization(self):
        """Test SEC-2025-004: Error message sanitization"""
        print("\n🧹 Testing Error Message Sanitization (SEC-2025-004)")

        # Test 1: Path sanitization
        error_msg = "File not found: /home/user/secret/file.txt"
        sanitized = self.downloader._sanitize_error(error_msg)
        path_removed = "[PATH_REDACTED]" in sanitized and "/home/user/secret/file.txt" not in sanitized
        self.log_test("Path sanitization", path_removed, f"Sanitized: {sanitized}")

        # Test 2: API key sanitization
        error_msg = "API error with key=abc123secret"
        sanitized = self.downloader._sanitize_error(error_msg)
        key_removed = "key=[REDACTED]" in sanitized and "abc123secret" not in sanitized
        self.log_test("API key sanitization", key_removed, f"Sanitized: {sanitized}")

    def test_secure_file_operations(self):
        """Test secure file operations and permissions"""
        print("\n📁 Testing Secure File Operations")

        # Test 1: Secure path creation
        try:
            secure_path = self.downloader._create_secure_path("AAPL", "2024-01-01_2024-01-31")
            path_valid = secure_path.exists() and secure_path.is_dir()
            self.log_test("Secure path creation", path_valid, f"Created: {secure_path}")

            # Check permissions (should be 0o700)
            permissions = oct(secure_path.stat().st_mode)[-3:]
            self.log_test("Directory permissions", permissions == "700", f"Permissions: {permissions}")

        except (SecurityError, ValidationError) as e:
            self.log_test("Secure path creation", False, str(e))

    def test_data_download_security(self):
        """Test secure data download with Yahoo Finance (no API key required)"""
        print("\n📊 Testing Secure Data Download")

        try:
            # Create a minimal download configuration
            config = DownloadConfig(
                ticker="AAPL",
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 10),
                interval="1d",
                source="yahoo",
                encrypt_data=False
            )

            # Attempt download
            file_path = self.downloader.download_data(config)

            # Verify file was created
            file_exists = file_path.exists()
            self.log_test("Data download", file_exists, f"File: {file_path}")

            if file_exists:
                # Check file permissions
                permissions = oct(file_path.stat().st_mode)[-3:]
                self.log_test("File permissions", permissions == "600", f"Permissions: {permissions}")

                # Check metadata file
                metadata_file = file_path.parent / f"{config.ticker}_{config.source}_metadata.json"
                metadata_exists = metadata_file.exists()
                self.log_test("Metadata creation", metadata_exists, f"Metadata: {metadata_file}")

        except (ValidationError, SecurityError, CredentialError) as e:
            self.log_test("Data download", False, str(e))

    def run_all_tests(self):
        """Run all security tests"""
        print("🔒 SECURE OHLCV DOWNLOADER - SECURITY TEST SUITE")
        print("=" * 60)
        print("Testing security fixes from audit SEC-2025-001 through SEC-2025-006")
        print()

        # Run all test methods
        self.test_path_traversal_protection()
        self.test_input_validation()
        self.test_api_key_security()
        self.test_error_sanitization()
        self.test_secure_file_operations()
        self.test_data_download_security()

        # Summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)

        total_tests = len(self.test_results)
        passed_tests = sum(1 for _, passed, _ in self.test_results if passed)
        failed_tests = total_tests - passed_tests

        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")

        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for test_name, passed, message in self.test_results:
                if not passed:
                    print(f"  • {test_name}: {message}")

        print("\n🛡️ Security Status:", "✅ SECURE" if failed_tests == 0 else "⚠️ NEEDS ATTENTION")

        return failed_tests == 0

def main():
    """Main test execution"""
    print("Starting security test suite...")

    # Check if required files exist
    required_files = [
        '/home/user/output/secure_ohlcv_downloader.py'
    ]

    for file_path in required_files:
        if not Path(file_path).exists():
            print(f"❌ Required file not found: {file_path}")
            return False

    # Run tests
    test_suite = SecurityTestSuite()
    success = test_suite.run_all_tests()

    if success:
        print("\n🎉 All security tests passed! The application is secure.")
    else:
        print("\n⚠️ Some tests failed. Please review the security implementation.")

    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
