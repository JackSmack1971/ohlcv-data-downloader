#!/usr/bin/env python3
"""
Secure OHLCV Data Downloader - Command Line Interface
Addresses critical security vulnerabilities from audit SEC-2025-001 through SEC-2025-006
"""

import argparse
import asyncio
import getpass
import sys
import re
from datetime import datetime, date
from pathlib import Path
from typing import Optional
import os
import keyring
from keyring import errors as keyring_errors
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import the secure downloader
from secure_ohlcv_downloader import (
    SecureOHLCVDownloader,
    DownloadConfig,
    ValidationError,
    SecurityError,
    CredentialError,
)


class SecureCLI:
    """
    Secure command-line interface for OHLCV data downloader
    Addresses SEC-2025-001: API keys removed from CLI arguments
    """

    def __init__(self):
        self.downloader = None

    def create_parser(self) -> argparse.ArgumentParser:
        """
        Create argument parser with secure parameter handling

        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description="Secure OHLCV Data Downloader - Download stock market data safely",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Security Features:
  • API keys loaded from environment variables only
  • Input validation and sanitization
  • Path traversal protection
  • JSON schema validation for API responses
  • Encrypted data storage option
  • Comprehensive audit logging

Environment Variables:
  ALPHA_VANTAGE_API_KEY    Alpha Vantage API key
  POLYGON_API_KEY          Polygon API key  
  OHLCV_ENCRYPTION_KEY     Data encryption key (optional)

Examples:
  %(prog)s AAPL --start-date 2024-01-01 --end-date 2024-01-31
  %(prog)s MSFT --source alpha_vantage --interval 1wk --encrypt
  %(prog)s GOOGL --interactive-auth  # Prompt for API keys securely
            """,
        )

        # Required arguments
        parser.add_argument(
            "ticker", help="Stock ticker symbol (e.g., AAPL, MSFT, GOOGL)", type=str
        )

        # Date range arguments with validation
        parser.add_argument(
            "--start-date",
            help="Start date (YYYY-MM-DD format)",
            type=self._parse_date,
            default=date(2024, 1, 1),
        )

        parser.add_argument(
            "--end-date",
            help="End date (YYYY-MM-DD format)",
            type=self._parse_date,
            default=date.today(),
        )

        # Data source and interval
        parser.add_argument(
            "--source",
            help="Data source",
            choices=["yahoo", "alpha_vantage"],
            default="yahoo",
        )

        parser.add_argument(
            "--interval",
            help="Data interval",
            choices=[
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
            ],
            default="1d",
        )

        # Security options
        parser.add_argument(
            "--encrypt", help="Encrypt downloaded data", action="store_true"
        )

        parser.add_argument(
            "--interactive-auth",
            help="Prompt for API keys interactively (secure input)",
            action="store_true",
        )

        # Output options
        parser.add_argument(
            "--output-dir",
            help="Output directory for downloaded data",
            type=Path,
            default=Path("/home/user/output"),
        )

        parser.add_argument(
            "--verbose", help="Enable verbose logging", action="store_true"
        )

        parser.add_argument(
            "--check-env",
            help="Check environment configuration and exit",
            action="store_true",
        )

        return parser

    def _parse_date(self, date_string: str) -> date:
        """
        Parse and validate date string with comprehensive validation
        Addresses SEC-2025-005: Missing input validation for date parameters

        Args:
            date_string: Date string in YYYY-MM-DD format

        Returns:
            Parsed date object

        Raises:
            argparse.ArgumentTypeError: If date is invalid
        """
        try:
            # Strict format validation
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_string):
                raise ValueError("Date must be in YYYY-MM-DD format")

            parsed_date = datetime.strptime(date_string, "%Y-%m-%d").date()

            # Business logic validation
            if parsed_date > date.today():
                raise ValueError("Date cannot be in the future")

            # Reasonable historical limit (prevent excessive API calls)
            min_date = date(1900, 1, 1)
            if parsed_date < min_date:
                raise ValueError(f"Date cannot be before {min_date}")

            return parsed_date

        except ValueError as e:
            raise argparse.ArgumentTypeError(f"Invalid date '{date_string}': {e}")

    def _setup_secure_environment(self, args) -> None:
        """
        Setup secure environment and handle API key authentication
        Addresses SEC-2025-001: Secure credential handling

        Args:
            args: Parsed command line arguments
        """
        if args.interactive_auth:
            asyncio.run(self._prompt_for_api_keys(args.source))

        # Validate required API keys for non-Yahoo sources
        if args.source == "alpha_vantage":
            api_key = os.getenv("ALPHA_VANTAGE_API_KEY")
            if not api_key:
                try:
                    api_key = keyring.get_password(
                        "ohlcv_downloader", "alpha_vantage_api_key"
                    )
                except keyring_errors.KeyringError as exc:
                    print(f"❌ Credential retrieval failed: {exc}")
                    sys.exit(1)

            if not api_key:
                print("❌ Alpha Vantage API key not found!")
                print(
                    "   Set ALPHA_VANTAGE_API_KEY environment variable or use --interactive-auth"
                )
                sys.exit(1)

        # Initialize secure downloader
        try:
            self.downloader = SecureOHLCVDownloader(str(args.output_dir))
        except (SecurityError, CredentialError, ValidationError, OSError) as e:
            print(f"❌ Failed to initialize secure downloader: {e}")
            sys.exit(1)

    async def _prompt_for_api_keys(self, source: str) -> None:
        """Prompt for API keys and store them securely using keyring."""

        if source == "alpha_vantage":
            print("🔐 Alpha Vantage API Key Required")
            print(
                "   Get your free API key at: https://www.alphavantage.co/support/#api-key"
            )

            loop = asyncio.get_event_loop()
            api_key = await loop.run_in_executor(
                None, getpass.getpass, "Enter Alpha Vantage API key (input hidden): "
            )
            api_key = api_key.strip()

            if not api_key:
                print("❌ No API key provided")
                sys.exit(1)

            try:
                keyring.set_password(
                    "ohlcv_downloader", "alpha_vantage_api_key", api_key
                )
                print("✅ API key stored securely")
            except keyring_errors.KeyringError as exc:
                raise SecurityError(f"Failed to store API key: {exc}") from exc

            # Clear variable from memory
            del api_key

    def _check_environment(self) -> None:
        """
        Check and display environment configuration

        Returns:
            None
        """
        print("🔍 Environment Configuration Check")
        print("=" * 50)

        # Check API keys (without exposing values)
        alpha_key = os.getenv("ALPHA_VANTAGE_API_KEY")
        if not alpha_key:
            try:
                alpha_key = keyring.get_password(
                    "ohlcv_downloader", "alpha_vantage_api_key"
                )
            except keyring_errors.KeyringError:
                alpha_key = None

        polygon_key = os.getenv("POLYGON_API_KEY")
        encryption_key = os.getenv("OHLCV_ENCRYPTION_KEY")

        print(f"Alpha Vantage API Key: {'✅ Set' if alpha_key else '❌ Not set'}")
        print(f"Polygon API Key: {'✅ Set' if polygon_key else '❌ Not set'}")
        print(
            f"Encryption Key: {'✅ Set' if encryption_key else '❌ Not set (will generate)'}"
        )

        # Check output directory
        output_dir = Path("/home/user/output")
        print(f"Output Directory: {output_dir}")
        print(f"Directory Exists: {'✅ Yes' if output_dir.exists() else '❌ No'}")
        print(
            f"Directory Writable: {'✅ Yes' if os.access(output_dir, os.W_OK) else '❌ No'}"
        )

        # Check dependencies
        try:
            import yfinance
            import pandas
            import requests
            import jsonschema
            import cryptography

            print("Dependencies: ✅ All required packages installed")
        except ImportError as e:
            print(f"Dependencies: ❌ Missing package: {e}")

        print("\n💡 Tips:")
        print("   • Use keyring or environment variables for API keys")
        print("   • Enable encryption for sensitive financial data")
        print("   • Check logs in output directory for detailed information")

    def _validate_arguments(self, args) -> None:
        """
        Validate command line arguments for security and business logic
        Addresses multiple security findings

        Args:
            args: Parsed arguments

        Raises:
            SystemExit: If validation fails
        """
        try:
            # Validate ticker (addresses SEC-2025-002: Path traversal)
            if not args.ticker:
                raise ValueError("Ticker symbol is required")

            # Additional ticker validation will be done by SecureOHLCVDownloader

            # Validate date range
            if args.start_date > args.end_date:
                raise ValueError("Start date must be before end date")

            # Validate date range size (prevent excessive API calls)
            date_diff = (args.end_date - args.start_date).days
            if date_diff > 3650:  # 10 years
                raise ValueError("Date range too large (maximum 10 years)")

            # Validate output directory
            if not args.output_dir.parent.exists():
                raise ValueError(
                    f"Parent directory does not exist: {args.output_dir.parent}"
                )

        except ValueError as e:
            print(f"❌ Validation Error: {e}")
            sys.exit(1)

    def run(self) -> None:
        """
        Main CLI execution with comprehensive error handling
        """
        parser = self.create_parser()
        args = parser.parse_args()

        # Handle special commands
        if args.check_env:
            self._check_environment()
            return

        try:
            # Validate arguments
            self._validate_arguments(args)

            # Setup secure environment
            self._setup_secure_environment(args)

            # Create download configuration
            config = DownloadConfig(
                ticker=args.ticker,
                start_date=args.start_date,
                end_date=args.end_date,
                interval=args.interval,
                source=args.source,
                encrypt_data=args.encrypt,
            )

            # Execute download
            print(f"🚀 Starting secure download...")
            print(f"   Ticker: {config.ticker}")
            print(f"   Source: {config.source}")
            print(f"   Date Range: {config.start_date} to {config.end_date}")
            print(f"   Interval: {config.interval}")
            print(f"   Encryption: {'Enabled' if config.encrypt_data else 'Disabled'}")

            file_path = self.downloader.download_data(config)

            print(f"✅ Download completed successfully!")
            print(f"   File saved: {file_path}")
            print(f"   Check logs: {args.output_dir}/secure_downloader.log")

        except KeyboardInterrupt:
            print("\n⚠️  Download interrupted by user")
            sys.exit(1)

        except (ValidationError, SecurityError, CredentialError, OSError, requests.RequestException) as e:
            print(f"❌ Security/Validation Error: {e}")
            sys.exit(1)



def main():
    """
    Main entry point for secure CLI
    """
    cli = SecureCLI()
    cli.run()


if __name__ == "__main__":
    main()
