#!/usr/bin/env python3
"""Run all validation checks mentioned in AGENTS.md."""

import subprocess
import sys


def run_command(cmd: str, description: str) -> bool:
    """Run a command and return success status."""
    print(f"\n=== {description} ===")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        print(f"Command: {cmd}")
        print(f"Return code: {result.returncode}")
        if result.stdout:
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {cmd}")
        return False
    except Exception as e:
        print(f"Command failed: {cmd} - {e}")
        return False


def main() -> int:
    """Run all validation checks."""
    commands = [
        ("python -m pytest -v --tb=short", "Running pytest"),
        ("python -m bandit -r . -f json -o security_scan.json", "Running bandit security scan"),
        ("python -m safety check --json --output safety_report.json", "Running safety dependency check"),
        ("flake8 --select=E9,F63,F7,F82 . --output-file=flake8_report.txt", "Running flake8 code quality"),
        ("mypy . --no-error-summary > mypy_report.txt", "Running mypy type checking"),
        ("python -m pytest tests/integration/ -k security -v --tb=short", "Running security integration tests"),
        ("python scripts/performance_baseline.py --output=perf_report.json", "Running performance baseline"),
    ]

    results = {}
    for cmd, desc in commands:
        success = run_command(cmd, desc)
        results[desc] = success

    print("\n=== VALIDATION SUMMARY ===")
    all_passed = True
    for desc, success in results.items():
        status = "PASS" if success else "FAIL"
        print(f"{status}: {desc}")
        if not success:
            all_passed = False

    if all_passed:
        print("\n✅ All validation checks passed!")
        return 0
    else:
        print("\n❌ Some validation checks failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
