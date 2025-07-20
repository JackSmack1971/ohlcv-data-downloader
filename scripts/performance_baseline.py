#!/usr/bin/env python3
"""Performance baseline measurement script for security implementations."""

import argparse
import json
import time
import psutil
import os
from pathlib import Path


def measure_baseline_performance() -> dict:
    """Measure baseline performance metrics."""
    return {
        "timestamp": time.time(),
        "memory_usage_mb": psutil.Process().memory_info().rss / 1024 / 1024,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "disk_usage": psutil.disk_usage('.').percent,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Measure performance baseline')
    parser.add_argument('--output', required=True, help='Output JSON file')
    args = parser.parse_args()

    metrics = measure_baseline_performance()

    with open(args.output, 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"Baseline metrics saved to {args.output}")


if __name__ == "__main__":
    main()
