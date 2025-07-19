#!/usr/bin/env python3
"""
Setup script for OHLCV Data Downloader
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
try:
    with open('requirements.txt', 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
except FileNotFoundError:
    requirements = [
        'pandas>=1.5.0',
        'yfinance>=0.2.0',
        'alpha-vantage>=2.3.1',
        'requests>=2.28.0',
        'python-dotenv>=0.19.0'
    ]

setup(
    name="ohlcv-downloader",
    version="1.0.0",
    author="OHLCV Downloader Team",
    author_email="contact@ohlcv-downloader.com",
    description="A comprehensive Python application for downloading OHLCV stock data from multiple free APIs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/ohlcv-downloader",
    packages=find_packages(),
    py_modules=['ohlcv_downloader', 'ohlcv_cli'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Financial and Insurance Industry",
        "Intended Audience :: Developers",
        "Topic :: Office/Business :: Financial :: Investment",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
            'black>=21.0',
            'flake8>=3.8',
            'mypy>=0.800',
        ],
        'analysis': [
            'matplotlib>=3.5.0',
            'plotly>=5.0.0',
            'jupyter>=1.0.0',
            'seaborn>=0.11.0',
        ],
        'all': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
            'black>=21.0',
            'flake8>=3.8',
            'mypy>=0.800',
            'matplotlib>=3.5.0',
            'plotly>=5.0.0',
            'jupyter>=1.0.0',
            'seaborn>=0.11.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'ohlcv-download=ohlcv_cli:main',
            'ohlcv-gui=ohlcv_downloader:main',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.md', '*.txt', '*.env.example'],
    },
    keywords='stock market data ohlcv yahoo finance alpha vantage polygon api financial',
    project_urls={
        'Bug Reports': 'https://github.com/your-username/ohlcv-downloader/issues',
        'Source': 'https://github.com/your-username/ohlcv-downloader',
        'Documentation': 'https://github.com/your-username/ohlcv-downloader/blob/main/README.md',
    },
)
