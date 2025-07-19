#!/usr/bin/env python3
"""
OHLCV Data Downloader - Command Line Interface
A command-line tool for downloading OHLCV data from multiple free APIs.
"""

import argparse
import sys
from datetime import datetime, timedelta
import pandas as pd
import yfinance as yf
import requests
import json
from pathlib import Path
import logging

class OHLCVDownloaderCLI:
    def __init__(self):
        # Create output directory
        self.output_dir = Path("data")
        self.output_dir.mkdir(exist_ok=True)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('downloader.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def download_yahoo_finance(self, ticker, output_dir, start_date, end_date, timeframe):
        """Download data from Yahoo Finance"""
        try:
            self.logger.info("Connecting to Yahoo Finance...")

            stock = yf.Ticker(ticker)
            data = stock.history(
                start=start_date,
                end=end_date,
                interval=timeframe
            )

            if data.empty:
                raise ValueError("No data returned from Yahoo Finance")

            # Clean and validate data
            data = data.dropna()

            # Save data
            filename = output_dir / f"{ticker}_yahoo_finance.csv"
            data.to_csv(filename)

            # Save metadata
            metadata = {
                "source": "Yahoo Finance",
                "ticker": ticker,
                "timeframe": timeframe,
                "start_date": start_date,
                "end_date": end_date,
                "download_time": datetime.now().isoformat(),
                "records_count": len(data),
                "filename": str(filename),
                "columns": list(data.columns),
                "date_range_actual": {
                    "start": str(data.index.min()),
                    "end": str(data.index.max())
                }
            }

            with open(output_dir / f"{ticker}_yahoo_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            self.logger.info(f"Yahoo Finance: {len(data)} records saved to {filename}")
            return True

        except Exception as e:
            self.logger.error(f"Yahoo Finance download failed: {str(e)}")
            return False

    def download_alpha_vantage(self, ticker, output_dir, start_date, end_date, timeframe, api_key):
        """Download data from Alpha Vantage"""
        try:
            if not api_key:
                self.logger.warning("Alpha Vantage: API key required, skipping...")
                return False

            self.logger.info("Connecting to Alpha Vantage...")

            # Map timeframe to Alpha Vantage format
            interval_map = {
                "1m": "1min", "5m": "5min", "15m": "15min", 
                "30m": "30min", "60m": "60min", "1d": "daily"
            }

            interval = interval_map.get(timeframe, "daily")

            if interval in ["1min", "5min", "15min", "30min", "60min"]:
                function = "TIME_SERIES_INTRADAY"
                url = f"https://www.alphavantage.co/query?function={function}&symbol={ticker}&interval={interval}&apikey={api_key}&outputsize=full"
            else:
                function = "TIME_SERIES_DAILY"
                url = f"https://www.alphavantage.co/query?function={function}&symbol={ticker}&apikey={api_key}&outputsize=full"

            response = requests.get(url, timeout=30)
            data = response.json()

            # Check for API errors
            if "Error Message" in data:
                raise ValueError(f"Alpha Vantage API Error: {data['Error Message']}")
            if "Note" in data:
                raise ValueError(f"Alpha Vantage API Limit: {data['Note']}")

            # Find the time series key
            time_series_key = None
            for key in data.keys():
                if "Time Series" in key:
                    time_series_key = key
                    break

            if not time_series_key or time_series_key not in data:
                raise ValueError("No time series data found in Alpha Vantage response")

            # Convert to DataFrame
            df_data = []
            for date_str, values in data[time_series_key].items():
                df_data.append({
                    'Date': date_str,
                    'Open': float(values['1. open']),
                    'High': float(values['2. high']),
                    'Low': float(values['3. low']),
                    'Close': float(values['4. close']),
                    'Volume': int(values['5. volume'])
                })

            df = pd.DataFrame(df_data)
            df['Date'] = pd.to_datetime(df['Date'])
            df = df.set_index('Date').sort_index()

            # Filter by date range
            start_dt = pd.to_datetime(start_date)
            end_dt = pd.to_datetime(end_date)
            df = df[(df.index >= start_dt) & (df.index <= end_dt)]

            if df.empty:
                raise ValueError("No data in specified date range")

            # Clean data
            df = df.dropna()

            # Save data
            filename = output_dir / f"{ticker}_alpha_vantage.csv"
            df.to_csv(filename)

            # Save metadata
            metadata = {
                "source": "Alpha Vantage",
                "ticker": ticker,
                "timeframe": timeframe,
                "start_date": start_date,
                "end_date": end_date,
                "download_time": datetime.now().isoformat(),
                "records_count": len(df),
                "filename": str(filename),
                "columns": list(df.columns),
                "date_range_actual": {
                    "start": str(df.index.min()),
                    "end": str(df.index.max())
                }
            }

            with open(output_dir / f"{ticker}_alpha_vantage_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            self.logger.info(f"Alpha Vantage: {len(df)} records saved to {filename}")
            return True

        except Exception as e:
            self.logger.error(f"Alpha Vantage download failed: {str(e)}")
            return False

    def download_polygon(self, ticker, output_dir, start_date, end_date, timeframe, api_key):
        """Download data from Polygon"""
        try:
            if not api_key:
                self.logger.warning("Polygon: API key required, skipping...")
                return False

            self.logger.info("Connecting to Polygon...")

            # Map timeframe to Polygon format
            timespan_map = {
                "1m": "minute", "5m": "minute", "15m": "minute",
                "30m": "minute", "1h": "hour", "1d": "day",
                "1wk": "week", "1mo": "month"
            }

            multiplier_map = {
                "1m": 1, "5m": 5, "15m": 15, "30m": 30,
                "1h": 1, "1d": 1, "1wk": 1, "1mo": 1
            }

            timespan = timespan_map.get(timeframe, "day")
            multiplier = multiplier_map.get(timeframe, 1)

            url = f"https://api.polygon.io/v2/aggs/ticker/{ticker}/range/{multiplier}/{timespan}/{start_date}/{end_date}"
            params = {
                "adjusted": "true",
                "sort": "asc",
                "limit": 50000,
                "apikey": api_key
            }

            response = requests.get(url, params=params, timeout=30)
            data = response.json()

            if data.get("status") != "OK":
                raise ValueError(f"Polygon API Error: {data.get('error', 'Unknown error')}")

            if not data.get("results"):
                raise ValueError("No data returned from Polygon")

            # Convert to DataFrame
            df_data = []
            for result in data["results"]:
                df_data.append({
                    'Date': pd.to_datetime(result['t'], unit='ms'),
                    'Open': result['o'],
                    'High': result['h'],
                    'Low': result['l'],
                    'Close': result['c'],
                    'Volume': result['v']
                })

            df = pd.DataFrame(df_data)
            df = df.set_index('Date').sort_index()

            # Clean data
            df = df.dropna()

            if df.empty:
                raise ValueError("No valid data after cleaning")

            # Save data
            filename = output_dir / f"{ticker}_polygon.csv"
            df.to_csv(filename)

            # Save metadata
            metadata = {
                "source": "Polygon",
                "ticker": ticker,
                "timeframe": timeframe,
                "start_date": start_date,
                "end_date": end_date,
                "download_time": datetime.now().isoformat(),
                "records_count": len(df),
                "filename": str(filename),
                "columns": list(df.columns),
                "date_range_actual": {
                    "start": str(df.index.min()),
                    "end": str(df.index.max())
                }
            }

            with open(output_dir / f"{ticker}_polygon_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            self.logger.info(f"Polygon: {len(df)} records saved to {filename}")
            return True

        except Exception as e:
            self.logger.error(f"Polygon download failed: {str(e)}")
            return False

    def download_data(self, ticker, source, start_date, end_date, timeframe, 
                     alpha_vantage_key=None, polygon_key=None):
        """Main download function"""
        try:
            ticker = ticker.upper().strip()
            self.logger.info(f"Starting download for {ticker}")

            # Create directory structure
            date_range = f"{start_date}_to_{end_date}"
            ticker_dir = self.output_dir / ticker / date_range
            ticker_dir.mkdir(parents=True, exist_ok=True)

            success_count = 0

            if source.lower() == "all":
                sources = ["yahoo", "alpha_vantage", "polygon"]
            else:
                sources = [source.lower()]

            for src in sources:
                try:
                    if src == "yahoo":
                        if self.download_yahoo_finance(ticker, ticker_dir, start_date, end_date, timeframe):
                            success_count += 1
                    elif src == "alpha_vantage":
                        if self.download_alpha_vantage(ticker, ticker_dir, start_date, end_date, timeframe, alpha_vantage_key):
                            success_count += 1
                    elif src == "polygon":
                        if self.download_polygon(ticker, ticker_dir, start_date, end_date, timeframe, polygon_key):
                            success_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to download from {src}: {str(e)}")

            if success_count > 0:
                self.logger.info(f"Download completed! {success_count} source(s) successful. Data saved to: {ticker_dir}")
                return True
            else:
                self.logger.error("All download sources failed!")
                return False

        except Exception as e:
            self.logger.error(f"Error during download: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="OHLCV Data Downloader - Download stock data from multiple APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download AAPL data from Yahoo Finance for the last year
  python ohlcv_cli.py AAPL --source yahoo --timeframe 1d

  # Download TSLA data from all sources with custom date range
  python ohlcv_cli.py TSLA --source all --start 2023-01-01 --end 2023-12-31 --timeframe 1d

  # Download with Alpha Vantage API key
  python ohlcv_cli.py MSFT --source alpha_vantage --alpha-key YOUR_API_KEY --timeframe 1h

  # Download intraday data from Polygon
  python ohlcv_cli.py GOOGL --source polygon --polygon-key YOUR_API_KEY --timeframe 5m --start 2024-01-01
        """
    )

    # Required arguments
    parser.add_argument("ticker", help="Stock ticker symbol (e.g., AAPL, TSLA)")

    # Optional arguments
    parser.add_argument("--source", "-s", 
                       choices=["yahoo", "alpha_vantage", "polygon", "all"],
                       default="yahoo",
                       help="Data source to use (default: yahoo)")

    parser.add_argument("--timeframe", "-t",
                       choices=["1m", "2m", "5m", "15m", "30m", "60m", "90m", 
                               "1h", "1d", "5d", "1wk", "1mo", "3mo"],
                       default="1d",
                       help="Timeframe for data (default: 1d)")

    parser.add_argument("--start", 
                       default=(datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d"),
                       help="Start date (YYYY-MM-DD, default: 1 year ago)")

    parser.add_argument("--end",
                       default=datetime.now().strftime("%Y-%m-%d"),
                       help="End date (YYYY-MM-DD, default: today)")

    parser.add_argument("--alpha-key",
                       help="Alpha Vantage API key")

    parser.add_argument("--polygon-key", 
                       help="Polygon API key")

    parser.add_argument("--output-dir", "-o",
                       default="data",
                       help="Output directory (default: data)")

    parser.add_argument("--verbose", "-v",
                       action="store_true",
                       help="Enable verbose logging")

    parser.add_argument("--version",
                       action="version",
                       version="OHLCV Downloader CLI v1.0.0")

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate date format
    try:
        datetime.strptime(args.start, "%Y-%m-%d")
        datetime.strptime(args.end, "%Y-%m-%d")
    except ValueError:
        print("Error: Date format must be YYYY-MM-DD")
        sys.exit(1)

    # Check if end date is after start date
    if args.start >= args.end:
        print("Error: End date must be after start date")
        sys.exit(1)

    # Create downloader instance
    downloader = OHLCVDownloaderCLI()

    # Override output directory if specified
    if args.output_dir != "data":
        downloader.output_dir = Path(args.output_dir)
        downloader.output_dir.mkdir(exist_ok=True)

    # Download data
    success = downloader.download_data(
        ticker=args.ticker,
        source=args.source,
        start_date=args.start,
        end_date=args.end,
        timeframe=args.timeframe,
        alpha_vantage_key=args.alpha_key,
        polygon_key=args.polygon_key
    )

    if success:
        print(f"\n✅ Download completed successfully!")
        print(f"📁 Data saved to: {downloader.output_dir / args.ticker}")
        sys.exit(0)
    else:
        print(f"\n❌ Download failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
