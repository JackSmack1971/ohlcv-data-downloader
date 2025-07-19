import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
import pandas as pd
import yfinance as yf
import requests
import json
import os
from pathlib import Path
import logging

class OHLCVDownloader:
    def __init__(self, root):
        self.root = root
        self.root.title("OHLCV Data Downloader")
        self.root.geometry("600x500")

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

        self.setup_ui()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(main_frame, text="OHLCV Data Downloader", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Ticker Symbol
        ttk.Label(main_frame, text="Ticker Symbol:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ticker_var = tk.StringVar(value="AAPL")
        ticker_entry = ttk.Entry(main_frame, textvariable=self.ticker_var, width=20)
        ticker_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

        # Timeframe
        ttk.Label(main_frame, text="Timeframe:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.timeframe_var = tk.StringVar(value="1d")
        timeframe_combo = ttk.Combobox(main_frame, textvariable=self.timeframe_var, 
                                      values=["1m", "2m", "5m", "15m", "30m", "60m", "90m", 
                                             "1h", "1d", "5d", "1wk", "1mo", "3mo"], 
                                      state="readonly", width=17)
        timeframe_combo.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)

        # Date Range
        ttk.Label(main_frame, text="Start Date:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.start_date_var = tk.StringVar(value=(datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d"))
        start_date_entry = ttk.Entry(main_frame, textvariable=self.start_date_var, width=20)
        start_date_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(main_frame, text="End Date:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.end_date_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
        end_date_entry = ttk.Entry(main_frame, textvariable=self.end_date_var, width=20)
        end_date_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5)

        # API Selection
        ttk.Label(main_frame, text="Data Source:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.api_var = tk.StringVar(value="Yahoo Finance")
        api_combo = ttk.Combobox(main_frame, textvariable=self.api_var,
                                values=["Yahoo Finance", "Alpha Vantage", "Polygon", "All Sources"],
                                state="readonly", width=17)
        api_combo.grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5)

        # Alpha Vantage API Key (optional)
        ttk.Label(main_frame, text="Alpha Vantage Key:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.api_key_var = tk.StringVar()
        api_key_entry = ttk.Entry(main_frame, textvariable=self.api_key_var, width=20, show="*")
        api_key_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5)

        # Polygon API Key (optional)
        ttk.Label(main_frame, text="Polygon API Key:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.polygon_key_var = tk.StringVar()
        polygon_key_entry = ttk.Entry(main_frame, textvariable=self.polygon_key_var, width=20, show="*")
        polygon_key_entry.grid(row=7, column=1, sticky=(tk.W, tk.E), pady=5)

        # Download Button
        download_btn = ttk.Button(main_frame, text="Download Data", 
                                 command=self.download_data)
        download_btn.grid(row=8, column=0, columnspan=2, pady=20)

        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=9, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # Status Text
        self.status_text = tk.Text(main_frame, height=10, width=70)
        self.status_text.grid(row=10, column=0, columnspan=2, pady=10)

        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.status_text.yview)
        scrollbar.grid(row=10, column=2, sticky=(tk.N, tk.S))
        self.status_text.configure(yscrollcommand=scrollbar.set)

        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def log_status(self, message):
        """Add message to status text and log file"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.status_text.insert(tk.END, formatted_message)
        self.status_text.see(tk.END)
        self.root.update()
        logging.info(message)

    def download_data(self):
        """Main download function"""
        try:
            # Validate inputs
            ticker = self.ticker_var.get().upper().strip()
            if not ticker:
                messagebox.showerror("Error", "Please enter a ticker symbol")
                return

            # Clear status
            self.status_text.delete(1.0, tk.END)
            self.progress.start()

            self.log_status(f"Starting download for {ticker}")

            # Create directory structure
            date_range = f"{self.start_date_var.get()}_to_{self.end_date_var.get()}"
            ticker_dir = self.output_dir / ticker / date_range
            ticker_dir.mkdir(parents=True, exist_ok=True)

            api_source = self.api_var.get()

            if api_source == "All Sources":
                self.download_from_all_sources(ticker, ticker_dir)
            else:
                self.download_from_single_source(ticker, ticker_dir, api_source)

            self.progress.stop()
            self.log_status("Download completed successfully!")
            messagebox.showinfo("Success", f"Data saved to: {ticker_dir}")

        except Exception as e:
            self.progress.stop()
            error_msg = f"Error during download: {str(e)}"
            self.log_status(error_msg)
            messagebox.showerror("Error", error_msg)

    def download_from_single_source(self, ticker, output_dir, source):
        """Download from a single API source"""
        if source == "Yahoo Finance":
            self.download_yahoo_finance(ticker, output_dir)
        elif source == "Alpha Vantage":
            self.download_alpha_vantage(ticker, output_dir)
        elif source == "Polygon":
            self.download_polygon(ticker, output_dir)

    def download_from_all_sources(self, ticker, output_dir):
        """Download from all available sources"""
        sources = ["Yahoo Finance", "Alpha Vantage", "Polygon"]
        for source in sources:
            try:
                self.log_status(f"Downloading from {source}...")
                self.download_from_single_source(ticker, output_dir, source)
            except Exception as e:
                self.log_status(f"Failed to download from {source}: {str(e)}")

    def download_yahoo_finance(self, ticker, output_dir):
        """Download data from Yahoo Finance"""
        try:
            self.log_status("Connecting to Yahoo Finance...")

            stock = yf.Ticker(ticker)
            data = stock.history(
                start=self.start_date_var.get(),
                end=self.end_date_var.get(),
                interval=self.timeframe_var.get()
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
                "timeframe": self.timeframe_var.get(),
                "start_date": self.start_date_var.get(),
                "end_date": self.end_date_var.get(),
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

            self.log_status(f"Yahoo Finance: {len(data)} records saved to {filename}")

        except Exception as e:
            raise Exception(f"Yahoo Finance download failed: {str(e)}")

    def download_alpha_vantage(self, ticker, output_dir):
        """Download data from Alpha Vantage"""
        try:
            api_key = self.api_key_var.get().strip()
            if not api_key:
                self.log_status("Alpha Vantage: API key required, skipping...")
                return

            self.log_status("Connecting to Alpha Vantage...")

            # Map timeframe to Alpha Vantage format
            interval_map = {
                "1m": "1min", "5m": "5min", "15m": "15min", 
                "30m": "30min", "60m": "60min", "1d": "daily"
            }

            interval = interval_map.get(self.timeframe_var.get(), "daily")

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
            start_date = pd.to_datetime(self.start_date_var.get())
            end_date = pd.to_datetime(self.end_date_var.get())
            df = df[(df.index >= start_date) & (df.index <= end_date)]

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
                "timeframe": self.timeframe_var.get(),
                "start_date": self.start_date_var.get(),
                "end_date": self.end_date_var.get(),
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

            self.log_status(f"Alpha Vantage: {len(df)} records saved to {filename}")

        except Exception as e:
            raise Exception(f"Alpha Vantage download failed: {str(e)}")

    def download_polygon(self, ticker, output_dir):
        """Download data from Polygon"""
        try:
            api_key = self.polygon_key_var.get().strip()
            if not api_key:
                self.log_status("Polygon: API key required, skipping...")
                return

            self.log_status("Connecting to Polygon...")

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

            timespan = timespan_map.get(self.timeframe_var.get(), "day")
            multiplier = multiplier_map.get(self.timeframe_var.get(), 1)

            # Convert dates to Polygon format
            start_date = self.start_date_var.get()
            end_date = self.end_date_var.get()

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
                "timeframe": self.timeframe_var.get(),
                "start_date": self.start_date_var.get(),
                "end_date": self.end_date_var.get(),
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

            self.log_status(f"Polygon: {len(df)} records saved to {filename}")

        except Exception as e:
            raise Exception(f"Polygon download failed: {str(e)}")

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = OHLCVDownloader(root)
    root.mainloop()

if __name__ == "__main__":
    main()
