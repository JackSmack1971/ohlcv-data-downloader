#!/usr/bin/env python3
"""
OHLCV Data Downloader - Comprehensive Demo Script

This script demonstrates various features and usage patterns of the OHLCV downloader.
Run this script to see examples of different data sources, analysis techniques, and workflows.
"""

import pandas as pd
import matplotlib.pyplot as plt
import json
import os
from pathlib import Path
from datetime import datetime, timedelta
import sys

# Add current directory to path to import our modules
sys.path.append('.')

try:
    from ohlcv_cli import OHLCVDownloaderCLI
    print("✅ Successfully imported OHLCVDownloaderCLI")
except ImportError as e:
    print(f"❌ Could not import OHLCVDownloaderCLI: {e}")
    print("Make sure ohlcv_cli.py is in the current directory")
    sys.exit(1)

class OHLCVDemo:
    def __init__(self):
        self.downloader = OHLCVDownloaderCLI()
        self.demo_tickers = ['AAPL', 'TSLA', 'MSFT', 'GOOGL']
        self.output_dir = Path("demo_data")
        self.output_dir.mkdir(exist_ok=True)

        # Override downloader output directory
        self.downloader.output_dir = self.output_dir

        print("🎯 OHLCV Data Downloader - Comprehensive Demo")
        print("=" * 60)

    def demo_basic_download(self):
        """Demonstrate basic data download from Yahoo Finance"""
        print("
📊 DEMO 1: Basic Data Download (Yahoo Finance)")
        print("-" * 50)

        ticker = "AAPL"
        start_date = "2024-01-01"
        end_date = "2024-01-31"
        timeframe = "1d"

        print(f"Downloading {ticker} data from {start_date} to {end_date}")
        print(f"Timeframe: {timeframe}")
        print(f"Source: Yahoo Finance (no API key required)")

        success = self.downloader.download_data(
            ticker=ticker,
            source="yahoo",
            start_date=start_date,
            end_date=end_date,
            timeframe=timeframe
        )

        if success:
            print(f"✅ Successfully downloaded {ticker} data")
            self.analyze_downloaded_data(ticker, start_date, end_date, "yahoo_finance")
        else:
            print(f"❌ Failed to download {ticker} data")

    def demo_multiple_tickers(self):
        """Demonstrate downloading multiple tickers"""
        print("
📈 DEMO 2: Multiple Tickers Download")
        print("-" * 50)

        tickers = ["AAPL", "TSLA", "MSFT"]
        start_date = "2024-06-01"
        end_date = "2024-06-30"

        print(f"Downloading data for: {', '.join(tickers)}")
        print(f"Date range: {start_date} to {end_date}")

        results = {}
        for ticker in tickers:
            print(f"\nDownloading {ticker}...")
            success = self.downloader.download_data(
                ticker=ticker,
                source="yahoo",
                start_date=start_date,
                end_date=end_date,
                timeframe="1d"
            )
            results[ticker] = success

        print(f"\n📊 Download Results:")
        for ticker, success in results.items():
            status = "✅ Success" if success else "❌ Failed"
            print(f"  {ticker}: {status}")

        # Compare performance if downloads were successful
        successful_tickers = [t for t, s in results.items() if s]
        if len(successful_tickers) > 1:
            self.compare_stock_performance(successful_tickers, start_date, end_date)

    def demo_different_timeframes(self):
        """Demonstrate different timeframe options"""
        print("
⏰ DEMO 3: Different Timeframes")
        print("-" * 50)

        ticker = "TSLA"
        timeframes = ["1d", "1wk", "1mo"]
        start_date = "2023-01-01"
        end_date = "2023-12-31"

        print(f"Downloading {ticker} data with different timeframes:")

        for timeframe in timeframes:
            print(f"\n📅 Timeframe: {timeframe}")
            success = self.downloader.download_data(
                ticker=ticker,
                source="yahoo",
                start_date=start_date,
                end_date=end_date,
                timeframe=timeframe
            )

            if success:
                # Show data summary for each timeframe
                date_range = f"{start_date}_to_{end_date}"
                csv_file = self.output_dir / ticker / date_range / f"{ticker}_yahoo_finance.csv"

                if csv_file.exists():
                    df = pd.read_csv(csv_file, index_col='Date', parse_dates=True)
                    print(f"  Records: {len(df)}")
                    print(f"  Date range: {df.index.min().strftime('%Y-%m-%d')} to {df.index.max().strftime('%Y-%m-%d')}")
                    print(f"  Price range: ${df['Low'].min():.2f} - ${df['High'].max():.2f}")

    def demo_data_analysis(self):
        """Demonstrate basic data analysis techniques"""
        print("
🔍 DEMO 4: Data Analysis Examples")
        print("-" * 50)

        # First ensure we have some data
        ticker = "AAPL"
        start_date = "2023-01-01"
        end_date = "2023-12-31"

        print(f"Downloading {ticker} data for analysis...")
        success = self.downloader.download_data(
            ticker=ticker,
            source="yahoo",
            start_date=start_date,
            end_date=end_date,
            timeframe="1d"
        )

        if not success:
            print("❌ Could not download data for analysis")
            return

        # Load and analyze the data
        date_range = f"{start_date}_to_{end_date}"
        csv_file = self.output_dir / ticker / date_range / f"{ticker}_yahoo_finance.csv"

        if not csv_file.exists():
            print("❌ Data file not found")
            return

        df = pd.read_csv(csv_file, index_col='Date', parse_dates=True)

        print(f"\n📊 Analysis for {ticker} ({len(df)} trading days)")
        print("-" * 30)

        # Basic statistics
        print("💰 Price Statistics:")
        print(f"  Opening Price: ${df['Open'].iloc[0]:.2f}")
        print(f"  Closing Price: ${df['Close'].iloc[-1]:.2f}")
        print(f"  Highest Price: ${df['High'].max():.2f}")
        print(f"  Lowest Price: ${df['Low'].min():.2f}")
        print(f"  Average Close: ${df['Close'].mean():.2f}")

        # Calculate returns
        df['Daily_Return'] = df['Close'].pct_change()
        df['Cumulative_Return'] = (1 + df['Daily_Return']).cumprod() - 1

        print(f"\n📈 Performance Metrics:")
        total_return = (df['Close'].iloc[-1] / df['Close'].iloc[0] - 1) * 100
        print(f"  Total Return: {total_return:.2f}%")
        print(f"  Average Daily Return: {df['Daily_Return'].mean() * 100:.3f}%")
        print(f"  Volatility (Daily): {df['Daily_Return'].std() * 100:.3f}%")
        print(f"  Best Day: {df['Daily_Return'].max() * 100:.2f}%")
        print(f"  Worst Day: {df['Daily_Return'].min() * 100:.2f}%")

        # Volume analysis
        print(f"\n📊 Volume Analysis:")
        print(f"  Average Volume: {df['Volume'].mean():,.0f}")
        print(f"  Highest Volume: {df['Volume'].max():,.0f}")
        print(f"  Lowest Volume: {df['Volume'].min():,.0f}")

        # Moving averages
        df['MA_20'] = df['Close'].rolling(window=20).mean()
        df['MA_50'] = df['Close'].rolling(window=50).mean()

        print(f"\n📉 Technical Indicators:")
        print(f"  20-day MA: ${df['MA_20'].iloc[-1]:.2f}")
        print(f"  50-day MA: ${df['MA_50'].iloc[-1]:.2f}")

        current_price = df['Close'].iloc[-1]
        ma20_signal = "Above" if current_price > df['MA_20'].iloc[-1] else "Below"
        ma50_signal = "Above" if current_price > df['MA_50'].iloc[-1] else "Below"

        print(f"  Price vs 20-day MA: {ma20_signal}")
        print(f"  Price vs 50-day MA: {ma50_signal}")

        # Save analysis results
        analysis_file = self.output_dir / f"{ticker}_analysis_results.json"
        analysis_results = {
            "ticker": ticker,
            "analysis_date": datetime.now().isoformat(),
            "data_period": f"{start_date} to {end_date}",
            "total_return_percent": round(total_return, 2),
            "average_daily_return_percent": round(df['Daily_Return'].mean() * 100, 4),
            "volatility_percent": round(df['Daily_Return'].std() * 100, 4),
            "price_statistics": {
                "opening": round(df['Open'].iloc[0], 2),
                "closing": round(df['Close'].iloc[-1], 2),
                "highest": round(df['High'].max(), 2),
                "lowest": round(df['Low'].min(), 2),
                "average": round(df['Close'].mean(), 2)
            },
            "volume_statistics": {
                "average": int(df['Volume'].mean()),
                "highest": int(df['Volume'].max()),
                "lowest": int(df['Volume'].min())
            },
            "technical_indicators": {
                "ma_20": round(df['MA_20'].iloc[-1], 2),
                "ma_50": round(df['MA_50'].iloc[-1], 2),
                "price_vs_ma20": ma20_signal,
                "price_vs_ma50": ma50_signal
            }
        }

        with open(analysis_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)

        print(f"\n💾 Analysis results saved to: {analysis_file}")

    def demo_visualization(self):
        """Demonstrate data visualization"""
        print("
📊 DEMO 5: Data Visualization")
        print("-" * 50)

        # Use existing data or download new
        ticker = "AAPL"
        start_date = "2023-01-01"
        end_date = "2023-12-31"
        date_range = f"{start_date}_to_{end_date}"
        csv_file = self.output_dir / ticker / date_range / f"{ticker}_yahoo_finance.csv"

        if not csv_file.exists():
            print(f"Downloading {ticker} data for visualization...")
            success = self.downloader.download_data(
                ticker=ticker,
                source="yahoo",
                start_date=start_date,
                end_date=end_date,
                timeframe="1d"
            )
            if not success:
                print("❌ Could not download data for visualization")
                return

        df = pd.read_csv(csv_file, index_col='Date', parse_dates=True)

        # Calculate moving averages
        df['MA_20'] = df['Close'].rolling(window=20).mean()
        df['MA_50'] = df['Close'].rolling(window=50).mean()
        df['Daily_Return'] = df['Close'].pct_change()

        print(f"Creating visualizations for {ticker}...")

        # Create multiple plots
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(f'{ticker} Stock Analysis - {start_date} to {end_date}', fontsize=16)

        # Plot 1: Price and Moving Averages
        axes[0, 0].plot(df.index, df['Close'], label='Close Price', linewidth=1)
        axes[0, 0].plot(df.index, df['MA_20'], label='20-day MA', alpha=0.7)
        axes[0, 0].plot(df.index, df['MA_50'], label='50-day MA', alpha=0.7)
        axes[0, 0].set_title('Price and Moving Averages')
        axes[0, 0].set_ylabel('Price ($)')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)

        # Plot 2: Volume
        axes[0, 1].bar(df.index, df['Volume'], alpha=0.6, color='orange')
        axes[0, 1].set_title('Trading Volume')
        axes[0, 1].set_ylabel('Volume')
        axes[0, 1].grid(True, alpha=0.3)

        # Plot 3: Daily Returns
        axes[1, 0].plot(df.index, df['Daily_Return'] * 100, alpha=0.7, color='green')
        axes[1, 0].axhline(y=0, color='black', linestyle='-', alpha=0.3)
        axes[1, 0].set_title('Daily Returns (%)')
        axes[1, 0].set_ylabel('Return (%)')
        axes[1, 0].grid(True, alpha=0.3)

        # Plot 4: Price Distribution
        axes[1, 1].hist(df['Close'], bins=30, alpha=0.7, color='purple', edgecolor='black')
        axes[1, 1].axvline(df['Close'].mean(), color='red', linestyle='--', label=f'Mean: ${df["Close"].mean():.2f}')
        axes[1, 1].set_title('Price Distribution')
        axes[1, 1].set_xlabel('Price ($)')
        axes[1, 1].set_ylabel('Frequency')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)

        plt.tight_layout()

        # Save the plot
        plot_file = self.output_dir / f"{ticker}_analysis_charts.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        print(f"📊 Charts saved to: {plot_file}")

        # Show plot if in interactive environment
        try:
            plt.show()
        except:
            print("📊 Charts created (display not available in this environment)")

        plt.close()

    def analyze_downloaded_data(self, ticker, start_date, end_date, source):
        """Analyze downloaded data and show summary"""
        date_range = f"{start_date}_to_{end_date}"
        csv_file = self.output_dir / ticker / date_range / f"{ticker}_{source}.csv"
        metadata_file = self.output_dir / ticker / date_range / f"{ticker}_{source.replace('_', '_')}_metadata.json"

        if csv_file.exists():
            df = pd.read_csv(csv_file, index_col='Date', parse_dates=True)

            print(f"\n📈 Data Summary:")
            print(f"  Records: {len(df)}")
            print(f"  Date Range: {df.index.min().strftime('%Y-%m-%d')} to {df.index.max().strftime('%Y-%m-%d')}")
            print(f"  Price Range: ${df['Low'].min():.2f} - ${df['High'].max():.2f}")
            print(f"  Average Volume: {df['Volume'].mean():,.0f}")

            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                print(f"  Download Time: {metadata.get('download_time', 'Unknown')}")
                print(f"  File Size: {csv_file.stat().st_size} bytes")

    def compare_stock_performance(self, tickers, start_date, end_date):
        """Compare performance of multiple stocks"""
        print(f"\n🏆 PERFORMANCE COMPARISON")
        print("-" * 30)

        performance_data = {}
        date_range = f"{start_date}_to_{end_date}"

        for ticker in tickers:
            csv_file = self.output_dir / ticker / date_range / f"{ticker}_yahoo_finance.csv"
            if csv_file.exists():
                df = pd.read_csv(csv_file, index_col='Date', parse_dates=True)

                # Calculate total return
                total_return = (df['Close'].iloc[-1] / df['Close'].iloc[0] - 1) * 100
                avg_volume = df['Volume'].mean()
                volatility = df['Close'].pct_change().std() * 100

                performance_data[ticker] = {
                    'total_return': total_return,
                    'avg_volume': avg_volume,
                    'volatility': volatility,
                    'max_price': df['High'].max(),
                    'min_price': df['Low'].min()
                }

        if performance_data:
            print(f"{'Ticker':<8} {'Return %':<10} {'Volatility %':<12} {'Max Price':<10} {'Avg Volume':<12}")
            print("-" * 60)

            for ticker, data in performance_data.items():
                print(f"{ticker:<8} {data['total_return']:<10.2f} {data['volatility']:<12.3f} "
                      f"${data['max_price']:<9.2f} {data['avg_volume']:<12,.0f}")

            # Find best and worst performers
            best_performer = max(performance_data.items(), key=lambda x: x[1]['total_return'])
            worst_performer = min(performance_data.items(), key=lambda x: x[1]['total_return'])

            print(f"\n🥇 Best Performer: {best_performer[0]} ({best_performer[1]['total_return']:.2f}%)")
            print(f"🥉 Worst Performer: {worst_performer[0]} ({worst_performer[1]['total_return']:.2f}%)")

    def demo_error_handling(self):
        """Demonstrate error handling with invalid inputs"""
        print("\n⚠️  DEMO 6: Error Handling Examples")
        print("-" * 50)

        print("Testing invalid ticker symbol...")
        success = self.downloader.download_data(
            ticker="INVALID_TICKER_12345",
            source="yahoo",
            start_date="2024-01-01",
            end_date="2024-01-31",
            timeframe="1d"
        )
        print(f"Result: {'✅ Handled gracefully' if not success else '❌ Unexpected success'}")

        print("\nTesting invalid date range...")
        success = self.downloader.download_data(
            ticker="AAPL",
            source="yahoo",
            start_date="2025-01-01",  # Future date
            end_date="2025-12-31",
            timeframe="1d"
        )
        print(f"Result: {'✅ Handled gracefully' if not success else '❌ Unexpected success'}")

    def run_all_demos(self):
        """Run all demonstration examples"""
        print("🚀 Starting comprehensive OHLCV downloader demonstration...")
        print("This will showcase various features and capabilities.\n")

        try:
            self.demo_basic_download()
            self.demo_multiple_tickers()
            self.demo_different_timeframes()
            self.demo_data_analysis()
            self.demo_visualization()
            self.demo_error_handling()

            print("\n" + "=" * 60)
            print("🎉 DEMONSTRATION COMPLETE!")
            print("=" * 60)
            print(f"📁 All demo data saved to: {self.output_dir}")
            print("\n📚 What you've seen:")
            print("  ✅ Basic data download from Yahoo Finance")
            print("  ✅ Multiple ticker downloads")
            print("  ✅ Different timeframe options")
            print("  ✅ Comprehensive data analysis")
            print("  ✅ Data visualization")
            print("  ✅ Error handling")
            print("\n🔗 Next steps:")
            print("  • Try the GUI version: python ohlcv_downloader.py")
            print("  • Use CLI for automation: python ohlcv_cli.py --help")
            print("  • Get API keys for Alpha Vantage and Polygon")
            print("  • Explore the generated data files and analysis")

        except Exception as e:
            print(f"\n❌ Demo encountered an error: {str(e)}")
            print("Please check your installation and try again.")

    def show_file_structure(self):
        """Show the created file structure"""
        print("\n📁 Generated File Structure:")
        print("-" * 30)

        for root, dirs, files in os.walk(self.output_dir):
            level = root.replace(str(self.output_dir), '').count(os.sep)
            indent = ' ' * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                file_path = Path(root) / file
                file_size = file_path.stat().st_size if file_path.exists() else 0
                print(f"{subindent}{file} ({file_size} bytes)")

def main():
    """Main function to run the demo"""
    print("OHLCV Data Downloader - Interactive Demo")
    print("=" * 50)
    print("This demo will showcase the capabilities of the OHLCV downloader.")
    print("It will download sample data and perform various analyses.\n")

    # Check if user wants to run the demo
    try:
        response = input("Do you want to run the full demo? (y/n): ").lower().strip()
        if response not in ['y', 'yes']:
            print("Demo cancelled. You can run individual functions by importing this module.")
            return
    except KeyboardInterrupt:
        print("\nDemo cancelled by user.")
        return

    # Run the demo
    demo = OHLCVDemo()
    demo.run_all_demos()
    demo.show_file_structure()

    print("\n🎯 Demo completed! Check the generated files and try the applications yourself.")

if __name__ == "__main__":
    main()
