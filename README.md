# OHLCV Data Downloader

A comprehensive Python application for downloading OHLCV (Open, High, Low, Close, Volume) stock data from multiple free APIs with both GUI and command-line interfaces.

## 🚀 Features

- **Multiple Data Sources**: Yahoo Finance, Alpha Vantage, and Polygon APIs
- **Dual Interface**: Both GUI (tkinter) and command-line versions
- **Flexible Timeframes**: Support for various intervals (1m, 5m, 15m, 30m, 1h, 1d, 1wk, 1mo, etc.)
- **Organized Storage**: Automatic folder structure by ticker and date range
- **Data Validation**: Built-in data cleaning and validation
- **Comprehensive Logging**: Detailed logs for debugging and monitoring
- **Metadata Tracking**: JSON metadata files with download information
- **Error Handling**: Robust error handling with user-friendly messages
- **Batch Downloads**: Download from all sources simultaneously
- **Data Retention**: Automatic cleanup of files older than a configurable period

## 📋 Requirements

- Python 3.7 or higher
- Internet connection for API access
- Optional: API keys for Alpha Vantage and Polygon (free tiers available)

## 🛠️ Installation

### 1. Clone or Download the Files

Download the following files to your project directory:
- `secure_ohlcv_downloader.py` (GUI version)
- `secure_ohlcv_cli.py` (Command-line version)
- `requirements-secure.txt`

### 2. Install Dependencies

```bash
pip install -r requirements-secure.txt
```

Or install manually:
```bash
pip install pandas yfinance alpha-vantage requests python-dotenv matplotlib plotly
```

### 3. API Keys Setup (Optional but Recommended)

#### Alpha Vantage (Free)
1. Visit [Alpha Vantage](https://www.alphavantage.co/support/#api-key)
2. Sign up for a free API key
3. Note: Free tier allows 5 API requests per minute and 500 requests per day

#### Polygon (Free Tier Available)
1. Visit [Polygon.io](https://polygon.io/)
2. Sign up for a free account
3. Get your API key from the dashboard
4. Note: Free tier has limitations on data access

## 🖥️ Usage

### GUI Version

Run the graphical interface:
```bash
python secure_ohlcv_downloader.py
```

**GUI Features:**
- User-friendly interface with input fields
- Real-time progress tracking
- Status logging window
- Error messages and success notifications
- Support for all data sources

### Command-Line Version

#### Basic Usage
```bash
# Download AAPL data from Yahoo Finance (default)
python secure_ohlcv_cli.py AAPL

# Download with specific timeframe
python secure_ohlcv_cli.py AAPL --timeframe 1h

# Download with custom date range
python secure_ohlcv_cli.py TSLA --start 2023-01-01 --end 2023-12-31
```

#### Advanced Usage
```bash
# Download from all sources
python secure_ohlcv_cli.py MSFT --source all --timeframe 1d

# Use Alpha Vantage with API key
python secure_ohlcv_cli.py GOOGL --source alpha_vantage --alpha-key YOUR_API_KEY

# Use Polygon with API key for intraday data
python secure_ohlcv_cli.py NVDA --source polygon --polygon-key YOUR_API_KEY --timeframe 5m

# Verbose logging
python secure_ohlcv_cli.py AAPL --verbose

# Custom output directory
python secure_ohlcv_cli.py AAPL --output-dir /path/to/custom/directory
```

#### Command-Line Options
```
positional arguments:
  ticker                Stock ticker symbol (e.g., AAPL, TSLA)

optional arguments:
  -h, --help            show this help message and exit
  --source {yahoo,alpha_vantage,polygon,all}
                        Data source to use (default: yahoo)
  --timeframe {1m,2m,5m,15m,30m,60m,90m,1h,1d,5d,1wk,1mo,3mo}
                        Timeframe for data (default: 1d)
  --start START         Start date (YYYY-MM-DD, default: 1 year ago)
  --end END             End date (YYYY-MM-DD, default: today)
  --alpha-key ALPHA_KEY Alpha Vantage API key
  --polygon-key POLYGON_KEY
                        Polygon API key
  --output-dir OUTPUT_DIR
                        Output directory (default: data)
  --verbose, -v         Enable verbose logging
  --version             show program's version number and exit
```

## 📁 Output Structure

The application creates an organized folder structure:

```
data/
├── AAPL/
│   └── 2023-01-01_to_2023-12-31/
│       ├── AAPL_yahoo_finance.csv
│       ├── AAPL_yahoo_metadata.json
│       ├── AAPL_alpha_vantage.csv
│       ├── AAPL_alpha_vantage_metadata.json
│       ├── AAPL_polygon.csv
│       └── AAPL_polygon_metadata.json
├── TSLA/
│   └── 2024-01-01_to_2024-01-31/
│       └── ...
└── secure_downloader.log
```

### CSV File Format

Each CSV file contains OHLCV data with the following columns:
- `Date` (index): Timestamp
- `Open`: Opening price
- `High`: Highest price
- `Low`: Lowest price
- `Close`: Closing price
- `Volume`: Trading volume

### Metadata Files

JSON metadata files contain:
```json
{
  "source": "Yahoo Finance",
  "ticker": "AAPL",
  "timeframe": "1d",
  "start_date": "2023-01-01",
  "end_date": "2023-12-31",
  "download_time": "2024-01-15T10:30:00",
  "records_count": 252,
  "filename": "data/AAPL/2023-01-01_to_2023-12-31/AAPL_yahoo_finance.csv",
  "columns": ["Open", "High", "Low", "Close", "Volume"],
  "date_range_actual": {
    "start": "2023-01-03",
    "end": "2023-12-29"
  }
}
```

## 🔧 Configuration

### Environment Variables (Optional)

Create a `.env` file in your project directory:
```env
ALPHA_VANTAGE_API_KEY=your_alpha_vantage_key_here
POLYGON_API_KEY=your_polygon_key_here
```

Then use python-dotenv to load them:
```python
from dotenv import load_dotenv
import os

load_dotenv()
alpha_key = os.getenv('ALPHA_VANTAGE_API_KEY')
polygon_key = os.getenv('POLYGON_API_KEY')
```

## 📊 Data Sources Comparison

| Feature | Yahoo Finance | Alpha Vantage | Polygon |
|---------|---------------|---------------|---------|
| **API Key Required** | No | Yes (Free) | Yes (Free tier) |
| **Rate Limits** | Reasonable | 5/min, 500/day | Varies by plan |
| **Intraday Data** | Yes | Yes | Yes |
| **Historical Range** | Extensive | Good | Good |
| **Data Quality** | High | High | High |
| **Reliability** | High | Medium | High |

## 🚨 Error Handling

The application handles various error scenarios:

- **Network Issues**: Timeout and connection errors
- **API Limits**: Rate limiting and quota exceeded
- **Invalid Tickers**: Non-existent stock symbols
- **Date Range Issues**: Invalid or future dates
- **Data Validation**: Missing or corrupted data

## 📝 Logging

Logs are saved to `secure_downloader.log` and include:
- Download start/completion times
- Success/failure status for each source
- Error messages and stack traces
- Data validation results
- API response information

## 🔍 Troubleshooting

### Common Issues

1. **"No display name and no $DISPLAY environment variable"**
   - Use the CLI version: `python secure_ohlcv_cli.py`
   - Or run on a system with GUI support

2. **"API key required"**
   - Obtain free API keys from Alpha Vantage or Polygon
   - Use Yahoo Finance (no key required) as alternative

3. **"No data returned"**
   - Check if ticker symbol is valid
   - Verify date range is not in the future
   - Ensure market was open during selected dates

4. **Rate limit exceeded**
   - Wait before making additional requests
   - Consider using multiple API keys
   - Use Yahoo Finance for unlimited requests

### Debug Mode

Enable verbose logging for detailed information:
```bash
python secure_ohlcv_cli.py AAPL --verbose
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is open source and available under the MIT License.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the log files for error details
3. Ensure all dependencies are installed correctly
4. Verify API keys are valid and have remaining quota

## 🔮 Future Enhancements

- [ ] Additional data sources (IEX Cloud, Quandl)
- [ ] Real-time data streaming
- [ ] Data visualization dashboard
- [ ] Database storage options
- [ ] Automated scheduling
- [ ] Portfolio tracking features
- [ ] Technical indicators calculation
- [ ] Export to multiple formats (Excel, JSON, Parquet)

## 📈 Example Data Analysis

After downloading data, you can analyze it with pandas:

```python
import pandas as pd
import matplotlib.pyplot as plt

# Load downloaded data
df = pd.read_csv('data/AAPL/2023-01-01_to_2023-12-31/AAPL_yahoo_finance.csv', 
                 index_col='Date', parse_dates=True)

# Basic statistics
print(df.describe())

# Plot closing prices
df['Close'].plot(title='AAPL Closing Prices', figsize=(12, 6))
plt.show()

# Calculate daily returns
df['Returns'] = df['Close'].pct_change()
print(f"Average daily return: {df['Returns'].mean():.4f}")
print(f"Volatility: {df['Returns'].std():.4f}")
```

---

**Happy Trading! 📈**
