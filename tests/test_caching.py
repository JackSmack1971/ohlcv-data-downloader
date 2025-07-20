import pandas as pd
from datetime import date
import pytest
import yfinance as yf
from secure_ohlcv_downloader import SecureOHLCVDownloader

class DummyTicker:
    calls = 0
    def __init__(self, ticker: str) -> None:
        self.ticker = ticker
    def history(self, start, end, interval):
        DummyTicker.calls += 1
        return pd.DataFrame({"Open":[1],"High":[1],"Low":[1],"Close":[1],"Volume":[1]}, index=[pd.Timestamp("2024-01-01")])

@pytest.mark.asyncio
async def test_yahoo_history_caching(monkeypatch, tmp_path):
    monkeypatch.setattr(yf, "Ticker", DummyTicker)
    dl = SecureOHLCVDownloader(str(tmp_path))
    await dl._yahoo_history("AAPL", date(2024,1,1), date(2024,1,2), "1d")
    await dl._yahoo_history("AAPL", date(2024,1,1), date(2024,1,2), "1d")
    assert DummyTicker.calls == 1
