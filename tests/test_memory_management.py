import pandas as pd
from datetime import date
import types
import psutil
import pytest
from secure_ohlcv_downloader import SecureOHLCVDownloader, SecurityError


def test_download_yahoo_stream(monkeypatch, tmp_path):
    dl = SecureOHLCVDownloader(str(tmp_path))
    dl.config.chunk_size_days = 1
    df1 = pd.DataFrame({"Open": [1], "High": [1], "Low": [1], "Close": [1], "Volume": [1]}, index=[pd.Timestamp("2024-01-01")])
    df2 = pd.DataFrame({"Open": [2], "High": [2], "Low": [2], "Close": [2], "Volume": [2]}, index=[pd.Timestamp("2024-01-02")])
    calls = [df1, df2]

    async def fake_hist(*args, **kwargs):
        return calls.pop(0)

    monkeypatch.setattr(dl, "_yahoo_history", fake_hist)
    file_path = tmp_path / "out.csv"
    records = dl._download_yahoo_stream("AAPL", date(2024, 1, 1), date(2024, 1, 2), "1d", file_path)
    assert records == 2
    data = pd.read_csv(file_path, index_col=0)
    assert len(data) == 2


def test_check_memory(monkeypatch, tmp_path):
    dl = SecureOHLCVDownloader(str(tmp_path))
    dl.config.max_memory_mb = 1024

    class FakeMem:
        def __init__(self, available):
            self.available = available

    monkeypatch.setattr(psutil, "virtual_memory", lambda: FakeMem(100 * 1024 * 1024))
    with pytest.raises(SecurityError):
        dl._check_memory()
