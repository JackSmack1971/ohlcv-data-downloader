import os
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from secure_ohlcv_downloader import SecureOHLCVDownloader


def test_cleanup_expired_data(tmp_path: Path) -> None:
    dl = SecureOHLCVDownloader(str(tmp_path))
    old_dir = tmp_path / "data" / "AAPL" / "old"
    old_dir.mkdir(parents=True)
    old_file = old_dir / "old.csv"
    old_file.write_text("test")
    old_time = datetime.now() - timedelta(days=8)
    os.utime(old_file, (old_time.timestamp(), old_time.timestamp()))

    new_dir = tmp_path / "data" / "AAPL" / "new"
    new_dir.mkdir(parents=True)
    new_file = new_dir / "new.csv"
    new_file.write_text("test")

    asyncio.run(dl.cleanup_expired_data(7))

    assert not old_file.exists()
    assert new_file.exists()
