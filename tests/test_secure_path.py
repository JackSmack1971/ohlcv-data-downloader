import os
import stat
import pytest
from secure_ohlcv_downloader import SecureOHLCVDownloader, SecurityError


def test_create_secure_path_valid(tmp_path):
    dl = SecureOHLCVDownloader(str(tmp_path))
    path = dl._create_secure_path("AAPL", "2024-01-01_2024-01-31")
    assert path.exists()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o700


def test_create_secure_path_symlink_attack(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    os.symlink(evil_dir, output_dir / "data")
    dl = SecureOHLCVDownloader(str(output_dir))
    with pytest.raises(SecurityError):
        dl._create_secure_path("AAPL", "2024-01-01_2024-01-31")
