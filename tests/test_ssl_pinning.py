from secure_ohlcv_downloader import SecureOHLCVDownloader, FingerprintAdapter


def test_create_pinned_session(tmp_path):
    downloader = SecureOHLCVDownloader(str(tmp_path))
    session = downloader._create_pinned_session("https://example.com", "AA" * 32)
    adapter = session.get_adapter("https://example.com")
    assert isinstance(adapter, FingerprintAdapter)
    assert adapter.fingerprint == "aa" * 32
