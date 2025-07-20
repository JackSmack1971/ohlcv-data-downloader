from secure_ohlcv_downloader import (
    SecureOHLCVDownloader,
    DataValidator,
    APIClient,
    FileManager,
    ConfigurationManager,
    EncryptionManager,
)


def test_components_initialization(tmp_path):
    downloader = SecureOHLCVDownloader(str(tmp_path))
    assert isinstance(downloader.validator, DataValidator)
    assert isinstance(downloader.api_client, APIClient)
    assert isinstance(downloader.file_manager, FileManager)
    assert isinstance(downloader.config_manager, ConfigurationManager)
    assert isinstance(downloader.encryption_manager, EncryptionManager)

