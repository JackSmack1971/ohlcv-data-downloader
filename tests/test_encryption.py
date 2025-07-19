import keyring
from keyrings.alt.file import PlaintextKeyring
import pandas as pd
from pathlib import Path
from secure_ohlcv_downloader import SecureOHLCVDownloader


def _clear_keys() -> None:
    try:
        keyring.delete_password("ohlcv_downloader", "encryption_key")
    except keyring.errors.PasswordDeleteError:
        pass
    try:
        keyring.delete_password("ohlcv_downloader", "encryption_key_prev")
    except keyring.errors.PasswordDeleteError:
        pass


def test_encryption_key_persistence(tmp_path: Path) -> None:
    keyring.set_keyring(PlaintextKeyring())
    _clear_keys()

    SecureOHLCVDownloader(str(tmp_path))
    key1 = keyring.get_password("ohlcv_downloader", "encryption_key")
    assert key1 is not None

    SecureOHLCVDownloader(str(tmp_path))
    key2 = keyring.get_password("ohlcv_downloader", "encryption_key")
    assert key2 == key1


def test_key_rotation(tmp_path: Path) -> None:
    keyring.set_keyring(PlaintextKeyring())
    _clear_keys()
    dl = SecureOHLCVDownloader(str(tmp_path))
    original_key = keyring.get_password("ohlcv_downloader", "encryption_key")

    dl.rotate_encryption_key()
    new_key = keyring.get_password("ohlcv_downloader", "encryption_key")
    prev_key = keyring.get_password("ohlcv_downloader", "encryption_key_prev")

    assert new_key != original_key
    assert prev_key == original_key


def test_decrypt_with_old_key(tmp_path: Path) -> None:
    keyring.set_keyring(PlaintextKeyring())
    _clear_keys()
    dl = SecureOHLCVDownloader(str(tmp_path))
    df = pd.DataFrame({"a": [1]})
    file_path = tmp_path / "data.csv"
    dl._save_encrypted_data(df, file_path)
    encrypted_file = Path(f"{file_path}.encrypted")
    dl.rotate_encryption_key()

    decrypted = dl.decrypt_file(encrypted_file)
    assert decrypted.equals(df)
