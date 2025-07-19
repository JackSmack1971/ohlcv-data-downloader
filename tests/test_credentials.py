import asyncio
import os
import keyring
from keyrings.alt.file import PlaintextKeyring
from secure_ohlcv_cli import SecureCLI
from secure_ohlcv_downloader import SecureOHLCVDownloader


def test_prompt_for_api_keys(monkeypatch):
    keyring.set_keyring(PlaintextKeyring())
    cli = SecureCLI()
    monkeypatch.setattr("getpass.getpass", lambda prompt: "secret123")

    asyncio.run(cli._prompt_for_api_keys("alpha_vantage"))

    stored = keyring.get_password("ohlcv_downloader", "alpha_vantage_api_key")
    assert stored == "secret123"
    assert "ALPHA_VANTAGE_API_KEY" not in os.environ


def test_get_api_key_from_keyring(tmp_path):
    keyring.set_keyring(PlaintextKeyring())
    keyring.set_password("ohlcv_downloader", "alpha_vantage_api_key", "supersecret")

    downloader = SecureOHLCVDownloader(str(tmp_path))
    assert downloader._get_api_key("alpha_vantage") == "supersecret"
