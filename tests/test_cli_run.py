import sys
from pathlib import Path
from secure_ohlcv_cli import SecureCLI


def test_cli_run_invokes_download(monkeypatch, tmp_path):
    cli = SecureCLI()
    called = {}

    def dummy_setup(args):
        class Dummy:
            def download_data(self, config):
                called["cfg"] = config
                return Path(tmp_path) / "data.csv"
        cli.downloader = Dummy()

    monkeypatch.setattr(cli, "_setup_secure_environment", dummy_setup)
    monkeypatch.setattr(sys, "argv", ["prog", "AAPL", "--start-date", "2024-01-01", "--end-date", "2024-01-02", "--output-dir", str(tmp_path)])
    cli.run()
    assert called["cfg"].ticker == "AAPL"


def test_cli_check_env(monkeypatch):
    cli = SecureCLI()
    called = {"env": False}
    monkeypatch.setattr(cli, "_check_environment", lambda: called.__setitem__("env", True))
    monkeypatch.setattr(sys, "argv", ["prog", "AAPL", "--check-env"])
    cli.run()
    assert called["env"] is True
