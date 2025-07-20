import pytest
from secure_ohlcv_cli import SecureCLI

def test_min_source_date(monkeypatch, tmp_path):
    cli = SecureCLI()
    parser = cli.create_parser()
    args = parser.parse_args([
        "AAPL",
        "--source",
        "alpha_vantage",
        "--start-date",
        "1998-12-31",
        "--end-date",
        "1999-01-02",
        "--output-dir",
        str(tmp_path),
    ])
    with pytest.raises(SystemExit):
        cli._validate_arguments(args)
