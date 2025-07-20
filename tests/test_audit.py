import json
import hmac
import hashlib
from pathlib import Path
from audit import AuditLogger


def test_audit_logger(tmp_path: Path) -> None:
    key = "secret"
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file, key)
    logger.log("tester", "download", {"file": "data.csv"})
    line = log_file.read_text().strip()
    data, sig = line.split("|")
    expected = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    assert sig == expected
    entry = json.loads(data)
    assert entry["user"] == "tester"
    assert entry["action"] == "download"

