import os
import json
import hmac
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

if os.name == "posix":
    import fcntl
else:
    import msvcrt

class AuditError(Exception):
    """Exception raised for audit logging failures."""

    pass

class AuditLogger:
    """Simple append-only audit logger with optional HMAC integrity."""

    def __init__(self, log_file: Path, hmac_key: Optional[str] = None) -> None:
        self.log_file = log_file
        self.hmac_key = hmac_key.encode() if hmac_key else None
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            if not log_file.exists():
                log_file.touch()
            os.chmod(log_file, 0o600)
        except OSError as exc:
            raise AuditError(f"Failed to initialize audit log: {exc}")

    def _write(self, line: str) -> None:
        try:
            with open(self.log_file, "a") as fh:
                if os.name == "posix":
                    fcntl.flock(fh, fcntl.LOCK_EX)
                fh.write(line + "\n")
                if os.name == "posix":
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except OSError as exc:
            raise AuditError(f"Audit log write failed: {exc}")

    def log(self, user: str, action: str, details: Dict[str, Any]) -> None:
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "user": user,
            "action": action,
            "details": details,
        }
        data = json.dumps(entry, sort_keys=True)
        signature = ""
        if self.hmac_key:
            signature = hmac.new(self.hmac_key, data.encode(), hashlib.sha256).hexdigest()
        self._write(f"{data}|{signature}")
