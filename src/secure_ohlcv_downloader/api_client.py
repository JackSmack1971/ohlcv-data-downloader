"""HTTP client with certificate pinning and retry logic."""

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .certificate_manager import CertificateManager
from .exceptions import SecurityError


class APIClient:
    """Perform HTTP requests with SSL pinning."""

    def __init__(self, cert_manager: CertificateManager) -> None:
        self.cert_manager = cert_manager

    def create_pinned_session(self, host: str, fingerprint: str) -> requests.Session:
        """Create a requests session that pins the server certificate.

        The session uses :class:`FingerprintAdapter` to verify the TLS
        fingerprint for every connection. Failure to match results in a
        :class:`SecurityError`. Retry logic is configured to resist transient
        network issues without indefinite blocking.
        """
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = FingerprintAdapter(fingerprint, max_retries=retries)
        session.mount(host, adapter)
        session.verify = True
        return session

    def fetch(self, session: requests.Session, url: str, **kwargs: Any) -> requests.Response:
        """Perform a GET request with standard timeout and error handling.

        Attack vector: if no timeout is specified an attacker could hold the
        connection open and exhaust resources. A default of 30 seconds is
        enforced and network errors raise :class:`SecurityError` to avoid
        leaking stack traces.
        """
        try:
            return session.get(url, timeout=kwargs.get("timeout", 30), **kwargs)
        except requests.RequestException as exc:
            raise SecurityError(str(exc))


class FingerprintAdapter(HTTPAdapter):
    """HTTPAdapter that validates server certificate fingerprint."""

    def __init__(self, fingerprint: str, *args: Any, **kwargs: Any) -> None:
        self.fingerprint = fingerprint.lower().replace(":", "")
        super().__init__(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert) -> None:  # type: ignore[override]
        super().cert_verify(conn, url, verify, cert)
        der_cert = conn.sock.getpeercert(True)
        import hashlib

        digest = hashlib.sha256(der_cert).hexdigest()
        if digest != self.fingerprint:
            raise SecurityError("Certificate fingerprint mismatch")

