import json
from datetime import datetime, timedelta
from secure_ohlcv_downloader import CertificateManager


def create_manager(tmp_path, fingerprints):
    conf = {
        "alpha_vantage_fingerprints": fingerprints,
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "rotation_window_hours": 72,
    }
    path = tmp_path / "certs.json"
    path.write_text(json.dumps(conf))
    return CertificateManager(str(path))


def test_certificate_validation_success(monkeypatch, tmp_path):
    manager = create_manager(tmp_path, ["AA"])
    monkeypatch.setattr(
        manager, "_get_certificate_details",
        lambda host, port: ("AA", datetime.utcnow() + timedelta(days=30)),
    )
    assert manager.validate_certificate("host")


def test_certificate_rotation_updates_fingerprint(monkeypatch, tmp_path):
    manager = create_manager(tmp_path, ["AA"])
    monkeypatch.setattr(
        manager, "_get_certificate_details",
        lambda host, port: ("BB", datetime.utcnow() + timedelta(days=30)),
    )
    monkeypatch.setattr(
        manager.rotation_detector,
        "is_legitimate_rotation",
        lambda fp, host: True,
    )
    manager.alert_manager.send_certificate_alert = lambda *a, **k: None
    assert manager.validate_certificate("host")
    assert manager.valid_fingerprints[0] == "BB"


def test_certificate_expiration_alert(monkeypatch, tmp_path):
    alerts = []
    manager = create_manager(tmp_path, ["AA"])
    monkeypatch.setattr(
        manager, "_get_certificate_details",
        lambda host, port: ("AA", datetime.utcnow() + timedelta(days=1)),
    )
    manager.alert_manager.send_certificate_alert = lambda *a, **k: alerts.append(k.get("msg", a[2]))
    assert manager.validate_certificate("host")
    assert any("expiring" in a for a in alerts)
