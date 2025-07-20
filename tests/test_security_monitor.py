from monitoring.security_monitor import SecurityEventMonitor, SecurityEventLevel


def test_log_security_event(tmp_path):
    monitor = SecurityEventMonitor({"notification": {"log_file": str(tmp_path / "log.txt")}})
    event_id = monitor.log_security_event(
        "test", "something happened", SecurityEventLevel.WARNING, "tester"
    )
    metrics = monitor.get_security_metrics()
    assert metrics["total_events"] == 1
    assert monitor.events[0].event_id == event_id

def test_memory_monitor(tmp_path):
    monitor = SecurityEventMonitor({"notification": {"log_file": str(tmp_path / "log.txt")}})
    finish = monitor.monitor_memory(0)
    # allocate memory
    data = [0] * 10000
    finish()
    assert monitor.metrics["memory_alerts"] >= 1
    assert monitor.events[-1].category == "memory"
    assert "delta_mb" in monitor.events[-1].metadata
