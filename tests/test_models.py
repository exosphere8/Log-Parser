from log_parser.models import AuthLog, CriticalNetworkLog, NetworkLog, SystemLog


def test_network_log_detects_internal_source():
    log = NetworkLog("10:00", "CRITICAL", "port scan", "192.168.1.5", "10.0.0.1")
    assert log.is_internal()
    assert log.is_suspicious()


def test_network_log_external_source_is_not_internal():
    log = NetworkLog("10:00", "INFO", "dns query", "8.8.8.8", "10.0.0.1")
    assert not log.is_internal()
    assert not log.is_suspicious()


def test_auth_log_brute_force_requires_critical_and_many_attempts():
    assert AuthLog("t", "CRITICAL", "m", "admin", 6).is_brute_force()
    assert not AuthLog("t", "CRITICAL", "m", "admin", 5).is_brute_force()
    assert not AuthLog("t", "WARNING", "m", "admin", 9).is_brute_force()


def test_system_log_crashed_on_nonzero_exit():
    assert SystemLog("t", "CRITICAL", "m", "core.py", 1).is_crashed()
    assert not SystemLog("t", "INFO", "m", "backup.py", 0).is_crashed()


def test_critical_network_log_is_both_network_and_auth():
    log = CriticalNetworkLog("t", "CRITICAL", "m", "192.168.1.9", "10.0.0.1", "root", 12)
    assert isinstance(log, NetworkLog)
    assert isinstance(log, AuthLog)
    assert log.is_internal()
    assert log.is_brute_force()
    assert "CRITICAL NET+AUTH" in log.summary()


def test_summary_includes_subclass_fields():
    log = AuthLog("10:02", "CRITICAL", "Login failed", "admin", 9)
    summary = log.summary()
    assert "admin" in summary
    assert "9" in summary
    assert "Login failed" in summary
