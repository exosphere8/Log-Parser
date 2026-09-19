from log_parser.models import AuthLog, NetworkLog, SystemLog
from log_parser.report import build_report


def test_report_includes_synopsis_counts():
    logs = [
        AuthLog("10:00", "CRITICAL", "Login failed", "admin", 9),
        SystemLog("10:01", "CRITICAL", "Crash", "core.py", 1),
    ]
    report = build_report(logs)
    assert "Total logs:            2" in report
    assert "Brute force attempts:  1" in report
    assert "Crashed processes:     1" in report


def test_report_lists_flagged_events():
    logs = [AuthLog("10:00", "CRITICAL", "Login failed", "admin", 9)]
    report = build_report(logs)
    assert "BRUTE FORCE" in report
    assert "admin" in report


def test_report_says_no_flagged_events_when_clean():
    logs = [NetworkLog("10:00", "INFO", "dns", "8.8.8.8", "10.0.0.1")]
    report = build_report(logs)
    assert "No flagged events." in report


def test_report_handles_empty_log_list():
    report = build_report([])
    assert "Total logs:            0" in report
