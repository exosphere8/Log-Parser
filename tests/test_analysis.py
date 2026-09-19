from log_parser.analysis import count_enumerator, find_flagged_events, ordinal
from log_parser.models import AuthLog, CriticalNetworkLog, NetworkLog, SystemLog


def test_ordinal_suffixes():
    assert ordinal(1) == "1st"
    assert ordinal(2) == "2nd"
    assert ordinal(3) == "3rd"
    assert ordinal(4) == "4th"
    assert ordinal(11) == "11th"
    assert ordinal(12) == "12th"
    assert ordinal(13) == "13th"
    assert ordinal(21) == "21st"


def test_count_enumerator_tallies_each_category():
    logs = [
        NetworkLog("t", "WARNING", "m", "1.2.3.4", "5.6.7.8"),  # suspicious
        AuthLog("t", "CRITICAL", "m", "admin", 9),  # suspicious + brute force
        SystemLog("t", "CRITICAL", "m", "core.py", 1),  # suspicious + crashed
        SystemLog("t", "INFO", "m", "backup.py", 0),  # neither
    ]
    suspicious, crashed, brute_force = count_enumerator(logs)
    assert suspicious == 3
    assert crashed == 1
    assert brute_force == 1


def test_find_flagged_events_detects_all_three_categories():
    logs = [
        AuthLog("t", "CRITICAL", "m", "admin", 9),
        SystemLog("t", "CRITICAL", "m", "core.py", 1),
        NetworkLog("t", "CRITICAL", "m", "192.168.1.5", "10.0.0.1"),
    ]
    flagged = find_flagged_events(logs)
    categories = {f.category for f in flagged}
    assert categories == {"brute_force", "crash", "internal_threat"}


def test_critical_network_log_can_trigger_both_brute_force_and_internal_threat():
    log = CriticalNetworkLog("t", "CRITICAL", "m", "192.168.1.9", "10.0.0.1", "root", 12)
    flagged = find_flagged_events([log])
    categories = {f.category for f in flagged}
    assert "brute_force" in categories
    assert "internal_threat" in categories


def test_no_flagged_events_for_clean_logs():
    logs = [NetworkLog("t", "INFO", "m", "8.8.8.8", "10.0.0.1")]
    assert find_flagged_events(logs) == []
