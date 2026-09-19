from log_parser.models import AuthLog, CriticalNetworkLog, NetworkLog, SystemLog
from log_parser.parser import parse_log


def test_parses_each_type_into_correct_class():
    raw = [
        {"type": "network", "timestamp": "t", "level": "INFO", "message": "m",
         "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"},
        {"type": "auth", "timestamp": "t", "level": "INFO", "message": "m",
         "user": "u", "attempts": 1},
        {"type": "system", "timestamp": "t", "level": "INFO", "message": "m",
         "process": "p", "exit_code": 0},
        {"type": "critical_network", "timestamp": "t", "level": "CRITICAL", "message": "m",
         "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "user": "u", "attempts": 9},
    ]
    parsed = parse_log(raw)
    assert [type(p) for p in parsed] == [NetworkLog, AuthLog, SystemLog, CriticalNetworkLog]


def test_missing_key_skips_that_log_but_keeps_others():
    raw = [
        {"type": "auth", "timestamp": "t", "level": "INFO", "message": "m"},  # missing user/attempts
        {"type": "auth", "timestamp": "t", "level": "INFO", "message": "m", "user": "u", "attempts": 1},
    ]
    parsed = parse_log(raw)
    assert len(parsed) == 1
    assert parsed[0].user == "u"


def test_unknown_type_is_silently_ignored():
    raw = [{"type": "unknown", "timestamp": "t"}]
    assert parse_log(raw) == []
