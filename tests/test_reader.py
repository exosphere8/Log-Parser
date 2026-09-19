from pathlib import Path

from log_parser.reader import read_log_file

FIXTURE = Path(__file__).parent / "fixtures" / "sample_log.txt"


def test_reads_all_valid_lines_from_fixture():
    logs = read_log_file(str(FIXTURE))
    assert len(logs) == 18
    assert logs[0]["type"] == "network"
    assert logs[0]["src_ip"] == "192.168.1.10"


def test_missing_file_returns_empty_list():
    assert read_log_file("does/not/exist.txt") == []


def test_skips_comments_and_blank_lines(tmp_path):
    f = tmp_path / "log.txt"
    f.write_text("# a comment\n\nnetwork | 10:00 | INFO | ok | 1.2.3.4 | 5.6.7.8\n")
    logs = read_log_file(str(f))
    assert len(logs) == 1


def test_skips_line_with_unrecognised_type(tmp_path):
    f = tmp_path / "log.txt"
    f.write_text("bogus_type | 10:00 | INFO | ok | a | b\n")
    assert read_log_file(str(f)) == []


def test_skips_line_with_non_integer_field(tmp_path):
    f = tmp_path / "log.txt"
    f.write_text(
        "auth | 10:00 | CRITICAL | bad attempts | admin | not-a-number\n"
        "auth | 10:01 | CRITICAL | good | admin | 9\n"
    )
    logs = read_log_file(str(f))
    assert len(logs) == 1
    assert logs[0]["attempts"] == 9


def test_parses_critical_network_type(tmp_path):
    f = tmp_path / "log.txt"
    f.write_text("critical_network | 10:00 | CRITICAL | m | 192.168.1.1 | 10.0.0.1 | root | 12\n")
    logs = read_log_file(str(f))
    assert len(logs) == 1
    assert logs[0]["user"] == "root"
    assert logs[0]["attempts"] == 12
