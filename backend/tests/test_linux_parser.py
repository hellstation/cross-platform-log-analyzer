from pathlib import Path

from sentineltrace.parsers.linux_syslog import LinuxSyslogParser

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "linux"


def test_ssh_failed_parsing():
    parser = LinuxSyslogParser()
    events = list(parser.parse_file(FIXTURES / "auth_bruteforce.log"))
    assert len(events) >= 5
    assert all(e.event_type == "ssh_login_failure" for e in events)
    assert events[0].source_ip == "203.0.113.50"


def test_corrupt_line_has_error_or_generic():
    parser = LinuxSyslogParser()
    events = list(parser.parse_file(FIXTURES / "corrupt.log"))
    assert len(events) >= 2
    assert any(e.parse_errors for e in events)


def test_dedup_fingerprint_stable():
    parser = LinuxSyslogParser()
    events = list(parser.parse_file(FIXTURES / "baseline.log"))
    fps = [e.event_fingerprint for e in events]
    assert len(fps) == len(set(fps))
