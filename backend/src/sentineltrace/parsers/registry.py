"""Parser registry and format detection."""

from pathlib import Path

from sentineltrace.core.models import Platform
from sentineltrace.parsers.auditd import AuditdParser
from sentineltrace.parsers.base import LogParser
from sentineltrace.parsers.journalctl import JournalctlJsonParser
from sentineltrace.parsers.linux_syslog import LinuxSyslogParser
from sentineltrace.parsers.windows_evtx import WindowsEvtxParser

PARSERS: list[LogParser] = [
    WindowsEvtxParser(),
    LinuxSyslogParser(),
    JournalctlJsonParser(),
    AuditdParser(),
]


def get_parser(path: Path, platform: Platform | None = None) -> LogParser:
    suffix = path.suffix.lower()
    if platform == Platform.WINDOWS or suffix == ".evtx":
        return WindowsEvtxParser()
    if platform == Platform.LINUX:
        for parser in (LinuxSyslogParser(), JournalctlJsonParser(), AuditdParser()):
            if parser.detect_format(path):
                return parser
        return LinuxSyslogParser()
    for parser in PARSERS:
        if parser.detect_format(path):
            return parser
    if suffix == ".evtx":
        return WindowsEvtxParser()
    return LinuxSyslogParser()
