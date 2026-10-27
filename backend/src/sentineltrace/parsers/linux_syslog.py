"""Linux auth.log, secure, syslog, messages parsers."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentineltrace.core.fingerprint import compute_fingerprint
from sentineltrace.core.models import (
    AuthenticationResult,
    NormalizedEvent,
    Platform,
    Severity,
)

# Traditional syslog: "Jan 15 10:23:45 hostname sshd[1234]: ..."
SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<body>.+)$"
)
MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+",
    re.I,
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+",
    re.I,
)
SUDO_RE = re.compile(
    r"(?P<user>\S+)\s+:\s+TTY=\S+\s+;?\s*PWD=\S+\s+;?\s*USER=(?P<target>\S+)\s+;?\s*COMMAND=(?P<cmd>.+)$",
    re.I,
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.I)


def _infer_source_type(path: Path) -> str:
    name = path.name.lower()
    if name in ("auth.log", "secure"):
        return "linux_auth"
    if name == "syslog":
        return "linux_syslog"
    if name == "messages":
        return "linux_messages"
    return "linux_syslog"


def _parse_syslog_timestamp(
    month: str, day: str, time_str: str, ref: datetime | None
) -> datetime | None:
    try:
        m = MONTH_MAP.get(month)
        if not m:
            return None
        h, mi, s = map(int, time_str.split(":"))
        year = ref.year if ref else datetime.now(timezone.utc).year
        return datetime(year, m, int(day), h, mi, s, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class LinuxSyslogParser:
    def detect_format(self, path: Path) -> bool:
        if path.suffix.lower() == ".evtx":
            return False
        if path.suffix.lower() == ".json":
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for _ in range(5):
                    line = f.readline()
                    if not line:
                        break
                    if SYSLOG_RE.match(line.strip()) or "sshd" in line or "sudo" in line:
                        return True
        except OSError:
            return False
        return path.suffix.lower() in (".log", ".txt", "")

    def parse_file(self, path: Path) -> Iterator[NormalizedEvent]:
        source_type = _infer_source_type(path)
        ref = datetime.now(timezone.utc)
        last_ts: datetime | None = None
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")
                if not line.strip():
                    continue
                event = self._parse_line(line, source_type, last_ts or ref)
                if event.timestamp:
                    if last_ts and event.timestamp < last_ts - timedelta(days=2):
                        event.timestamp = event.timestamp.replace(year=event.timestamp.year + 1)
                    last_ts = event.timestamp
                event.event_fingerprint = compute_fingerprint(event)
                yield event

    def _parse_line(self, line: str, source_type: str, ref: datetime | None) -> NormalizedEvent:
        errors: list[str] = []
        m = SYSLOG_RE.match(line)
        hostname = None
        body = line
        ts: datetime | None = None
        if m:
            hostname = m.group("host")
            body = m.group("body")
            ts = _parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"), ref)
        else:
            errors.append("unrecognized_syslog_format")

        event = NormalizedEvent(
            platform=Platform.LINUX,
            hostname=hostname,
            source_type=source_type,
            timestamp=ts,
            message=body,
            raw_event=line,
            parse_errors=errors,
        )

        if fm := SSH_FAILED_RE.search(body):
            event.event_type = "ssh_login_failure"
            event.event_id = "ssh_failed"
            event.username = fm.group("user")
            event.source_ip = fm.group("ip")
            event.authentication_result = AuthenticationResult.FAILURE
            event.severity = Severity.MEDIUM
        elif am := SSH_ACCEPTED_RE.search(body):
            event.event_type = "ssh_login_success"
            event.event_id = "ssh_accepted"
            event.username = am.group("user")
            event.source_ip = am.group("ip")
            event.authentication_result = AuthenticationResult.SUCCESS
            event.severity = Severity.INFO
        elif iu := INVALID_USER_RE.search(body):
            event.event_type = "ssh_invalid_user"
            event.event_id = "ssh_invalid_user"
            event.username = iu.group("user")
            event.source_ip = iu.group("ip")
            event.authentication_result = AuthenticationResult.FAILURE
            event.severity = Severity.MEDIUM
        elif "sudo" in body.lower():
            sudo_msg = body
            if ":" in body:
                sudo_msg = body.split(":", 1)[-1].strip()
                sudo_msg = re.sub(r"^\S+\s*:\s*", "", sudo_msg, count=1)
            sm = SUDO_RE.search(sudo_msg) or SUDO_RE.search(body)
            if sm:
                event.event_type = "sudo_command"
                event.event_id = "sudo"
                event.username = sm.group("user")
                event.message = sm.group("cmd")
                event.extra["sudo_target_user"] = sm.group("target")
                event.severity = Severity.LOW
        elif "systemd" in body and ("Started" in body or "Stopped" in body):
            event.event_type = "service_lifecycle"
            event.severity = Severity.INFO
        else:
            event.event_type = "linux_generic"
            event.severity = Severity.INFO

        proc_match = re.search(r"(\w+)\[(\d+)\]:", body)
        if proc_match:
            event.process_name = proc_match.group(1)
            try:
                event.process_id = int(proc_match.group(2))
            except ValueError:
                pass

        return event
