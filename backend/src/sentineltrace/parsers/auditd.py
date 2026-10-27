"""auditd log line parser (type=USER_AUTH etc.)."""

import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from sentineltrace.core.fingerprint import compute_fingerprint
from sentineltrace.core.models import AuthenticationResult, NormalizedEvent, Platform, Severity

AUDIT_RE = re.compile(r"type=(?P<type>\w+).*?msg=audit\((?P<epoch>[\d.]+):\d+\): (?P<msg>.*)$")


class AuditdParser:
    def detect_format(self, path: Path) -> bool:
        name = path.name.lower()
        if "audit" not in name:
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                sample = f.read(2048)
            return "type=" in sample and "msg=audit" in sample
        except OSError:
            return False

    def parse_file(self, path: Path) -> Iterator[NormalizedEvent]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = AUDIT_RE.search(line)
                errors: list[str] = []
                if not m:
                    yield NormalizedEvent(
                        platform=Platform.LINUX,
                        source_type="auditd",
                        raw_event=line,
                        message=line,
                        parse_errors=["audit_format_unrecognized"],
                        event_type="audit_unknown",
                    )
                    continue
                ts = None
                try:
                    ts = datetime.fromtimestamp(float(m.group("epoch")), tz=timezone.utc)
                except ValueError:
                    errors.append("invalid_audit_epoch")
                atype = m.group("type")
                msg = m.group("msg")
                event = NormalizedEvent(
                    platform=Platform.LINUX,
                    source_type="auditd",
                    timestamp=ts,
                    event_id=atype,
                    event_type=f"audit_{atype.lower()}",
                    message=msg,
                    raw_event=line,
                    parse_errors=errors,
                    severity=Severity.INFO,
                )
                if "acct=" in msg:
                    acct = re.search(r"acct=\"?(?P<a>[^\"\s]+)", msg)
                    if acct:
                        event.username = acct.group("a")
                if "res=failed" in msg:
                    event.authentication_result = AuthenticationResult.FAILURE
                elif "res=success" in msg:
                    event.authentication_result = AuthenticationResult.SUCCESS
                event.event_fingerprint = compute_fingerprint(event)
                yield event
