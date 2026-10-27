"""journalctl JSON export parser."""

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from sentineltrace.core.fingerprint import compute_fingerprint
from sentineltrace.core.models import NormalizedEvent, Platform, Severity


class JournalctlJsonParser:
    def detect_format(self, path: Path) -> bool:
        if path.suffix.lower() != ".json":
            return False
        try:
            with path.open("r", encoding="utf-8") as f:
                chunk = f.read(4096)
            if "__REALTIME_TIMESTAMP" in chunk or '"MESSAGE"' in chunk:
                return True
        except OSError:
            return False
        return False

    def parse_file(self, path: Path) -> Iterator[NormalizedEvent]:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
        if not content:
            return
        records: list[dict]
        if content.startswith("["):
            records = json.loads(content)
        else:
            records = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        records.append({"MESSAGE": line, "_parse_error": True})

        for rec in records:
            yield self._normalize(rec)

    def _normalize(self, rec: dict) -> NormalizedEvent:
        errors: list[str] = []
        ts = None
        if us := rec.get("__REALTIME_TIMESTAMP"):
            try:
                ts = datetime.fromtimestamp(int(us) / 1_000_000, tz=timezone.utc)
            except (ValueError, TypeError):
                errors.append("invalid_realtime_timestamp")
        elif sec := rec.get("timestamp"):
            try:
                if isinstance(sec, (int, float)):
                    ts = datetime.fromtimestamp(sec, tz=timezone.utc)
                else:
                    ts = datetime.fromisoformat(str(sec).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                errors.append("invalid_timestamp")

        message = rec.get("MESSAGE") or rec.get("message") or ""
        hostname = rec.get("_HOSTNAME") or rec.get("hostname")
        unit = rec.get("_SYSTEMD_UNIT") or rec.get("SYSLOG_IDENTIFIER")
        event = NormalizedEvent(
            platform=Platform.LINUX,
            source_type="journalctl_json",
            timestamp=ts,
            hostname=hostname,
            process_name=unit,
            message=str(message),
            raw_event=json.dumps(rec, ensure_ascii=False)[:8000],
            parse_errors=errors,
            event_type="journal_entry",
            severity=Severity.INFO,
        )
        if "sshd" in str(message).lower():
            event.source_type = "linux_auth"
        event.event_fingerprint = compute_fingerprint(event)
        return event
