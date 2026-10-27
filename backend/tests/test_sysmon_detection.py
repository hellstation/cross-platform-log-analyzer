from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sentineltrace.core.models import NormalizedEvent, Platform
from sentineltrace.detection.engine import DetectionEngine

RULES = Path(__file__).resolve().parents[1] / "rules"


def _sysmon_event(event_id: str, data: dict) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid4(),
        timestamp=datetime(2020, 11, 26, 10, 45, 0, tzinfo=timezone.utc),
        platform=Platform.WINDOWS,
        hostname="lab-host",
        source_type="windows_microsoft-windows-sysmon/operational",
        event_id=event_id,
        event_type=f"windows_event_{event_id}",
        extra={"provider": "Microsoft-Windows-Sysmon", "event_data": data},
    )


def test_sysmon_dll_spool_rule():
    engine = DetectionEngine.from_path(RULES)
    ev = _sysmon_event(
        "7",
        {
            "Image": "C:\\Windows\\System32\\spoolsv.exe",
            "ImageLoaded": "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\payload.dll",
        },
    )
    alerts = engine.run([ev])
    assert any(a.rule_id == "DET-SYS-001" for a in alerts)


def test_sysmon_registry_print_rule():
    engine = DetectionEngine.from_path(RULES)
    ev = _sysmon_event(
        "13",
        {
            "Image": "C:\\Windows\\System32\\spoolsv.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\X",
            "Details": "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\payload.dll",
        },
    )
    alerts = engine.run([ev])
    assert any(a.rule_id == "DET-SYS-002" for a in alerts)
