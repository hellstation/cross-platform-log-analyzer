"""Windows EVTX parser using python-evtx."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from Evtx.Evtx import Evtx

from sentineltrace.core.fingerprint import compute_fingerprint
from sentineltrace.core.models import AuthenticationResult, NormalizedEvent, Platform, Severity

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _text(elem: ET.Element | None) -> str | None:
    if elem is None or elem.text is None:
        return None
    return elem.text.strip()


def _event_data_map(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for ed in root.findall(".//e:EventData/e:Data", NS):
        name = ed.get("Name")
        if name:
            data[name] = (ed.text or "").strip()
    user_data = root.find(".//e:UserData", NS)
    if user_data is not None:
        for child in user_data.iter():
            if child is user_data:
                continue
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text:
                data[tag] = child.text.strip()
    return data


def _source_type_from_channel(channel: str | None) -> str:
    if not channel:
        return "windows_evtx"
    value = f"windows_{channel.lower()}"
    return value[:255]


def _map_event_type(event_id: str) -> str:
    mapping = {
        "4624": "windows_logon_success",
        "4625": "windows_logon_failure",
        "4648": "windows_explicit_credentials",
        "4672": "windows_special_privileges",
        "4688": "windows_process_create",
        "4697": "windows_service_install",
        "4720": "windows_account_created",
        "4728": "windows_group_member_added",
        "4732": "windows_group_member_added",
        "4740": "windows_account_locked",
        "7045": "windows_service_install_system",
    }
    return mapping.get(event_id, f"windows_event_{event_id}")


class WindowsEvtxParser:
    def detect_format(self, path: Path) -> bool:
        return path.suffix.lower() == ".evtx"

    def parse_file(self, path: Path) -> Iterator[NormalizedEvent]:
        log_name = "Security" if "security" in path.name.lower() else "System"
        with Evtx(str(path)) as evtx:
            for record in evtx.records():
                xml = record.xml()
                yield self._parse_xml(xml, log_name)

    def _parse_xml(self, xml: str, default_log: str) -> NormalizedEvent:
        errors: list[str] = []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            ev = NormalizedEvent(
                platform=Platform.WINDOWS,
                source_type="windows_evtx",
                raw_event=xml[:8000],
                parse_errors=["xml_parse_error"],
            )
            ev.event_fingerprint = compute_fingerprint(ev)
            return ev

        system = root.find("e:System", NS)
        event_id_el = system.find("e:EventID", NS) if system is not None else None
        event_id = _text(event_id_el)
        provider = system.find("e:Provider", NS) if system is not None else None
        channel = _text(system.find("e:Channel", NS)) if system is not None else default_log
        computer = _text(system.find("e:Computer", NS)) if system is not None else None
        time_created = system.find("e:TimeCreated", NS) if system is not None else None
        ts: datetime | None = None
        if time_created is not None and (attr := time_created.get("SystemTime")):
            try:
                ts = datetime.fromisoformat(attr.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                errors.append("invalid_system_time")

        data = _event_data_map(root)
        provider_name = provider.get("Name") if provider is not None else None

        username = (
            data.get("TargetUserName") or data.get("SubjectUserName") or data.get("AccountName")
        )
        source_ip = data.get("IpAddress") or data.get("WorkstationName")
        if source_ip in ("-", "", None):
            source_ip = data.get("IpAddress")
        logon_type = data.get("LogonType")
        process_name = data.get("NewProcessName") or data.get("ProcessName")
        pid = data.get("ProcessId")
        process_id = None
        if pid:
            try:
                process_id = int(pid, 0) if pid.startswith("0x") else int(pid)
            except ValueError:
                errors.append("invalid_process_id")

        auth_result = None
        severity = Severity.INFO
        if event_id == "4625":
            auth_result = AuthenticationResult.FAILURE
            severity = Severity.MEDIUM
        elif event_id == "4624":
            auth_result = AuthenticationResult.SUCCESS
        elif event_id in ("4720", "4728", "4732", "4697", "7045", "4672"):
            severity = Severity.HIGH

        message_parts = [
            f"EventID {event_id}",
            provider_name or "",
            username or "",
            source_ip or "",
        ]
        event = NormalizedEvent(
            platform=Platform.WINDOWS,
            hostname=computer,
            source_type=_source_type_from_channel(channel),
            event_id=event_id,
            event_type=_map_event_type(event_id or ""),
            timestamp=ts,
            username=username,
            source_ip=source_ip if source_ip and source_ip != "-" else None,
            logon_type=logon_type,
            process_name=process_name,
            process_id=process_id,
            authentication_result=auth_result,
            severity=severity,
            message=" | ".join(p for p in message_parts if p),
            raw_event=xml[:12000],
            parse_errors=errors,
            extra={
                "provider": provider_name,
                "event_data": data,
            },
        )
        if event_id == "7045":
            event.message = data.get("ServiceName") or event.message
        event.event_fingerprint = compute_fingerprint(event)
        return event
