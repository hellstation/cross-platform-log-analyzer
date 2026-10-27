"""Log channel filters for API and UI."""

from sqlalchemy import ColumnElement, or_

from sentineltrace.storage.orm import EventRow

CHANNEL_FILTERS: dict[str, list[ColumnElement[bool]]] = {
    "sysmon": [EventRow.source_type.ilike("%sysmon%")],
    "security": [EventRow.source_type.ilike("%security%")],
    "system": [
        EventRow.source_type.ilike("%_system%"),
        EventRow.source_type == "windows_system",
    ],
    "rdp": [
        EventRow.source_type.ilike("%remotedesktop%"),
        EventRow.source_type.ilike("%rdpcore%"),
    ],
    "linux_auth": [
        EventRow.source_type.in_(["linux_auth", "linux_secure"]),
        EventRow.source_type.ilike("%auth%"),
    ],
    "linux_syslog": [
        EventRow.source_type.in_(["linux_syslog", "linux_messages"]),
    ],
}


def channel_where(channel: str) -> ColumnElement[bool] | None:
    key = channel.lower().strip()
    clauses = CHANNEL_FILTERS.get(key)
    if not clauses:
        return None
    return or_(*clauses)
