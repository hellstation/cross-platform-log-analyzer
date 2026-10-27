"""Export events and alerts to JSON, CSV, HTML."""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentineltrace.storage.mappers import row_to_alert, row_to_event
from sentineltrace.storage.orm import AlertRow, EventRow


def export_json(session: Session, output: Path) -> None:
    events = session.scalars(select(EventRow).limit(100_000)).all()
    alerts = session.scalars(select(AlertRow).limit(10_000)).all()
    payload = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "events": [row_to_event(e).model_dump(mode="json") for e in events],
        "alerts": [row_to_alert(a).model_dump(mode="json") for a in alerts],
    }
    output.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def export_csv(session: Session, output: Path) -> None:
    events = session.scalars(select(EventRow).limit(100_000)).all()
    fields = [
        "id",
        "timestamp",
        "platform",
        "hostname",
        "event_id",
        "event_type",
        "username",
        "source_ip",
        "severity",
        "message",
    ]
    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in events:
            ev = row_to_event(row)
            writer.writerow(
                {
                    "id": str(ev.id),
                    "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
                    "platform": ev.platform.value,
                    "hostname": ev.hostname or "",
                    "event_id": ev.event_id or "",
                    "event_type": ev.event_type or "",
                    "username": ev.username or "",
                    "source_ip": ev.source_ip or "",
                    "severity": ev.severity.value if ev.severity else "",
                    "message": (ev.message or "")[:500],
                }
            )


def export_html(session: Session, output: Path) -> None:
    alerts = session.scalars(select(AlertRow).order_by(AlertRow.created_at.desc()).limit(500)).all()
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>SentinelTrace Report</title>",
        "<style>body{font-family:system-ui;background:#111;color:#e5e5e5;padding:2rem}",
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:8px}",
        "h1,h2{color:#f5f5f5}</style></head><body>",
        "<h1>SentinelTrace Investigation Report</h1>",
        f"<p>Generated: {html.escape(datetime.utcnow().isoformat())}Z</p>",
        "<h2>Alerts</h2><table><tr><th>Title</th><th>Severity</th><th>Rule</th><th>Explanation</th></tr>",
    ]
    for a in alerts:
        parts.append(
            "<tr><td>"
            + html.escape(a.title)
            + "</td><td>"
            + html.escape(a.severity)
            + "</td><td>"
            + html.escape(a.rule_id)
            + "</td><td>"
            + html.escape(a.explanation or "")
            + "</td></tr>"
        )
    parts.append("</table></body></html>")
    output.write_text("\n".join(parts), encoding="utf-8")


def export_case_html(session: Session, case_id: UUID, output: Path) -> None:
    from sentineltrace.storage.orm import CaseRow

    case = session.get(CaseRow, case_id)
    if not case:
        raise ValueError("case not found")
    notes = html.escape(case.notes or "")
    title = html.escape(case.title)
    body = (
        f"<h1>{title}</h1><p>Status: {html.escape(case.status)}</p><h2>Notes</h2><pre>{notes}</pre>"
    )
    output.write_text(
        f"<!DOCTYPE html><html><head><meta charset='utf-8'></head><body>{body}</body></html>",
        encoding="utf-8",
    )
