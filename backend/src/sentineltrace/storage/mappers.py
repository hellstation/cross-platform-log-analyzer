"""ORM <-> domain mappers."""

from datetime import datetime, timezone
from uuid import UUID

from sentineltrace.core.models import (
    AlertStatus,
    AuthenticationResult,
    DetectionAlert,
    InvestigationCase,
    InvestigationStatus,
    NormalizedEvent,
    Platform,
    Severity,
)
from sentineltrace.storage.orm import AlertRow, CaseRow, EventRow


def event_to_row(event: NormalizedEvent) -> EventRow:
    return EventRow(
        id=event.id,
        timestamp=event.timestamp,
        ingested_at=event.ingested_at or datetime.now(timezone.utc),
        platform=event.platform.value,
        hostname=event.hostname,
        source_type=event.source_type,
        event_id=event.event_id,
        event_type=event.event_type,
        username=event.username,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        process_name=event.process_name,
        process_id=event.process_id,
        logon_type=event.logon_type,
        authentication_result=(
            event.authentication_result.value if event.authentication_result else None
        ),
        severity=event.severity.value if event.severity else None,
        message=event.message,
        raw_event=event.raw_event,
        event_fingerprint=event.event_fingerprint or "",
        ingestion_id=event.ingestion_id,
        parse_errors=event.parse_errors,
        extra=event.extra,
    )


def row_to_event(row: EventRow) -> NormalizedEvent:
    auth = None
    if row.authentication_result:
        try:
            auth = AuthenticationResult(row.authentication_result)
        except ValueError:
            auth = AuthenticationResult.UNKNOWN
    sev = None
    if row.severity:
        try:
            sev = Severity(row.severity)
        except ValueError:
            sev = None
    return NormalizedEvent(
        id=row.id,
        timestamp=row.timestamp,
        ingested_at=row.ingested_at,
        platform=Platform(row.platform),
        hostname=row.hostname,
        source_type=row.source_type,
        event_id=row.event_id,
        event_type=row.event_type,
        username=row.username,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        process_name=row.process_name,
        process_id=row.process_id,
        logon_type=row.logon_type,
        authentication_result=auth,
        severity=sev,
        message=row.message,
        raw_event=row.raw_event,
        event_fingerprint=row.event_fingerprint,
        ingestion_id=row.ingestion_id,
        parse_errors=list(row.parse_errors or []),
        extra=dict(row.extra or {}),
    )


def alert_to_row(alert: DetectionAlert) -> AlertRow:
    return AlertRow(
        id=alert.id,
        rule_id=alert.rule_id,
        title=alert.title,
        description=alert.description,
        severity=alert.severity.value,
        confidence=alert.confidence,
        platform=alert.platform.value,
        created_at=alert.created_at,
        explanation=alert.explanation,
        mitre_attack=alert.mitre_attack,
        false_positive_notes=alert.false_positive_notes,
        recommendations=alert.recommendations,
        event_ids=[str(e) for e in alert.event_ids],
        hosts=alert.hosts,
        users=alert.users,
        source_ips=alert.source_ips,
        status=alert.status.value,
        metadata=alert.metadata,
    )


def row_to_alert(row: AlertRow) -> DetectionAlert:
    return DetectionAlert(
        id=row.id,
        rule_id=row.rule_id,
        title=row.title,
        description=row.description,
        severity=Severity(row.severity),
        confidence=row.confidence,
        platform=Platform(row.platform),
        created_at=row.created_at,
        explanation=row.explanation,
        mitre_attack=list(row.mitre_attack or []),
        false_positive_notes=list(row.false_positive_notes or []),
        recommendations=list(row.recommendations or []),
        event_ids=[UUID(str(e)) for e in (row.event_ids or [])],
        hosts=list(row.hosts or []),
        users=list(row.users or []),
        source_ips=list(row.source_ips or []),
        status=AlertStatus(row.status),
        metadata=dict(row.metadata or {}),
    )


def row_to_case(row: CaseRow) -> InvestigationCase:
    return InvestigationCase(
        id=row.id,
        title=row.title,
        status=InvestigationStatus(row.status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        notes=row.notes or "",
        alert_ids=[UUID(str(a)) for a in (row.alert_ids or [])],
        event_ids=[UUID(str(e)) for e in (row.event_ids or [])],
    )
