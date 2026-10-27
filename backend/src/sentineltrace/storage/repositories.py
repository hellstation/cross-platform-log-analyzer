"""Data access repositories."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sentineltrace.core.models import DetectionAlert, NormalizedEvent, Platform, Severity
from sentineltrace.storage.channels import channel_where
from sentineltrace.storage.mappers import alert_to_row, event_to_row, row_to_alert, row_to_event
from sentineltrace.storage.orm import AlertRow, CaseRow, EventRow, IngestionRow, RuleStatsRow


class EventRepository:
    def __init__(self, session: Session):
        self.session = session

    def insert_batch(self, events: list[NormalizedEvent]) -> tuple[int, int]:
        """Insert events; return (inserted, skipped_duplicates)."""
        if not events:
            return 0, 0
        inserted = 0
        skipped = 0
        for event in events:
            row = event_to_row(event)
            stmt = (
                insert(EventRow)
                .values(
                    id=row.id,
                    timestamp=row.timestamp,
                    ingested_at=row.ingested_at,
                    platform=row.platform,
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
                    authentication_result=row.authentication_result,
                    severity=row.severity,
                    message=row.message,
                    raw_event=row.raw_event,
                    event_fingerprint=row.event_fingerprint,
                    ingestion_id=row.ingestion_id,
                    parse_errors=row.parse_errors,
                    extra=row.extra,
                )
                .on_conflict_do_nothing(index_elements=["event_fingerprint"])
            )
            result = self.session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        return inserted, skipped

    def get(self, event_id: UUID) -> NormalizedEvent | None:
        row = self.session.get(EventRow, event_id)
        return row_to_event(row) if row else None

    def list_events(
        self,
        *,
        platform: Platform | None = None,
        event_id: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        severity: Severity | None = None,
        search: str | None = None,
        channel: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        offset: int = 0,
        limit: int = 50,
        sort_desc: bool = True,
    ) -> tuple[list[NormalizedEvent], int]:
        q = select(EventRow)
        count_q = select(func.count()).select_from(EventRow)
        filters = []
        if platform:
            filters.append(EventRow.platform == platform.value)
        if event_id:
            filters.append(EventRow.event_id == event_id)
        if hostname:
            filters.append(EventRow.hostname.ilike(f"%{hostname}%"))
        if username:
            filters.append(EventRow.username.ilike(f"%{username}%"))
        if source_ip:
            filters.append(EventRow.source_ip == source_ip)
        if severity:
            filters.append(EventRow.severity == severity.value)
        if since:
            filters.append(EventRow.timestamp >= since)
        if until:
            filters.append(EventRow.timestamp <= until)
        if search:
            filters.append(EventRow.message.ilike(f"%{search}%"))
        if channel:
            ch = channel_where(channel)
            if ch is not None:
                filters.append(ch)
        for f in filters:
            q = q.where(f)
            count_q = count_q.where(f)
        order = EventRow.timestamp.desc() if sort_desc else EventRow.timestamp.asc()
        q = q.order_by(order.nullslast()).offset(offset).limit(limit)
        rows = self.session.scalars(q).all()
        total = self.session.scalar(count_q) or 0
        return [row_to_event(r) for r in rows], total

    def fetch_for_detection(
        self,
        since: datetime | None,
        platform: Platform | None = None,
    ) -> list[NormalizedEvent]:
        q = select(EventRow)
        if since:
            q = q.where(EventRow.timestamp >= since)
        if platform:
            q = q.where(EventRow.platform == platform.value)
        q = q.order_by(EventRow.timestamp.asc())
        rows = self.session.scalars(q).all()
        return [row_to_event(r) for r in rows]

    def delete_by_ingestion(self, ingestion_id: UUID) -> int:
        result = self.session.execute(delete(EventRow).where(EventRow.ingestion_id == ingestion_id))
        return result.rowcount or 0


class AlertRepository:
    def __init__(self, session: Session):
        self.session = session

    def save(self, alert: DetectionAlert) -> DetectionAlert:
        existing = self.session.get(AlertRow, alert.id)
        if existing:
            row = alert_to_row(alert)
            for col in (
                "status",
                "explanation",
                "metadata",
            ):
                setattr(existing, col, getattr(row, col))
        else:
            self.session.add(alert_to_row(alert))
        return alert

    def save_many(self, alerts: list[DetectionAlert]) -> int:
        for a in alerts:
            self.save(a)
        return len(alerts)

    def get(self, alert_id: UUID) -> DetectionAlert | None:
        row = self.session.get(AlertRow, alert_id)
        return row_to_alert(row) if row else None

    def list_alerts(
        self,
        *,
        status: str | None = None,
        severity: Severity | None = None,
        search: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[DetectionAlert], int]:
        q = select(AlertRow)
        count_q = select(func.count()).select_from(AlertRow)
        if status:
            q = q.where(AlertRow.status == status)
            count_q = count_q.where(AlertRow.status == status)
        if severity:
            q = q.where(AlertRow.severity == severity.value)
            count_q = count_q.where(AlertRow.severity == severity.value)
        if search:
            like = f"%{search}%"
            q = q.where(AlertRow.title.ilike(like) | AlertRow.description.ilike(like))
            count_q = count_q.where(AlertRow.title.ilike(like) | AlertRow.description.ilike(like))
        q = q.order_by(AlertRow.created_at.desc()).offset(offset).limit(limit)
        rows = self.session.scalars(q).all()
        total = self.session.scalar(count_q) or 0
        return [row_to_alert(r) for r in rows], total

    def update_status(self, alert_id: UUID, status: str) -> DetectionAlert | None:
        row = self.session.get(AlertRow, alert_id)
        if not row:
            return None
        row.status = status
        return row_to_alert(row)


class IngestionRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, filename: str, platform: str, source_format: str | None) -> IngestionRow:
        row = IngestionRow(filename=filename, platform=platform, source_format=source_format)
        self.session.add(row)
        self.session.flush()
        return row

    def complete(
        self,
        row: IngestionRow,
        *,
        imported: int,
        skipped: int,
        errors: int,
        error_samples: list[str],
        status: str = "completed",
    ) -> None:
        row.imported_count = imported
        row.skipped_count = skipped
        row.error_count = errors
        row.errors_sample = error_samples[:20]
        row.status = status
        row.completed_at = datetime.now()

    def list_recent(self, limit: int = 20) -> list[IngestionRow]:
        q = select(IngestionRow).order_by(IngestionRow.started_at.desc()).limit(limit)
        return list(self.session.scalars(q).all())

    def get(self, ingestion_id: UUID) -> IngestionRow | None:
        return self.session.get(IngestionRow, ingestion_id)

    def delete_row(self, row: IngestionRow) -> None:
        self.session.delete(row)

    def purge_all(self) -> dict[str, int]:
        alerts = self.session.execute(delete(AlertRow)).rowcount or 0
        events = self.session.execute(delete(EventRow)).rowcount or 0
        cases = self.session.execute(delete(CaseRow)).rowcount or 0
        ingestions = self.session.execute(delete(IngestionRow)).rowcount or 0
        for stat in self.session.scalars(select(RuleStatsRow)).all():
            stat.trigger_count = 0
            stat.last_triggered_at = None
        return {
            "alerts_deleted": alerts,
            "events_deleted": events,
            "cases_deleted": cases,
            "ingestions_deleted": ingestions,
        }


class CaseRepository:
    def __init__(self, session: Session):
        self.session = session

    def list_cases(self, limit: int = 20) -> list[CaseRow]:
        q = select(CaseRow).order_by(CaseRow.updated_at.desc()).limit(limit)
        return list(self.session.scalars(q).all())

    def get(self, case_id: UUID) -> CaseRow | None:
        return self.session.get(CaseRow, case_id)

    def create(self, title: str) -> CaseRow:
        row = CaseRow(title=title)
        self.session.add(row)
        self.session.flush()
        return row

    def delete(self, case_id: UUID) -> bool:
        row = self.session.get(CaseRow, case_id)
        if not row:
            return False
        self.session.delete(row)
        return True

    def delete_all(self) -> int:
        result = self.session.execute(delete(CaseRow))
        return result.rowcount or 0


class StatsRepository:
    def __init__(self, session: Session):
        self.session = session

    def overview(self) -> dict:
        total_events = self.session.scalar(select(func.count()).select_from(EventRow)) or 0
        windows = (
            self.session.scalar(
                select(func.count()).select_from(EventRow).where(EventRow.platform == "windows")
            )
            or 0
        )
        linux = (
            self.session.scalar(
                select(func.count()).select_from(EventRow).where(EventRow.platform == "linux")
            )
            or 0
        )
        active_alerts = (
            self.session.scalar(
                select(func.count())
                .select_from(AlertRow)
                .where(AlertRow.status.in_(["new", "in_progress"]))
            )
            or 0
        )
        high_crit = (
            self.session.scalar(
                select(func.count())
                .select_from(AlertRow)
                .where(AlertRow.severity.in_(["high", "critical"]))
            )
            or 0
        )
        return {
            "total_events": total_events,
            "windows_events": windows,
            "linux_events": linux,
            "active_alerts": active_alerts,
            "high_critical_alerts": high_crit,
        }

    def events_timeline(
        self,
        since: datetime | None,
        *,
        hostname: str | None = None,
        channel: str | None = None,
        platform: str | None = None,
    ) -> list[dict]:
        trunc = "minute" if hostname else "hour"
        q = select(
            func.date_trunc(trunc, EventRow.timestamp).label("bucket"),
            func.count().label("count"),
        ).where(EventRow.timestamp.isnot(None))
        if since:
            q = q.where(EventRow.timestamp >= since)
        if hostname:
            q = q.where(EventRow.hostname.ilike(f"%{hostname}%"))
        if platform:
            q = q.where(EventRow.platform == platform)
        if channel:
            ch = channel_where(channel)
            if ch is not None:
                q = q.where(ch)
        q = q.group_by("bucket").order_by("bucket")
        rows = self.session.execute(q).all()
        return [{"timestamp": r.bucket.isoformat(), "count": r.count} for r in rows if r.bucket]

    def events_timeline_points(
        self,
        *,
        hostname: str,
        limit: int = 200,
    ) -> list[dict]:
        """Individual events for host timeline (time + label)."""
        q = (
            select(EventRow)
            .where(EventRow.hostname.ilike(f"%{hostname}%"))
            .where(EventRow.timestamp.isnot(None))
            .order_by(EventRow.timestamp.asc())
            .limit(limit)
        )
        rows = self.session.scalars(q).all()
        out = []
        for r in rows:
            ev = row_to_event(r)
            label = ev.event_id or ev.event_type or "?"
            out.append(
                {
                    "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                    "event_id": ev.event_id,
                    "label": label,
                    "id": str(ev.id),
                }
            )
        return out

    def alert_severity_distribution(self) -> list[dict]:
        q = (
            select(AlertRow.severity, func.count())
            .group_by(AlertRow.severity)
            .order_by(AlertRow.severity)
        )
        return [{"severity": s, "count": c} for s, c in self.session.execute(q).all()]

    def top_source_ips(self, limit: int = 10) -> list[dict]:
        q = (
            select(EventRow.source_ip, func.count())
            .where(EventRow.source_ip.isnot(None))
            .group_by(EventRow.source_ip)
            .order_by(func.count().desc())
            .limit(limit)
        )
        return [{"source_ip": ip, "count": c} for ip, c in self.session.execute(q).all()]

    def increment_rule_trigger(self, rule_id: str) -> None:
        row = self.session.get(RuleStatsRow, rule_id)
        if not row:
            row = RuleStatsRow(rule_id=rule_id, trigger_count=0, enabled=True)
            self.session.add(row)
        row.trigger_count += 1
        row.last_triggered_at = datetime.now()
