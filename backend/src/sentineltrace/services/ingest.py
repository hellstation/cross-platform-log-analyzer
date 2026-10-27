"""Log ingestion service."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from sentineltrace.config import get_settings
from sentineltrace.core.fingerprint import compute_fingerprint
from sentineltrace.core.models import Platform
from sentineltrace.parsers.registry import get_parser
from sentineltrace.storage.repositories import EventRepository, IngestionRepository


class IngestService:
    def __init__(self, session: Session):
        self.session = session
        self.settings = get_settings()
        self.events = EventRepository(session)
        self.ingestions = IngestionRepository(session)

    def ingest_path(
        self,
        path: Path,
        platform: Platform | None = None,
    ) -> dict:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(str(path))
        parser = get_parser(path, platform)
        plat = platform or (Platform.WINDOWS if path.suffix.lower() == ".evtx" else Platform.LINUX)
        row = self.ingestions.create(path.name, plat.value, parser.__class__.__name__)
        imported = 0
        skipped = 0
        errors = 0
        error_samples: list[str] = []
        batch: list = []
        batch_size = self.settings.ingest_batch_size

        try:
            for event in parser.parse_file(path):
                event.ingested_at = datetime.now(timezone.utc)
                event.ingestion_id = row.id
                if not event.event_fingerprint:
                    event.event_fingerprint = compute_fingerprint(event)
                if event.parse_errors:
                    errors += 1
                    if len(error_samples) < 20:
                        error_samples.append("; ".join(event.parse_errors))
                batch.append(event)
                if len(batch) >= batch_size:
                    ins, sk = self.events.insert_batch(batch)
                    imported += ins
                    skipped += sk
                    batch.clear()
            if batch:
                ins, sk = self.events.insert_batch(batch)
                imported += ins
                skipped += sk
            self.ingestions.complete(
                row,
                imported=imported,
                skipped=skipped,
                errors=errors,
                error_samples=error_samples,
                status="completed",
            )
            self.session.commit()
        except Exception as exc:
            self.session.rollback()
            self.ingestions.complete(
                row,
                imported=imported,
                skipped=skipped,
                errors=errors + 1,
                error_samples=error_samples + [str(exc)],
                status="failed",
            )
            self.session.commit()
            raise

        return {
            "ingestion_id": str(row.id),
            "filename": path.name,
            "imported": imported,
            "skipped": skipped,
            "errors": errors,
            "platform": plat.value,
        }

    def delete_ingestion(self, ingestion_id: UUID) -> dict | None:
        row = self.ingestions.get(ingestion_id)
        if not row:
            return None
        events_deleted = self.events.delete_by_ingestion(ingestion_id)
        self.ingestions.delete_row(row)
        self.session.commit()
        return {
            "ingestion_id": str(ingestion_id),
            "events_deleted": events_deleted,
        }

    def purge_all(self) -> dict[str, int]:
        counts = self.ingestions.purge_all()
        self.session.commit()
        return counts
