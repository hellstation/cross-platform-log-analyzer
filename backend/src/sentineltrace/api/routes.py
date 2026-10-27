"""FastAPI route modules."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from sentineltrace import __version__
from sentineltrace.api.deps import get_session
from sentineltrace.api.schemas import (
    AlertListResponse,
    CaseCreate,
    CaseOut,
    CaseUpdate,
    EventListResponse,
    HealthResponse,
    IngestionResponse,
    PaginatedMeta,
    RuleOut,
    StatisticsOverview,
)
from sentineltrace.config import get_settings
from sentineltrace.core.models import Platform, Severity
from sentineltrace.detection.loader import load_rules, validate_rules
from sentineltrace.services.export import export_csv, export_html, export_json
from sentineltrace.services.hunt import HuntService
from sentineltrace.services.ingest import IngestService
from sentineltrace.storage.mappers import row_to_case
from sentineltrace.storage.orm import CaseRow, RuleStatsRow
from sentineltrace.storage.repositories import (
    AlertRepository,
    CaseRepository,
    EventRepository,
    IngestionRepository,
    StatsRepository,
)

health_router = APIRouter(tags=["health"])
events_router = APIRouter(prefix="/events", tags=["events"])
alerts_router = APIRouter(prefix="/alerts", tags=["alerts"])
ingest_router = APIRouter(prefix="/ingestions", tags=["ingestions"])
rules_router = APIRouter(prefix="/rules", tags=["rules"])
cases_router = APIRouter(prefix="/cases", tags=["cases"])
stats_router = APIRouter(prefix="/statistics", tags=["statistics"])
export_router = APIRouter(prefix="/export", tags=["export"])


@health_router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=__version__,
        environment=settings.sentineltrace_env,
    )


@events_router.get("", response_model=EventListResponse)
def list_events(
    session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    platform: str | None = None,
    event_id: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    channel: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> EventListResponse:
    repo = EventRepository(session)
    plat = Platform(platform) if platform else None
    sev = Severity(severity) if severity else None
    items, total = repo.list_events(
        platform=plat,
        event_id=event_id,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
        severity=sev,
        search=search,
        channel=channel,
        since=since,
        until=until,
        offset=(page - 1) * page_size,
        limit=page_size,
    )
    return EventListResponse(
        items=items,
        meta=PaginatedMeta(total=total, page=page, page_size=page_size),
    )


@events_router.get("/{event_id}")
def get_event(event_id: UUID, session: Session = Depends(get_session)):
    repo = EventRepository(session)
    event = repo.get(event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return event


@alerts_router.get("", response_model=AlertListResponse)
def list_alerts(
    session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
) -> AlertListResponse:
    repo = AlertRepository(session)
    sev = Severity(severity) if severity else None
    items, total = repo.list_alerts(
        status=status,
        severity=sev,
        search=search,
        offset=(page - 1) * page_size,
        limit=page_size,
    )
    return AlertListResponse(
        items=items,
        meta=PaginatedMeta(total=total, page=page, page_size=page_size),
    )


@alerts_router.get("/{alert_id}")
def get_alert(alert_id: UUID, session: Session = Depends(get_session)):
    repo = AlertRepository(session)
    alert = repo.get(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@alerts_router.patch("/{alert_id}")
def patch_alert(
    alert_id: UUID,
    body: dict,
    session: Session = Depends(get_session),
):
    status = body.get("status")
    if not status:
        raise HTTPException(400, "status required")
    repo = AlertRepository(session)
    updated = repo.update_status(alert_id, status)
    if not updated:
        raise HTTPException(404, "Alert not found")
    return updated


@ingest_router.get("")
def list_ingestions(session: Session = Depends(get_session)):
    repo = IngestionRepository(session)
    rows = repo.list_recent()
    return [
        {
            "id": str(r.id),
            "filename": r.filename,
            "platform": r.platform,
            "status": r.status,
            "imported_count": r.imported_count,
            "skipped_count": r.skipped_count,
            "error_count": r.error_count,
            "started_at": r.started_at,
            "completed_at": r.completed_at,
        }
        for r in rows
    ]


@ingest_router.post("", response_model=IngestionResponse)
async def upload_ingestion(
    session: Session = Depends(get_session),
    file: UploadFile = File(...),
    platform: str = Query("linux"),
):
    settings = get_settings()
    if not file.filename:
        raise HTTPException(400, "filename required")
    safe_name = Path(file.filename).name
    if ".." in safe_name or safe_name.startswith("/"):
        raise HTTPException(400, "invalid filename")
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    dest = settings.upload_dir / f"{uuid.uuid4()}_{safe_name}"
    size = 0
    with dest.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                dest.unlink(missing_ok=True)
                raise HTTPException(413, "file too large")
            out.write(chunk)
    svc = IngestService(session)
    try:
        result = svc.ingest_path(dest, Platform(platform))
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return IngestionResponse(**result)


@ingest_router.post("/hunt")
def run_hunt(
    session: Session = Depends(get_session),
    platform: str | None = None,
    since_hours: int = 168,
):
    svc = HuntService(session)
    plat = Platform(platform) if platform else None
    alerts = svc.run(platform=plat, since_hours=since_hours)
    return {"created": len(alerts)}


@ingest_router.delete("/purge-all")
def purge_all_data(
    confirm: bool = Query(False, description="Must be true to wipe all imported data"),
    session: Session = Depends(get_session),
):
    if not confirm:
        raise HTTPException(
            400,
            "Pass confirm=true to delete all events, alerts, cases, and import history",
        )
    svc = IngestService(session)
    return svc.purge_all()


@ingest_router.delete("/{ingestion_id}")
def delete_ingestion(
    ingestion_id: UUID,
    session: Session = Depends(get_session),
):
    svc = IngestService(session)
    result = svc.delete_ingestion(ingestion_id)
    if not result:
        raise HTTPException(404, "Ingestion not found")
    return result


@rules_router.get("")
def list_rules(session: Session = Depends(get_session)) -> list[RuleOut]:
    settings = get_settings()
    rules = load_rules(settings.rules_path)
    out = []
    for r in rules:
        stat = session.get(RuleStatsRow, r.id)
        out.append(
            RuleOut(
                id=r.id,
                name=r.name,
                description=r.description,
                platform=str(r.platform),
                severity=r.severity.value,
                enabled=r.enabled,
                mitre_attack=r.mitre_attack,
                trigger_count=stat.trigger_count if stat else 0,
                config=r.model_dump(exclude={"id", "name", "description"}),
            )
        )
    return out


@rules_router.get("/validate")
def rules_validate_endpoint():
    settings = get_settings()
    return {"results": validate_rules(settings.rules_path)}


@cases_router.get("")
def list_cases(session: Session = Depends(get_session)) -> list[CaseOut]:
    repo = CaseRepository(session)
    return [CaseOut(**row_to_case(r).model_dump()) for r in repo.list_cases()]


@cases_router.post("")
def create_case(body: CaseCreate, session: Session = Depends(get_session)) -> CaseOut:
    repo = CaseRepository(session)
    row = repo.create(body.title)
    row.alert_ids = [str(a) for a in body.alert_ids]
    row.event_ids = [str(e) for e in body.event_ids]
    return CaseOut(**row_to_case(row).model_dump())


@cases_router.delete("/purge-all")
def purge_all_cases(
    confirm: bool = Query(False),
    session: Session = Depends(get_session),
):
    if not confirm:
        raise HTTPException(400, "Pass confirm=true to delete all investigations")
    repo = CaseRepository(session)
    deleted = repo.delete_all()
    return {"cases_deleted": deleted}


@cases_router.delete("/{case_id}")
def delete_case(case_id: UUID, session: Session = Depends(get_session)):
    repo = CaseRepository(session)
    if not repo.delete(case_id):
        raise HTTPException(404, "Case not found")
    return {"deleted": True, "case_id": str(case_id)}


@cases_router.get("/{case_id}")
def get_case(case_id: UUID, session: Session = Depends(get_session)) -> CaseOut:
    repo = CaseRepository(session)
    row = repo.get(case_id)
    if not row:
        raise HTTPException(404, "Case not found")
    return CaseOut(**row_to_case(row).model_dump())


@cases_router.patch("/{case_id}")
def update_case(
    case_id: UUID, body: CaseUpdate, session: Session = Depends(get_session)
) -> CaseOut:
    row = session.get(CaseRow, case_id)
    if not row:
        raise HTTPException(404, "Case not found")
    if body.title is not None:
        row.title = body.title
    if body.status is not None:
        row.status = body.status
    if body.notes is not None:
        row.notes = body.notes
    if body.alert_ids is not None:
        row.alert_ids = [str(a) for a in body.alert_ids]
    if body.event_ids is not None:
        row.event_ids = [str(e) for e in body.event_ids]
    row.updated_at = datetime.now(timezone.utc)
    return CaseOut(**row_to_case(row).model_dump())


@stats_router.get("/overview", response_model=StatisticsOverview)
def stats_overview(session: Session = Depends(get_session)) -> StatisticsOverview:
    repo = StatsRepository(session)
    return StatisticsOverview(**repo.overview())


@stats_router.get("/timeline")
def stats_timeline(
    since: datetime | None = None,
    hostname: str | None = None,
    channel: str | None = None,
    platform: str | None = None,
    session: Session = Depends(get_session),
):
    repo = StatsRepository(session)
    return repo.events_timeline(since, hostname=hostname, channel=channel, platform=platform)


@stats_router.get("/timeline/host-events")
def stats_host_event_points(
    hostname: str = Query(..., min_length=1),
    session: Session = Depends(get_session),
):
    repo = StatsRepository(session)
    return repo.events_timeline_points(hostname=hostname)


@stats_router.get("/alerts-by-severity")
def stats_alerts_severity(session: Session = Depends(get_session)):
    repo = StatsRepository(session)
    return repo.alert_severity_distribution()


@stats_router.get("/top-source-ips")
def stats_top_ips(session: Session = Depends(get_session)):
    repo = StatsRepository(session)
    return repo.top_source_ips()


@export_router.get("")
def export_data(
    format: str = Query("json"),
    session: Session = Depends(get_session),
):
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    path = settings.upload_dir / f"export_{uuid.uuid4()}.{format}"
    if format == "json":
        export_json(session, path)
    elif format == "csv":
        export_csv(session, path)
    elif format == "html":
        export_html(session, path)
    else:
        raise HTTPException(400, "unsupported format")
    return FileResponse(path, filename=path.name)
