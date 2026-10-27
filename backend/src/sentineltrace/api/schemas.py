"""API Pydantic schemas."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from sentineltrace.core.models import DetectionAlert, NormalizedEvent


class PaginatedMeta(BaseModel):
    total: int
    page: int
    page_size: int


class EventListResponse(BaseModel):
    items: list[NormalizedEvent]
    meta: PaginatedMeta


class AlertListResponse(BaseModel):
    items: list[DetectionAlert]
    meta: PaginatedMeta


class IngestionResponse(BaseModel):
    ingestion_id: str
    filename: str
    imported: int
    skipped: int
    errors: int
    platform: str


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str


class StatisticsOverview(BaseModel):
    total_events: int
    windows_events: int
    linux_events: int
    active_alerts: int
    high_critical_alerts: int


class RuleOut(BaseModel):
    id: str
    name: str
    description: str
    platform: str
    severity: str
    enabled: bool
    mitre_attack: list[str]
    trigger_count: int = 0
    config: dict[str, Any] = Field(default_factory=dict)


class CaseCreate(BaseModel):
    title: str
    alert_ids: list[UUID] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = None
    status: str | None = None
    notes: str | None = None
    alert_ids: list[UUID] | None = None
    event_ids: list[UUID] | None = None


class CaseOut(BaseModel):
    id: UUID
    title: str
    status: str
    created_at: datetime
    updated_at: datetime
    notes: str
    alert_ids: list[UUID]
    event_ids: list[UUID]
