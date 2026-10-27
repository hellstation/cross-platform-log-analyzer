"""Core domain models (Pydantic)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Platform(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthenticationResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class NormalizedEvent(BaseModel):
    """Unified security event schema."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime | None = None
    ingested_at: datetime | None = None
    platform: Platform = Platform.UNKNOWN
    hostname: str | None = None
    source_type: str | None = None
    event_id: str | None = None
    event_type: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    logon_type: str | None = None
    authentication_result: AuthenticationResult | None = None
    severity: Severity | None = None
    message: str | None = None
    raw_event: str | None = None
    event_fingerprint: str | None = None
    ingestion_id: UUID | None = None
    parse_errors: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    def fingerprint_material(self) -> str:
        parts = [
            self.platform.value,
            self.source_type or "",
            self.event_id or "",
            self.timestamp.isoformat() if self.timestamp else "",
            self.hostname or "",
            self.username or "",
            self.source_ip or "",
            self.message or "",
            (self.raw_event or "")[:2000],
        ]
        return "|".join(parts)


class AlertStatus(StrEnum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class DetectionAlert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    platform: Platform
    created_at: datetime
    explanation: str
    mitre_attack: list[str] = Field(default_factory=list)
    false_positive_notes: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class InvestigationCase(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    status: InvestigationStatus = InvestigationStatus.OPEN
    created_at: datetime
    updated_at: datetime
    notes: str = ""
    alert_ids: list[UUID] = Field(default_factory=list)
    event_ids: list[UUID] = Field(default_factory=list)
