"""Detection rule schema and validation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from sentineltrace.core.models import Severity


class ConditionLeaf(BaseModel):
    field: str
    op: Literal["eq", "ne", "in", "not_in", "contains", "gte", "lte", "exists"]
    value: Any = None


class ConditionGroup(BaseModel):
    all: list[ConditionLeaf | dict] | None = None
    any: list[ConditionLeaf | dict] | None = None

    def resolved_all(self) -> list[ConditionLeaf]:
        items = self.all or []
        return [ConditionLeaf(**i) if isinstance(i, dict) else i for i in items]

    def resolved_any(self) -> list[ConditionLeaf]:
        items = self.any or []
        return [ConditionLeaf(**i) if isinstance(i, dict) else i for i in items]


class AggregationSpec(BaseModel):
    group_by: list[str] = Field(default_factory=list)
    window_minutes: int = 15
    threshold: int = 5
    event_filter: ConditionGroup | None = None


class CorrelationSpec(BaseModel):
    window_minutes: int = 60
    link_fields: list[str] = Field(default_factory=lambda: ["source_ip", "username"])
    platforms: list[str] = Field(default_factory=lambda: ["linux", "windows"])
    left_filter: ConditionGroup | None = None
    right_filter: ConditionGroup | None = None
    min_left: int = 3
    min_right: int = 1


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    platform: str = "any"
    enabled: bool = True
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_attack: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    false_positive_notes: list[str] = Field(default_factory=list)
    type: Literal["aggregation", "single_event", "correlation"] = "aggregation"
    match: ConditionGroup | None = None
    aggregation: AggregationSpec | None = None
    correlation: CorrelationSpec | None = None

    @field_validator("platform", mode="before")
    @classmethod
    def platform_any(cls, v: Any) -> Any:
        if v == "any":
            return "any"
        return v
