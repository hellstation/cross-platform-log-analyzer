"""Safe condition evaluation (no eval)."""

from __future__ import annotations

from typing import Any

from sentineltrace.core.models import NormalizedEvent
from sentineltrace.detection.rule_schema import ConditionGroup, ConditionLeaf


def _get_field(event: NormalizedEvent, field: str) -> Any:
    mapping = {
        "platform": event.platform.value,
        "hostname": event.hostname,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "username": event.username,
        "source_ip": event.source_ip,
        "authentication_result": (
            event.authentication_result.value if event.authentication_result else None
        ),
        "process_name": event.process_name,
        "severity": event.severity.value if event.severity else None,
        "message": event.message,
    }
    if field in mapping:
        return mapping[field]
    if field.startswith("event_data."):
        ed = event.extra.get("event_data") if event.extra else None
        if isinstance(ed, dict):
            return ed.get(field.removeprefix("event_data."))
    if field in event.extra:
        return event.extra[field]
    return None


def _eval_leaf(event: NormalizedEvent, leaf: ConditionLeaf) -> bool:
    val = _get_field(event, leaf.field)
    op = leaf.op
    expected = leaf.value
    if op == "exists":
        return val is not None and val != ""
    if op == "eq":
        return val == expected
    if op == "ne":
        return val != expected
    if op == "in":
        return val in (expected or [])
    if op == "not_in":
        return val not in (expected or [])
    if op == "contains":
        return (
            expected is not None and val is not None and str(expected).lower() in str(val).lower()
        )
    if op == "gte":
        try:
            return val is not None and float(val) >= float(expected)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return val is not None and float(val) <= float(expected)
        except (TypeError, ValueError):
            return False
    return False


def matches_group(event: NormalizedEvent, group: ConditionGroup | None) -> bool:
    if group is None:
        return True
    all_items = group.resolved_all()
    any_items = group.resolved_any()
    if all_items:
        if not all(_eval_leaf(event, leaf) for leaf in all_items):
            return False
    if any_items:
        if not any(_eval_leaf(event, leaf) for leaf in any_items):
            return False
    return True


def group_key(event: NormalizedEvent, fields: list[str]) -> str:
    parts = []
    for f in fields:
        v = _get_field(event, f)
        parts.append(str(v) if v is not None else "")
    return "|".join(parts)
