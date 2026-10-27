"""Run detection against stored events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from sentineltrace.config import get_settings
from sentineltrace.core.models import DetectionAlert, Platform, Severity
from sentineltrace.detection.engine import DetectionEngine
from sentineltrace.storage.repositories import AlertRepository, EventRepository, StatsRepository


class HuntService:
    def __init__(self, session: Session):
        self.session = session
        self.settings = get_settings()
        self.events = EventRepository(session)
        self.alerts = AlertRepository(session)
        self.stats = StatsRepository(session)

    def run(
        self,
        *,
        platform: Platform | None = None,
        min_severity: Severity | None = None,
        since_hours: int | None = None,
        persist: bool = True,
    ) -> list[DetectionAlert]:
        since = None
        hours = since_hours or self.settings.detection_default_since_hours
        if hours:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
        engine = DetectionEngine.from_path(self.settings.rules_path)
        stored = self.events.fetch_for_detection(since, platform)
        findings = engine.run(stored, platform=platform, min_severity=min_severity, since=since)
        if persist:
            for alert in findings:
                self.alerts.save(alert)
                self.stats.increment_rule_trigger(alert.rule_id)
            self.session.commit()
        return findings
