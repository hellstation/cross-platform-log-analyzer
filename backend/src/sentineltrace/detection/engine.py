"""Detection engine — shared by API and CLI."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sentineltrace.core.models import DetectionAlert, NormalizedEvent, Platform, Severity
from sentineltrace.detection.evaluator import group_key, matches_group
from sentineltrace.detection.loader import load_rules
from sentineltrace.detection.rule_schema import DetectionRule


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule]):
        self.rules = [r for r in rules if r.enabled]

    @classmethod
    def from_path(cls, rules_dir) -> DetectionEngine:
        return cls(load_rules(rules_dir))

    def run(
        self,
        events: list[NormalizedEvent],
        *,
        platform: Platform | None = None,
        min_severity: Severity | None = None,
        since: datetime | None = None,
    ) -> list[DetectionAlert]:
        filtered = []
        for e in events:
            if since and e.timestamp and e.timestamp < since:
                continue
            if platform and e.platform != platform:
                continue
            filtered.append(e)
        filtered.sort(key=lambda x: x.timestamp or datetime.min.replace(tzinfo=timezone.utc))

        alerts: list[DetectionAlert] = []
        for rule in self.rules:
            if platform and rule.platform != "any" and rule.platform != platform.value:
                continue
            if min_severity and _severity_rank(rule.severity) < _severity_rank(min_severity):
                continue
            if rule.type == "single_event":
                alerts.extend(self._single_event(rule, filtered))
            elif rule.type == "aggregation":
                alerts.extend(self._aggregation(rule, filtered))
            elif rule.type == "correlation":
                alerts.extend(self._correlation(rule, filtered))
        return alerts

    def _single_event(
        self, rule: DetectionRule, events: list[NormalizedEvent]
    ) -> list[DetectionAlert]:
        out = []
        for event in events:
            if rule.platform != "any" and event.platform.value != rule.platform:
                continue
            if matches_group(event, rule.match):
                out.append(self._build_alert(rule, [event], self._explain_single(rule, event)))
        return out

    def _aggregation(
        self, rule: DetectionRule, events: list[NormalizedEvent]
    ) -> list[DetectionAlert]:
        if not rule.aggregation:
            return []
        spec = rule.aggregation
        window = timedelta(minutes=spec.window_minutes)
        buckets: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if rule.platform != "any" and event.platform.value != rule.platform:
                continue
            filt = spec.event_filter or rule.match
            if not matches_group(event, filt):
                continue
            key = group_key(event, spec.group_by or ["source_ip"])
            buckets[key].append(event)

        out = []
        for key, evs in buckets.items():
            evs.sort(key=lambda e: e.timestamp or datetime.min.replace(tzinfo=timezone.utc))
            i = 0
            while i < len(evs):
                window_start = evs[i].timestamp
                if not window_start:
                    i += 1
                    continue
                window_end = window_start + window
                cluster = [evs[i]]
                j = i + 1
                while j < len(evs) and evs[j].timestamp and evs[j].timestamp <= window_end:
                    cluster.append(evs[j])
                    j += 1
                if len(cluster) >= spec.threshold:
                    explanation = (
                        f"Rule '{rule.name}' matched {len(cluster)} events within "
                        f"{spec.window_minutes} minutes for grouping key '{key}' "
                        f"(threshold {spec.threshold})."
                    )
                    out.append(self._build_alert(rule, cluster, explanation))
                    i = j
                else:
                    i += 1
        return out

    def _correlation(
        self, rule: DetectionRule, events: list[NormalizedEvent]
    ) -> list[DetectionAlert]:
        if not rule.correlation:
            return []
        spec = rule.correlation
        window = timedelta(minutes=spec.window_minutes)
        left = [
            e
            for e in events
            if e.platform.value in spec.platforms[:1] or e.platform == Platform.LINUX
        ]
        right = [e for e in events if e.platform == Platform.WINDOWS]
        if rule.correlation.left_filter:
            left = [e for e in left if matches_group(e, rule.correlation.left_filter)]
        if rule.correlation.right_filter:
            right = [e for e in right if matches_group(e, rule.correlation.right_filter)]

        out = []
        for l_evt in left:
            if not l_evt.timestamp:
                continue
            link_vals = {f: group_key(l_evt, [f]).split("|")[0] for f in spec.link_fields}
            if not any(link_vals.values()):
                continue
            matched_left = [
                e
                for e in left
                if e.timestamp
                and l_evt.timestamp <= e.timestamp <= l_evt.timestamp + window
                and all(group_key(e, [f]).split("|")[0] == v or not v for f, v in link_vals.items())
            ]
            matched_right = [
                e
                for e in right
                if e.timestamp
                and l_evt.timestamp <= e.timestamp <= l_evt.timestamp + window
                and all(
                    (group_key(e, [f]).split("|")[0] == v or not v)
                    for f, v in link_vals.items()
                    if f in ("username", "source_ip")
                )
            ]
            if len(matched_left) >= spec.min_left and len(matched_right) >= spec.min_right:
                combined = matched_left + matched_right
                explanation = (
                    f"Correlated {len(matched_left)} Linux and {len(matched_right)} Windows "
                    f"events within {spec.window_minutes}m for {link_vals}."
                )
                out.append(self._build_alert(rule, combined, explanation))
                break
        return out

    def _build_alert(
        self,
        rule: DetectionRule,
        events: list[NormalizedEvent],
        explanation: str,
    ) -> DetectionAlert:
        hosts = sorted({e.hostname for e in events if e.hostname})
        users = sorted({e.username for e in events if e.username})
        ips = sorted({e.source_ip for e in events if e.source_ip})
        created = max(
            (e.timestamp for e in events if e.timestamp),
            default=datetime.now(timezone.utc),
        )
        return DetectionAlert(
            rule_id=rule.id,
            title=rule.name,
            description=rule.description,
            severity=rule.severity,
            confidence=rule.confidence,
            platform=(
                Platform(rule.platform)
                if rule.platform != "any"
                else (events[0].platform if events else Platform.UNKNOWN)
            ),
            created_at=created,
            explanation=explanation,
            mitre_attack=rule.mitre_attack,
            false_positive_notes=rule.false_positive_notes,
            recommendations=rule.recommendations,
            event_ids=[e.id for e in events],
            hosts=hosts,
            users=users,
            source_ips=ips,
            metadata={"event_count": len(events)},
        )

    def _explain_single(self, rule: DetectionRule, event: NormalizedEvent) -> str:
        return (
            f"Rule '{rule.name}' matched event {event.id} "
            f"(type={event.event_type}, event_id={event.event_id}) on host {event.hostname}."
        )


def _severity_rank(s: Severity) -> int:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order.index(s)
