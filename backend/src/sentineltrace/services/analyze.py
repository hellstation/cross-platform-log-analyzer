"""Analyze log files without database persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sentineltrace.config import get_settings
from sentineltrace.core.models import DetectionAlert, NormalizedEvent, Platform
from sentineltrace.detection.engine import DetectionEngine
from sentineltrace.parsers.registry import get_parser


@dataclass
class AnalyzeResult:
    path: str
    events: list[NormalizedEvent] = field(default_factory=list)
    alerts: list[DetectionAlert] = field(default_factory=list)
    parse_error_count: int = 0
    skipped_lines: int = 0


class AnalyzeService:
    def __init__(self):
        self.settings = get_settings()

    def analyze_file(self, path: Path, platform: Platform | None = None) -> AnalyzeResult:
        parser = get_parser(path, platform)
        events = list(parser.parse_file(path))
        parse_errors = sum(1 for e in events if e.parse_errors)
        engine = DetectionEngine.from_path(self.settings.rules_path)
        alerts = engine.run(events, platform=platform)
        return AnalyzeResult(
            path=str(path),
            events=events,
            alerts=alerts,
            parse_error_count=parse_errors,
        )

    def analyze_paths(
        self,
        paths: list[Path],
        *,
        recursive: bool = False,
        platform: Platform | None = None,
    ) -> list[AnalyzeResult]:
        files: list[Path] = []
        for p in paths:
            if p.is_dir():
                pattern = "**/*" if recursive else "*"
                files.extend([f for f in p.glob(pattern) if f.is_file()])
            elif p.is_file():
                files.append(p)
        results = []
        for f in sorted(files):
            try:
                results.append(self.analyze_file(f, platform))
            except OSError:
                continue
        return results
