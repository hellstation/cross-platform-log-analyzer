"""SentinelTrace CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional
from uuid import UUID

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentineltrace import __version__
from sentineltrace.config import get_settings
from sentineltrace.core.models import AlertStatus, Platform, Severity
from sentineltrace.detection.engine import DetectionEngine
from sentineltrace.detection.loader import load_rules, validate_rules
from sentineltrace.services.analyze import AnalyzeService
from sentineltrace.services.export import export_csv, export_html, export_json
from sentineltrace.services.hunt import HuntService
from sentineltrace.services.ingest import IngestService
from sentineltrace.storage.db import get_session_factory
from sentineltrace.storage.repositories import AlertRepository, EventRepository

app = typer.Typer(
    name="sentineltrace",
    help="SentinelTrace — Cross-Platform Security Log Analyzer",
    no_args_is_help=True,
)
console = Console(stderr=True)


def _parse_since(value: str) -> int:
    if value.endswith("h"):
        return int(value[:-1])
    if value.endswith("d"):
        return int(value[:-1]) * 24
    return int(value)


def _exit_json(data: dict, code: int = 0) -> None:
    print(json.dumps(data, default=str, indent=2))
    raise typer.Exit(code)


@app.command()
def version(
    output_json: Annotated[
        bool, typer.Option("--output-json", help="Machine-readable output")
    ] = False,
) -> None:
    """Print version information."""
    info = {"name": "sentineltrace", "version": __version__}
    if output_json:
        _exit_json(info)
    console.print(f"SentinelTrace {__version__}")


@app.command()
def doctor(
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    """Check configuration, database, and rules."""
    settings = get_settings()
    checks: list[dict] = []

    rules_ok = settings.rules_path.is_dir() and any(settings.rules_path.glob("*.yaml"))
    checks.append(
        {
            "name": "rules",
            "ok": rules_ok,
            "detail": str(settings.rules_path),
        }
    )

    db_ok = False
    db_detail = ""
    try:
        factory = get_session_factory()
        with factory() as session:
            session.execute(__import__("sqlalchemy").text("SELECT 1"))
            db_ok = True
            db_detail = "connected"
    except Exception as exc:
        db_detail = str(exc)

    checks.append({"name": "database", "ok": db_ok, "detail": db_detail})

    if db_ok:
        try:
            factory = get_session_factory()
            with factory() as session:
                session.execute(__import__("sqlalchemy").text("SELECT 1 FROM events LIMIT 1"))
        except Exception as exc:
            checks.append({"name": "schema", "ok": False, "detail": str(exc)})
        else:
            checks.append({"name": "schema", "ok": True, "detail": "events table present"})
    else:
        checks.append({"name": "schema", "ok": False, "detail": "skipped"})

    all_ok = all(c["ok"] for c in checks if c["name"] != "schema" or db_ok)
    if output_json:
        _exit_json({"checks": checks, "ok": all_ok}, 0 if all_ok else 1)

    for c in checks:
        status = "[green]OK[/green]" if c["ok"] else "[red]FAIL[/red]"
        console.print(f"{status} {c['name']}: {c['detail']}")
    if not all_ok:
        raise typer.Exit(1)


@app.command()
def analyze(
    paths: Annotated[list[Path], typer.Argument(help="Files or directories to analyze")],
    recursive: Annotated[bool, typer.Option("--recursive", "-r")] = False,
    platform: Annotated[Optional[str], typer.Option("--platform")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    """Analyze log files without importing to the database."""
    plat = Platform(platform) if platform else None
    svc = AnalyzeService()
    results = svc.analyze_paths(paths, recursive=recursive, platform=plat)
    total_events = sum(len(r.events) for r in results)
    total_alerts = sum(len(r.alerts) for r in results)
    if output_json:
        _exit_json(
            {
                "files": len(results),
                "events": total_events,
                "alerts": total_alerts,
                "results": [
                    {
                        "path": r.path,
                        "events": len(r.events),
                        "alerts": [a.model_dump(mode="json") for a in r.alerts],
                    }
                    for r in results
                ],
            }
        )
    if not quiet:
        console.print(
            Panel.fit(
                f"Files: {len(results)} | Events: {total_events} | Detections: {total_alerts}",
                title="Analyze Summary",
            )
        )
        for r in results:
            for alert in r.alerts:
                console.print(f"[yellow]{alert.severity.value}[/yellow] {alert.title} — {r.path}")
    if output:
        payload = {
            "results": [
                {
                    "path": r.path,
                    "alerts": [a.model_dump(mode="json") for a in r.alerts],
                }
                for r in results
            ]
        }
        output.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


@app.command()
def import_cmd(
    path: Annotated[Path, typer.Argument(help="Log file to import")],
    platform: Annotated[str, typer.Option("--platform")] = "linux",
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    """Import logs into PostgreSQL."""
    factory = get_session_factory()
    with factory() as session:
        svc = IngestService(session)
        try:
            result = svc.ingest_path(path, Platform(platform))
        except Exception as exc:
            console.print(f"[red]Import failed:[/red] {exc}")
            raise typer.Exit(2) from exc
    if output_json:
        _exit_json(result)
    console.print(
        f"Imported {result['imported']}, skipped {result['skipped']}, errors {result['errors']}"
    )


# Typer uses `import` as keyword — register as `import` via callback
app.command("import")(import_cmd)


@app.command()
def hunt(
    platform: Annotated[Optional[str], typer.Option("--platform")] = None,
    severity: Annotated[Optional[str], typer.Option("--severity")] = None,
    since: Annotated[str, typer.Option("--since", help="e.g. 24h, 7d")] = "168h",
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
) -> None:
    """Run detection rules against stored events."""
    plat = Platform(platform) if platform else None
    sev = Severity(severity) if severity else None
    hours = _parse_since(since)
    factory = get_session_factory()
    with factory() as session:
        svc = HuntService(session)
        alerts = svc.run(platform=plat, min_severity=sev, since_hours=hours)
    if output_json:
        _exit_json({"count": len(alerts), "alerts": [a.model_dump(mode="json") for a in alerts]})
    if quiet:
        print(len(alerts))
        return
    table = Table(title=f"Detections ({len(alerts)})")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Rule")
    for a in alerts:
        table.add_row(a.severity.value, a.title, a.rule_id)
    console.print(table)


events_app = typer.Typer(help="Search normalized events")
alerts_app = typer.Typer(help="Manage alerts")
rules_app = typer.Typer(help="Detection rules")
app.add_typer(events_app, name="events")
app.add_typer(alerts_app, name="alerts")
app.add_typer(rules_app, name="rules")


@events_app.command("list")
def events_list(
    platform: Annotated[Optional[str], typer.Option("--platform")] = None,
    username: Annotated[Optional[str], typer.Option("--username")] = None,
    source_ip: Annotated[Optional[str], typer.Option("--source-ip")] = None,
    page: Annotated[int, typer.Option("--page")] = 1,
    page_size: Annotated[int, typer.Option("--page-size")] = 20,
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    factory = get_session_factory()
    with factory() as session:
        repo = EventRepository(session)
        plat = Platform(platform) if platform else None
        items, total = repo.list_events(
            platform=plat,
            username=username,
            source_ip=source_ip,
            offset=(page - 1) * page_size,
            limit=page_size,
        )
    if output_json:
        _exit_json({"total": total, "items": [e.model_dump(mode="json") for e in items]})
    table = Table(title=f"Events ({total})")
    for col in ("timestamp", "platform", "event_id", "username", "source_ip", "message"):
        table.add_column(col)
    for e in items:
        table.add_row(
            e.timestamp.isoformat() if e.timestamp else "",
            e.platform.value,
            e.event_id or "",
            e.username or "",
            e.source_ip or "",
            (e.message or "")[:60],
        )
    console.print(table)


@events_app.command("show")
def events_show(
    event_id: Annotated[str, typer.Argument()],
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    factory = get_session_factory()
    with factory() as session:
        repo = EventRepository(session)
        event = repo.get(UUID(event_id))
    if not event:
        console.print("[red]Event not found[/red]")
        raise typer.Exit(1)
    if output_json:
        _exit_json(event.model_dump(mode="json"))
    console.print_json(data=event.model_dump(mode="json"))


@alerts_app.command("list")
def alerts_list(
    status: Annotated[Optional[str], typer.Option("--status")] = None,
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    factory = get_session_factory()
    with factory() as session:
        repo = AlertRepository(session)
        items, total = repo.list_alerts(status=status)
    if output_json:
        _exit_json({"total": total, "items": [a.model_dump(mode="json") for a in items]})
    table = Table(title=f"Alerts ({total})")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Status")
    for a in items:
        table.add_row(str(a.id)[:8], a.severity.value, a.title, a.status.value)
    console.print(table)


@alerts_app.command("show")
def alerts_show(
    alert_id: Annotated[str, typer.Argument()],
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    factory = get_session_factory()
    with factory() as session:
        repo = AlertRepository(session)
        alert = repo.get(UUID(alert_id))
    if not alert:
        console.print("[red]Alert not found[/red]")
        raise typer.Exit(1)
    if output_json:
        _exit_json(alert.model_dump(mode="json"))
    console.print(Panel(alert.explanation, title=alert.title))
    console.print("Recommendations:", ", ".join(alert.recommendations))


@alerts_app.command("update")
def alerts_update(
    alert_id: Annotated[str, typer.Argument()],
    status: Annotated[str, typer.Option("--status")],
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    AlertStatus(status)  # validate
    factory = get_session_factory()
    with factory() as session:
        repo = AlertRepository(session)
        updated = repo.update_status(UUID(alert_id), status)
        session.commit()
    if not updated:
        raise typer.Exit(1)
    if output_json:
        _exit_json(updated.model_dump(mode="json"))
    console.print(f"Alert {alert_id} -> {status}")


@rules_app.command("list")
def rules_list(output_json: Annotated[bool, typer.Option("--output-json")] = False) -> None:
    settings = get_settings()
    rules = load_rules(settings.rules_path)
    if output_json:
        _exit_json({"rules": [r.model_dump() for r in rules]})
    table = Table(title="Detection Rules")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Platform")
    table.add_column("Severity")
    for r in rules:
        table.add_row(r.id, r.name, str(r.platform), r.severity.value)
    console.print(table)


@rules_app.command("validate")
def rules_validate(output_json: Annotated[bool, typer.Option("--output-json")] = False) -> None:
    settings = get_settings()
    results = validate_rules(settings.rules_path)
    ok = all(r["valid"] for r in results)
    if output_json:
        _exit_json({"valid": ok, "results": results}, 0 if ok else 1)
    for r in results:
        status = "OK" if r["valid"] else f"FAIL: {r['error']}"
        console.print(f"{r['file']}: {status}")
    if not ok:
        raise typer.Exit(1)


@rules_app.command("test")
def rules_test(
    rule_id: Annotated[str, typer.Argument()],
    fixtures: Annotated[
        Optional[Path],
        typer.Option("--fixtures", help="Path to fixtures directory"),
    ] = None,
    output_json: Annotated[bool, typer.Option("--output-json")] = False,
) -> None:
    """Run a rule against fixture data."""
    settings = get_settings()
    rules = load_rules(settings.rules_path)
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        console.print("[red]Rule not found[/red]")
        raise typer.Exit(1)
    fix_dir = fixtures or (Path(__file__).resolve().parents[4] / "fixtures")
    svc = AnalyzeService()
    all_events = []
    for path in fix_dir.rglob("*"):
        if path.is_file() and path.suffix in (".log", ".txt", ""):
            try:
                all_events.extend(svc.analyze_file(path).events)
            except Exception:
                continue
    engine = DetectionEngine([rule])
    alerts = engine.run(all_events)
    payload = {
        "rule_id": rule_id,
        "matches": len(alerts),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }
    if output_json:
        _exit_json(payload)
    console.print(f"Rule {rule_id}: {len(alerts)} match(es) on fixture corpus")


@app.command()
def export(
    fmt: Annotated[str, typer.Option("--format", "-f")] = "json",
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("report.json"),
) -> None:
    """Export events and alerts."""
    factory = get_session_factory()
    with factory() as session:
        if fmt == "json":
            export_json(session, output)
        elif fmt == "csv":
            export_csv(session, output)
        elif fmt == "html":
            export_html(session, output)
        else:
            console.print("[red]Unknown format[/red]")
            raise typer.Exit(2)
    console.print(f"Wrote {output}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
