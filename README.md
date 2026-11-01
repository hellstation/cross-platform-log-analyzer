<div align="center">

# **Cross-platform security log analyzer for local SOC-style investigations.**

Import Windows and Linux logs, normalize them into one schema, run YAML-based detections, triage alerts, and export reports — from a web dashboard or the CLI.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Backend](https://img.shields.io/badge/backend-FastAPI-009688.svg)
![Frontend](https://img.shields.io/badge/frontend-React-61dafb.svg)
![Database](https://img.shields.io/badge/database-PostgreSQL-336791.svg)
![Docker](https://img.shields.io/badge/docker-ready-2496ed.svg)

[Quick start](#quick-start) · [Detections](#detection-catalog) · [Log sources](#supported-log-sources) · [API](#api) · [Roadmap](#roadmap)

</div>

---

## Overview

SentinelTrace is a Blue Team / SOC analyst toolkit that runs entirely on your machine. Feed it raw logs, and it parses them, removes duplicates, applies detection rules mapped to MITRE ATT&CK, and gives you alerts to investigate.

The web dashboard and the CLI share the **same core engine**, so results are identical no matter how you work.

## Features

| | |
|---|---|
| **Windows** | `.evtx` import (Security & System) via `python-evtx`. Priority Event IDs: 4624, 4625, 4672, 4688, 4720, 4728, 4732, 4697, 7045 and more |
| **Linux** | `auth.log`, `secure`, `syslog`, `messages`, `journalctl` JSON export, auditd lines |
| **Detections** | 10 built-in rules: SSH brute force, password spraying, login after failures, privilege activity, new accounts, group changes, service installation, sudo bursts, cross-platform auth correlation |
| **Safe rules** | Structured YAML conditions — no `eval()`, no arbitrary code |
| **Storage** | PostgreSQL with Alembic migrations; fingerprint-based deduplication on re-import |
| **Investigation** | Alerts, cases, event search and filters |
| **Reporting** | Export to JSON, CSV or HTML |

## Architecture

```
React UI ──► FastAPI ──► Repositories ──► PostgreSQL
                ▲
Typer CLI ──────┴──► Core (parsers + DetectionEngine + rules/*.yaml)
```

Details: [docs/architecture.md](docs/architecture.md)

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/hellstation/cross-platform-log-analyzer.git
cd cross-platform-log-analyzer

cp .env.example .env
docker compose up --build
```

| Service   | URL                                |
|-----------|------------------------------------|
| Dashboard | http://localhost:5173              |
| API docs  | http://localhost:8000/api/docs     |
| Health    | http://localhost:8000/api/health   |

Try the CLI inside the backend container with a bundled sample log:

```bash
docker compose exec backend sentineltrace doctor
docker compose exec backend sentineltrace rules list
docker compose exec backend sentineltrace import /app/fixtures/linux/auth_bruteforce.log --platform linux
docker compose exec backend sentineltrace hunt --since 24h
```

### Local (without Docker)

You need a running PostgreSQL instance.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

export DATABASE_URL=postgresql+psycopg://sentineltrace:changeme_local_only@localhost:5432/sentineltrace
export RULES_PATH=$(pwd)/rules
alembic upgrade head
```

## CLI usage

```bash
# Analyze a file
sentineltrace analyze ../fixtures/linux/auth_bruteforce.log

# Import into the database
sentineltrace import ../fixtures/linux/password_spray.log --platform linux

# Hunt through stored events
sentineltrace hunt --severity high

# Query events
sentineltrace events list --username alice

# Export a report
sentineltrace export --format html --output report.html
```

Run `sentineltrace --help` for all commands.

## Detection catalog

| ID            | Name                                      | Platform | MITRE ATT&CK |
|---------------|-------------------------------------------|----------|--------------|
| `DET-LNX-001` | SSH Brute Force                           | Linux    | T1110.001    |
| `DET-LNX-002` | Password Spraying                         | Linux    | T1110.003    |
| `DET-LNX-003` | Successful Login After Failures           | Linux    | T1110        |
| `DET-LNX-004` | Linux Sudo Activity                       | Linux    | T1548.003    |
| `DET-WIN-001` | Windows Failed Logons                     | Windows  | T1110        |
| `DET-WIN-002` | Suspicious Privilege Activity             | Windows  | T1078        |
| `DET-WIN-003` | New Windows Account                       | Windows  | T1136.001    |
| `DET-WIN-004` | Security Group Modification               | Windows  | T1098        |
| `DET-WIN-005` | Suspicious Service Installation           | Windows  | T1543.003    |
| `DET-X-001`   | Cross-Platform Authentication Correlation | Any      | T1078        |

Rules live in `backend/rules/*.yaml`. Tune `window_minutes` and `threshold` per rule to match your environment.

## Supported log sources

| Source                    | Format / file             |
|---------------------------|---------------------------|
| Windows Security / System | `.evtx`                   |
| Debian / Ubuntu auth      | `auth.log`                |
| RHEL auth                 | `secure`                  |
| Syslog                    | `syslog`, `messages`      |
| systemd                   | `journalctl` JSON export  |
| auditd                    | `audit.log` (line parser) |

> **Note:** synthetic Linux scenarios are included in `fixtures/linux/`. Binary `.evtx` fixtures are intentionally not shipped — use your own exports for Windows testing.

## API

Interactive OpenAPI docs are available at `/api/docs`.

| Endpoint                                  | Purpose                         |
|-------------------------------------------|---------------------------------|
| `GET /api/health`                         | Health check                    |
| `GET, POST /api/ingestions`               | List / create ingestions        |
| `POST /api/ingestions/hunt`               | Run detections over stored data |
| `GET /api/events`, `GET /api/events/{id}` | Search and view events          |
| `GET, PATCH /api/alerts`                  | List / update alerts            |
| `GET /api/rules`, `GET /api/rules/validate` | List and validate rules       |
| `GET, POST, PATCH /api/cases`             | Case management                 |
| `GET /api/statistics/*`                   | Dashboard statistics            |
| `GET /api/export?format=json\|csv\|html`  | Export reports                  |

## Testing

```bash
cd backend
pip install -e ".[dev]"
RULES_PATH=$PWD/rules pytest -q
ruff check src tests
```

GitHub Actions runs `pytest`, Ruff and the frontend build on every push.

## Security considerations

- Built for **local, trusted** use — there is no authentication by default.
- Uploads: size limits, filename sanitization, uploaded content is never executed.
- HTML export escapes all user-controlled data.
- Detection rules use a limited condition DSL, not arbitrary code.
- Never expose PostgreSQL publicly. If the API is reachable from a network, rotate the credentials in `.env`.

## Limitations

- No Kafka / Elasticsearch / Kubernetes in the MVP.
- Cross-platform correlation is a time / IP / user heuristic, not a full graph engine.
- journald and auditd formats vary between distros; edge cases may end up in `parse_errors`.
- UI settings store display preferences locally; server-side detection windows use API/env defaults.
