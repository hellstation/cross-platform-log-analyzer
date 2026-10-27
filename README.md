# SentinelTrace

**Cross-Platform Security Log Analyzer** — import and normalize Windows and Linux security logs, run YAML-based detections, investigate alerts, and export reports. Built for SOC analysts and Blue Team portfolios.

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

- **Shared core engine** — parsers, normalization, deduplication, detection, and correlation power both the **web dashboard** and **CLI**.
- **Windows** — `.evtx` import (Security & System) via `python-evtx`, priority Event IDs (4624, 4625, 4672, 4688, 4720, 4728, 4732, 4697, 7045, …).
- **Linux** — `auth.log`, `secure`, `syslog`, `messages`, `journalctl` JSON export, auditd lines.
- **10+ detections** — SSH brute force, password spraying, login-after-failures, Windows failed logons, privilege activity, new accounts, group changes, service install, sudo bursts, cross-platform auth correlation.
- **Safe rule format** — structured YAML conditions (no `eval()`).
- **PostgreSQL** storage with Alembic migrations and fingerprint-based dedup on re-import.

## Quick start (Docker)

```bash
cp .env.example .env
docker compose up --build
```

| Service   | URL                        |
|-----------|----------------------------|
| Dashboard | http://localhost:5173      |
| API docs  | http://localhost:8000/api/docs |
| Health    | http://localhost:8000/api/health |

CLI inside the backend container:

```bash
docker compose exec backend sentineltrace --help
docker compose exec backend sentineltrace doctor
docker compose exec backend sentineltrace rules list
docker compose exec backend sentineltrace import /app/fixtures/linux/auth_bruteforce.log --platform linux
docker compose exec backend sentineltrace hunt --since 24h
```

## CLI examples (local)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+psycopg://sentineltrace:changeme_local_only@localhost:5432/sentineltrace
export RULES_PATH=$(pwd)/rules
alembic upgrade head

sentineltrace analyze ../fixtures/linux/auth_bruteforce.log
sentineltrace import ../fixtures/linux/password_spray.log --platform linux
sentineltrace hunt --severity high
sentineltrace events list --username alice
sentineltrace export --format html --output report.html
```

## Architecture

See [docs/architecture.md](docs/architecture.md).

```text
React UI ──► FastAPI ──► Repositories ──► PostgreSQL
                ▲
Typer CLI ──────┴──► Core (parsers + DetectionEngine + rules/*.yaml)
```

## Detection catalog

| ID | Name | Platform | MITRE (examples) |
|----|------|----------|------------------|
| DET-LNX-001 | SSH Brute Force | Linux | T1110.001 |
| DET-LNX-002 | Password Spraying | Linux | T1110.003 |
| DET-LNX-003 | Successful Login After Failures | Linux | T1110 |
| DET-LNX-004 | Linux Sudo Activity | Linux | T1548.003 |
| DET-WIN-001 | Windows Failed Logons | Windows | T1110 |
| DET-WIN-002 | Suspicious Privilege Activity | Windows | T1078 |
| DET-WIN-003 | New Windows Account | Windows | T1136.001 |
| DET-WIN-004 | Security Group Modification | Windows | T1098 |
| DET-WIN-005 | Suspicious Service Installation | Windows | T1543.003 |
| DET-X-001 | Cross-Platform Authentication Correlation | Any | T1078 |

Rules live in `backend/rules/*.yaml`. Tune `window_minutes` and `threshold` per rule.

## Supported log sources

| Source | Format |
|--------|--------|
| Windows Security / System | `.evtx` |
| Debian/Ubuntu auth | `auth.log` |
| RHEL auth | `secure` |
| Syslog | `syslog`, `messages` |
| systemd | `journalctl` JSON export |
| auditd | `audit.log` (line parser) |

Synthetic scenarios under `fixtures/linux/`; binary `.evtx` fixtures are intentionally not shipped — use your own exports for Windows testing.

## API

- `GET /api/health`
- `GET/POST /api/ingestions` (+ `POST /api/ingestions/hunt`)
- `GET /api/events`, `GET /api/events/{id}`
- `GET/PATCH /api/alerts`
- `GET /api/rules`, `GET /api/rules/validate`
- `GET/POST/PATCH /api/cases`
- `GET /api/statistics/*`
- `GET /api/export?format=json|csv|html`

Interactive OpenAPI: `/api/docs`.

## Testing

```bash
cd backend
pip install -e ".[dev]"
RULES_PATH=$PWD/rules pytest -q
ruff check src tests
```

GitHub Actions runs pytest, Ruff, and frontend build on push.

## Security considerations

- Designed for **local trusted** use; no authentication by default.
- Upload size limits, filename sanitization, no execution of uploaded content, HTML export escapes user data.
- Detection rules use a **limited condition DSL** (no arbitrary code).
- Do not expose PostgreSQL publicly; rotate `.env` credentials if the API is network-facing.

## Limitations

- No Kafka/Elasticsearch/K8s in MVP.
- Cross-platform correlation is time/IP/user heuristic, not a full graph engine.
- Journald and auditd formats vary by distro; edge cases may land in `parse_errors`.
- Settings in the UI store display preferences locally; server-side detection windows use API/env defaults unless extended.

## Roadmap

- Authentication and RBAC for multi-user deployments
- Rule enable/disable API and per-tenant thresholds
- Additional parsers (JSON Loki export, WEF XML bundles)
- Enrichment (GeoIP offline DB, asset tags)
- Case templates and scheduled hunt jobs

## License

MIT — see [LICENSE](LICENSE).
