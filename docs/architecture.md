# Architecture

```mermaid
flowchart LR
  subgraph clients [Clients]
    Web[React Dashboard]
    CLI[Typer CLI]
  end
  subgraph backend [Backend]
    API[FastAPI]
    Core[Core Engine]
    Parsers[Parsers]
    Detection[Detection Engine]
    Storage[SQLAlchemy Repos]
  end
  DB[(PostgreSQL)]
  Rules[YAML Rules]

  Web --> API
  CLI --> Core
  API --> Storage
  CLI --> Storage
  Storage --> DB
  Parsers --> Core
  Detection --> Rules
  Core --> Parsers
  Core --> Detection
  API --> Core
```

- **Single detection implementation**: `DetectionEngine` loads YAML from `backend/rules` and is invoked by `HuntService` (API/CLI) and `AnalyzeService` (CLI file-only mode).
- **Parsers** are independent of FastAPI; they yield `NormalizedEvent` models.
- **Ingestion** batches inserts with fingerprint-based deduplication.
