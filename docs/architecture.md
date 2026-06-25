# Detection-as-Code Platform — Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Docker Compose Network                              │
│                                                                             │
│  ┌───────────────────┐   HTTP/REST    ┌──────────────────────────────────┐  │
│  │   Frontend        │◄─────────────►│   Backend (FastAPI)              │  │
│  │   React + TS      │               │   Port 8000                      │  │
│  │   Port 3000       │               │                                  │  │
│  │   (nginx serving  │               │  ┌──────────────────────────┐    │  │
│  │    built assets)  │               │  │  Routers                 │    │  │
│  └───────────────────┘               │  │  /api/logs               │    │  │
│                                      │  │  /api/rules              │    │  │
│                                      │  │  /api/detections         │    │  │
│                                      │  │  /api/alerts             │    │  │
│                                      │  │  /api/dashboard          │    │  │
│                                      │  └──────────┬───────────────┘    │  │
│                                      │             │                    │  │
│                                      │  ┌──────────▼───────────────┐    │  │
│                                      │  │  Services                │    │  │
│                                      │  │  ┌────────────────────┐  │    │  │
│                                      │  │  │  IngestionService   │  │    │  │
│                                      │  │  │  DetectionRunner    │  │    │  │
│                                      │  │  │  ┌──────────────┐   │  │    │  │
│                                      │  │  │  │ DetectionEngine│  │    │  │
│                                      │  │  │  │ (ABC Layer)  │   │  │    │  │
│                                      │  │  │  ├──────────────┤   │  │    │  │
│                                      │  │  │  │PySigmaEval   │   │  │    │  │
│                                      │  │  │  │SigmaCLIRunner│   │  │    │  │
│                                      │  │  │  └──────────────┘   │  │    │  │
│                                      │  │  │  ReportingService   │  │    │  │
│                                      │  │  │  MitreService       │  │    │  │
│                                      │  │  └────────────────────┘  │    │  │
│                                      │  └──────────────────────────┘    │  │
│                                      └─────────────────┬────────────────┘  │
│                                                        │ SQLAlchemy ORM    │
│                                      ┌─────────────────▼────────────────┐  │
│                                      │   PostgreSQL 15                  │  │
│                                      │   Port 5432                      │  │
│                                      │                                  │  │
│                                      │  Tables:                         │  │
│                                      │  • upload_batches                │  │
│                                      │  • log_entries                   │  │
│                                      │  • sigma_rules                   │  │
│                                      │  • alerts                        │  │
│                                      └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Frontend (React + TypeScript)
- Built with Vite, React Router, TanStack Query, Recharts, Lucide icons
- Dark SIEM-inspired design with CSS custom properties
- 5 pages: Dashboard, Logs, Rules, Alerts, ATT&CK Coverage
- Nginx serves built assets + proxies `/api/` to backend

### Backend (FastAPI)
- Python 3.11, SQLAlchemy ORM, Pydantic v2 validation
- Modular architecture: routers → services → models
- Auto-generates OpenAPI docs at `/docs`
- Seeds 20 Sigma rules on first startup

### Detection Engine (Abstraction Layer)
```
DetectionEngine (ABC)
    ├── PySigmaEvaluator   ← Active v1 engine
    │   ├── ConditionParser (recursive-descent)
    │   ├── _flatten_dict
    │   ├── _match_keywords
    │   └── _apply_modifiers (contains|startswith|endswith)
    └── SigmaCLIRunner     ← Placeholder for future sigma-cli backend
```

### Database Schema
```sql
upload_batches  (id, filename, upload_time, log_count, status, detections_run)
log_entries     (id, batch_id, event_id, hostname, username, timestamp, raw_json)
sigma_rules     (id, name, title, severity, yaml_content, mitre_*, enabled)
alerts          (id, rule_id, log_entry_id, batch_id, severity, hostname,
                 username, rule_name, technique_id, tactic, triggered_at)
```

## Data Flow

```
1. Analyst uploads JSON log file
        │
        ▼
2. Ingestion Service parses + stores log entries
        │
        ▼
3. Analyst clicks "Run Detections" on a batch
        │
        ▼
4. DetectionRunner loads all enabled Sigma rules
        │
        ▼
5. PySigmaEvaluator.batch_evaluate() for each rule
        │    ├─ Flatten log dict
        │    ├─ Evaluate named groups
        │    └─ Parse & evaluate condition expression
        │
        ▼
6. Matched entries → Alert records with MITRE metadata
        │
        ▼
7. Dashboard aggregates alerts → stats, timeline, coverage
        │
        ▼
8. Alerts exported to CSV or viewed in filtered table
```

## Sigma Syntax Support (v1)

| Feature | Supported | Notes |
|---------|-----------|-------|
| `selection` | ✅ | dict-style field matching |
| `keywords` | ✅ | full-text search across all fields |
| `\|contains` | ✅ | substring modifier |
| `\|startswith` | ✅ | prefix modifier |
| `\|endswith` | ✅ | suffix modifier |
| `all of selection*` | ✅ | wildcard quantifier |
| `1 of selection*` | ✅ | wildcard quantifier |
| `all of them` | ✅ | global quantifier |
| `1 of them` | ✅ | global quantifier |
| `and` / `or` / `not` | ✅ | logical operators |
| Parentheses | ✅ | grouping |
| Wildcards (`*`, `?`) | ✅ | in exact match values |
| List values (OR) | ✅ | within a field |
| List of dicts (OR) | ✅ | across selections |
| `\|re` regex | ❌ | v2 roadmap |
| `\|base64offset` | ❌ | v2 roadmap |
| `near` | ❌ | v2 roadmap |
