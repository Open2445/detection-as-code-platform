# Detection-as-Code Platform — Implementation Plan

## Overview

A full-stack SIEM-like Detection-as-Code platform enabling security analysts to upload Windows/Sysmon JSON logs, run Sigma detection rules against them, generate alerts, and visualize detections mapped to MITRE ATT&CK via an interactive dashboard.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Docker Compose                              │
│                                                                     │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │   Frontend   │    │     Backend      │    │   PostgreSQL DB  │  │
│  │  React + TS  │◄──►│  Python FastAPI  │◄──►│   (Port 5432)   │  │
│  │  (Port 3000) │    │  (Port 8000)     │    └──────────────────┘  │
│  └──────────────┘    └────────┬─────────┘                          │
│                               │                                    │
│                    ┌──────────▼──────────┐                         │
│                    │   Sigma CLI Runner   │                         │
│                    │ (sigma-cli + pySigma)│                         │
│                    └─────────────────────┘                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Backend Module Architecture

```
backend/
├── app/
│   ├── main.py                  # FastAPI app entry point
│   ├── config.py                # Settings / env vars
│   ├── database.py              # SQLAlchemy engine + session
│   ├── models/                  # SQLAlchemy ORM models
│   │   ├── log.py               # LogEntry model
│   │   ├── rule.py              # SigmaRule model
│   │   ├── alert.py             # Alert model
│   │   └── upload.py            # UploadBatch model
│   ├── schemas/                 # Pydantic request/response schemas
│   │   ├── log.py
│   │   ├── rule.py
│   │   ├── alert.py
│   │   └── dashboard.py
│   ├── routers/                 # FastAPI route handlers
│   │   ├── logs.py              # /api/logs — upload & query
│   │   ├── rules.py             # /api/rules — CRUD sigma rules
│   │   ├── detections.py        # /api/detections — run engine
│   │   ├── alerts.py            # /api/alerts — query & export
│   │   └── dashboard.py         # /api/dashboard — stats
│   ├── services/
│   │   ├── ingestion.py         # Log parsing & storage service
│   │   ├── detection.py         # Sigma rule execution engine
│   │   ├── reporting.py         # Alert aggregation & stats
│   │   └── mitre.py             # MITRE ATT&CK mapping service
│   └── tests/
│       ├── test_ingestion.py
│       ├── test_detection.py
│       └── test_reporting.py
```

### Frontend Structure

```
frontend/
├── src/
│   ├── pages/
│   │   ├── Dashboard.tsx        # Main stats dashboard
│   │   ├── Logs.tsx             # Log upload & browsing
│   │   ├── Rules.tsx            # Sigma rules management
│   │   ├── Alerts.tsx           # Alert list & filter/export
│   │   └── Coverage.tsx         # MITRE ATT&CK heatmap
│   ├── components/
│   │   ├── Sidebar.tsx          # Navigation sidebar
│   │   ├── AlertTable.tsx       # Filterable alert table
│   │   ├── MitreHeatmap.tsx     # ATT&CK coverage heatmap
│   │   ├── SeverityChart.tsx    # Donut / bar chart
│   │   ├── TimelineChart.tsx    # Alert timeline (recharts)
│   │   └── StatCard.tsx         # KPI stat cards
│   ├── hooks/                   # Custom React hooks
│   ├── api/                     # Axios API client
│   └── types/                   # TypeScript interfaces
```

---

## Database Schema

### Tables

| Table         | Key Columns                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `upload_batches` | id, filename, upload_time, log_count, status                            |
| `log_entries`    | id, batch_id, event_id, hostname, username, timestamp, raw_json          |
| `sigma_rules`    | id, name, title, description, severity, tags, mitre_tactics, mitre_techniques, yaml_content, enabled |
| `alerts`         | id, rule_id, log_entry_id, severity, hostname, username, technique_id, tactic, triggered_at, details_json |

---

## API Endpoints

### Logs  (`/api/logs`)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/logs/upload` | Upload JSON log file (batch) |
| `GET`  | `/api/logs` | List log batches with pagination |
| `GET`  | `/api/logs/{batch_id}/entries` | Get entries in a batch |
| `DELETE` | `/api/logs/{batch_id}` | Delete a log batch |

### Rules (`/api/rules`)
| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/rules` | List all Sigma rules |
| `GET`  | `/api/rules/{id}` | Get a single rule |
| `POST` | `/api/rules` | Create/upload a new rule |
| `PUT`  | `/api/rules/{id}` | Update rule |
| `DELETE` | `/api/rules/{id}` | Delete rule |

### Detections (`/api/detections`)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/detections/run` | Run detection on batch(es) |
| `GET`  | `/api/detections/status/{job_id}` | Check detection job status |

### Alerts (`/api/alerts`)
| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/alerts` | List alerts (filterable by hostname, user, rule, technique, time range) |
| `GET`  | `/api/alerts/{id}` | Get alert details |
| `GET`  | `/api/alerts/export/csv` | Export filtered alerts as CSV |

### Dashboard (`/api/dashboard`)
| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/dashboard/stats` | Total alerts, severity dist., top rules |
| `GET`  | `/api/dashboard/timeline` | Alert counts over time |
| `GET`  | `/api/dashboard/mitre-coverage` | MITRE ATT&CK technique hit counts |

---

## Sigma Detection Engine Strategy

Because `sigma-cli` is a CLI tool and running it against individual JSON logs may be slow, we'll use **pySigma** Python library directly:

1. Load Sigma rules as YAML from the database.
2. Parse each rule using `pySigma` into a condition tree.
3. For each log entry (dict), evaluate conditions in-memory using a custom Python matcher.
4. For rules needing field transformations, use `sigma-backend-elasticsearch` or a custom flat-dict evaluator.
5. Alerts are generated when a condition matches and stored with MITRE metadata extracted from rule tags.

### Alternative (CLI approach)
For rules incompatible with Python eval, shell out to `sigma convert` and `jq` pipe approach.

---

## MITRE ATT&CK Mapping

- Sigma rules encode techniques in their `tags` field (e.g., `attack.t1059.001`).
- We parse tags on rule creation and store `mitre_tactics[]` and `mitre_techniques[]`.
- The Coverage page renders a MITRE ATT&CK Navigator-style heatmap using technique IDs mapped to alert counts.
- Static MITRE Enterprise ATT&CK v14 technique list embedded as JSON seed data.

---

## Sample Data & Seed Content

### 20 Sigma Rules (categories)
1. Suspicious PowerShell Execution (T1059.001)
2. Mimikatz Detection via EventID (T1003.001)
3. Net User Command (T1136)
4. Scheduled Task Creation (T1053.005)
5. Lateral Movement via PsExec (T1570)
6. Pass-the-Hash via NTLM (T1550.002)
7. LSASS Memory Dump (T1003.001)
8. Suspicious Reg Query (T1012)
9. WMI Subscription (T1546.003)
10. DLL Side-Loading (T1574.002)
11. Certutil Download (T1105)
12. Mshta Suspicious Execution (T1218.005)
13. Regsvr32 Network Connection (T1218.010)
14. Suspicious BITS Job (T1197)
15. Admin Share Access (T1021.002)
16. RDP Session Hijacking (T1563.002)
17. Token Impersonation (T1134.001)
18. New Local Admin Account (T1136.001)
19. Audit Log Cleared (T1070.001)
20. DNS Query to TOR Exit Nodes (T1090.003)

### Sample Sysmon Dataset
- 500 synthetic Sysmon Event ID 1 (Process Create) logs
- 200 Event ID 3 (Network Connection) logs
- 100 Event ID 11 (File Create) logs
- Embedded in `sample_data/sysmon_sample.json`

---

## Docker Compose Services

| Service | Image | Ports |
|---------|-------|-------|
| `db` | `postgres:15-alpine` | 5432 |
| `backend` | Custom (`backend/Dockerfile`) | 8000 |
| `frontend` | Custom (`frontend/Dockerfile`) | 3000 |

---

## Proposed File Structure (Repository Root)

```
detection-as-code/
├── docker-compose.yml
├── README.md
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic/               # DB migrations
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── routers/
│   │   ├── services/
│   │   └── tests/
│   └── seed/
│       ├── sigma_rules/       # 20 .yml rule files
│       └── seed.py            # DB seeder script
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
├── sample_data/
│   └── sysmon_sample.json
└── docs/
    ├── architecture.md
    ├── api_docs.md
    └── screenshots/
```

---

## Implementation Phases

### Phase 1 — Infrastructure & Backend Foundation
- [ ] Repository structure + Docker Compose
- [ ] FastAPI app scaffolding + PostgreSQL + Alembic migrations
- [ ] ORM models + Pydantic schemas
- [ ] Log ingestion router + service

### Phase 2 — Detection Engine
- [ ] Sigma rule storage (seed 20 rules)
- [ ] pySigma-based in-memory detection engine
- [ ] Alert generation + MITRE mapping
- [ ] Detection router

### Phase 3 — Reporting & Export
- [ ] Dashboard stats aggregation
- [ ] Alert filtering + CSV export
- [ ] Unit tests (ingestion, detection, reporting)

### Phase 4 — Frontend
- [ ] React + TypeScript Vite setup
- [ ] Dark-theme design system (CSS variables)
- [ ] Sidebar navigation
- [ ] Dashboard page (stat cards, charts, timeline)
- [ ] Logs page (upload + table)
- [ ] Rules page (list + detail)
- [ ] Alerts page (filterable table + export)
- [ ] Coverage page (MITRE heatmap)

### Phase 5 — Polish & Docs
- [ ] Sample dataset (500+ synthetic logs)
- [ ] README + Architecture diagram
- [ ] Screenshots

---

## Open Questions

> [!IMPORTANT]
> **Detection Engine**: Should detection run automatically on every log upload, or only on-demand via a "Run Detections" button? 
> — **Recommended**: On-demand per batch for performance clarity. Auto-run can be added later.

> [!IMPORTANT]
> **Sigma Rule Format**: Rules will be stored as YAML in the database and also in seed files. The detection engine will use `pySigma` with a custom flat-dict evaluator (no SIEM backend dependency). Is this acceptable?

> [!NOTE]
> **Authentication**: No user authentication is included in scope. All data is accessible without login (single-tenant).

> [!NOTE]
> **Real-time Updates**: Alert generation is synchronous (triggered via API). WebSocket-based real-time updates are out of scope for v1.

---

## Verification Plan

### Automated Tests
```bash
cd backend && python -m pytest app/tests/ -v
```

### Manual Verification
1. Start via `docker compose up --build`
2. Upload `sample_data/sysmon_sample.json` via Logs page
3. Navigate to Dashboard and run detections
4. Verify alerts appear with MITRE technique mappings
5. Filter alerts by hostname / technique
6. Export alerts as CSV
7. View Coverage heatmap

