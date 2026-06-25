# Detection-as-Code Platform

> A full-stack SIEM-like platform for security analysts to upload Sysmon/Windows Event logs, run Sigma detection rules, generate alerts, and visualize MITRE ATT&CK coverage.

![Stack](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)
![Stack](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-61DAFB?logo=react)
![Stack](https://img.shields.io/badge/Database-PostgreSQL-336791?logo=postgresql)
![Stack](https://img.shields.io/badge/Container-Docker%20Compose-2496ED?logo=docker)

---

## Features

- 📤 **Log Ingestion** — Upload Sysmon JSON / Windows Event JSON logs (array or NDJSON)
- 🔍 **Sigma Detection** — Run 20 seeded Sigma rules with an in-memory PySigma evaluator
- 🚨 **Alert Generation** — Per-log-entry alerts with severity, hostname, username, MITRE context
- 🗺️ **MITRE ATT&CK Heatmap** — Visual coverage map with heat-level colour coding
- 📊 **Dashboard** — Stat cards, severity donut, 30-day timeline, top rules table
- 🔎 **Alert Filtering** — Filter by hostname, username, rule, technique, tactic, time range
- 📥 **CSV Export** — Export filtered alerts to CSV
- 📖 **OpenAPI Docs** — Interactive Swagger UI at `/docs`

---

## Quick Start (Docker Compose)

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac/Linux)

### 1. Clone the repo
```bash
git clone <repo-url>
cd detection-as-code
```

### 2. Configure environment
```bash
copy .env.example .env      # Windows
# or
cp .env.example .env        # Mac/Linux
```

Edit `.env` if you want to change default credentials (optional for local dev).

### 3. Start all services
```bash
docker compose up --build
```

This will:
- Start PostgreSQL on port 5432
- Build and start FastAPI backend on port 8000
- Build and start React frontend on port 3000
- Auto-seed 20 Sigma rules into the database

### 4. Open the app

| Service | URL |
|---------|-----|
| **Frontend** | http://localhost:3000 |
| **API Docs** | http://localhost:8000/docs |
| **ReDoc** | http://localhost:8000/redoc |
| **Health** | http://localhost:8000/health |

### 5. Upload sample data
1. Go to **Logs** page
2. Upload `sample_data/sysmon_sample.json` (614 events)
3. Click **Run Detections** on the batch
4. Navigate to **Dashboard** and **Alerts** to see results

---

## Local Development (without Docker)

### Backend
```bash
cd backend

# Create and activate virtualenv
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Start a local PostgreSQL instance first, then:
set DATABASE_URL=postgresql://dacuser:dacpassword@localhost:5432/dacdb
set SEED_ON_STARTUP=true
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev     # Starts on http://localhost:3000
```

The Vite dev server proxies `/api` requests to `http://localhost:8000` automatically.

---

## Running Tests
```bash
cd backend
pip install -r requirements.txt
python -m pytest app/tests/ -v
```

Tests use an in-memory SQLite database — no PostgreSQL needed.

---

## Generating More Sample Data
```bash
cd sample_data
python generate_sample.py --count 1000 --output large_dataset.json
```

---

## Supported Sigma Syntax (v1)

| Feature | Status |
|---------|--------|
| `selection` (field matching) | ✅ |
| `keywords` | ✅ |
| `\|contains`, `\|startswith`, `\|endswith` | ✅ |
| `all of selection*`, `1 of selection*` | ✅ |
| `all of them`, `1 of them` | ✅ |
| `and`, `or`, `not`, parentheses | ✅ |
| Wildcards (`*`, `?`) | ✅ |
| `\|re` regex modifier | ❌ (v2) |
| `near` / timeframe | ❌ (v2) |

---

## Repository Structure

```
detection-as-code/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py               # FastAPI app + lifespan
│   │   ├── config.py             # Pydantic settings
│   │   ├── database.py           # SQLAlchemy engine + session
│   │   ├── models/               # ORM models
│   │   ├── schemas/              # Pydantic schemas
│   │   ├── routers/              # API route handlers
│   │   ├── services/
│   │   │   ├── ingestion.py      # Log parsing service
│   │   │   ├── detection_runner.py
│   │   │   ├── mitre.py          # ATT&CK mapping
│   │   │   ├── reporting.py      # Stats aggregation
│   │   │   └── detection/
│   │   │       ├── base.py       # DetectionEngine ABC
│   │   │       ├── pysigma_evaluator.py   # v1 engine
│   │   │       └── sigma_cli_runner.py    # v2 placeholder
│   │   └── tests/                # pytest unit tests
│   └── seed/
│       ├── seed.py               # DB seeder (idempotent)
│       └── sigma_rules/          # 20 × Sigma YAML files
│
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── api/client.ts         # Axios API client
│       ├── types/index.ts        # TypeScript types
│       ├── components/           # Reusable components
│       └── pages/                # Route pages
│
├── sample_data/
│   ├── generate_sample.py        # Synthetic log generator
│   └── sysmon_sample.json        # 614 pre-generated events
│
└── docs/
    ├── architecture.md
    └── api_docs.md
```

---

## Seeded Sigma Rules

| # | Rule | Severity | ATT&CK |
|---|------|----------|--------|
| 1 | Suspicious PowerShell Execution | Medium | T1059.001 |
| 2 | Encoded PowerShell Command | High | T1059.001 |
| 3 | Office Application Spawning Command Shell | High | T1204.002 |
| 4 | Mimikatz Credential Dumping | Critical | T1003.001 |
| 5 | Net User Account Enumeration | Medium | T1136 |
| 6 | Scheduled Task Creation | Medium | T1053.005 |
| 7 | Lateral Movement via PsExec | High | T1570 |
| 8 | Pass-the-Hash via NTLM | Critical | T1550.002 |
| 9 | LSASS Memory Dump | Critical | T1003.001 |
| 10 | Suspicious Registry Query | Medium | T1012 |
| 11 | WMI Event Subscription | High | T1546.003 |
| 12 | Certutil Used for Download | High | T1105 |
| 13 | Mshta Suspicious Execution | High | T1218.005 |
| 14 | Regsvr32 Network Activity | High | T1218.010 |
| 15 | Suspicious BITS Job | Medium | T1197 |
| 16 | Admin Share Access | Medium | T1021.002 |
| 17 | RDP Session Hijacking | High | T1563.002 |
| 18 | Token Impersonation | High | T1134.001 |
| 19 | New Local Administrator Account | High | T1136.001 |
| 20 | Windows Audit Log Cleared | High | T1070.001 |

---

## API Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/logs/upload` | Upload JSON log file |
| `GET` | `/api/logs` | List batches |
| `DELETE` | `/api/logs/{id}` | Delete batch |
| `GET` | `/api/rules` | List Sigma rules |
| `POST` | `/api/rules` | Create rule |
| `PUT` | `/api/rules/{id}` | Update rule |
| `POST` | `/api/detections/run` | Run detections on batch |
| `GET` | `/api/alerts` | List alerts (filterable) |
| `GET` | `/api/alerts/export/csv` | Export CSV |
| `GET` | `/api/dashboard/stats` | Dashboard KPIs |
| `GET` | `/api/dashboard/timeline` | Alert timeline |
| `GET` | `/api/dashboard/mitre-coverage` | ATT&CK coverage |

Full API reference: [docs/api_docs.md](docs/api_docs.md)  
Architecture: [docs/architecture.md](docs/architecture.md)

---

## License
MIT
