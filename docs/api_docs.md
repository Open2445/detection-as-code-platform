# Detection-as-Code Platform — API Reference

**Base URL**: `http://localhost:8000`  
**Interactive Docs**: `http://localhost:8000/docs` (Swagger UI)  
**ReDoc**: `http://localhost:8000/redoc`

---

## Authentication
No authentication required in v1 (single-tenant deployment).

---

## Logs (`/api/logs`)

### `POST /api/logs/upload`
Upload a JSON log file.

**Request**: `multipart/form-data`
| Field | Type | Description |
|-------|------|-------------|
| `file` | File | `.json` file (array or NDJSON) |

**Response `201`**:
```json
{
  "batch": {
    "id": 1,
    "filename": "sysmon_sample.json",
    "upload_time": "2024-03-01T10:00:00",
    "log_count": 614,
    "status": "processed",
    "detections_run": false,
    "detections_run_at": null
  },
  "message": "Successfully ingested 614 log entries"
}
```

---

### `GET /api/logs`
List all upload batches.

**Query params**: `skip`, `limit`

**Response `200`**: Array of `UploadBatch`

---

### `GET /api/logs/{batch_id}`
Get a single batch by ID.

---

### `GET /api/logs/{batch_id}/entries`
Get paginated log entries for a batch.

**Query params**: `page`, `page_size`

**Response `200`**:
```json
{
  "total": 614,
  "page": 1,
  "page_size": 50,
  "items": [...]
}
```

---

### `DELETE /api/logs/{batch_id}`
Delete a batch and all associated entries/alerts (cascade).

**Response**: `204 No Content`

---

## Rules (`/api/rules`)

### `GET /api/rules`
List Sigma rules with optional filtering.

**Query params**: `skip`, `limit`, `enabled` (bool), `severity`

**Response `200`**:
```json
{
  "total": 20,
  "items": [
    {
      "id": 1,
      "name": "suspicious_powershell_execution",
      "title": "Suspicious PowerShell Execution",
      "severity": "medium",
      "mitre_techniques": "T1059.001",
      "mitre_tactics": "execution",
      "enabled": true,
      ...
    }
  ]
}
```

---

### `GET /api/rules/{rule_id}`
Get a single rule by ID (includes full YAML content).

---

### `POST /api/rules`
Create a new Sigma rule.

**Request body**:
```json
{
  "name": "my_custom_rule",
  "title": "My Custom Rule",
  "severity": "high",
  "yaml_content": "title: My Rule\ndetection:\n  selection:\n    EventID: 4688\n  condition: selection"
}
```

---

### `PUT /api/rules/{rule_id}`
Update a rule (partial updates supported).

---

### `DELETE /api/rules/{rule_id}`
Delete a Sigma rule. **Response**: `204 No Content`

---

## Detections (`/api/detections`)

### `POST /api/detections/run`
Run all enabled Sigma rules against a log batch (synchronous).

**Request body**:
```json
{ "batch_id": 1 }
```

**Response `200`**:
```json
{
  "batch_id": 1,
  "logs_scanned": 614,
  "rules_evaluated": 20,
  "alerts_generated": 47,
  "duration_seconds": 1.234
}
```

> ⚠️ Existing alerts for the batch are replaced on each run.

---

## Alerts (`/api/alerts`)

### `GET /api/alerts`
List alerts with filtering and pagination.

**Query params**:
| Param | Type | Example |
|-------|------|---------|
| `hostname` | string | `WORKSTATION-01` |
| `username` | string | `alice` |
| `rule_name` | string | `mimikatz` |
| `technique_id` | string | `T1059.001` |
| `tactic` | string | `execution` |
| `severity` | string | `high` |
| `batch_id` | int | `1` |
| `from_date` | datetime | `2024-03-01T00:00:00` |
| `to_date` | datetime | `2024-03-31T23:59:59` |
| `page` | int | `1` |
| `page_size` | int | `50` |

**Response `200`**: Paginated `AlertPage`

---

### `GET /api/alerts/export/csv`
Export filtered alerts as CSV download. Same filter params as list endpoint.

**Response**: `text/csv` attachment `alerts_export.csv`

---

### `GET /api/alerts/{alert_id}`
Get a single alert with full `details_json`.

---

## Dashboard (`/api/dashboard`)

### `GET /api/dashboard/stats`
Overall platform statistics.

**Response `200`**:
```json
{
  "total_alerts": 47,
  "total_logs": 614,
  "total_rules": 20,
  "total_batches": 1,
  "severity_distribution": [
    {"severity": "critical", "count": 8},
    {"severity": "high", "count": 25},
    {"severity": "medium", "count": 14}
  ],
  "top_rules": [
    {"rule_id": 1, "rule_name": "suspicious_powershell_execution", "count": 5, "severity": "medium"}
  ],
  "attack_coverage_pct": 68.4,
  "unique_hosts_affected": 7,
  "unique_techniques_triggered": 13
}
```

---

### `GET /api/dashboard/timeline`
Daily alert counts for the last N days.

**Query params**: `days` (default: 30, max: 365)

**Response `200`**:
```json
{
  "points": [
    {"date": "2024-03-01", "count": 12},
    {"date": "2024-03-02", "count": 8}
  ],
  "granularity": "day"
}
```

---

### `GET /api/dashboard/mitre-coverage`
Per-technique alert counts for the ATT&CK heatmap.

**Response `200`**:
```json
{
  "total_techniques_in_rules": 19,
  "techniques_triggered": 13,
  "coverage_pct": 68.4,
  "techniques": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic": "execution",
      "tactic_id": "TA0002",
      "count": 8
    }
  ]
}
```

---

## Health

### `GET /health`
Health check for Docker/load balancer.

**Response**:
```json
{"status": "ok", "version": "1.0.0"}
```
