"""Tests for Alert Triage, History Tracking, Duplicate Validation, Counters, and Rule Validation."""
import os
import tempfile
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base, create_tables
from app.models.log import UploadBatch, LogEntry
from app.models.rule import SigmaRule
from app.models.alert import Alert, AlertTriageHistory


def test_alert_triage_and_history(client, db):
    """Test updating alert triage fields and verifying history logging."""
    # Create rule, batch, log entry, and alert
    rule = SigmaRule(
        name="test_rule_triage",
        title="Test Rule Triage",
        severity="high",
        yaml_content="title: Test Rule Triage\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
    )
    batch = UploadBatch(filename="test_logs.json", log_count=1, status="processed")
    db.add_all([rule, batch])
    db.commit()

    log_entry = LogEntry(batch_id=batch.id, event_id=1, hostname="HOST-01", username="admin", raw_json="{}")
    db.add(log_entry)
    db.commit()

    alert1 = Alert(
        rule_id=rule.id,
        log_entry_id=log_entry.id,
        batch_id=batch.id,
        severity="high",
        rule_name=rule.name,
        hostname="HOST-01",
        username="admin",
        classification="unclassified",
        triage_status="open",
    )
    db.add(alert1)
    db.commit()

    # Update triage to true_positive and in_progress
    payload = {
        "classification": "true_positive",
        "triage_status": "in_progress",
        "analyst_notes": "Confirmed malicious activity.",
        "reviewed_by": "analyst_alice",
    }
    response = client.put(f"/api/alerts/{alert1.id}/triage", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "true_positive"
    assert data["triage_status"] == "in_progress"
    assert data["analyst_notes"] == "Confirmed malicious activity."
    assert data["reviewed_by"] == "analyst_alice"
    assert data["reviewed_at"] is not None

    # Check triage history endpoint
    hist_resp = client.get(f"/api/alerts/{alert1.id}/history")
    assert hist_resp.status_code == 200
    history = hist_resp.json()
    assert len(history) == 1
    assert history[0]["previous_classification"] == "unclassified"
    assert history[0]["new_classification"] == "true_positive"
    assert history[0]["previous_triage_status"] == "open"
    assert history[0]["new_triage_status"] == "in_progress"
    assert history[0]["analyst_notes"] == "Confirmed malicious activity."
    assert history[0]["reviewed_by"] == "analyst_alice"


def test_duplicate_validation_and_circularity(client, db):
    """Test duplicate alert references, self-references, nonexistent primary IDs, and circular chains."""
    rule = SigmaRule(name="rule_dup", title="Rule Dup", yaml_content="...")
    batch = UploadBatch(filename="test.json", log_count=1, status="processed")
    db.add_all([rule, batch])
    db.commit()

    log_entry = LogEntry(batch_id=batch.id, event_id=1, raw_json="{}")
    db.add(log_entry)
    db.commit()

    a1 = Alert(rule_id=rule.id, log_entry_id=log_entry.id, batch_id=batch.id, severity="low", rule_name=rule.name)
    a2 = Alert(rule_id=rule.id, log_entry_id=log_entry.id, batch_id=batch.id, severity="low", rule_name=rule.name)
    a3 = Alert(rule_id=rule.id, log_entry_id=log_entry.id, batch_id=batch.id, severity="low", rule_name=rule.name)
    db.add_all([a1, a2, a3])
    db.commit()

    # 1. Self reference check
    resp = client.put(f"/api/alerts/{a1.id}/triage", json={"classification": "duplicate", "primary_alert_id": a1.id})
    assert resp.status_code == 400
    assert "cannot reference itself" in resp.json()["detail"]

    # 2. Nonexistent primary alert check
    resp = client.put(f"/api/alerts/{a1.id}/triage", json={"classification": "duplicate", "primary_alert_id": 99999})
    assert resp.status_code == 404

    # 3. Valid duplicate reference (a2 is duplicate of a1)
    resp = client.put(f"/api/alerts/{a2.id}/triage", json={"classification": "duplicate", "primary_alert_id": a1.id})
    assert resp.status_code == 200
    assert resp.json()["primary_alert_id"] == a1.id

    # 4. Circular duplicate chain check: try to make a1 duplicate of a2 (which points to a1)
    resp = client.put(f"/api/alerts/{a1.id}/triage", json={"classification": "duplicate", "primary_alert_id": a2.id})
    assert resp.status_code == 400
    assert "Circular duplicate" in resp.json()["detail"]

    # 5. Changing classification away from duplicate clears primary_alert_id
    resp = client.put(f"/api/alerts/{a2.id}/triage", json={"classification": "false_positive"})
    assert resp.status_code == 200
    assert resp.json()["classification"] == "false_positive"
    assert resp.json()["primary_alert_id"] is None


def test_alert_filtering_and_counters(client, db):
    """Test filtering by classification/status and verifying metric counters."""
    initial_counters = client.get("/api/alerts/counters").json()

    rule = SigmaRule(name="rule_counters", title="Rule Counters", yaml_content="...")
    batch = UploadBatch(filename="batch.json", log_count=1, status="processed")
    db.add_all([rule, batch])
    db.commit()

    log_entry = LogEntry(batch_id=batch.id, event_id=1, raw_json="{}")
    db.add(log_entry)
    db.commit()

    alerts_data = [
        ("unclassified", "open"),
        ("true_positive", "closed"),
        ("true_positive", "in_progress"),
        ("false_positive", "closed"),
        ("duplicate", "closed"),
        ("needs_investigation", "open"),
    ]
    for cls_name, st in alerts_data:
        db.add(Alert(
            rule_id=rule.id, log_entry_id=log_entry.id, batch_id=batch.id,
            severity="medium", rule_name=rule.name,
            classification=cls_name, triage_status=st,
        ))
    db.commit()

    # Check counters endpoint
    resp = client.get("/api/alerts/counters")
    assert resp.status_code == 200
    counters = resp.json()
    assert counters["open_alerts"] == initial_counters["open_alerts"] + 2  # unclassified(open), needs_investigation(open)
    assert counters["true_positives"] == initial_counters["true_positives"] + 2
    assert counters["false_positives"] == initial_counters["false_positives"] + 1
    assert counters["duplicates"] == initial_counters["duplicates"] + 1
    assert counters["needs_investigation"] == initial_counters["needs_investigation"] + 1

    # Check alert list filter
    resp = client.get(f"/api/alerts?rule_name={rule.name}&classification=true_positive")
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    resp = client.get(f"/api/alerts?rule_name={rule.name}&triage_status=closed")
    assert resp.status_code == 200
    assert resp.json()["total"] == 3



def test_rule_validation_metadata(client, db):
    """Test setting and retrieving detection rule validation metadata."""
    rule = SigmaRule(
        name="lab_rule_001",
        title="Lab Rule 001",
        yaml_content="title: Lab Rule 001\n",
    )
    batch = UploadBatch(filename="powershell_lab.evtx", log_count=10, status="processed")
    db.add_all([rule, batch])
    db.commit()


    # Update validation status
    val_payload = {
        "validation_status": "validated_in_lab",
        "validation_notes": "Tested in cyber range environment with attack simulation.",
        "validation_evidence_batch_id": batch.id,
        "primary_validated_rule": True,
    }
    resp = client.put(f"/api/rules/{rule.id}/validation", json=val_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["validation_status"] == "validated_in_lab"
    assert data["validation_notes"] == "Tested in cyber range environment with attack simulation."
    assert data["validation_evidence_batch_id"] == batch.id
    assert data["validation_evidence_filename"] == "powershell_lab.evtx"
    assert data["primary_validated_rule"] is True
    assert data["validated_at"] is not None


def test_existing_sqlite_db_migration():
    """Test schema auto-migration against an existing SQLite DB with alerts/rules tables without triage/validation columns."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    try:
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

        # Create legacy schema without triage/validation columns
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE upload_batches (
                    id INTEGER PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    upload_time DATETIME NOT NULL,
                    log_count INTEGER NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    detections_run BOOLEAN DEFAULT 0 NOT NULL,
                    detections_run_at DATETIME
                );
            """))
            conn.execute(text("""
                CREATE TABLE log_entries (
                    id INTEGER PRIMARY KEY,
                    batch_id INTEGER REFERENCES upload_batches(id),
                    event_id INTEGER,
                    hostname VARCHAR(255),
                    username VARCHAR(255),
                    timestamp DATETIME,
                    raw_json TEXT NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE sigma_rules (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE,
                    title VARCHAR(500) NOT NULL,
                    description TEXT,
                    severity VARCHAR(50) DEFAULT 'medium' NOT NULL,
                    yaml_content TEXT NOT NULL,
                    mitre_tactics VARCHAR(500),
                    mitre_techniques VARCHAR(500),
                    mitre_tactic_ids VARCHAR(500),
                    tags TEXT,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME,
                    enabled BOOLEAN DEFAULT 1 NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY,
                    rule_id INTEGER REFERENCES sigma_rules(id),
                    log_entry_id INTEGER REFERENCES log_entries(id),
                    batch_id INTEGER REFERENCES upload_batches(id),
                    severity VARCHAR(50) NOT NULL,
                    hostname VARCHAR(255),
                    username VARCHAR(255),
                    rule_name VARCHAR(255) NOT NULL,
                    technique_id VARCHAR(50),
                    technique_name VARCHAR(255),
                    tactic VARCHAR(100),
                    tactic_id VARCHAR(50),
                    event_id INTEGER,
                    triggered_at DATETIME NOT NULL,
                    details_json TEXT
                );
            """))
            # Insert pre-existing rule and alert
            conn.execute(text("""
                INSERT INTO sigma_rules (id, name, title, severity, yaml_content, created_at, enabled)
                VALUES (1, 'legacy_rule', 'Legacy Rule', 'high', '...', '2026-01-01 00:00:00', 1);
            """))
            conn.execute(text("""
                INSERT INTO alerts (id, rule_id, log_entry_id, batch_id, severity, rule_name, triggered_at)
                VALUES (1, 1, 1, 1, 'high', 'legacy_rule', '2026-01-01 00:00:00');
            """))

        # Now run create_tables() using an overridden engine
        from app import database
        orig_engine = database.engine
        database.engine = engine
        try:
            database.create_tables()

            # Verify that columns were added and existing data preserved
            Session = sessionmaker(bind=engine)
            session = Session()

            rule = session.get(SigmaRule, 1)
            assert rule is not None
            assert rule.name == "legacy_rule"
            assert rule.validation_status == "unvalidated"

            alert = session.get(Alert, 1)
            assert alert is not None
            assert alert.rule_name == "legacy_rule"
            assert alert.classification == "unclassified"
            assert alert.triage_status == "open"

            session.close()
        finally:
            database.engine = orig_engine
            engine.dispose()

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

