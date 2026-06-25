"""Unit tests for the reporting service."""
import json
import pytest
from datetime import datetime, timedelta

from app.models.log import UploadBatch, LogEntry
from app.models.rule import SigmaRule
from app.models.alert import Alert
from app.services.reporting import (
    get_dashboard_stats, get_alert_timeline, get_mitre_coverage, export_alerts_csv
)


def _make_batch(db, filename="test.json", log_count=5):
    b = UploadBatch(filename=filename, log_count=log_count, status="processed")
    db.add(b)
    db.flush()
    return b


def _make_rule(db, name, severity="high", techniques="T1059.001", tactics="execution"):
    r = SigmaRule(
        name=name,
        title=f"Rule {name}",
        severity=severity,
        yaml_content="title: test\ndetection:\n  condition: none",
        mitre_techniques=techniques,
        mitre_tactics=tactics,
        mitre_tactic_ids="TA0002",
        enabled=True,
    )
    db.add(r)
    db.flush()
    return r


def _make_log(db, batch_id):
    entry = LogEntry(
        batch_id=batch_id,
        event_id=1,
        hostname="HOST-01",
        username="alice",
        timestamp=datetime.utcnow(),
        raw_json=json.dumps({"EventID": 1}),
    )
    db.add(entry)
    db.flush()
    return entry


def _make_alert(db, rule, log_entry, batch_id, severity=None, technique_id="T1059.001",
                tactic="execution", hostname="HOST-01", username="alice",
                triggered_at=None):
    a = Alert(
        rule_id=rule.id,
        log_entry_id=log_entry.id,
        batch_id=batch_id,
        severity=severity or rule.severity,
        hostname=hostname,
        username=username,
        rule_name=rule.name,
        technique_id=technique_id,
        technique_name="PowerShell",
        tactic=tactic,
        tactic_id="TA0002",
        triggered_at=triggered_at or datetime.utcnow(),
        details_json="{}",
    )
    db.add(a)
    db.flush()
    return a


class TestDashboardStats:
    def test_empty_database(self):
        """Use a completely fresh in-memory DB to guarantee zero rows."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.database import Base
        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=eng)
        Session = sessionmaker(bind=eng)
        fresh_db = Session()
        try:
            stats = get_dashboard_stats(fresh_db)
            assert stats["total_alerts"] == 0
            assert stats["total_logs"] == 0
            assert stats["attack_coverage_pct"] == 0.0
        finally:
            fresh_db.close()

    def test_with_data(self, db):
        batch = _make_batch(db)
        rule = _make_rule(db, "test_rule_stats")
        log_entry = _make_log(db, batch.id)
        _make_alert(db, rule, log_entry, batch.id)
        db.commit()

        stats = get_dashboard_stats(db)
        assert stats["total_alerts"] >= 1
        assert stats["total_logs"] >= 1
        assert stats["unique_hosts_affected"] >= 1

    def test_severity_distribution(self, db):
        batch = _make_batch(db, filename="sev_test.json")
        rule_h = _make_rule(db, "rule_high_sev", severity="high")
        rule_c = _make_rule(db, "rule_crit_sev", severity="critical")
        log_e = _make_log(db, batch.id)
        _make_alert(db, rule_h, log_e, batch.id, severity="high")
        _make_alert(db, rule_c, log_e, batch.id, severity="critical")
        db.commit()

        stats = get_dashboard_stats(db)
        sev_map = {s["severity"]: s["count"] for s in stats["severity_distribution"]}
        assert "high" in sev_map
        assert "critical" in sev_map

    def test_coverage_pct(self, db):
        batch = _make_batch(db, filename="cov_test.json")
        rule = _make_rule(db, "coverage_rule", techniques="T1059.001,T1003.001")
        log_e = _make_log(db, batch.id)
        _make_alert(db, rule, log_e, batch.id, technique_id="T1059.001")
        db.commit()

        stats = get_dashboard_stats(db)
        assert stats["attack_coverage_pct"] > 0


class TestAlertTimeline:
    def test_empty_timeline(self, db):
        result = get_alert_timeline(db, days=30)
        assert "points" in result
        assert result["granularity"] == "day"

    def test_timeline_has_today(self, db):
        batch = _make_batch(db, filename="timeline_test.json")
        rule = _make_rule(db, "timeline_rule")
        log_e = _make_log(db, batch.id)
        _make_alert(db, rule, log_e, batch.id, triggered_at=datetime.utcnow())
        db.commit()

        result = get_alert_timeline(db, days=7)
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        dates = [p["date"] for p in result["points"]]
        assert today_str in dates


class TestMitreCoverage:
    def test_empty_coverage(self, db):
        result = get_mitre_coverage(db)
        assert result["coverage_pct"] >= 0
        assert isinstance(result["techniques"], list)


class TestCSVExport:
    def test_csv_export_headers(self, db):
        batch = _make_batch(db, filename="csv_test.json")
        rule = _make_rule(db, "csv_rule")
        log_e = _make_log(db, batch.id)
        _make_alert(db, rule, log_e, batch.id)
        db.commit()

        csv_str = export_alerts_csv(db, {})
        assert "Rule Name" in csv_str
        assert "Severity" in csv_str
        assert "Technique ID" in csv_str

    def test_csv_export_with_filter(self, db):
        batch = _make_batch(db, filename="csv_filter_test.json")
        rule = _make_rule(db, "filter_rule")
        log_e = _make_log(db, batch.id)
        _make_alert(db, rule, log_e, batch.id, hostname="FILTERED-HOST")
        db.commit()

        csv_str = export_alerts_csv(db, {"hostname": "FILTERED-HOST"})
        assert "FILTERED-HOST" in csv_str
