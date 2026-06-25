"""Reporting service — aggregated stats for dashboard and alert listing."""
import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import func, distinct
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.rule import SigmaRule
from app.models.log import UploadBatch, LogEntry
from app.services.mitre import TECHNIQUE_MAP, TACTIC_NAME_TO_ID


def get_dashboard_stats(db: Session) -> dict:
    """Return aggregated stats for the main dashboard."""
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_logs = db.query(func.count(LogEntry.id)).scalar() or 0
    total_rules = db.query(func.count(SigmaRule.id)).scalar() or 0
    total_batches = db.query(func.count(UploadBatch.id)).scalar() or 0

    # Severity distribution
    sev_rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    severity_distribution = [
        {"severity": row[0], "count": row[1]} for row in sev_rows
    ]

    # Top triggered rules (top 10)
    top_rule_rows = (
        db.query(
            Alert.rule_id,
            Alert.rule_name,
            Alert.severity,
            func.count(Alert.id).label("count"),
        )
        .group_by(Alert.rule_id, Alert.rule_name, Alert.severity)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
        .all()
    )
    top_rules = [
        {
            "rule_id": row.rule_id,
            "rule_name": row.rule_name,
            "severity": row.severity,
            "count": row.count,
        }
        for row in top_rule_rows
    ]

    # Unique hosts affected
    unique_hosts = (
        db.query(func.count(distinct(Alert.hostname)))
        .filter(Alert.hostname.isnot(None))
        .scalar() or 0
    )

    # Unique techniques triggered
    triggered_techniques = (
        db.query(distinct(Alert.technique_id))
        .filter(Alert.technique_id.isnot(None))
        .all()
    )
    triggered_set = {row[0] for row in triggered_techniques if row[0]}
    unique_techniques_triggered = len(triggered_set)

    # ATT&CK coverage %: (triggered techniques / total unique techniques in rules)
    all_rule_techniques = (
        db.query(SigmaRule.mitre_techniques)
        .filter(SigmaRule.mitre_techniques.isnot(None))
        .all()
    )
    rule_tech_set = set()
    for (techs_csv,) in all_rule_techniques:
        if techs_csv:
            for t in techs_csv.split(","):
                t = t.strip()
                if t:
                    rule_tech_set.add(t)

    coverage_pct = (
        round(len(triggered_set) / len(rule_tech_set) * 100, 1)
        if rule_tech_set else 0.0
    )

    return {
        "total_alerts": total_alerts,
        "total_logs": total_logs,
        "total_rules": total_rules,
        "total_batches": total_batches,
        "severity_distribution": severity_distribution,
        "top_rules": top_rules,
        "attack_coverage_pct": coverage_pct,
        "unique_hosts_affected": unique_hosts,
        "unique_techniques_triggered": unique_techniques_triggered,
    }


def get_alert_timeline(db: Session, days: int = 30) -> dict:
    """Return daily alert counts for the last `days` days."""
    since = datetime.utcnow() - timedelta(days=days)

    rows = (
        db.query(
            func.date(Alert.triggered_at).label("day"),
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.triggered_at >= since)
        .group_by(func.date(Alert.triggered_at))
        .order_by(func.date(Alert.triggered_at))
        .all()
    )

    points = [{"date": str(row.day), "count": row.count} for row in rows]
    return {"points": points, "granularity": "day"}


def get_mitre_coverage(db: Session) -> dict:
    """Return per-technique alert counts for the MITRE heatmap."""
    rows = (
        db.query(
            Alert.technique_id,
            Alert.technique_name,
            Alert.tactic,
            Alert.tactic_id,
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.technique_id.isnot(None))
        .group_by(Alert.technique_id, Alert.technique_name, Alert.tactic, Alert.tactic_id)
        .order_by(func.count(Alert.id).desc())
        .all()
    )

    techniques = [
        {
            "technique_id": row.technique_id or "",
            "technique_name": row.technique_name or "",
            "tactic": row.tactic or "",
            "tactic_id": row.tactic_id or "",
            "count": row.count,
        }
        for row in rows
    ]

    # Summary
    all_rule_techniques = (
        db.query(SigmaRule.mitre_techniques)
        .filter(SigmaRule.mitre_techniques.isnot(None))
        .all()
    )
    rule_tech_set = set()
    for (techs_csv,) in all_rule_techniques:
        if techs_csv:
            for t in techs_csv.split(","):
                t = t.strip()
                if t:
                    rule_tech_set.add(t)

    triggered_set = {t["technique_id"] for t in techniques}
    total = len(rule_tech_set)
    triggered = len(triggered_set)
    coverage_pct = round(triggered / total * 100, 1) if total else 0.0

    return {
        "total_techniques_in_rules": total,
        "techniques_triggered": triggered,
        "coverage_pct": coverage_pct,
        "techniques": techniques,
    }


def export_alerts_csv(db: Session, filters: dict) -> str:
    """Export filtered alerts as a CSV string."""
    query = _build_alert_query(db, filters)
    alerts = query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Rule Name", "Severity", "Hostname", "Username",
        "Technique ID", "Technique Name", "Tactic", "Event ID",
        "Triggered At", "Details",
    ])
    for alert in alerts:
        writer.writerow([
            alert.id, alert.rule_name, alert.severity,
            alert.hostname or "", alert.username or "",
            alert.technique_id or "", alert.technique_name or "",
            alert.tactic or "", alert.event_id or "",
            alert.triggered_at.isoformat() if alert.triggered_at else "",
            alert.details_json or "",
        ])
    return output.getvalue()


def get_alerts_page(db: Session, filters: dict) -> dict:
    """Return a paginated list of filtered alerts."""
    page = filters.get("page", 1)
    page_size = filters.get("page_size", 50)

    query = _build_alert_query(db, filters)
    total = query.count()
    items = (
        query.order_by(Alert.triggered_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {"total": total, "page": page, "page_size": page_size, "items": items}


def _build_alert_query(db: Session, filters: dict):
    """Build a filtered SQLAlchemy query for alerts."""
    q = db.query(Alert)

    if hostname := filters.get("hostname"):
        q = q.filter(Alert.hostname.ilike(f"%{hostname}%"))
    if username := filters.get("username"):
        q = q.filter(Alert.username.ilike(f"%{username}%"))
    if rule_name := filters.get("rule_name"):
        q = q.filter(Alert.rule_name.ilike(f"%{rule_name}%"))
    if technique_id := filters.get("technique_id"):
        q = q.filter(Alert.technique_id.ilike(f"%{technique_id}%"))
    if tactic := filters.get("tactic"):
        q = q.filter(Alert.tactic.ilike(f"%{tactic}%"))
    if severity := filters.get("severity"):
        q = q.filter(Alert.severity == severity.lower())
    if batch_id := filters.get("batch_id"):
        q = q.filter(Alert.batch_id == batch_id)
    if from_date := filters.get("from_date"):
        q = q.filter(Alert.triggered_at >= from_date)
    if to_date := filters.get("to_date"):
        q = q.filter(Alert.triggered_at <= to_date)

    return q
