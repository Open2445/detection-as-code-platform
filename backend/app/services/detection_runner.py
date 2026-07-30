"""
Detection runner service — orchestrates Sigma rule evaluation against log batches.
"""
import json
import logging
import time
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.log import UploadBatch, LogEntry
from app.models.rule import SigmaRule
from app.models.alert import Alert
from app.services.detection.pysigma_evaluator import PySigmaEvaluator
from app.services.mitre import get_technique_info, parse_sigma_tags

logger = logging.getLogger(__name__)

# Use the PySigmaEvaluator as the active v1 engine
_ENGINE = PySigmaEvaluator()


def run_detections(db: Session, batch_id: int) -> dict:
    """
    Run all enabled Sigma rules against every log entry in the specified batch.

    Returns a summary dict with keys:
      batch_id, logs_scanned, rules_evaluated, alerts_generated, duration_seconds
    """
    t_start = time.perf_counter()

    # Load batch
    batch: Optional[UploadBatch] = db.get(UploadBatch, batch_id)
    if not batch:
        raise ValueError(f"Batch {batch_id} not found")

    # Load all log entries
    log_entries: List[LogEntry] = (
        db.query(LogEntry).filter(LogEntry.batch_id == batch_id).all()
    )

    # Load all enabled rules
    rules: List[SigmaRule] = (
        db.query(SigmaRule).filter(SigmaRule.enabled.is_(True)).all()
    )

    logs_scanned = len(log_entries)
    rules_evaluated = len(rules)
    alerts_generated = 0

    # Delete old alerts for this batch before re-running
    db.query(Alert).filter(Alert.batch_id == batch_id).delete(synchronize_session=False)

    new_alerts: List[Alert] = []

    for rule in rules:
        # Parse MITRE context from rule (primary technique & tactic)
        first_technique = _first_technique(rule.mitre_techniques)
        tech_name, tactic_name, tactic_id = get_technique_info(first_technique or "")

        # Deserialise log JSON once per rule iteration
        log_dicts = []
        for entry in log_entries:
            try:
                log_dicts.append((entry, json.loads(entry.raw_json)))
            except json.JSONDecodeError:
                log_dicts.append((entry, {}))

        # Batch evaluate all log entries against this rule
        log_data_only = [d for _, d in log_dicts]
        rule_format = getattr(rule, "rule_format", "yaml")
        rule_content = rule.json_content if rule_format == "json" else rule.yaml_content
        results = _ENGINE.batch_evaluate(rule_content, log_data_only, rule_format=rule_format)

        for (entry, log_dict), matched in zip(log_dicts, results):
            if matched:
                alert = Alert(
                    rule_id=rule.id,
                    log_entry_id=entry.id,
                    batch_id=batch_id,
                    severity=rule.severity,
                    hostname=entry.hostname,
                    username=entry.username,
                    rule_name=rule.name,
                    technique_id=first_technique,
                    technique_name=tech_name,
                    tactic=tactic_name,
                    tactic_id=tactic_id,
                    event_id=entry.event_id,
                    triggered_at=entry.timestamp or datetime.utcnow(),
                    details_json=_build_details_snippet(log_dict),
                )
                new_alerts.append(alert)
                alerts_generated += 1

    # Bulk insert alerts
    db.bulk_save_objects(new_alerts)

    # Update batch status
    batch.detections_run = True
    batch.detections_run_at = datetime.utcnow()
    db.commit()

    duration = time.perf_counter() - t_start
    logger.info(
        "Detections complete: batch=%d logs=%d rules=%d alerts=%d duration=%.2fs",
        batch_id, logs_scanned, rules_evaluated, alerts_generated, duration,
    )

    return {
        "batch_id": batch_id,
        "logs_scanned": logs_scanned,
        "rules_evaluated": rules_evaluated,
        "alerts_generated": alerts_generated,
        "duration_seconds": round(duration, 3),
    }


def _first_technique(techniques_csv: Optional[str]) -> Optional[str]:
    """Extract the first technique from a comma-separated list."""
    if not techniques_csv:
        return None
    parts = [t.strip() for t in techniques_csv.split(",") if t.strip()]
    return parts[0] if parts else None


def _build_details_snippet(log_dict: dict) -> str:
    """Build a compact JSON snippet of key fields for the alert detail view."""
    keys_of_interest = [
        "CommandLine", "Image", "ParentImage", "User", "Computer",
        "EventID", "SubjectUserName", "TargetUserName", "IpAddress",
        "DestinationIp", "DestinationPort",
    ]
    snippet = {}
    for key in keys_of_interest:
        val = log_dict.get(key) or _nested_get(log_dict, key)
        if val is not None:
            snippet[key] = val
    if not snippet:
        # Fallback: include first 5 keys
        snippet = dict(list(log_dict.items())[:5])
    return json.dumps(snippet)


def _nested_get(d: dict, key: str):
    """Search nested dicts (one level deep) for a key."""
    for v in d.values():
        if isinstance(v, dict) and key in v:
            return v[key]
    return None
