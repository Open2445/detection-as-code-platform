from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert, AlertTriageHistory
from app.schemas.alert import AlertOut, AlertPage, AlertCounters, AlertTriageUpdate, AlertTriageHistoryOut
from app.services.reporting import export_alerts_csv, get_alerts_page, get_alert_counters

router = APIRouter()


@router.get("", response_model=AlertPage)
def list_alerts(
    hostname: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
    tactic: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    batch_id: Optional[int] = Query(None),
    classification: Optional[str] = Query(None),
    triage_status: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    List alerts with multi-dimensional filtering.

    Filter by: hostname, username, rule_name, technique_id, tactic,
               severity, batch_id, classification, triage_status, from_date, to_date.
    """
    filters = {
        "hostname": hostname, "username": username, "rule_name": rule_name,
        "technique_id": technique_id, "tactic": tactic, "severity": severity,
        "batch_id": batch_id, "classification": classification, "triage_status": triage_status,
        "from_date": from_date, "to_date": to_date,
        "page": page, "page_size": page_size,
    }
    return get_alerts_page(db, filters)


@router.get("/counters", response_model=AlertCounters)
def get_counters(db: Session = Depends(get_db)):
    """Return summary metric counters for alerts."""
    return get_alert_counters(db)


@router.get("/export/csv")
def export_csv(
    hostname: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
    tactic: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    batch_id: Optional[int] = Query(None),
    classification: Optional[str] = Query(None),
    triage_status: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    """Export filtered alerts as a CSV file download."""
    filters = {
        "hostname": hostname, "username": username, "rule_name": rule_name,
        "technique_id": technique_id, "tactic": tactic, "severity": severity,
        "batch_id": batch_id, "classification": classification, "triage_status": triage_status,
        "from_date": from_date, "to_date": to_date,
    }
    csv_content = export_alerts_csv(db, filters)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get a single alert by ID with full details."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}/history", response_model=List[AlertTriageHistoryOut])
def get_alert_history(alert_id: int, db: Session = Depends(get_db)):
    """Get immutable triage history entries for an alert."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    history = (
        db.query(AlertTriageHistory)
        .filter(AlertTriageHistory.alert_id == alert_id)
        .order_by(AlertTriageHistory.created_at.desc())
        .all()
    )
    return history


@router.put("/{alert_id}/triage", response_model=AlertOut)
def update_alert_triage(
    alert_id: int,
    payload: AlertTriageUpdate,
    db: Session = Depends(get_db),
):
    """Update triage classification, status, notes, and duplicate reference for an alert."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    prev_class = alert.classification
    prev_status = alert.triage_status

    # Set new classification / status if provided
    new_classification = payload.classification if payload.classification is not None else alert.classification
    new_triage_status = payload.triage_status if payload.triage_status is not None else alert.triage_status

    # Duplicate reference validation
    primary_alert_id = payload.primary_alert_id
    if new_classification != "duplicate":
        # Clear primary_alert_id if classification is not duplicate
        primary_alert_id = None
    elif primary_alert_id is not None:
        if primary_alert_id == alert_id:
            raise HTTPException(status_code=400, detail="An alert cannot reference itself as primary_alert_id")

        target_alert = db.get(Alert, primary_alert_id)
        if not target_alert:
            raise HTTPException(status_code=404, detail=f"Referenced primary alert #{primary_alert_id} does not exist")

        # Check circular duplicate chains
        curr_id = primary_alert_id
        visited = {alert_id}
        while curr_id is not None:
            if curr_id in visited:
                raise HTTPException(status_code=400, detail="Circular duplicate reference chain detected")
            visited.add(curr_id)
            curr = db.get(Alert, curr_id)
            if not curr:
                break
            curr_id = curr.primary_alert_id

    # Update alert fields
    alert.classification = new_classification
    alert.triage_status = new_triage_status
    if payload.analyst_notes is not None:
        alert.analyst_notes = payload.analyst_notes
    alert.primary_alert_id = primary_alert_id
    alert.reviewed_at = datetime.now(timezone.utc)
    if payload.reviewed_by:
        alert.reviewed_by = payload.reviewed_by.strip() or "local analyst"

    # Append immutable history entry
    history_entry = AlertTriageHistory(
        alert_id=alert.id,
        previous_classification=prev_class,
        new_classification=alert.classification,
        previous_triage_status=prev_status,
        new_triage_status=alert.triage_status,
        analyst_notes=alert.analyst_notes,
        primary_alert_id=alert.primary_alert_id,
        reviewed_by=alert.reviewed_by or "local analyst",
        created_at=datetime.now(timezone.utc),
    )
    db.add(history_entry)
    db.commit()
    db.refresh(alert)
    return alert

