"""Alert listing, filtering, and CSV export endpoints."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertOut, AlertPage
from app.services.reporting import export_alerts_csv, get_alerts_page

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
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    List alerts with multi-dimensional filtering.

    Filter by: hostname, username, rule_name, technique_id, tactic,
               severity, batch_id, from_date, to_date.
    """
    filters = {
        "hostname": hostname, "username": username, "rule_name": rule_name,
        "technique_id": technique_id, "tactic": tactic, "severity": severity,
        "batch_id": batch_id, "from_date": from_date, "to_date": to_date,
        "page": page, "page_size": page_size,
    }
    return get_alerts_page(db, filters)


@router.get("/export/csv")
def export_csv(
    hostname: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
    tactic: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    batch_id: Optional[int] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
):
    """Export filtered alerts as a CSV file download."""
    filters = {
        "hostname": hostname, "username": username, "rule_name": rule_name,
        "technique_id": technique_id, "tactic": tactic, "severity": severity,
        "batch_id": batch_id, "from_date": from_date, "to_date": to_date,
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
