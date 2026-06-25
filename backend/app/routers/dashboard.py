"""Dashboard statistics endpoints."""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.dashboard import DashboardStats, MitreCoverage, TimelineResponse
from app.services.reporting import get_dashboard_stats, get_alert_timeline, get_mitre_coverage

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db)):
    """
    Return aggregated dashboard statistics:
    - Total alerts, logs, rules, batches
    - Severity distribution
    - Top triggered rules
    - ATT&CK coverage percentage
    - Unique hosts & techniques
    """
    return get_dashboard_stats(db)


@router.get("/timeline", response_model=TimelineResponse)
def alert_timeline(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
):
    """Return daily alert counts for the last N days."""
    return get_alert_timeline(db, days=days)


@router.get("/mitre-coverage", response_model=MitreCoverage)
def mitre_coverage(db: Session = Depends(get_db)):
    """
    Return per-technique alert counts for the MITRE ATT&CK heatmap,
    plus overall coverage percentage.
    """
    return get_mitre_coverage(db)
