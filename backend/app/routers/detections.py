"""Detection run endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.alert import DetectionRunRequest, DetectionRunResult
from app.services.detection_runner import run_detections

router = APIRouter()


@router.post("/run", response_model=DetectionRunResult)
def trigger_detection(
    payload: DetectionRunRequest,
    db: Session = Depends(get_db),
):
    """
    Run all enabled Sigma rules against the specified log batch.

    This is a synchronous operation — existing alerts for the batch
    are replaced on each run.
    """
    try:
        result = run_detections(db, payload.batch_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Detection failed: {exc}")

    return DetectionRunResult(**result)
