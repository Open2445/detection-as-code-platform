"""Log upload and retrieval endpoints."""
import json
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.log import LogEntry, UploadBatch
from app.schemas.log import LogEntryPage, UploadBatchOut, UploadResponse
from app.services.ingestion import ingest_logs

router = APIRouter()


@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Upload a log file (JSON array, NDJSON, or native Windows .evtx).

    Accepts:
    - EVTX: binary Windows Event log file (.evtx)
    - JSON array: `[{...}, {...}]`
    - NDJSON: one JSON object per line
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = file.filename.lower()
    if not (ext.endswith(".json") or ext.endswith(".evtx")):
        raise HTTPException(
            status_code=400,
            detail="Only .json and .evtx files are supported.",
        )


    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        batch = ingest_logs(db, content, file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return UploadResponse(
        batch=UploadBatchOut.model_validate(batch),
        message=f"Successfully ingested {batch.log_count} log entries",
    )


@router.get("", response_model=list[UploadBatchOut])
def list_batches(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List all uploaded log batches."""
    return db.query(UploadBatch).order_by(UploadBatch.upload_time.desc()).offset(skip).limit(limit).all()


@router.get("/{batch_id}", response_model=UploadBatchOut)
def get_batch(batch_id: int, db: Session = Depends(get_db)):
    """Get a single upload batch by ID."""
    batch = db.get(UploadBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return batch


@router.get("/{batch_id}/entries", response_model=LogEntryPage)
def get_batch_entries(
    batch_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Get paginated log entries for a specific batch."""
    batch = db.get(UploadBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    q = db.query(LogEntry).filter(LogEntry.batch_id == batch_id)
    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()

    return LogEntryPage(total=total, page=page, page_size=page_size, items=items)


@router.delete("/{batch_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_batch(batch_id: int, db: Session = Depends(get_db)):
    """Delete a log batch and all its entries/alerts (cascade)."""
    batch = db.get(UploadBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    db.delete(batch)
    db.commit()
