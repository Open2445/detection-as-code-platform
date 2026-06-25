"""Pydantic schemas for log upload and retrieval."""
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, ConfigDict


class UploadBatchBase(BaseModel):
    filename: str


class UploadBatchCreate(UploadBatchBase):
    pass


class UploadBatchOut(UploadBatchBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    upload_time: datetime
    log_count: int
    status: str
    detections_run: bool
    detections_run_at: Optional[datetime] = None


class LogEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_id: int
    event_id: Optional[int] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_json: str


class LogEntryPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[LogEntryOut]


class UploadResponse(BaseModel):
    batch: UploadBatchOut
    message: str
