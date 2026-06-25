"""Pydantic schemas for alerts."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int
    log_entry_id: int
    batch_id: int
    severity: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    rule_name: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    event_id: Optional[int] = None
    triggered_at: datetime
    details_json: Optional[str] = None


class AlertFilter(BaseModel):
    hostname: Optional[str] = None
    username: Optional[str] = None
    rule_name: Optional[str] = None
    technique_id: Optional[str] = None
    tactic: Optional[str] = None
    severity: Optional[str] = None
    batch_id: Optional[int] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    page: int = 1
    page_size: int = 50


class AlertPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AlertOut]


class DetectionRunRequest(BaseModel):
    batch_id: int


class DetectionRunResult(BaseModel):
    batch_id: int
    logs_scanned: int
    rules_evaluated: int
    alerts_generated: int
    duration_seconds: float
