"""Pydantic schemas for alerts."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


from pydantic import field_validator

ALLOWED_CLASSIFICATIONS = {"unclassified", "true_positive", "false_positive", "duplicate", "needs_investigation"}
ALLOWED_TRIAGE_STATUSES = {"open", "in_progress", "closed"}


class AlertTriageHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    previous_classification: Optional[str] = None
    new_classification: str
    previous_triage_status: Optional[str] = None
    new_triage_status: str
    analyst_notes: Optional[str] = None
    primary_alert_id: Optional[int] = None
    reviewed_by: str
    created_at: datetime


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

    # Triage metadata
    classification: str = "unclassified"
    triage_status: str = "open"
    analyst_notes: Optional[str] = None
    primary_alert_id: Optional[int] = None
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = "local analyst"


class AlertTriageUpdate(BaseModel):
    classification: Optional[str] = None
    triage_status: Optional[str] = None
    analyst_notes: Optional[str] = None
    primary_alert_id: Optional[int] = None
    reviewed_by: Optional[str] = "local analyst"

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ALLOWED_CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {ALLOWED_CLASSIFICATIONS}")
        return v.lower() if v is not None else v

    @field_validator("triage_status")
    @classmethod
    def validate_triage_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ALLOWED_TRIAGE_STATUSES:
            raise ValueError(f"triage_status must be one of {ALLOWED_TRIAGE_STATUSES}")
        return v.lower() if v is not None else v


class AlertFilter(BaseModel):
    hostname: Optional[str] = None
    username: Optional[str] = None
    rule_name: Optional[str] = None
    technique_id: Optional[str] = None
    tactic: Optional[str] = None
    severity: Optional[str] = None
    batch_id: Optional[int] = None
    classification: Optional[str] = None
    triage_status: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    page: int = 1
    page_size: int = 50


class AlertCounters(BaseModel):
    open_alerts: int
    true_positives: int
    false_positives: int
    duplicates: int
    needs_investigation: int


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

