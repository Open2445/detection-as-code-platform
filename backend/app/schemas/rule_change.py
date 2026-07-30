"""Pydantic schemas for Rule Changes."""
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, field_validator, field_serializer


class RuleChangeCreate(BaseModel):
    rule_format: str
    new_content: str
    change_reason: str
    expected_outcome: Optional[str] = None

    @field_validator("rule_format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = {"yaml", "json"}
        if v.lower() not in allowed:
            raise ValueError(f"rule_format must be one of {allowed}")
        return v.lower()


class RuleChangeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int
    rule_format: str
    previous_content: Optional[str] = None
    new_content: str
    change_reason: str
    expected_outcome: Optional[str] = None
    changed_by: str
    changed_at: datetime
    change_type: str
    parent_change_id: Optional[int] = None

    @field_serializer("changed_at")
    def serialize_changed_at(self, dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


class RuleValidateRequest(BaseModel):
    rule_format: str
    content: str


class RuleValidateResponse(BaseModel):
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    parsed_format: str


class RuleApplyRequest(BaseModel):
    pass


class RuleRevertRequest(BaseModel):
    pass
