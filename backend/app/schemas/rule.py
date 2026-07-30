"""Pydantic schemas for Sigma rules."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, field_validator


class SigmaRuleCreate(BaseModel):
    name: str
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    yaml_content: str
    enabled: bool = True

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "informational"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()


class SigmaRuleRawCreate(BaseModel):
    rule_text: str
    format: str = "auto"  # "yaml", "json", "auto"


ALLOWED_VALIDATION_STATUSES = {"unvalidated", "validated_in_lab", "needs_tuning"}


class SigmaRuleUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    yaml_content: Optional[str] = None
    enabled: Optional[bool] = None
    validation_status: Optional[str] = None
    validation_notes: Optional[str] = None
    validation_evidence_batch_id: Optional[int] = None
    validation_evidence_filename: Optional[str] = None
    primary_validated_rule: Optional[bool] = None

    @field_validator("validation_status")
    @classmethod
    def validate_validation_status(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ALLOWED_VALIDATION_STATUSES:
            raise ValueError(f"validation_status must be one of {ALLOWED_VALIDATION_STATUSES}")
        return v.lower() if v is not None else v


class SigmaRuleValidationUpdate(BaseModel):
    validation_status: str
    validation_notes: Optional[str] = None
    validation_evidence_batch_id: Optional[int] = None
    validation_evidence_filename: Optional[str] = None
    primary_validated_rule: bool = False

    @field_validator("validation_status")
    @classmethod
    def validate_validation_status(cls, v: str) -> str:
        if v.lower() not in ALLOWED_VALIDATION_STATUSES:
            raise ValueError(f"validation_status must be one of {ALLOWED_VALIDATION_STATUSES}")
        return v.lower()


class SigmaRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    title: str
    description: Optional[str] = None
    severity: str
    yaml_content: str
    mitre_tactics: Optional[str] = None
    mitre_techniques: Optional[str] = None
    mitre_tactic_ids: Optional[str] = None
    tags: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    enabled: bool

    # Validation Metadata
    validation_status: str = "unvalidated"
    validated_at: Optional[datetime] = None
    validation_notes: Optional[str] = None
    validation_evidence_batch_id: Optional[int] = None
    validation_evidence_filename: Optional[str] = None
    primary_validated_rule: bool = False

    @property
    def mitre_techniques_list(self) -> List[str]:
        if not self.mitre_techniques:
            return []
        return [t.strip() for t in self.mitre_techniques.split(",") if t.strip()]

    @property
    def mitre_tactics_list(self) -> List[str]:
        if not self.mitre_tactics:
            return []
        return [t.strip() for t in self.mitre_tactics.split(",") if t.strip()]


class SigmaRuleListOut(BaseModel):
    total: int
    items: List[SigmaRuleOut]

