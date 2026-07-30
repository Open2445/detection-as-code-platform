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


class SigmaRuleUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    yaml_content: Optional[str] = None
    enabled: Optional[bool] = None


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
