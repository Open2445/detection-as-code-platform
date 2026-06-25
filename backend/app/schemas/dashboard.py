"""Pydantic schemas for dashboard stats and MITRE coverage."""
from typing import List, Dict, Optional
from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopRule(BaseModel):
    rule_name: str
    rule_id: int
    count: int
    severity: str


class TimelinePoint(BaseModel):
    date: str       # ISO date string "YYYY-MM-DD"
    count: int


class DashboardStats(BaseModel):
    total_alerts: int
    total_logs: int
    total_rules: int
    total_batches: int
    severity_distribution: List[SeverityCount]
    top_rules: List[TopRule]
    attack_coverage_pct: float   # % of seeded-rule techniques that fired
    unique_hosts_affected: int
    unique_techniques_triggered: int


class MitreTechniqueCount(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    count: int


class MitreCoverage(BaseModel):
    total_techniques_in_rules: int
    techniques_triggered: int
    coverage_pct: float
    techniques: List[MitreTechniqueCount]


class TimelineResponse(BaseModel):
    points: List[TimelinePoint]
    granularity: str    # "hour" | "day"
