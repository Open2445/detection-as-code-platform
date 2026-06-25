"""Sigma rules CRUD endpoints."""
import yaml
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.rule import SigmaRule
from app.schemas.rule import SigmaRuleCreate, SigmaRuleListOut, SigmaRuleOut, SigmaRuleUpdate
from app.services.mitre import parse_sigma_tags

router = APIRouter()


def _extract_mitre_from_yaml(yaml_content: str) -> dict:
    """Parse tags from YAML and return MITRE metadata."""
    try:
        rule_dict = yaml.safe_load(yaml_content)
        tags = rule_dict.get("tags", []) or []
        mitre = parse_sigma_tags(tags)
        return {
            "tags": ", ".join(tags),
            "mitre_tactics": ", ".join(mitre["tactics"]),
            "mitre_techniques": ", ".join(mitre["techniques"]),
            "mitre_tactic_ids": ", ".join(mitre["tactic_ids"]),
        }
    except Exception:
        return {}


@router.get("", response_model=SigmaRuleListOut)
def list_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    enabled: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List all Sigma rules with optional filtering."""
    q = db.query(SigmaRule)
    if enabled is not None:
        q = q.filter(SigmaRule.enabled == enabled)
    if severity:
        q = q.filter(SigmaRule.severity == severity.lower())
    total = q.count()
    items = q.order_by(SigmaRule.created_at.desc()).offset(skip).limit(limit).all()
    return SigmaRuleListOut(total=total, items=items)


@router.get("/{rule_id}", response_model=SigmaRuleOut)
def get_rule(rule_id: int, db: Session = Depends(get_db)):
    """Get a single Sigma rule by ID."""
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("", response_model=SigmaRuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(payload: SigmaRuleCreate, db: Session = Depends(get_db)):
    """Create a new Sigma rule. YAML is validated and MITRE tags extracted."""
    # Check unique name
    existing = db.query(SigmaRule).filter(SigmaRule.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Rule '{payload.name}' already exists")

    # Validate YAML
    try:
        yaml.safe_load(payload.yaml_content)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {exc}")

    mitre = _extract_mitre_from_yaml(payload.yaml_content)

    rule = SigmaRule(
        name=payload.name,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        yaml_content=payload.yaml_content,
        enabled=payload.enabled,
        **mitre,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/{rule_id}", response_model=SigmaRuleOut)
def update_rule(rule_id: int, payload: SigmaRuleUpdate, db: Session = Depends(get_db)):
    """Update fields of an existing Sigma rule."""
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_data = payload.model_dump(exclude_unset=True)

    if "yaml_content" in update_data:
        try:
            yaml.safe_load(update_data["yaml_content"])
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid YAML: {exc}")
        mitre = _extract_mitre_from_yaml(update_data["yaml_content"])
        update_data.update(mitre)

    for field, value in update_data.items():
        setattr(rule, field, value)

    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """Delete a Sigma rule."""
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
