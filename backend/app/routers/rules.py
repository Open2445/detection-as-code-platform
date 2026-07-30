import json
import re
import yaml
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.rule import SigmaRule
from app.schemas.rule import (
    SigmaRuleCreate,
    SigmaRuleListOut,
    SigmaRuleOut,
    SigmaRuleRawCreate,
    SigmaRuleUpdate,
)
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


@router.post("/raw", response_model=SigmaRuleOut, status_code=status.HTTP_201_CREATED)
def create_raw_rule(payload: SigmaRuleRawCreate, db: Session = Depends(get_db)):
    """Create a new Sigma rule from raw YAML or JSON input."""
    raw_text = payload.rule_text.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Rule content cannot be empty")

    fmt = payload.format.lower()
    is_json = False

    if fmt == "json" or (fmt == "auto" and raw_text.startswith("{")):
        is_json = True

    parsed_dict = None
    yaml_str = ""

    if is_json:
        try:
            parsed_dict = json.loads(raw_text)
            if not isinstance(parsed_dict, dict):
                raise ValueError("JSON rule must be a JSON object")
            yaml_str = yaml.dump(parsed_dict, sort_keys=False)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid JSON rule format: {exc}")
    else:
        try:
            parsed_dict = yaml.safe_load(raw_text)
            if not isinstance(parsed_dict, dict):
                raise ValueError("YAML rule must be a valid mapping")
            yaml_str = raw_text
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid YAML rule format: {exc}")

    # Extract metadata fields
    title = parsed_dict.get("title") or "Untitled Sigma Rule"
    rule_name = parsed_dict.get("name") or parsed_dict.get("id")
    if not rule_name:
        rule_name = re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_")
    rule_name = str(rule_name)

    description = parsed_dict.get("description")
    raw_level = (parsed_dict.get("level") or parsed_dict.get("severity") or "medium").lower()

    allowed_severities = {"critical", "high", "medium", "low", "informational"}
    severity = raw_level if raw_level in allowed_severities else "medium"

    # Check for duplicate rule name
    existing = db.query(SigmaRule).filter(SigmaRule.name == rule_name).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Rule with name/identifier '{rule_name}' already exists"
        )

    mitre = _extract_mitre_from_yaml(yaml_str)

    rule = SigmaRule(
        name=rule_name,
        title=title,
        description=description,
        severity=severity,
        yaml_content=yaml_str,
        enabled=True,
        **mitre,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


from datetime import datetime, timezone

from app.models.log import UploadBatch
from app.schemas.rule import (
    SigmaRuleCreate,
    SigmaRuleListOut,
    SigmaRuleOut,
    SigmaRuleRawCreate,
    SigmaRuleUpdate,
    SigmaRuleValidationUpdate,
)


@router.put("/{rule_id}/validation", response_model=SigmaRuleOut)
def update_rule_validation(
    rule_id: int,
    payload: SigmaRuleValidationUpdate,
    db: Session = Depends(get_db),
):
    """Update rule validation status, notes, evidence batch/filename, and primary status."""
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    batch_id = payload.validation_evidence_batch_id
    filename = payload.validation_evidence_filename

    if batch_id is not None:
        batch = db.get(UploadBatch, batch_id)
        if not batch:
            raise HTTPException(status_code=404, detail=f"Upload batch #{batch_id} not found")
        if not filename:
            filename = batch.filename

    rule.validation_status = payload.validation_status
    rule.validation_notes = payload.validation_notes
    rule.validation_evidence_batch_id = batch_id
    rule.validation_evidence_filename = filename
    rule.primary_validated_rule = payload.primary_validated_rule
    rule.validated_at = datetime.now(timezone.utc)

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

