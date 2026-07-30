"""API router for rule changes (draft, submit, apply, revert)."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database import get_db
from app.models.rule import SigmaRule
from app.models.rule_change import RuleChange
from app.schemas.rule_change import (
    RuleChangeCreate,
    RuleChangeOut,
    RuleValidateRequest,
    RuleValidateResponse,
    RuleApplyRequest,
    RuleRevertRequest,
)
from app.services.rule_validator import RuleValidator

router = APIRouter()


@router.post("/{rule_id}/changes/validate", response_model=RuleValidateResponse)
def validate_change(rule_id: int, payload: RuleValidateRequest, db: Session = Depends(get_db)):
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    res = RuleValidator.validate(payload.content, payload.rule_format, active_rule_name=rule.name)
    return RuleValidateResponse(
        valid=res.valid,
        errors=res.errors,
        warnings=res.warnings,
        parsed_format=res.parsed_format
    )


@router.get("/{rule_id}/changes", response_model=List[RuleChangeOut])
def list_changes(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    changes = db.query(RuleChange).filter(RuleChange.rule_id == rule_id).order_by(RuleChange.changed_at.desc()).all()
    return changes


@router.post("/{rule_id}/changes", response_model=RuleChangeOut, status_code=status.HTTP_201_CREATED)
def create_change(rule_id: int, payload: RuleChangeCreate, change_type: str = "draft", db: Session = Depends(get_db)):
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    if change_type not in ("draft", "submitted"):
        raise HTTPException(status_code=400, detail="Invalid change_type")
        
    # Validate before submit (drafts can technically be invalid, but we'll validate both)
    val_res = RuleValidator.validate(payload.new_content, payload.rule_format, active_rule_name=rule.name)
    if not val_res.valid:
        raise HTTPException(status_code=422, detail=f"Validation failed: {val_res.errors}")

    previous_content = rule.json_content if payload.rule_format == "json" else rule.yaml_content

    change = RuleChange(
        rule_id=rule_id,
        rule_format=payload.rule_format,
        previous_content=previous_content,
        new_content=payload.new_content,
        change_reason=payload.change_reason,
        expected_outcome=payload.expected_outcome,
        change_type=change_type
    )
    db.add(change)
    db.commit()
    db.refresh(change)
    return change


@router.post("/{rule_id}/changes/{change_id}/apply", response_model=RuleChangeOut)
def apply_change(rule_id: int, change_id: int, payload: RuleApplyRequest, db: Session = Depends(get_db)):
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    change = db.get(RuleChange, change_id)
    if not change or change.rule_id != rule_id:
        raise HTTPException(status_code=404, detail="Change not found")
        
    if change.change_type != "submitted":
        raise HTTPException(status_code=400, detail="Only 'submitted' changes can be applied")

    current_active = rule.json_content if change.rule_format == "json" else rule.yaml_content

    # Stale change detection
    # Treat None previous_content as "" to avoid false stale mismatch on newly seeded json fields
    prev = change.previous_content or ""
    curr = current_active or ""
    if prev.strip() != curr.strip():
        raise HTTPException(
            status_code=409, 
            detail="Stale change: The active rule has been modified since this change was proposed. Please rebase."
        )

    # Append-only: create new 'applied' record referencing the submitted change
    import json, yaml
    applied_record = RuleChange(
        rule_id=rule_id,
        rule_format=change.rule_format,
        previous_content=current_active,
        new_content=change.new_content,
        change_reason=change.change_reason,
        expected_outcome=change.expected_outcome,
        changed_by=change.changed_by,
        changed_at=datetime.now(timezone.utc),
        change_type="applied",
        parent_change_id=change.id,
    )
    db.add(applied_record)
    db.flush()

    # Update active rule after audit record creation
    if change.rule_format == "json":
        rule.json_content = change.new_content
        parsed = json.loads(change.new_content)
    else:
        rule.yaml_content = change.new_content
        parsed = yaml.safe_load(change.new_content)
        
    if "title" in parsed:
        rule.title = parsed["title"]
    
    db.commit()
    db.refresh(applied_record)
    return applied_record


@router.post("/{rule_id}/changes/{change_id}/revert", response_model=RuleChangeOut)
def revert_change(rule_id: int, change_id: int, payload: RuleRevertRequest, db: Session = Depends(get_db)):
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    change = db.get(RuleChange, change_id)
    if not change or change.rule_id != rule_id:
        raise HTTPException(status_code=404, detail="Change not found")
        
    if change.change_type != "applied":
        raise HTTPException(status_code=400, detail="Can only revert 'applied' changes")
        
    # Validation of the old content
    val_res = RuleValidator.validate(change.previous_content or "", change.rule_format, active_rule_name=rule.name)
    if not val_res.valid:
        raise HTTPException(status_code=422, detail=f"Cannot revert: previous content is invalid: {val_res.errors}")

    current_active = rule.json_content if change.rule_format == "json" else rule.yaml_content

    # Create new revert record
    revert_record = RuleChange(
        rule_id=rule_id,
        rule_format=change.rule_format,
        previous_content=current_active,
        new_content=change.previous_content or "",
        change_reason=f"Reverted change #{change.id}",
        changed_at=datetime.now(timezone.utc),
        change_type="reverted",
        parent_change_id=change.id,
    )
    db.add(revert_record)
    db.flush()
    
    # Restore content
    import json, yaml
    if change.rule_format == "json":
        rule.json_content = change.previous_content
        parsed = json.loads(change.previous_content) if change.previous_content else {}
    else:
        rule.yaml_content = change.previous_content
        parsed = yaml.safe_load(change.previous_content) if change.previous_content else {}
        
    if "title" in parsed:
        rule.title = parsed["title"]

    db.commit()
    db.refresh(revert_record)
    return revert_record
