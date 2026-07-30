"""Unit tests for raw Sigma rule creation (YAML and JSON formats)."""
import pytest
from app.models.rule import SigmaRule


YAML_SAMPLE = """title: Suspicious WMI Process Execution
name: suspicious_wmi_exec
description: Detects execution of WMI process creation commands
level: high
tags:
  - attack.execution
  - attack.t1047
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\\wmic.exe'
  condition: selection
"""

JSON_SAMPLE = """{
  "title": "Suspicious PowerShell Encoded Command",
  "name": "suspicious_ps_encoded",
  "description": "Detects encoded PowerShell execution commands",
  "level": "critical",
  "tags": [
    "attack.execution",
    "attack.t1059.001"
  ],
  "logsource": {
    "category": "process_creation",
    "product": "windows"
  },
  "detection": {
    "selection": {
      "EventID": 1,
      "CommandLine|contains": "-Enc"
    },
    "condition": "selection"
  }
}"""


def test_create_raw_rule_yaml(client, db):
    """Test importing a Sigma rule via raw YAML."""
    response = client.post(
        "/api/rules/raw",
        json={"rule_text": YAML_SAMPLE, "format": "yaml"},
    )
    assert response.status_code == 201
    data = response.json()

    assert data["name"] == "suspicious_wmi_exec"
    assert data["title"] == "Suspicious WMI Process Execution"
    assert data["severity"] == "high"
    assert "T1047" in data["mitre_techniques"]
    assert "execution" in data["mitre_tactics"]

    # Verify DB entry
    db_rule = db.query(SigmaRule).filter(SigmaRule.name == "suspicious_wmi_exec").first()
    assert db_rule is not None
    assert "wmic.exe" in db_rule.yaml_content


def test_create_raw_rule_json(client, db):
    """Test importing a Sigma rule via raw JSON."""
    response = client.post(
        "/api/rules/raw",
        json={"rule_text": JSON_SAMPLE, "format": "json"},
    )
    assert response.status_code == 201
    data = response.json()

    assert data["name"] == "suspicious_ps_encoded"
    assert data["title"] == "Suspicious PowerShell Encoded Command"
    assert data["severity"] == "critical"
    assert "T1059.001" in data["mitre_techniques"]
    assert "execution" in data["mitre_tactics"]

    # Verify DB entry
    db_rule = db.query(SigmaRule).filter(SigmaRule.name == "suspicious_ps_encoded").first()
    assert db_rule is not None
    assert "-Enc" in db_rule.yaml_content


JSON_SAMPLE_AUTO = """{
  "title": "Suspicious PowerShell DownloadString",
  "name": "suspicious_ps_dl_auto",
  "description": "Detects DownloadString execution",
  "level": "high",
  "tags": ["attack.execution"],
  "detection": {
    "selection": { "EventID": 1, "CommandLine|contains": "DownloadString" },
    "condition": "selection"
  }
}"""


def test_create_raw_rule_auto_format(client):
    """Test format auto-detection."""
    response = client.post(
        "/api/rules/raw",
        json={"rule_text": JSON_SAMPLE_AUTO, "format": "auto"},
    )
    assert response.status_code == 201
    assert response.json()["name"] == "suspicious_ps_dl_auto"


def test_create_raw_rule_duplicate(client):
    """Test error handling for duplicate rule name."""
    client.post("/api/rules/raw", json={"rule_text": YAML_SAMPLE, "format": "yaml"})
    response = client.post("/api/rules/raw", json={"rule_text": YAML_SAMPLE, "format": "yaml"})

    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_create_raw_rule_invalid_syntax(client):
    """Test error handling for invalid YAML/JSON."""
    response = client.post(
        "/api/rules/raw",
        json={"rule_text": "{invalid json syntax: ...", "format": "json"},
    )
    assert response.status_code == 422
    assert "Invalid JSON" in response.json()["detail"]
