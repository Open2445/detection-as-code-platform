"""MITRE ATT&CK mapping service — parses Sigma rule tags into ATT&CK metadata."""
import re
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Tactic name → ID mapping (MITRE Enterprise ATT&CK v14)
# ─────────────────────────────────────────────────────────────────────────────
TACTIC_NAME_TO_ID: Dict[str, str] = {
    "reconnaissance":      "TA0043",
    "resource-development": "TA0042",
    "initial-access":      "TA0001",
    "execution":           "TA0002",
    "persistence":         "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion":     "TA0005",
    "credential-access":   "TA0006",
    "discovery":           "TA0007",
    "lateral-movement":    "TA0008",
    "collection":          "TA0009",
    "command-and-control": "TA0011",
    "exfiltration":        "TA0010",
    "impact":              "TA0040",
}

# ─────────────────────────────────────────────────────────────────────────────
# Technique ID → (name, primary tactic name) — expanded subset
# ─────────────────────────────────────────────────────────────────────────────
TECHNIQUE_MAP: Dict[str, Tuple[str, str]] = {
    # Execution
    "T1059":      ("Command and Scripting Interpreter", "execution"),
    "T1059.001":  ("PowerShell", "execution"),
    "T1059.003":  ("Windows Command Shell", "execution"),
    "T1059.005":  ("Visual Basic", "execution"),
    "T1059.007":  ("JavaScript", "execution"),
    "T1204":      ("User Execution", "execution"),
    "T1204.001":  ("Malicious Link", "execution"),
    "T1204.002":  ("Malicious File", "execution"),
    "T1053":      ("Scheduled Task/Job", "execution"),
    "T1053.005":  ("Scheduled Task", "execution"),
    "T1047":      ("Windows Management Instrumentation", "execution"),
    "T1569":      ("System Services", "execution"),
    "T1569.002":  ("Service Execution", "execution"),

    # Persistence
    "T1136":      ("Create Account", "persistence"),
    "T1136.001":  ("Local Account", "persistence"),
    "T1546":      ("Event Triggered Execution", "persistence"),
    "T1546.003":  ("Windows Management Instrumentation Event Subscription", "persistence"),
    "T1547":      ("Boot or Logon Autostart Execution", "persistence"),
    "T1547.001":  ("Registry Run Keys / Startup Folder", "persistence"),

    # Privilege Escalation
    "T1134":      ("Access Token Manipulation", "privilege-escalation"),
    "T1134.001":  ("Token Impersonation/Theft", "privilege-escalation"),

    # Defense Evasion
    "T1218":      ("System Binary Proxy Execution", "defense-evasion"),
    "T1218.005":  ("Mshta", "defense-evasion"),
    "T1218.010":  ("Regsvr32", "defense-evasion"),
    "T1218.011":  ("Rundll32", "defense-evasion"),
    "T1197":      ("BITS Jobs", "defense-evasion"),
    "T1070":      ("Indicator Removal", "defense-evasion"),
    "T1070.001":  ("Clear Windows Event Logs", "defense-evasion"),
    "T1550":      ("Use Alternate Authentication Material", "defense-evasion"),
    "T1550.002":  ("Pass the Hash", "defense-evasion"),

    # Credential Access
    "T1003":      ("OS Credential Dumping", "credential-access"),
    "T1003.001":  ("LSASS Memory", "credential-access"),
    "T1110":      ("Brute Force", "credential-access"),

    # Discovery
    "T1012":      ("Query Registry", "discovery"),
    "T1057":      ("Process Discovery", "discovery"),
    "T1082":      ("System Information Discovery", "discovery"),
    "T1049":      ("System Network Connections Discovery", "discovery"),

    # Lateral Movement
    "T1021":      ("Remote Services", "lateral-movement"),
    "T1021.002":  ("SMB/Windows Admin Shares", "lateral-movement"),
    "T1563":      ("Remote Service Session Hijacking", "lateral-movement"),
    "T1563.002":  ("RDP Hijacking", "lateral-movement"),
    "T1570":      ("Lateral Tool Transfer", "lateral-movement"),

    # Command and Control
    "T1105":      ("Ingress Tool Transfer", "command-and-control"),
    "T1090":      ("Proxy", "command-and-control"),
    "T1071":      ("Application Layer Protocol", "command-and-control"),

    # Exfiltration
    "T1041":      ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048":      ("Exfiltration Over Alternative Protocol", "exfiltration"),
}


def parse_sigma_tags(tags: List[str]) -> Dict[str, List[str]]:
    """
    Parse Sigma rule tags into tactic and technique lists.

    Sigma uses tags like:
      attack.execution
      attack.t1059.001
      attack.persistence

    Returns dict with keys: tactics, techniques, tactic_ids
    """
    tactics: List[str] = []
    techniques: List[str] = []
    tactic_ids: List[str] = []

    for tag in tags:
        tag = tag.strip().lower()
        if not tag.startswith("attack."):
            continue
        value = tag[7:]  # strip "attack."

        # Technique ID: starts with "t" followed by digits
        if re.match(r"^t\d{4}(\.\d{3})?$", value):
            tech_id = value.upper()
            techniques.append(tech_id)
            # Derive tactic from technique map
            if tech_id in TECHNIQUE_MAP:
                _, tactic_name = TECHNIQUE_MAP[tech_id]
                if tactic_name not in tactics:
                    tactics.append(tactic_name)
                tid = TACTIC_NAME_TO_ID.get(tactic_name, "")
                if tid and tid not in tactic_ids:
                    tactic_ids.append(tid)
        else:
            # Tactic name
            tactic_name = value.replace("_", "-")
            if tactic_name in TACTIC_NAME_TO_ID and tactic_name not in tactics:
                tactics.append(tactic_name)
                tid = TACTIC_NAME_TO_ID[tactic_name]
                if tid not in tactic_ids:
                    tactic_ids.append(tid)

    return {
        "tactics": tactics,
        "techniques": techniques,
        "tactic_ids": tactic_ids,
    }


def get_technique_info(technique_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Return (technique_name, tactic_name, tactic_id) for a technique ID.
    Returns (None, None, None) if not found.
    """
    info = TECHNIQUE_MAP.get(technique_id)
    if not info:
        # Try parent technique
        parent_id = technique_id.split(".")[0] if "." in technique_id else technique_id
        info = TECHNIQUE_MAP.get(parent_id)

    if not info:
        return None, None, None

    tech_name, tactic_name = info
    tactic_id = TACTIC_NAME_TO_ID.get(tactic_name)
    return tech_name, tactic_name, tactic_id
