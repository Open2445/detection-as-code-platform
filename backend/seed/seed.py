"""
Database seeder — loads 20 Sigma rules from YAML files into the database.
Skips rules that already exist (idempotent).
"""
import logging
import os
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.rule import SigmaRule
from app.services.mitre import parse_sigma_tags

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "sigma_rules"


def _load_rule_from_yaml(filepath: Path) -> dict | None:
    """Parse a Sigma YAML file and return a dict suitable for SigmaRule creation."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw_yaml = f.read()
        rule_dict = yaml.safe_load(raw_yaml)

        if not isinstance(rule_dict, dict):
            logger.warning("Skipping %s: not a valid YAML dict", filepath.name)
            return None

        name = rule_dict.get("name") or filepath.stem
        title = rule_dict.get("title", name)
        description = rule_dict.get("description", "")
        level = rule_dict.get("level", "medium").lower()

        # Map Sigma level → severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "informational",
        }
        severity = severity_map.get(level, "medium")

        tags = rule_dict.get("tags", []) or []
        mitre = parse_sigma_tags(tags)

        return {
            "name": name,
            "title": title,
            "description": description,
            "severity": severity,
            "yaml_content": raw_yaml,
            "tags": ", ".join(tags),
            "mitre_tactics": ", ".join(mitre["tactics"]),
            "mitre_techniques": ", ".join(mitre["techniques"]),
            "mitre_tactic_ids": ", ".join(mitre["tactic_ids"]),
            "enabled": True,
        }
    except Exception as exc:
        logger.error("Failed to load rule from %s: %s", filepath.name, exc)
        return None


def run_seed(db: Session | None = None) -> int:
    """
    Seed the database with Sigma rules from the sigma_rules/ directory.
    Returns the number of rules newly inserted.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        if not RULES_DIR.exists():
            logger.warning("Sigma rules directory not found: %s", RULES_DIR)
            return 0

        yaml_files = sorted(RULES_DIR.glob("*.yml"))
        if not yaml_files:
            logger.warning("No .yml files found in %s", RULES_DIR)
            return 0

        inserted = 0
        for filepath in yaml_files:
            rule_data = _load_rule_from_yaml(filepath)
            if not rule_data:
                continue

            # Idempotent: skip if rule with same name exists
            existing = (
                db.query(SigmaRule)
                .filter(SigmaRule.name == rule_data["name"])
                .first()
            )
            if existing:
                logger.debug("Rule '%s' already exists, skipping", rule_data["name"])
                continue

            rule = SigmaRule(**rule_data)
            db.add(rule)
            inserted += 1
            logger.info("Seeded rule: %s (%s)", rule_data["name"], rule_data["severity"])

        db.commit()
        logger.info("Seeding complete: %d rules inserted", inserted)
        return inserted

    finally:
        if close_db:
            db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    count = run_seed()
    print(f"Seeded {count} rules")
