"""Server-side rule validation service."""
import json
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parsed_format: str = ""


class RuleValidator:
    @staticmethod
    def validate(content: str, format_type: str, active_rule_name: str = None) -> ValidationResult:
        result = ValidationResult(valid=True, parsed_format=format_type)

        if not content.strip():
            result.valid = False
            result.errors.append("Rule content cannot be empty.")
            return result

        parsed_dict: Dict[str, Any] = {}

        if format_type == "json":
            from app.schemas.rule import SigmaRuleJSONSchema
            try:
                parsed_dict = json.loads(content)
                SigmaRuleJSONSchema.model_validate(parsed_dict)
            except Exception as exc:
                result.valid = False
                result.errors.append(f"Invalid JSON Rule: {exc}")
                return result
        elif format_type == "yaml":
            try:
                parsed_dict = yaml.safe_load(content)
                if not isinstance(parsed_dict, dict):
                    raise ValueError("YAML must map to a dictionary.")
            except Exception as exc:
                result.valid = False
                result.errors.append(f"Invalid YAML: {exc}")
                return result
        else:
            result.valid = False
            result.errors.append(f"Unsupported format: {format_type}")
            return result

        # Required Sigma fields
        required_fields = ["title", "logsource", "detection", "level"]
        for req in required_fields:
            if req not in parsed_dict:
                result.valid = False
                result.errors.append(f"Missing required field: '{req}'")

        if "detection" in parsed_dict and isinstance(parsed_dict["detection"], dict):
            if "condition" not in parsed_dict["detection"]:
                result.valid = False
                result.errors.append("Missing 'condition' within 'detection' block.")
            
            # Check for unsupported modifiers
            for key, val in parsed_dict["detection"].items():
                if key == "condition":
                    continue
                if isinstance(val, dict):
                    for sel_key in val.keys():
                        if "|re" in sel_key:
                            result.warnings.append(f"Regular expression modifier '|re' is not fully supported in this engine: {sel_key}")

        # Check name immutability if active_rule_name is provided
        if active_rule_name:
            proposed_name = parsed_dict.get("name") or parsed_dict.get("id")
            if proposed_name and str(proposed_name) != str(active_rule_name):
                result.valid = False
                result.errors.append(f"Rule name/ID is immutable. Cannot change '{active_rule_name}' to '{proposed_name}'.")

        return result
