"""
PySigmaEvaluator — in-memory Sigma rule evaluator.

Supported Sigma syntax subset (v1):
  ─ Selections:   field:value, field|contains, field|startswith, field|endswith
  ─ Keywords:     plain keyword search across all field values
  ─ List values:  OR logic within a field
  ─ Multi-field:  AND logic across fields in a selection
  ─ Quantifiers:  1 of <name>*, all of <name>*, 1 of them, all of them
  ─ Operators:    and, or, not
  ─ Grouping:     parentheses
  ─ Wildcards:    * and ? in exact-match values
"""
import re
import fnmatch
import logging
import yaml
from typing import Any, Dict, List, Optional

from app.services.detection.base import DetectionEngine

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Condition Tokenizer + Parser
# ─────────────────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r"(?:1|all)\s+of\s+(?:\w+\*?|them)"   # quantifiers FIRST (greedy)
    r"|\(|\)"                              # parentheses
    r"|\bnot\b"                            # logical NOT
    r"|\band\b"                            # logical AND
    r"|\bor\b"                             # logical OR
    r"|\w+",                               # identifiers / group names
    re.IGNORECASE,
)


class ConditionParser:
    """Recursive-descent parser for Sigma condition expressions."""

    def __init__(self, condition: str, groups: Dict[str, bool]) -> None:
        self.tokens: List[str] = _TOKEN_RE.findall(condition)
        self.pos: int = 0
        self.groups = groups

    def parse(self) -> bool:
        if not self.tokens:
            return False
        result = self._or_expr()
        return result

    # ── Grammar ──────────────────────────────────────────────────────────────
    # expr     = or_expr
    # or_expr  = and_expr  ('or'  and_expr)*
    # and_expr = not_expr  ('and' not_expr)*
    # not_expr = 'not' primary | primary
    # primary  = '(' or_expr ')' | quantifier | identifier
    # ─────────────────────────────────────────────────────────────────────────

    def _or_expr(self) -> bool:
        left = self._and_expr()
        while self._peek_lower() == "or":
            self._consume()
            left = left or self._and_expr()
        return left

    def _and_expr(self) -> bool:
        left = self._not_expr()
        while self._peek_lower() == "and":
            self._consume()
            left = left and self._not_expr()
        return left

    def _not_expr(self) -> bool:
        if self._peek_lower() == "not":
            self._consume()
            return not self._primary()
        return self._primary()

    def _primary(self) -> bool:
        token = self._consume()
        if token is None:
            return False

        if token == "(":
            result = self._or_expr()
            if self._peek() == ")":
                self._consume()
            return result

        tl = token.lower()

        # Quantifiers: "1 of them", "all of them", "1 of sel*", "all of sel_*"
        if tl.startswith("1 of ") or tl.startswith("all of "):
            parts = re.split(r"\s+", tl, maxsplit=2)
            quantifier = parts[0]          # "1" or "all"
            scope = parts[2]               # "them" or pattern like "selection*"

            if scope == "them":
                targets = list(self.groups.keys())
            elif scope.endswith("*"):
                prefix = scope[:-1]
                targets = [k for k in self.groups if k.lower().startswith(prefix)]
            else:
                targets = [k for k in self.groups if k.lower() == scope]

            if quantifier == "1":
                return any(self.groups.get(t, False) for t in targets)
            else:  # "all"
                return all(self.groups.get(t, False) for t in targets) if targets else False

        # Plain identifier → group name
        return self.groups.get(token, False)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_lower(self) -> Optional[str]:
        t = self._peek()
        return t.lower() if t else None

    def _consume(self) -> Optional[str]:
        t = self._peek()
        if t is not None:
            self.pos += 1
        return t


# ─────────────────────────────────────────────────────────────────────────────
# PySigmaEvaluator
# ─────────────────────────────────────────────────────────────────────────────

class PySigmaEvaluator(DetectionEngine):
    """
    In-memory Sigma rule evaluator that supports the documented v1 syntax
    subset without requiring sigma-cli or any SIEM backend.
    """

    def evaluate(self, rule_yaml: str, log_dict: Dict[str, Any]) -> bool:
        """Return True if log_dict matches the Sigma rule."""
        try:
            rule = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as exc:
            logger.warning("Failed to parse Sigma rule YAML: %s", exc)
            return False

        detection = rule.get("detection", {})
        if not detection:
            return False

        condition_str = str(detection.get("condition", "")).strip()
        if not condition_str:
            return False

        # Flatten nested log dict for field lookups
        flat_log = _flatten_dict(log_dict)

        # Evaluate each named selection group
        groups: Dict[str, bool] = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if key == "keywords":
                groups["keywords"] = _match_keywords(value, flat_log)
            else:
                groups[key] = _match_selection(value, flat_log)

        # Evaluate the condition expression
        try:
            return ConditionParser(condition_str, groups).parse()
        except Exception as exc:
            logger.warning("Condition evaluation error for rule: %s", exc)
            return False

    def batch_evaluate(
        self, rule_yaml: str, log_entries: List[Dict[str, Any]]
    ) -> List[bool]:
        """Evaluate one rule against many log entries.

        Pre-parses YAML once for efficiency.
        """
        try:
            rule = yaml.safe_load(rule_yaml)
        except yaml.YAMLError:
            return [False] * len(log_entries)

        detection = rule.get("detection", {})
        if not detection:
            return [False] * len(log_entries)

        condition_str = str(detection.get("condition", "")).strip()
        if not condition_str:
            return [False] * len(log_entries)

        results = []
        for log_dict in log_entries:
            flat_log = _flatten_dict(log_dict)
            groups: Dict[str, bool] = {}
            for key, value in detection.items():
                if key == "condition":
                    continue
                if key == "keywords":
                    groups["keywords"] = _match_keywords(value, flat_log)
                else:
                    groups[key] = _match_selection(value, flat_log)
            try:
                result = ConditionParser(condition_str, groups).parse()
            except Exception:
                result = False
            results.append(result)
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Field-matching helpers
# ─────────────────────────────────────────────────────────────────────────────

def _flatten_dict(
    d: Any, prefix: str = "", sep: str = "."
) -> Dict[str, Any]:
    """
    Recursively flatten a nested dict.
    Both the full dotted key and the short leaf key are stored,
    so 'EventData.CommandLine' and 'CommandLine' both work.
    """
    result: Dict[str, Any] = {}
    if not isinstance(d, dict):
        return result
    for key, value in d.items():
        full_key = f"{prefix}{sep}{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_dict(value, full_key, sep))
            # Also expose short name at current level
            if key not in result:
                pass  # will be populated by recursive call
        else:
            result[full_key] = value
            # Short key (last segment) — don't overwrite longer path
            if key not in result:
                result[key] = value
    return result


def _match_keywords(keywords: Any, flat_log: Dict[str, Any]) -> bool:
    """
    Keywords: search every field value for any keyword (OR logic).
    Case-insensitive.
    """
    if isinstance(keywords, str):
        keywords = [keywords]
    elif not isinstance(keywords, list):
        return False

    all_text = " ".join(
        str(v) for v in flat_log.values() if v is not None
    ).lower()

    for kw in keywords:
        if str(kw).lower() in all_text:
            return True
    return False


def _match_selection(selection: Any, flat_log: Dict[str, Any]) -> bool:
    """
    Match a named selection against the log.
      - dict  → all field conditions must match (AND)
      - list  → any element must match (OR over dicts)
    """
    if isinstance(selection, list):
        return any(
            _match_selection_dict(item, flat_log)
            for item in selection
            if isinstance(item, dict)
        )
    elif isinstance(selection, dict):
        return _match_selection_dict(selection, flat_log)
    return False


def _match_selection_dict(sel_dict: Dict[str, Any], flat_log: Dict[str, Any]) -> bool:
    """All field specs in sel_dict must match (AND logic)."""
    for field_spec, expected in sel_dict.items():
        if not _match_field(field_spec, expected, flat_log):
            return False
    return True


def _match_field(
    field_spec: str, expected: Any, flat_log: Dict[str, Any]
) -> bool:
    """
    Match field_spec (possibly with | modifiers) against the log entry.
    field_spec examples: 'CommandLine', 'CommandLine|contains',
                         'Image|endswith', 'EventID'
    """
    parts = field_spec.split("|")
    field = parts[0].strip()
    modifiers: List[str] = [m.lower().strip() for m in parts[1:]]

    # Resolve field value — try exact, then case-insensitive key
    actual = flat_log.get(field)
    if actual is None:
        field_lower = field.lower()
        for k, v in flat_log.items():
            if k.lower() == field_lower:
                actual = v
                break

    # Null check
    if expected is None:
        return actual is None

    # List of expected → OR logic
    if isinstance(expected, list):
        return any(_apply_modifiers(actual, str(e), modifiers) for e in expected)
    elif isinstance(expected, bool):
        # Boolean match
        return str(actual).lower() == str(expected).lower()
    else:
        return _apply_modifiers(actual, str(expected), modifiers)


def _apply_modifiers(actual: Any, expected_str: str, modifiers: List[str]) -> bool:
    """
    Apply Sigma field-match modifiers to compare actual vs expected.
    Supported: contains, startswith, endswith, (plain/wildcard exact).
    """
    if actual is None:
        return False

    actual_str = str(actual).lower()
    expected_lower = expected_str.lower()

    if "contains" in modifiers:
        return expected_lower in actual_str
    elif "startswith" in modifiers:
        return actual_str.startswith(expected_lower)
    elif "endswith" in modifiers:
        return actual_str.endswith(expected_lower)
    else:
        # Exact match; support * and ? wildcards
        if "*" in expected_lower or "?" in expected_lower:
            return fnmatch.fnmatch(actual_str, expected_lower)
        return actual_str == expected_lower
