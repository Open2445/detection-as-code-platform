"""Unit tests for the PySigmaEvaluator detection engine."""
import pytest
from app.services.detection.pysigma_evaluator import PySigmaEvaluator, _flatten_dict

evaluator = PySigmaEvaluator()


# ── Helper ────────────────────────────────────────────────────────────────────
def make_rule(detection: str) -> str:
    return f"""
title: Test Rule
name: test_rule
detection:
{detection}
"""


# ── Flatten dict tests ────────────────────────────────────────────────────────
class TestFlattenDict:
    def test_simple_dict(self):
        result = _flatten_dict({"a": 1, "b": 2})
        assert result["a"] == 1
        assert result["b"] == 2

    def test_nested_dict(self):
        result = _flatten_dict({"EventData": {"CommandLine": "cmd.exe"}})
        assert result["CommandLine"] == "cmd.exe"
        assert result["EventData.CommandLine"] == "cmd.exe"

    def test_deep_nesting(self):
        result = _flatten_dict({"A": {"B": {"C": "value"}}})
        assert result["C"] == "value"


# ── Selection matching ────────────────────────────────────────────────────────
class TestSelectionMatching:
    def test_exact_match(self):
        rule = make_rule("""
  selection:
    EventID: 4688
  condition: selection""")
        assert evaluator.evaluate(rule, {"EventID": 4688}) is True
        assert evaluator.evaluate(rule, {"EventID": 1}) is False

    def test_contains_modifier(self):
        rule = make_rule("""
  selection:
    CommandLine|contains: 'powershell'
  condition: selection""")
        assert evaluator.evaluate(rule, {"CommandLine": "C:\\powershell.exe -ep bypass"}) is True
        assert evaluator.evaluate(rule, {"CommandLine": "cmd.exe /c whoami"}) is False

    def test_startswith_modifier(self):
        rule = make_rule("""
  selection:
    Image|startswith: 'C:\\Windows'
  condition: selection""")
        assert evaluator.evaluate(rule, {"Image": "C:\\Windows\\System32\\cmd.exe"}) is True
        assert evaluator.evaluate(rule, {"Image": "C:\\Users\\admin\\tool.exe"}) is False

    def test_endswith_modifier(self):
        rule = make_rule("""
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection""")
        assert evaluator.evaluate(rule, {"Image": "C:\\Windows\\System32\\powershell.exe"}) is True
        assert evaluator.evaluate(rule, {"Image": "C:\\Windows\\cmd.exe"}) is False

    def test_list_values_or_logic(self):
        rule = make_rule("""
  selection:
    CommandLine|contains:
      - 'mimikatz'
      - 'sekurlsa'
  condition: selection""")
        assert evaluator.evaluate(rule, {"CommandLine": "mimikatz.exe"}) is True
        assert evaluator.evaluate(rule, {"CommandLine": "sekurlsa::logonpasswords"}) is True
        assert evaluator.evaluate(rule, {"CommandLine": "whoami"}) is False

    def test_multi_field_and_logic(self):
        rule = make_rule("""
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection""")
        assert evaluator.evaluate(rule, {
            "Image": "C:\\powershell.exe", "CommandLine": "powershell -enc abc123"
        }) is True
        assert evaluator.evaluate(rule, {
            "Image": "C:\\powershell.exe", "CommandLine": "powershell whoami"
        }) is False

    def test_nested_field_access(self):
        rule = make_rule("""
  selection:
    CommandLine|contains: 'malware'
  condition: selection""")
        log = {"EventData": {"CommandLine": "run malware.exe"}}
        assert evaluator.evaluate(rule, log) is True

    def test_wildcard_exact(self):
        rule = make_rule("""
  selection:
    Image: '*\\mimikatz*'
  condition: selection""")
        assert evaluator.evaluate(rule, {"Image": "C:\\tools\\mimikatz64.exe"}) is True
        assert evaluator.evaluate(rule, {"Image": "C:\\tools\\whoami.exe"}) is False


# ── Keywords ──────────────────────────────────────────────────────────────────
class TestKeywords:
    def test_keyword_match(self):
        rule = make_rule("""
  keywords:
    - 'sekurlsa::logonpasswords'
    - 'lsadump::sam'
  condition: keywords""")
        log = {"CommandLine": "mimikatz sekurlsa::logonpasswords"}
        assert evaluator.evaluate(rule, log) is True

    def test_keyword_no_match(self):
        rule = make_rule("""
  keywords:
    - 'mimikatz'
  condition: keywords""")
        assert evaluator.evaluate(rule, {"CommandLine": "whoami"}) is False


# ── Quantifiers ───────────────────────────────────────────────────────────────
class TestQuantifiers:
    def test_1_of_selection_star(self):
        rule = make_rule("""
  selection_a:
    Image|contains: 'mimikatz'
  selection_b:
    CommandLine|contains: 'sekurlsa'
  condition: 1 of selection*""")
        assert evaluator.evaluate(rule, {"Image": "mimikatz.exe"}) is True
        assert evaluator.evaluate(rule, {"CommandLine": "sekurlsa::logonpasswords"}) is True
        assert evaluator.evaluate(rule, {"Image": "cmd.exe"}) is False

    def test_all_of_selection_star(self):
        rule = make_rule("""
  selection_a:
    Image|endswith: '\\powershell.exe'
  selection_b:
    CommandLine|contains: '-enc'
  condition: all of selection*""")
        assert evaluator.evaluate(rule, {
            "Image": "C:\\powershell.exe", "CommandLine": "ps -enc abc"
        }) is True
        assert evaluator.evaluate(rule, {
            "Image": "C:\\powershell.exe", "CommandLine": "whoami"
        }) is False

    def test_1_of_them(self):
        rule = make_rule("""
  selection_a:
    EventID: 1102
  selection_b:
    EventID: 104
  condition: 1 of them""")
        assert evaluator.evaluate(rule, {"EventID": 1102}) is True
        assert evaluator.evaluate(rule, {"EventID": 104}) is True
        assert evaluator.evaluate(rule, {"EventID": 4688}) is False


# ── Logical operators ─────────────────────────────────────────────────────────
class TestLogicalOperators:
    def test_and_condition(self):
        rule = make_rule("""
  sel_a:
    Image|endswith: '\\cmd.exe'
  sel_b:
    CommandLine|contains: 'whoami'
  condition: sel_a and sel_b""")
        assert evaluator.evaluate(rule, {
            "Image": "C:\\cmd.exe", "CommandLine": "cmd whoami"
        }) is True
        assert evaluator.evaluate(rule, {
            "Image": "C:\\cmd.exe", "CommandLine": "ipconfig"
        }) is False

    def test_or_condition(self):
        rule = make_rule("""
  sel_a:
    Image|endswith: '\\cmd.exe'
  sel_b:
    Image|endswith: '\\powershell.exe'
  condition: sel_a or sel_b""")
        assert evaluator.evaluate(rule, {"Image": "C:\\cmd.exe"}) is True
        assert evaluator.evaluate(rule, {"Image": "C:\\powershell.exe"}) is True
        assert evaluator.evaluate(rule, {"Image": "C:\\notepad.exe"}) is False

    def test_not_condition(self):
        rule = make_rule("""
  sel_main:
    Image|endswith: '\\powershell.exe'
  sel_filter:
    CommandLine|contains: 'legit'
  condition: sel_main and not sel_filter""")
        assert evaluator.evaluate(rule, {
            "Image": "C:\\powershell.exe", "CommandLine": "ps -enc evil"
        }) is True
        assert evaluator.evaluate(rule, {
            "Image": "C:\\powershell.exe", "CommandLine": "legit script"
        }) is False

    def test_invalid_yaml_returns_false(self):
        bad_rule = "not: valid: yaml: :::"
        assert evaluator.evaluate(bad_rule, {"EventID": 1}) is False

    def test_missing_detection_returns_false(self):
        rule = "title: Test\nname: test\n"
        assert evaluator.evaluate(rule, {"EventID": 1}) is False
