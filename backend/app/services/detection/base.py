"""Abstract base class for Sigma detection engines."""
from abc import ABC, abstractmethod
from typing import Dict, Any


class DetectionEngine(ABC):
    """
    Abstract interface for Sigma detection engines.

    v1 Implementation: PySigmaEvaluator (in-memory custom evaluator)
    Future:            SigmaCLIRunner   (subprocess sigma-cli)
    """

    @abstractmethod
    def evaluate(self, rule_yaml: str, log_dict: Dict[str, Any]) -> bool:
        """
        Evaluate whether a log entry matches a Sigma rule.

        Args:
            rule_yaml: Raw YAML string of the Sigma rule.
            log_dict:  The log event as a Python dictionary.

        Returns:
            True if the rule fires against the log entry, False otherwise.
        """

    def batch_evaluate(
        self, rule_yaml: str, log_entries: list[Dict[str, Any]]
    ) -> list[bool]:
        """
        Evaluate a rule against a list of log entries.
        Default: calls evaluate() per entry. Override for batch optimisation.
        """
        return [self.evaluate(rule_yaml, entry) for entry in log_entries]
