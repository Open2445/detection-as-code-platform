"""
SigmaCLIRunner — placeholder for future sigma-cli subprocess backend.

This implementation raises NotImplementedError and serves as a documented
extension point. To activate, install sigma-cli and implement the methods below.

Installation (future):
    pip install sigma-cli
    sigma plugin install splunk  # or any other backend
"""
import logging
from typing import Any, Dict, List

from app.services.detection.base import DetectionEngine

logger = logging.getLogger(__name__)


class SigmaCLIRunner(DetectionEngine):
    """
    Future detection engine backend that shells out to sigma-cli.

    Planned workflow:
      1. Write rule YAML to a temp file.
      2. Write log entries to a temp JSON file.
      3. Run: sigma convert -t <backend> -p <pipeline> <rule.yml>
      4. Execute the generated query against the log file.
      5. Parse output and return match results.
    """

    def __init__(self, backend: str = "elasticsearch", pipeline: str = "ecs_windows") -> None:
        self.backend = backend
        self.pipeline = pipeline
        logger.warning(
            "SigmaCLIRunner is a placeholder. "
            "Use PySigmaEvaluator for v1 detections."
        )

    def evaluate(self, rule_yaml: str, log_dict: Dict[str, Any]) -> bool:
        raise NotImplementedError(
            "SigmaCLIRunner is not implemented in v1. "
            "Use PySigmaEvaluator instead."
        )

    def batch_evaluate(
        self, rule_yaml: str, log_entries: List[Dict[str, Any]]
    ) -> List[bool]:
        raise NotImplementedError(
            "SigmaCLIRunner is not implemented in v1. "
            "Use PySigmaEvaluator instead."
        )
