"""Detection engine abstraction layer."""
from app.services.detection.base import DetectionEngine
from app.services.detection.pysigma_evaluator import PySigmaEvaluator
from app.services.detection.sigma_cli_runner import SigmaCLIRunner

__all__ = ["DetectionEngine", "PySigmaEvaluator", "SigmaCLIRunner"]
