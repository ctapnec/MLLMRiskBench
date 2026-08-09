from ..data_models import DataPoint, EvalResult
from .base import BaseAdapter

class MMSafetyAdapter(BaseAdapter):
    """Evaluates image‑induced attacks from MM‑SafetyBench (offline GT)."""

    def run(self, sample: DataPoint) -> EvalResult:
        # TODO: real evaluation; now echo expected_behavior
        safe = sample.expected_behavior == "safe-answer"
        return EvalResult(id=sample.id, metric="ASR", value=not safe, raw={})