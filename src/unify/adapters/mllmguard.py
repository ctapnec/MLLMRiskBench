from ..data_models import DataPoint, EvalResult
from .base import BaseAdapter

class MLLMGuardAdapter(BaseAdapter):
    """Maps GuardRank outputs to unified risk_score metric."""

    def run(self, sample: DataPoint) -> EvalResult:
        # TODO: call GuardRank; placeholder constant
        guardrank = 0.42
        return EvalResult(id=sample.id, metric="risk_score", value=guardrank, raw={})