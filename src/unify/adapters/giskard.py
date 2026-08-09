from ..data_models import DataPoint, EvalResult
from .base import BaseAdapter

class GiskardAdapter(BaseAdapter):
    """Runs Giskard bias & security scans; returns risk score ∈ [0,1]."""

    def run(self, sample: DataPoint) -> EvalResult:
        # TODO: integrate giskard scanner
        risk_score = 0.25  # dummy
        return EvalResult(id=sample.id, metric="risk_score", value=risk_score, raw={})