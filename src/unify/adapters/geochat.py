from ..data_models import DataPoint, EvalResult
from .base import BaseAdapter

class GeoChatAdapter(BaseAdapter):
    """Calculates haversine distance error for GPTGeoChat samples."""

    def run(self, sample: DataPoint) -> EvalResult:
        # TODO: compute distance vs ground‑truth coordinates
        error_km = 999.9
        return EvalResult(id=sample.id, metric="geo_error_km", value=error_km, raw={})