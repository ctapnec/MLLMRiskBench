from abc import ABC, abstractmethod
from pathlib import Path
from ..data_models import DataPoint, EvalResult

class BaseAdapter(ABC):
    """Abstract interface every framework adapter must implement."""

    @abstractmethod
    def run(self, sample: DataPoint) -> EvalResult:  # pragma: no cover
        ...

    @classmethod
    def batch(cls, samples: list[DataPoint]) -> list[EvalResult]:
        self = cls()
        return [self.run(s) for s in samples]