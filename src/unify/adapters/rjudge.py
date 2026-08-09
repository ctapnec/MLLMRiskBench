import json
from pathlib import Path
from ..data_models import DataPoint, EvalResult
from .base import BaseAdapter

class RJudgeAdapter(BaseAdapter):
    """Parses the original R‑Judge JSONL and emits unified EvalResult.

    The original file has keys: id, dialog, risk_type, is_safe (bool).
    """

    def __init__(self):
        pass

    def run(self, sample: DataPoint) -> EvalResult:
        # For now, delegate to stored ground‑truth – no model inference yet.
        success = sample.expected_behavior == "safe-answer" and sample.attack_tag != "cybersec"
        return EvalResult(
            id=sample.id,
            metric="ground_truth",
            value=success,
            raw={"debug": "placeholder"},
        )

    @staticmethod
    def parse_original(path: Path) -> list[DataPoint]:
        datapoints: list[DataPoint] = []
        with path.open() as fp:
            for line in fp:
                row = json.loads(line)
                datapoints.append(
                    DataPoint(
                        id=row["id"],
                        modalities=["text"],
                        dialog_history=[
                            # convert turns to DialogTurn objects
                        ],
                        attack_tag="cybersec" if row["risk_type"].startswith("code") else "legality",
                        risk_type=row["risk_type"],
                        expected_behavior="safe-answer" if row["is_safe"] else "refuse",
                        meta_source="R-Judge",
                    )
                )
        return datapoints