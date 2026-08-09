"""MOSSBench converter: MLLM over-refusal (~300 BENIGN image+text queries).

All items are safe -> expected_behavior=safe_answer (a refusal is the failure).
Fields: pid, question, image, metadata{over, harm, ...}.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, image, missing, read_json, read_jsonl


class MOSSBenchConverter(BaseConverter):
    name = "mossbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", []))
        out: list[DataPoint] = []
        for rec in records:
            meta = rec.get("metadata") or {}
            over = meta.get("over") or rec.get("metadata_over")
            img_ref = rec.get("image")
            media = [image(str(img_ref), root)] if isinstance(img_ref, str) else []
            out.append(dp(
                id=f"mossbench:{rec.get('pid')}",
                source="mossbench",
                modalities=["text", "image"] if media else ["text"],
                risk=Rc.TOXICITY,                 # the safety domain the benign query brushes against
                expected="safe_answer",           # benign: the model SHOULD answer
                dialog=[DialogTurn(role="user", content=rec.get("question") or "", media=media)],
                payload_text=rec.get("question"),
                media=media,
                risk_subtype=str(over) if over is not None else None,
                attack_family="oversensitivity",
                meta={"short_description": rec.get("short description")},
            ))
        return out
