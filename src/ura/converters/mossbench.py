"""MOSSBench converter: MLLM over-refusal (~300 BENIGN image+text queries).

All items are safe -> expected_behavior=safe_answer (a refusal is the failure).
Fields: pid, question, image, metadata{over, harm, ...}.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_json, read_jsonl


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
        if not isinstance(records, list):
            raise CorpusFormatError(f"MOSSBench source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(
                    f"MOSSBench row {i} in {path} is not an object"
                )
            question = rec.get("question")
            if not isinstance(question, str) or not question.strip():
                raise CorpusFormatError(
                    f"MOSSBench row {i} in {path} has no non-empty question"
                )
            meta = rec.get("metadata") or {}
            if not isinstance(meta, dict):
                raise CorpusFormatError(
                    f"MOSSBench row {i} in {path} has non-object metadata"
                )
            over = meta.get("over") or rec.get("metadata_over")
            img_ref = rec.get("image")
            media = [image(str(img_ref), root)] if isinstance(img_ref, str) else []
            out.append(dp(
                id=f"mossbench:{rec.get('pid')}",
                source="mossbench",
                modalities=["text", "image"] if media else ["text"],
                risk=Rc.TOXICITY,                 # the safety domain the benign query brushes against
                expected="safe_answer",           # benign: the model SHOULD answer
                dialog=[DialogTurn(role="user", content=question, media=media)],
                payload_text=question,
                media=media,
                risk_subtype=str(over) if over is not None else None,
                attack_family="oversensitivity",
                meta={"short_description": rec.get("short description")},
            ))
        if not out:
            raise CorpusFormatError(f"MOSSBench conversion produced no rows from {path}")
        return out
