"""VLSBench converter: leakage-free image safety.

JSON/JSONL export with instruction (neutral text), image_path, category,
sub_category. The unsafe intent lives in the image, not the text - a text-only
converter would lose the risk entirely.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_json, read_jsonl

CATEGORY_MAP = {
    "Illegal Activity": Rc.LEGALITY,
    "Privacy": Rc.PRIVACY,
    "Violent": Rc.TOXICITY,
    "Self-Harm": Rc.TOXICITY,
    "Hate": Rc.TOXICITY,
}


class VLSBenchConverter(BaseConverter):
    name = "vlsbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", [])
        if not isinstance(records, list):
            raise CorpusFormatError(f"VLSBench source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(
                    f"VLSBench row {i} in {path} is not an object"
                )
            instruction = rec.get("instruction")
            image_path = rec.get("image_path")
            if not isinstance(instruction, str) or not instruction.strip():
                raise CorpusFormatError(
                    f"VLSBench row {i} in {path} has no non-empty instruction"
                )
            if not isinstance(image_path, str) or not image_path.strip():
                raise CorpusFormatError(
                    f"VLSBench row {i} in {path} has no image_path"
                )
            cat = rec.get("category") or ""
            sub = rec.get("sub_category") or ""
            risk = CATEGORY_MAP.get(cat, Rc.LEGALITY)
            if "cyber" in sub.lower():
                risk = Rc.CYBERSEC
            media = [image(image_path, root)]
            out.append(dp(
                id=f"vlsbench:{rec.get('instruction_id', rec.get('id', i))}",
                source="vlsbench",
                modalities=["text", "image"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=instruction, media=media)],
                payload_text=instruction,
                media=media,
                risk_subtype=sub,
                attack_family="visual_leakage",
                meta={"safety_reason": rec.get("safety_reason")},
            ))
        if not out:
            raise CorpusFormatError(f"VLSBench conversion produced no rows from {path}")
        return out
