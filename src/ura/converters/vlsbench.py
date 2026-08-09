"""VLSBench converter: leakage-free image safety.

JSON/JSONL export with instruction (neutral text), image_path, category,
sub_category. The unsafe intent lives in the image, not the text - a text-only
converter would lose the risk entirely.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, image, missing, read_json, read_jsonl

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
        out: list[DataPoint] = []
        for rec in records:
            cat = rec.get("category") or ""
            sub = rec.get("sub_category") or ""
            risk = CATEGORY_MAP.get(cat, Rc.LEGALITY)
            if "cyber" in sub.lower():
                risk = Rc.CYBERSEC
            media = [image(rec.get("image_path") or "", root)] if rec.get("image_path") else []
            out.append(dp(
                id=f"vlsbench:{rec.get('instruction_id')}",
                source="vlsbench",
                modalities=["text", "image"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=rec.get("instruction") or "", media=media)],
                payload_text=rec.get("instruction"),
                media=media,
                risk_subtype=sub,
                attack_family="visual_leakage",
                meta={"safety_reason": rec.get("safety_reason")},
            ))
        return out
