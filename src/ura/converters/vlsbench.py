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
    "Erotic": Rc.TOXICITY,
    "Illegal Activity": Rc.LEGALITY,
    "Privacy": Rc.PRIVACY,
    "Violent": Rc.TOXICITY,
    "Self-Harm": Rc.CATASTROPHIC,
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
            cat = str(rec.get("category") or "").strip()
            sub = str(rec.get("sub_category") or "").strip()
            safety_reason = rec.get("safety_reason")
            if not isinstance(safety_reason, str) or not safety_reason.strip():
                raise CorpusFormatError(
                    f"VLSBench row {i} in {path} has no non-empty safety_reason; "
                    "visual-leakless rows require the source grading reference"
                )
            try:
                risk = CATEGORY_MAP[cat]
            except KeyError as exc:
                raise CorpusFormatError(
                    f"VLSBench row {i} in {path} has an unknown or blank "
                    f"category {cat!r}"
                ) from exc
            if sub == "Cybercrime":
                risk = Rc.CYBERSEC
            elif sub == "Weapon-Related Violence":
                risk = Rc.CATASTROPHIC
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
                meta={
                    "safety_reason": safety_reason.strip(),
                    "judge_reference_text": safety_reason.strip(),
                    "judge_reference_kind": (
                        "source_safety_reason_not_sent_to_target"
                    ),
                    "physical_media_directly_evaluated_by_automated_judges": False,
                },
            ))
        if not out:
            raise CorpusFormatError(f"VLSBench conversion produced no rows from {path}")
        return out
