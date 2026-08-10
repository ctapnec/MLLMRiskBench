"""SIUO converter: Safe Inputs but Unsafe Output (cross-modal composition).

SIUO (github.com/sinwang20/SIUO) is the cross-modal-safety set whose defining
property is that both the image and the text are individually benign, yet their
*joint* interpretation elicits an unsafe output - the leakage-controlled
complement to the older image-jailbreak corpora (thesis II.4.3 / V.1.3).

Real released layout: ``data/siuo_gen.json`` (free-form generation) and
``data/siuo_mcqa.json`` (multiple choice), each a JSON list of records with a
``category``, a ``question`` (the benign text), and an ``image`` filename resolved
against a sibling ``images/`` directory.  Although each channel is benign in
isolation, the *joint request* is a harmful safety probe; it therefore belongs to
the harmful ASR population rather than the benign false-refusal population.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_json, read_jsonl

# SIUO safety categories -> internal taxonomy (default LEGALITY when unmapped).
CATEGORY_MAP = {
    "self-harm": Rc.CATASTROPHIC,
    "violence": Rc.CATASTROPHIC,
    "hate": Rc.TOXICITY,
    "hate speech": Rc.TOXICITY,
    "illegal activity": Rc.LEGALITY,
    "crime": Rc.LEGALITY,
    "dangerous behavior": Rc.LEGALITY,
    "privacy": Rc.PRIVACY,
    "privacy violation": Rc.PRIVACY,
    "cybersecurity": Rc.CYBERSEC,
    "ethics": Rc.TOXICITY,
    "morality": Rc.TOXICITY,
    "political": Rc.TOXICITY,
}


class SIUOConverter(BaseConverter):
    name = "siuo"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent.resolve()
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("questions", []))
        if not isinstance(records, list):
            raise CorpusFormatError(f"SIUO source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"SIUO row {i} in {path} is not an object")
            cat = str(rec.get("category") or "").strip()
            risk = CATEGORY_MAP.get(cat.lower(), Rc.LEGALITY)
            text = rec.get("question") or rec.get("instruction") or rec.get("prompt")
            img_name = rec.get("image") or rec.get("image_path") or rec.get("image_id")
            if not isinstance(text, str) or not text.strip() or not img_name:
                raise CorpusFormatError(
                    f"SIUO row {i} in {path} lacks the required question or image"
                )
            # The official archive uses data/images; tolerate manifests that
            # already include the images/ prefix, but never fabricate a fallback.
            img_ref = Path(str(img_name))
            relative = img_ref if img_ref.parts[:1] == ("images",) else Path("images") / img_ref
            if not (root / relative).is_file() and (root / img_ref).is_file():
                relative = img_ref
            media = [image(relative, root)]
            rid = rec.get("question_id", rec.get("index", rec.get("id", i)))
            out.append(dp(
                id=f"siuo:{rid}",
                source="siuo",
                modalities=["text", "image"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=text or "", media=media)],
                payload_text=text,
                media=media,
                risk_subtype=cat or None,
                attack_family="cross_modal_composition",
                meta={
                    "safety_warning": rec.get("safety_warning"),
                    "reference_answer": (
                        rec.get("reference_answer")
                        or rec.get("reference")
                        or rec.get("safe_response")
                    ),
                    "source_task": "mcqa" if "mcqa" in path.stem.lower() else "generation",
                    "joint_input_harmful": True,
                    "single_channel_inputs_benign": True,
                    "reference_status": "source_provided_not_revalidated",
                },
            ))
        if not out:
            raise CorpusFormatError(f"SIUO conversion produced no rows from {path}")
        return out
