"""SIUO converter: Safe Inputs but Unsafe Output (cross-modal composition).

SIUO (github.com/sinwang20/SIUO) is the cross-modal-safety set whose defining
property is that both the image and the text are individually benign, yet their
*joint* interpretation elicits an unsafe output - the leakage-controlled
complement to the older image-jailbreak corpora (thesis II.4.3 / V.1.3).

Real released layout: ``data/siuo_gen.json`` (free-form generation) and
``data/siuo_mcqa.json`` (multiple choice), each a JSON list of records with a
``category``, a ``question`` (the benign text), and an ``image`` filename resolved
against a sibling ``images/`` directory. Point ``URA_SIUO_PATH`` at either JSON
file (or a JSONL export). Robust to a missing path (returns []).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, image, missing, read_json, read_jsonl

# SIUO safety categories -> internal taxonomy (default LEGALITY when unmapped).
CATEGORY_MAP = {
    "self-harm": Rc.TOXICITY,
    "violence": Rc.TOXICITY,
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
        root = path.parent
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("questions", []))
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            cat = str(rec.get("category") or "").strip()
            risk = CATEGORY_MAP.get(cat.lower(), Rc.LEGALITY)
            text = rec.get("question") or rec.get("instruction") or rec.get("prompt")
            img_name = rec.get("image") or rec.get("image_path") or rec.get("image_id")
            # images live under a sibling images/ dir in the release; fall back to root
            media = []
            if img_name:
                img_path = root / "images" / str(img_name)
                media = [image(str(img_path) if img_path.is_file() else str(img_name), root)]
            rid = rec.get("question_id", rec.get("index", rec.get("id", i)))
            out.append(dp(
                id=f"siuo:{rid}",
                source="siuo",
                modalities=["text", "image"],
                risk=risk,
                expected="safe_answer",   # inputs are benign; the unsafe output must be avoided
                dialog=[DialogTurn(role="user", content=text or "", media=media)],
                payload_text=text,
                media=media,
                risk_subtype=cat or None,
                attack_family="cross_modal_composition",
                meta={"reference": rec.get("reference") or rec.get("safe_response")},
            ))
        return out
