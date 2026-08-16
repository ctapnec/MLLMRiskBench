"""HarmBench converter: standardized behaviors CSV (text + multimodal).

Text header: Behavior, FunctionalCategory, SemanticCategory, Tags, ContextString,
BehaviorID. Multimodal adds ImageFileName. Parse by header name (column order
differs between the two CSVs).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_csv

SEMANTIC_MAP = {
    "cybercrime_intrusion": Rc.CYBERSEC,
    "chemical_biological": Rc.CATASTROPHIC,
    "illegal": Rc.LEGALITY,
    "copyright": Rc.LEGALITY,
    "misinformation_disinformation": Rc.HALLUCINATION,
    "harmful": Rc.TOXICITY,
    "harassment_bullying": Rc.TOXICITY,
}

# The official multimodal behaviors CSV lists some images with a .jpeg
# extension while the released image folder ships the same stems as .png.
# Resolve by the exact listed name first, then by stem across the maintained
# image extensions; the byte-level type is still verified downstream.
_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff")


def _resolve_image_name(name: str, imgroot: Path) -> str:
    if (imgroot / name).is_file():
        return name
    stem = Path(name).stem
    for extension in _IMAGE_EXTENSIONS:
        if (imgroot / f"{stem}{extension}").is_file():
            return f"{stem}{extension}"
    # Fall through with the declared name so image() raises the canonical
    # fail-closed "media asset does not exist" error.
    return name


class HarmBenchConverter(BaseConverter):
    name = "harmbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        imgroot = path.parent.parent / "multimodal_behavior_images"
        records = read_csv(path)
        if not isinstance(records, list):
            raise CorpusFormatError(f"HarmBench source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, row in enumerate(records):
            if not isinstance(row, dict):
                raise CorpusFormatError(f"HarmBench row {i} in {path} is not an object")
            behavior = row.get("Behavior")
            if not isinstance(behavior, str) or not behavior.strip():
                raise CorpusFormatError(
                    f"HarmBench row {i} in {path} lacks non-empty Behavior"
                )
            context = row.get("ContextString") or ""
            if not isinstance(context, str):
                raise CorpusFormatError(
                    f"HarmBench row {i} in {path} has non-text ContextString"
                )
            content = (f"{context}\n\n{behavior}").strip() if context else behavior
            sem = (row.get("SemanticCategory") or "").strip()
            if sem not in SEMANTIC_MAP:
                raise CorpusFormatError(
                    f"HarmBench row {i} in {path} has unknown or blank "
                    f"SemanticCategory: {sem!r}"
                )
            media = []
            modalities = ["text"]
            if row.get("ImageFileName"):
                media = [image(_resolve_image_name(row["ImageFileName"], imgroot), imgroot)]
                modalities = ["text", "image"]
            out.append(dp(
                id=f"harmbench:{row.get('BehaviorID')}",
                source="harmbench",
                modalities=modalities,
                risk=SEMANTIC_MAP[sem],
                expected="refuse",
                dialog=[DialogTurn(role="user", content=content, media=media)],
                payload_text=content,
                media=media,
                risk_subtype=sem,
                attack_family=row.get("FunctionalCategory"),
                meta={
                    "tags": row.get("Tags"),
                    **({
                        # HarmBench's released behavior (and optional context)
                        # is the semantic request presented alongside the image.
                        # The automated judges still do not inspect pixels, so
                        # retain this as proxy-grading context rather than
                        # treating transport as media-aware validity.
                        "judge_reference_text": content,
                        "judge_reference_kind": "source_behavior_sent_with_image",
                    } if media else {}),
                },
            ))
        if not out:
            raise CorpusFormatError(f"HarmBench conversion produced no rows from {path}")
        return out
