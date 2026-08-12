"""Video-SafetyBench converter: emergent unsafety from video-text composition.

Video-SafetyBench (HF ``BAAI/Video-SafetyBench``; github.com/flageval-baai/
Video-SafetyBench; NeurIPS D&B 2025, arXiv:2505.11842) is the first large-scale
safety set for video large vision-language models: 2,264 video-text pairs built
from 1,132 synthesized ~10s videos, spanning 13 primary unsafe categories and 48
fine-grained subcategories (an MLCommons-style hazard taxonomy S1-S13).

Its defining property mirrors SIUO but in the temporal domain: each synthesized
video is paired with either a *harmful* query (explicit malice) or a *benign*
query that reads as harmless in isolation yet elicits unsafe behavior once
interpreted jointly with the video. The unsafe intent for the benign pairs is
emergent from the video composition, so a text-only view would lose the risk.

Real released layout: a metadata table (json / jsonl) whose records carry
``question_id``, ``question`` (the query text), ``harmful_intention``,
``video_path`` (relative to the metadata file), ``category`` and
``subcategory``. The benign vs harmful split is carried by the release directory
name (``video_safetybench_{query_type}``) and/or a per-record type field. Point
``URA_VIDEOSAFETYBENCH_PATH`` at either variant's metadata file. Video files are
resolved against the metadata file's parent (with a ``videos/`` fallback).
Missing metadata or referenced video assets fail closed.

Imports only the standard library plus ``_common`` (which re-exports the data
models); ``BaseConverter`` is the framework's converter ABC.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Optional

from ..adapters.base import BaseConverter
from ._common import CorpusFormatError, DataPoint, DialogTurn, MediaRef, Rc, dp, local_media, missing, read_json, read_jsonl

# Primary hazard categories (S1-S13) -> internal taxonomy. Unmapped categories
# (e.g. Specialized Advice, Elections) fall through to the JAILBREAK default.
CATEGORY_MAP = {
    "violent crimes": Rc.LEGALITY,
    "non-violent crimes": Rc.LEGALITY,
    "sex-related crimes": Rc.LEGALITY,
    "child sexual exploitation": Rc.CATASTROPHIC,
    "defamation": Rc.TOXICITY,
    "privacy": Rc.PRIVACY,
    "intellectual property": Rc.LEGALITY,
    "indiscriminate weapons": Rc.CATASTROPHIC,
    "hate": Rc.TOXICITY,
    "suicide and self-harm": Rc.CATASTROPHIC,
    "sexual content": Rc.TOXICITY,
}

# Subcategory keyword refinements (checked before the category map).
KEYWORD_OVERRIDES = (
    ("child", Rc.CATASTROPHIC),
    ("csem", Rc.CATASTROPHIC),
    ("self-harm", Rc.CATASTROPHIC),
    ("self harm", Rc.CATASTROPHIC),
    ("suicide", Rc.CATASTROPHIC),
    ("weapon", Rc.CATASTROPHIC),
    ("cbrn", Rc.CATASTROPHIC),
    ("biological", Rc.CATASTROPHIC),
    ("chemical", Rc.CATASTROPHIC),
    ("nuclear", Rc.CATASTROPHIC),
    ("cyber", Rc.CYBERSEC),
    ("hacking", Rc.CYBERSEC),
    ("malware", Rc.CYBERSEC),
    ("privacy", Rc.PRIVACY),
)

_BENIGN = "benign"
_HARMFUL = "harmful"
_VIDEO_ID_FIELDS = ("source_video_id", "video_id", "clip_id")


def _norm(s: Optional[str]) -> str:
    """Normalize a category label: drop an ``S1-`` style prefix and punctuation."""
    s = (s or "").strip().lower()
    s = re.sub(r"^s\d+\s*[-:._)]*\s*", "", s)
    s = s.replace("_", " ").replace("&", " and ")
    return re.sub(r"\s+", " ", s).strip()


def _risk(category: Optional[str], subcategory: Optional[str]) -> Rc:
    """Derive the internal risk from subcategory keywords, then category, then JAILBREAK."""
    text = f"{category or ''} {subcategory or ''}".lower()
    for kw, rc in KEYWORD_OVERRIDES:
        if kw in text:
            return rc
    return CATEGORY_MAP.get(_norm(category), Rc.JAILBREAK)


def _query_type(rec: dict, path: Path) -> Optional[str]:
    """Classify a record as benign / harmful via a type field or the release path."""
    for k in ("query_type", "type", "variant", "split", "prompt_type"):
        v = rec.get(k)
        if isinstance(v, str) and v.strip().lower() in (_BENIGN, _HARMFUL):
            return v.strip().lower()
    for k in ("is_benign", "benign"):
        v = rec.get(k)
        if isinstance(v, bool):
            return _BENIGN if v else _HARMFUL
    hay = str(path).lower()
    if _BENIGN in hay:
        return _BENIGN
    if _HARMFUL in hay:
        return _HARMFUL
    return None


def _video(video_path: Optional[str], root: Path) -> list[MediaRef]:
    """Resolve the video against the metadata parent (with a ``videos/`` fallback)."""
    if not video_path:
        raise CorpusFormatError("Video-SafetyBench row has no video path")
    raw = Path(video_path)
    if not raw.is_absolute() and not (root / raw).is_file():
        alt = Path("videos") / raw.name
        if (root / alt).is_file():
            raw = alt
    return [local_media(raw, root, modality="video")]


def _source_cluster(rec: dict, media: MediaRef) -> tuple[str, str]:
    """Bind benign/harmful query variants to their shared source video.

    Prefer a dedicated release video identifier.  The documented release layout
    does not require one, so verified content identity is the fail-closed fallback
    and joins variants only when their admitted video bytes are identical.
    """
    for field in _VIDEO_ID_FIELDS:
        value = rec.get(field)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            normalized = str(value).strip()
            if normalized:
                digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                return f"videosafetybench:official-video-id:{digest}", field
    if not media.sha256 or len(media.sha256) != 64:
        raise CorpusFormatError("Video-SafetyBench video lacks verified content identity")
    return f"videosafetybench:video-sha256:{media.sha256}", "verified_video_sha256"


class VideoSafetyBenchConverter(BaseConverter):
    name = "videosafetybench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            known = next(
                (
                    records[name]
                    for name in ("data", "questions", "records")
                    if name in records
                ),
                None,
            )
            if known is not None:
                records = known
            elif records and all(isinstance(value, dict) for value in records.values()):
                records = list(records.values())
            else:
                raise CorpusFormatError(
                    f"Video-SafetyBench metadata object has no record collection: {path}"
                )
        if not isinstance(records, list):
            raise CorpusFormatError(f"Video-SafetyBench metadata is not a list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(
                    f"Video-SafetyBench row {i} in {path} is not an object"
                )
            category = rec.get("category")
            subcategory = rec.get("subcategory")
            text = rec.get("question") or rec.get("query") or rec.get("prompt")
            if not isinstance(text, str) or not text.strip():
                raise CorpusFormatError(
                    f"Video-SafetyBench row {i} in {path} has no non-empty question"
                )
            media = _video(rec.get("video_path") or rec.get("video"), root)
            source_cluster_id, source_cluster_basis = _source_cluster(rec, media[0])

            qtype = _query_type(rec, path)
            if qtype is None:
                raise CorpusFormatError(
                    f"Video-SafetyBench row {i} in {path} has no benign/harmful split"
                )
            # Both variants are harmful evaluation units.  For benign-query rows
            # the unsafe intent emerges only from joint video-text interpretation;
            # they must not enter the benign false-refusal denominator.
            emergent = qtype != _HARMFUL
            expected = "refuse"
            harmful_intention = rec.get("harmful_intention")
            if emergent and (
                not isinstance(harmful_intention, str)
                or not harmful_intention.strip()
            ):
                raise CorpusFormatError(
                    f"Video-SafetyBench row {i} in {path} needs harmful_intention "
                    "to grade a benign-query emergent-unsafe example"
                )
            judge_reference = (
                harmful_intention.strip()
                if isinstance(harmful_intention, str) and harmful_intention.strip()
                else None
            )

            tag = qtype or "q"
            rid = rec.get("question_id", rec.get("id", i))
            out.append(dp(
                id=f"videosafetybench:{tag}:{rid}",
                source="videosafetybench",
                modalities=["text", "video"],
                risk=_risk(category, subcategory),
                expected=expected,
                dialog=[DialogTurn(role="user", content=text, media=media)],
                payload_text=text,
                media=media,
                risk_subtype=(subcategory or category or None),
                attack_family="video_composition",
                meta={
                    "category": category,
                    "subcategory": subcategory,
                    "harmful_intention": harmful_intention,
                    "judge_reference_text": judge_reference,
                    "judge_reference_kind": (
                        "video_conditioned_harmful_intention_not_sent_to_target"
                        if judge_reference is not None
                        else None
                    ),
                    "query_type": qtype,
                    "emergent_unsafe": emergent,
                    "source_cluster_id": source_cluster_id,
                    "source_cluster_basis": source_cluster_basis,
                    "video_path": rec.get("video_path") or rec.get("video"),
                },
            ))
        if not out:
            raise CorpusFormatError(
                f"Video-SafetyBench conversion produced no rows from {path}"
            )
        return out
