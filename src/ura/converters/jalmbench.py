"""JALMBench converter: jailbreak vulnerabilities in Audio Language Models.

JALMBench (github.com/sfofgalaxy/JALMBench, HF: AnonymousUser000/JALMBench;
arXiv:2505.17568) is the audio-LM jailbreak corpus - 11,316 text prompts and
245,355 audio samples (>1,000 h) covering three families: harmful queries
(AHarm/THarm/ADiv, harmful requests read aloud), text-transferred jailbreaks
(ICA, DAN, DI, PAP) and audio-originated jailbreaks (SSJ, AMSE, BoN, AdvWave).
Its defining property is that the harmful intent is carried by an *audio* signal,
so a text-only converter would miss the attack surface entirely (thesis II.4.3).

Real released layout: the HF export is Parquet with per-attack configs (AHarm,
THarm, ADiv, ICA, DAN, DI, PAP, SSJ, AMSE, BoN, AdvWave), each row carrying an
``id``, the spoken/adversarial ``text`` and ``original_text``, a ``source``
(AdvBench / MM-SafetyBench / JailbreakBench / HarmBench) and acoustic metadata
(``language``, ``gender``, ``accent``); audio ships as bytes inside the Parquet.
For folder-based evaluation the repo documents a companion JSON/JSONL manifest
whose records reference audio *files* by name (``{"id": "1.mp3",
"original_text": ...}``), audio stored as sibling ``.mp3`` / ``.wav`` files.

This converter reads that JSON/JSONL/CSV manifest (stdlib only - Parquet audio
bytes are out of scope), resolving each audio filename against the manifest's
parent directory (or a sibling ``audio/`` dir). Point ``URA_JALMBENCH_PATH`` at
the manifest file. Robust to a missing path (returns []).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn, MediaRef
from ._common import Rc, dp, missing, read_csv, read_json, read_jsonl

# JALMBench harm categories (inherited from the source corpora) -> internal
# taxonomy. JALMBench is fundamentally a jailbreak set, so JAILBREAK is the
# default when a row carries no harm-category label (only an attack method).
CATEGORY_MAP = {
    "self-harm": Rc.CATASTROPHIC,
    "self harm": Rc.CATASTROPHIC,
    "suicide": Rc.CATASTROPHIC,
    "cbrn": Rc.CATASTROPHIC,
    "weapons": Rc.CATASTROPHIC,
    "bioweapons": Rc.CATASTROPHIC,
    "violence": Rc.TOXICITY,
    "hate": Rc.TOXICITY,
    "hate speech": Rc.TOXICITY,
    "harassment": Rc.TOXICITY,
    "toxicity": Rc.TOXICITY,
    "sexual": Rc.TOXICITY,
    "privacy": Rc.PRIVACY,
    "privacy violation": Rc.PRIVACY,
    "illegal activity": Rc.LEGALITY,
    "illegal": Rc.LEGALITY,
    "crime": Rc.LEGALITY,
    "fraud": Rc.LEGALITY,
    "economic harm": Rc.LEGALITY,
    "malware": Rc.CYBERSEC,
    "cybersecurity": Rc.CYBERSEC,
    "hacking": Rc.CYBERSEC,
    "misinformation": Rc.HALLUCINATION,
    "disinformation": Rc.HALLUCINATION,
    "bias": Rc.BIAS,
}

AUDIO_EXTS = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".opus")

# Candidate fields for the spoken/adversarial transcript (the harmful request).
_TEXT_FIELDS = ("text", "transcript", "prompt", "query", "instruction", "original_text")
# Candidate fields naming the audio asset.
_AUDIO_FIELDS = ("audio_path", "audio_file", "audio_filename", "audio", "wav", "file", "path")


def _first(rec: dict, fields: tuple[str, ...]) -> object:
    for f in fields:
        v = rec.get(f)
        if v not in (None, ""):
            return v
    return None


def _audio_ref(name: str, root: Path) -> MediaRef:
    """Build an audio MediaRef, resolving a relative filename against the manifest dir.

    The image() helper is image-only, so construct the MediaRef directly. Prefer a
    sibling ``audio/`` directory (the release layout) then fall back to the parent dir.
    """
    p = Path(name)
    if not p.is_absolute():
        sib = root / "audio" / name
        p = sib if sib.is_file() else (root / name)
    return MediaRef(modality="audio", path=str(p))


class JALMBenchConverter(BaseConverter):
    name = "jalmbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent
        if path.suffix == ".jsonl":
            records = read_jsonl(path)
        elif path.suffix == ".csv":
            records = read_csv(path)
        else:
            records = read_json(path)
        if isinstance(records, dict):
            records = (
                records.get("data")
                or records.get("rows")
                or records.get("train")
                or []
            )
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            rid_raw = rec.get("id", rec.get("index", i))
            text = _first(rec, _TEXT_FIELDS)

            # Locate the audio asset. Explicit audio field wins; otherwise the
            # folder-based manifest uses ``id`` as the audio filename (e.g. 1.mp3).
            audio_name = _first(rec, _AUDIO_FIELDS)
            if audio_name is None and isinstance(rid_raw, str) and rid_raw.lower().endswith(AUDIO_EXTS):
                audio_name = rid_raw
            media = [_audio_ref(str(audio_name), root)] if audio_name is not None else []

            cat = str(rec.get("category") or rec.get("harm_category") or rec.get("subcategory") or "").strip()
            risk = CATEGORY_MAP.get(cat.lower(), Rc.JAILBREAK)
            # The per-attack config / method (ICA, DAN, PAP, SSJ, AMSE, ...) if present.
            method = rec.get("attack") or rec.get("method") or rec.get("config") or rec.get("subset")

            out.append(dp(
                id=f"jalmbench:{rid_raw}",
                source="jalmbench",
                modalities=["text", "audio"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=str(text) if text is not None else "", media=media)],
                payload_text=str(text) if text is not None else None,
                media=media,
                risk_subtype=cat or (str(method) if method else None),
                attack_family="audio_jailbreak",
                meta={
                    "origin_source": rec.get("source"),
                    "original_text": rec.get("original_text"),
                    "attack_method": str(method) if method else None,
                    "language": rec.get("language"),
                    "gender": rec.get("gender"),
                    "accent": rec.get("accent"),
                    "attempt_id": rec.get("attempt_id"),
                    "target_model": rec.get("target_model"),
                },
            ))
        return out
