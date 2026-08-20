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

This converter reads that JSON/JSONL/CSV manifest with the standard library,
resolving and content-addressing each audio filename under the manifest's
declared root. ``python -m experiments.export_jalmbench`` is the bounded,
offline PyArrow bridge from the official Parquet release to this file layout.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn, MediaRef
from ._common import CorpusFormatError, Rc, dp, local_media, missing, read_csv, read_json, read_jsonl

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
    "malware": Rc.INFORMATION_SECURITY,
    "cybersecurity": Rc.INFORMATION_SECURITY,
    "hacking": Rc.INFORMATION_SECURITY,
    "misinformation": Rc.HALLUCINATION,
    "disinformation": Rc.HALLUCINATION,
    "bias": Rc.BIAS,
}

AUDIO_EXTS = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".opus")

# Candidate fields for the spoken/adversarial transcript (the harmful request).
_TEXT_FIELDS = ("text", "transcript", "prompt", "query", "instruction", "original_text")
# Candidate fields naming the audio asset.
_AUDIO_FIELDS = ("audio_path", "audio_file", "audio_filename", "audio", "wav", "file", "path")
# Dedicated source-prompt identifiers take precedence over text-derived identity.
# The release's generic ``id`` can name an audio asset, so it is deliberately not
# treated as an underlying-prompt identifier.
_PROMPT_ID_FIELDS = (
    "source_prompt_id", "original_prompt_id", "prompt_id", "query_id",
    "behavior_id", "source_id", "original_id",
)


def _first(rec: dict, fields: tuple[str, ...]) -> object:
    for f in fields:
        v = rec.get(f)
        if v not in (None, ""):
            return v
    return None


def _audio_ref(name: str, root: Path) -> MediaRef:
    """Resolve audio under the manifest root and stamp MIME + SHA-256."""
    p = Path(name)
    if not p.is_absolute():
        sib = root / "audio" / name
        p = Path("audio") / name if sib.is_file() else p
    return local_media(p, root, modality="audio")


def _source_cluster(rec: dict, reference_transcript: str) -> tuple[str, str]:
    """Return an opaque, stable identity for the underlying source prompt.

    A dedicated prompt identifier from the official row is strongest.  The
    released ``original_text`` is the next-best cross-attack identity.  Rows
    without either use an exact-transcript hash as a conservative fallback; it
    groups only byte-identical normalized transcripts and therefore does not
    claim semantic equivalence across transformed variants.  Text is hashed into
    metadata identity only and is never added to the target-visible dialog.
    """
    origin = str(rec.get("source") or "unknown").strip()
    for field in _PROMPT_ID_FIELDS:
        value = rec.get(field)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            normalized = str(value).strip()
            if normalized:
                digest = hashlib.sha256(
                    f"{origin}\x1f{normalized}".encode("utf-8")
                ).hexdigest()
                return f"jalmbench:official-prompt-id:{digest}", field

    original = rec.get("original_text")
    if isinstance(original, str) and original.strip():
        digest = hashlib.sha256(
            f"{origin}\x1f{original.strip()}".encode("utf-8")
        ).hexdigest()
        return f"jalmbench:original-text-sha256:{digest}", "original_text_sha256"

    digest = hashlib.sha256(
        f"{origin}\x1f{reference_transcript}".encode("utf-8")
    ).hexdigest()
    return (
        f"jalmbench:exact-transcript-sha256:{digest}",
        "exact_reference_transcript_sha256_fallback",
    )


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
        if not isinstance(records, list):
            raise CorpusFormatError(f"JALMBench manifest is not a list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"JALMBench row {i} in {path} is not an object")
            rid_raw = rec.get("id", rec.get("index", i))
            text = _first(rec, _TEXT_FIELDS)
            if not isinstance(text, str) or not text.strip():
                raise CorpusFormatError(
                    f"JALMBench row {i} in {path} lacks the reference transcript "
                    "required for source-conditioned automated grading"
                )
            reference_transcript = text.strip()
            source_cluster_id, source_cluster_basis = _source_cluster(
                rec, reference_transcript
            )

            # Locate the audio asset. Explicit audio field wins; otherwise the
            # folder-based manifest uses ``id`` as the audio filename (e.g. 1.mp3).
            audio_name = _first(rec, _AUDIO_FIELDS)
            if audio_name is None and isinstance(rid_raw, str) and rid_raw.lower().endswith(AUDIO_EXTS):
                audio_name = rid_raw
            if audio_name is None:
                raise CorpusFormatError(
                    f"JALMBench row {i} in {path} does not reference an audio asset"
                )
            media = [_audio_ref(str(audio_name), root)]

            cat = str(rec.get("category") or rec.get("harm_category") or rec.get("subcategory") or "").strip()
            # Blank is the documented default for the label-free audio release
            # (JAILBREAK); an unknown non-blank label fails closed instead of being
            # silently absorbed into JAILBREAK, matching every other converter
            # (RA-006/010/015/030) so denominators cannot be silently mis-stratified.
            if not cat:
                risk = Rc.JAILBREAK
            elif cat.lower() in CATEGORY_MAP:
                risk = CATEGORY_MAP[cat.lower()]
            else:
                raise CorpusFormatError(
                    f"JALMBench row {i} in {path} has unknown harm category {cat!r}; "
                    "add it to CATEGORY_MAP or leave the category blank for the "
                    "audio-jailbreak default"
                )
            # The per-attack config / method (ICA, DAN, PAP, SSJ, AMSE, ...) if present.
            method = rec.get("attack") or rec.get("method") or rec.get("config") or rec.get("subset")

            neutral_instruction = "Respond to the request carried in the audio."
            out.append(dp(
                id=f"jalmbench:{rid_raw}",
                source="jalmbench",
                modalities=["text", "audio"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(
                    role="user", content=neutral_instruction, media=media
                )],
                payload_text=neutral_instruction,
                media=media,
                risk_subtype=cat or (str(method) if method else None),
                attack_family="audio_jailbreak",
                meta={
                    "origin_source": rec.get("source"),
                    "original_text": rec.get("original_text"),
                    "reference_transcript": reference_transcript,
                    "judge_reference_text": reference_transcript,
                    "judge_reference_kind": "audio_transcript_not_sent_to_target",
                    "transcript_sent_to_target": False,
                    "source_cluster_id": source_cluster_id,
                    "source_cluster_basis": source_cluster_basis,
                    "source_cluster_text_exposed_to_target": False,
                    "audio_condition": "audio_only_harmful_intent",
                    "attack_method": str(method) if method else None,
                    "language": rec.get("language"),
                    "gender": rec.get("gender"),
                    "accent": rec.get("accent"),
                    "attempt_id": rec.get("attempt_id"),
                    "target_model": rec.get("target_model"),
                },
            ))
        if not out:
            raise CorpusFormatError(f"JALMBench conversion produced no rows from {path}")
        return out
