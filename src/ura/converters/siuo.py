"""SIUO converter: Safe Inputs but Unsafe Output (cross-modal composition).

SIUO (github.com/sinwang20/SIUO) is the cross-modal-safety set whose defining
property is that both the image and the text are individually benign, yet their
*joint* interpretation elicits an unsafe output - the leakage-controlled
complement to the older image-jailbreak corpora (thesis II.4.3 / V.1.3).

Real released layout: ``data/siuo_gen.json`` (free-form generation), a JSON list
of records with a ``category``, a ``question`` (the benign text), an ``image``
filename resolved against a sibling ``images/`` directory, and a
``safety_warning`` grading reference.  Although each channel is benign in
isolation, the *joint request* is a harmful safety probe; it therefore belongs to
the harmful ASR population rather than the benign false-refusal population.

Only the generation layout is convertible.  The separate ``data/siuo_mcqa.json``
multiple-choice track carries no ``safety_warning`` and its answer-choice
construct is not modelled by the unified ASR/refusal schema, so pointing the
converter at it fails closed with a clear error rather than mis-scoring the rows.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_json, read_jsonl

# The nine category strings in the pinned 167-row SIUO release.  Conversion is
# fail-closed below: silently treating a new/misspelled category as LEGALITY
# would corrupt the risk stratum while leaving the row apparently valid.
CATEGORY_MAP = {
    "controversial topics, politics": Rc.TOXICITY,
    "dangerous behavior": Rc.TOXICITY,
    "discrimination & stereotyping": Rc.BIAS,
    "illegal activities & crime": Rc.LEGALITY,
    "information misinterpretation": Rc.HALLUCINATION,
    "morality": Rc.TOXICITY,
    "privacy violation": Rc.PRIVACY,
    "religion beliefs": Rc.BIAS,
    "self-harm": Rc.CATASTROPHIC,
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
        # The multiple-choice release (siuo_mcqa.json) carries answer choices but
        # no safety_warning grading reference; its choose-the-safe-option construct
        # is not modelled by the ASR/refusal schema, so reject it up front with a
        # precise message instead of the generic missing-safety_warning error.
        first = records[0] if records and isinstance(records[0], dict) else {}
        if ("mcqa" in path.stem.lower()) or (
            ("options" in first or "correct_option" in first)
            and "safety_warning" not in first
        ):
            raise CorpusFormatError(
                f"SIUO multiple-choice layout is not supported ({path}); convert "
                "the free-form generation release data/siuo_gen.json instead"
            )
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"SIUO row {i} in {path} is not an object")
            text = rec.get("question") or rec.get("instruction") or rec.get("prompt")
            img_name = rec.get("image") or rec.get("image_path") or rec.get("image_id")
            if not isinstance(text, str) or not text.strip() or not img_name:
                raise CorpusFormatError(
                    f"SIUO row {i} in {path} lacks the required question or image"
                )
            cat = str(rec.get("category") or "").strip()
            try:
                risk = CATEGORY_MAP[cat.lower()]
            except KeyError as exc:
                raise CorpusFormatError(
                    f"SIUO row {i} in {path} has an unknown or blank category "
                    f"{cat!r}"
                ) from exc
            safety_warning = rec.get("safety_warning")
            if not isinstance(safety_warning, str) or not safety_warning.strip():
                raise CorpusFormatError(
                    f"SIUO row {i} in {path} has no non-empty safety_warning; "
                    "jointly harmful rows require the source grading reference"
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
                    "safety_warning": safety_warning.strip(),
                    "reference_answer": (
                        rec.get("reference_answer")
                        or rec.get("reference")
                        or rec.get("safe_response")
                    ),
                    "source_task": "generation",
                    "joint_input_harmful": True,
                    "single_channel_inputs_benign": True,
                    "reference_status": "source_provided_not_revalidated",
                    "judge_reference_text": safety_warning.strip(),
                    "judge_reference_kind": (
                        "source_safety_warning_not_sent_to_target"
                    ),
                    "physical_media_directly_evaluated_by_automated_judges": False,
                },
            ))
        if not out:
            raise CorpusFormatError(f"SIUO conversion produced no rows from {path}")
        return out
