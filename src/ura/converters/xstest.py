"""XSTest converter: exaggerated-safety / over-refusal contrast set (thesis II.4).

XSTest (Rottger et al. 2024, "XSTest: A Test Suite for Identifying Exaggerated
Safety Behaviours"; a HELM Safety constituent) is 450 prompts: 250 SAFE prompts
that a well-calibrated model should answer, and 200 UNSAFE contrast prompts that
share surface features (homonyms, figurative language, safe targets/contexts)
but genuinely should be refused. It is the canonical text over-refusal benchmark,
and it supplies URA the benign false-refusal population its multimodal-only
over-refusal sources (MOSSBench, VSCBench) do not.

Released layout (GitHub CSV ``paul-rottger/xstest/xstest_prompts.csv``): columns
``id, prompt, type, label, focus, note``. ``label`` in {safe, unsafe} fixes the
population; ``type`` (18 values, 10 safe + 8 ``contrast_*`` unsafe) fixes the
construct. Use a real CSV reader - one prompt embeds a quoted comma.

Mapping is fail-closed on (label, type): safe prompts -> OVER_REFUSAL with
``expected_behavior=safe_answer`` (refusing them is the failure, feeding the
false-refusal/exaggerated-safety rate); unsafe contrast prompts -> ``refuse``
with a RiskCategory from the contrast type. The source type is kept in
``risk_subtype``. Point ``URA_XSTEST_PATH`` at the CSV (JSON/JSONL also accepted).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_csv, read_json, read_jsonl

# The 10 SAFE prompt types: every one is a benign prompt whose only correct
# behaviour is to answer, so they populate the over-refusal (false-refusal) axis.
SAFE_TYPES: frozenset[str] = frozenset({
    "definitions", "figurative_language", "historical_events", "homonyms",
    "nons_group_real_discr", "privacy_fictional", "privacy_public",
    "real_group_nons_discr", "safe_contexts", "safe_targets",
})

# The 8 UNSAFE contrast types -> unified RiskCategory (fail-closed). Most contrast
# types are violence homonyms/frames (kill/execute/attack a person) -> TOXICITY;
# discrimination advocacy -> BIAS; atrocity denial/disinformation -> HALLUCINATION;
# real-credential/account extraction -> PRIVACY.
UNSAFE_TYPE_MAP: dict[str, Rc] = {
    "contrast_homonyms": Rc.TOXICITY,
    "contrast_figurative_language": Rc.TOXICITY,
    "contrast_safe_targets": Rc.TOXICITY,
    "contrast_safe_contexts": Rc.TOXICITY,
    "contrast_definitions": Rc.TOXICITY,
    "contrast_discr": Rc.BIAS,
    "contrast_historical_events": Rc.HALLUCINATION,
    "contrast_privacy": Rc.PRIVACY,
}


class XSTestConverter(BaseConverter):
    name = "xstest"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        if path.suffix == ".jsonl":
            records = read_jsonl(path)
        elif path.suffix in (".json",):
            records = read_json(path)
        else:
            records = read_csv(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("prompts", records))
        if not isinstance(records, list) or not records:
            raise CorpusFormatError(
                f"XSTest source is not a non-empty record list: {path}"
            )

        out: list[DataPoint] = []
        seen: set[str] = set()
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"XSTest row {i} in {path} is not an object")
            prompt = rec.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise CorpusFormatError(
                    f"XSTest row {i} in {path} lacks a non-empty prompt"
                )
            label = str(rec.get("label") or "").strip().lower()
            rtype = str(rec.get("type") or "").strip()
            if not rtype:
                raise CorpusFormatError(
                    f"XSTest row {i} in {path} lacks a non-empty type"
                )
            if label == "safe":
                if rtype not in SAFE_TYPES:
                    raise CorpusFormatError(
                        f"XSTest row {i} in {path} has unknown safe type {rtype!r}"
                    )
                risk = Rc.OVER_REFUSAL
                expected = "safe_answer"
            elif label == "unsafe":
                if rtype not in UNSAFE_TYPE_MAP:
                    raise CorpusFormatError(
                        f"XSTest row {i} in {path} has unknown unsafe type {rtype!r}"
                    )
                risk = UNSAFE_TYPE_MAP[rtype]
                expected = "refuse"
            else:
                raise CorpusFormatError(
                    f"XSTest row {i} in {path} has unknown label {label!r} "
                    "(expected 'safe' or 'unsafe')"
                )

            rid = rec.get("id")
            point_id = (
                f"xstest:{str(rid).strip()}"
                if rid is not None and str(rid).strip()
                else f"xstest:{i}"
            )
            if point_id in seen:
                raise CorpusFormatError(f"XSTest duplicate id {point_id!r} at row {i}")
            seen.add(point_id)

            out.append(dp(
                id=point_id,
                source="xstest",
                modalities=["text"],
                risk=risk,
                expected=expected,  # type: ignore[arg-type]
                dialog=[DialogTurn(role="user", content=prompt)],
                payload_text=prompt,
                risk_subtype=rtype,
                attack_family="exaggerated_safety_contrast",
                meta={
                    "source_cluster_id": point_id,
                    "xstest_label": label,
                    "xstest_type": rtype,
                    "xstest_focus": rec.get("focus") or None,
                    "xstest_note": rec.get("note") or None,
                    "official_evaluator_executed": False,
                },
            ))
        return out
