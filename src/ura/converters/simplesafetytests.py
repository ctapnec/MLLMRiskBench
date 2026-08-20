"""SimpleSafetyTests converter: a compact critical-harm probe set (thesis II.4).

SimpleSafetyTests (Vidgen et al. 2023, arXiv:2311.08370; a HELM Safety
constituent) is 100 hand-written English prompts spanning five severe harm areas.
Every prompt is a request a safe model should decline, so the set is a small,
high-signal harmful-ASR probe rather than a graded or multiple-choice benchmark.

Released layout (Hugging Face ``Bertievidgen/SimpleSafetyTests`` or the
``walledai`` mirror, exported to JSON/JSONL/CSV): each record carries ``id``
(e.g. ``sst_001``), ``harm_area`` (one of the five below), ``category`` (the
prompt STYLE - "Information and advice seeking" or "Instructions and actions",
not a harm type, kept as provenance only), ``counter``, and ``prompt``.

The unified ``RiskCategory`` is assigned from the exact ``harm_area`` label
(fail-closed; unknown/blank raises), with the source label preserved in
``risk_subtype``. Each of the 100 prompts is a distinct intent, so every row is
its own source cluster. Point ``URA_SIMPLESAFETYTESTS_PATH`` at the export.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_csv, read_json, read_jsonl

# Exact SimpleSafetyTests harm areas -> unified RiskCategory (fail-closed). The
# area-level label is the faithful granularity the source ships; self-harm and
# child abuse follow the project's CATASTROPHIC convention, physical violence
# follows the violence -> TOXICITY convention, and the illegal/fraud areas map
# to LEGALITY.
HARM_AREA_MAP: dict[str, Rc] = {
    "Suicide, Self-Harm, and Eating Disorders": Rc.CATASTROPHIC,
    "Physical Harm and Violence": Rc.TOXICITY,
    "Illegal and Highly Regulated items": Rc.LEGALITY,
    "Scams and Fraud": Rc.LEGALITY,
    "Child Abuse": Rc.CATASTROPHIC,
}


class SimpleSafetyTestsConverter(BaseConverter):
    name = "simplesafetytests"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        if path.suffix == ".jsonl":
            records = read_jsonl(path)
        elif path.suffix == ".csv":
            records = read_csv(path)
        else:
            records = read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", records.get("test", records)))
        if not isinstance(records, list) or not records:
            raise CorpusFormatError(
                f"SimpleSafetyTests source is not a non-empty record list: {path}"
            )

        out: list[DataPoint] = []
        seen: set[str] = set()
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(
                    f"SimpleSafetyTests row {i} in {path} is not an object"
                )
            prompt = rec.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise CorpusFormatError(
                    f"SimpleSafetyTests row {i} in {path} lacks a non-empty prompt"
                )
            harm_area = rec.get("harm_area")
            if not isinstance(harm_area, str) or not harm_area.strip():
                raise CorpusFormatError(
                    f"SimpleSafetyTests row {i} in {path} lacks a non-empty harm_area"
                )
            harm_area = harm_area.strip()
            if harm_area not in HARM_AREA_MAP:
                raise CorpusFormatError(
                    f"SimpleSafetyTests row {i} in {path} has unknown harm_area "
                    f"{harm_area!r}; extend HARM_AREA_MAP to admit it"
                )
            risk = HARM_AREA_MAP[harm_area]

            rid = rec.get("id")
            point_id = (
                f"simplesafetytests:{str(rid).strip()}"
                if rid is not None and str(rid).strip()
                else f"simplesafetytests:{i}"
            )
            if point_id in seen:
                raise CorpusFormatError(
                    f"SimpleSafetyTests duplicate id {point_id!r} at row {i}"
                )
            seen.add(point_id)

            out.append(dp(
                id=point_id,
                source="simplesafetytests",
                modalities=["text"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=prompt)],
                payload_text=prompt,
                risk_subtype=harm_area,
                attack_family="direct_request",
                meta={
                    "source_cluster_id": point_id,
                    "sst_harm_area": harm_area,
                    "sst_prompt_style": rec.get("category"),
                    "official_evaluator_executed": False,
                },
            ))
        return out
