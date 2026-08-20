"""HoliSafe converter: a holistic multimodal safety aggregator (thesis II.4).

HoliSafe (Lee et al. 2025, arXiv:2506.04704; HF ``etri-vilab/holisafe-bench``)
is the aggregator's multimodal representative: 4,031 image+text pairs over ~1,796
images spanning all five image-text safeness combinations (SSS, SSU, SUU, USU,
UUU), where the harmful intent genuinely lives in the *image* - its headline
finding is that unsafe images pose greater risk than unsafe text. That makes it a
true image-carries-harm source, distinct from the text-with-decorative-image
pattern, and complementary to URA's existing multimodal families.

Released layout (gated HF dataset; ``holisafe_bench.json`` + an ``images/``
folder): each record has ``image`` (relative path under ``images/``),
``image_safe``/``image_safety_label``, ``type`` (the S/U safeness combo),
``category`` (7 values), ``subcategory`` (19 values), ``id`` and ``query``.

The unified ``RiskCategory`` is assigned from the exact 7-member ``category``
(fail-closed; unknown/blank raises), refined at ``subcategory`` for weapon/
terrorism violence. ``type`` fixes the population: the all-safe ``SSS`` combo is a
benign probe (``expected_behavior=safe_answer``, feeding the false-refusal axis);
every combo with an unsafe component expects a refusal. Multiple queries share
one image, so the image path is the source cluster. Point
``URA_HOLISAFE_PATH`` at ``holisafe_bench.json`` beside its ``images/`` folder.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_json, read_jsonl

# Exact HoliSafe categories -> unified RiskCategory (fail-closed on category).
CATEGORY_MAP: dict[str, Rc] = {
    "hate": Rc.TOXICITY,
    "illegal_activity": Rc.LEGALITY,
    "privacy": Rc.PRIVACY,
    "self_harm": Rc.CATASTROPHIC,
    "sexual_content": Rc.TOXICITY,
    "specialized_advice": Rc.LEGALITY,
    "violence": Rc.TOXICITY,
}

# Weapon/terrorism violence escalates to CATASTROPHIC; ordinary violence stays
# TOXICITY. Keyed on (category, subcategory).
SUBCATEGORY_OVERRIDE: dict[tuple[str, str], Rc] = {
    ("violence", "weapon_related_violence"): Rc.CATASTROPHIC,
    ("violence", "terrorism"): Rc.CATASTROPHIC,
}

#: The five released image-text safeness combinations. Only the all-safe SSS
#: combo is a benign probe; the rest carry an unsafe image and/or text.
_KNOWN_TYPES = frozenset({"SSS", "SSU", "SUU", "USU", "UUU"})


class HoliSafeConverter(BaseConverter):
    name = "holisafe"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", records))
        if not isinstance(records, list) or not records:
            raise CorpusFormatError(
                f"HoliSafe source is not a non-empty record list: {path}"
            )
        images_root = path.parent / "images"

        out: list[DataPoint] = []
        seen: set[str] = set()
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"HoliSafe row {i} in {path} is not an object")
            query = rec.get("query")
            if not isinstance(query, str) or not query.strip():
                raise CorpusFormatError(
                    f"HoliSafe row {i} in {path} lacks a non-empty query"
                )
            rel_image = rec.get("image")
            if not isinstance(rel_image, str) or not rel_image.strip():
                raise CorpusFormatError(
                    f"HoliSafe row {i} in {path} lacks a non-empty image path"
                )
            category = str(rec.get("category") or "").strip()
            subcategory = str(rec.get("subcategory") or "").strip()
            if category not in CATEGORY_MAP:
                raise CorpusFormatError(
                    f"HoliSafe row {i} in {path} has unknown category {category!r}; "
                    "extend CATEGORY_MAP to admit it"
                )
            rtype = str(rec.get("type") or "").strip()
            if rtype not in _KNOWN_TYPES:
                raise CorpusFormatError(
                    f"HoliSafe row {i} in {path} has unknown safeness type {rtype!r}"
                )
            risk = SUBCATEGORY_OVERRIDE.get((category, subcategory), CATEGORY_MAP[category])
            expected = "safe_answer" if rtype == "SSS" else "refuse"

            media = [image(rel_image, images_root)]

            rid = rec.get("id")
            point_id = (
                f"holisafe:{str(rid).strip()}"
                if rid is not None and str(rid).strip()
                else f"holisafe:{i}"
            )
            if point_id in seen:
                raise CorpusFormatError(f"HoliSafe duplicate id {point_id!r} at row {i}")
            seen.add(point_id)

            out.append(dp(
                id=point_id,
                source="holisafe",
                modalities=["text", "image"],
                risk=risk,
                expected=expected,  # type: ignore[arg-type]
                dialog=[DialogTurn(role="user", content=query, media=media)],
                payload_text=query,
                media=media,
                risk_subtype=f"{category}/{subcategory}" if subcategory else category,
                attack_family="holistic_multimodal",
                meta={
                    "source_cluster_id": f"holisafe:image:{rel_image}",
                    "holisafe_type": rtype,
                    "holisafe_image_safe": rec.get("image_safe"),
                    "holisafe_category": category,
                    "holisafe_subcategory": subcategory or None,
                    "official_evaluator_executed": False,
                },
            ))
        return out
