"""MLLMGuard converter: multi-dimensional multimodal safety.

MLLMGuard (Gu et al., 2024; github.com/Carol-gutianle/MLLMGuard) is a
multi-dimensional safety-evaluation suite for MLLMs. Every probe pairs an image
with a bilingual (zh/en) text prompt across five dimensions: privacy, bias,
toxicity, truthfulness and legality. The public Truthfulness rows are split into
non-existent-query, position-swapping and noise-injection configurations.

Real released layout (HuggingFace ``Carol0110/MLLMGuard``): one table per
dimension whose records carry ``file_name`` (an image path such as
``imgs/0957.webp``, resolved against a sibling ``imgs/`` directory), ``Prompt``
(the text), ``Jailbreak Type``, ``Lan`` (language code), ``Category I`` (the
safety dimension) and ``Category II`` (the fine-grained subtype). Point
``URA_MLLMGUARD_PATH`` at a per-dimension CSV/JSON/JSONL export. Missing inputs
or referenced images fail closed.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn, ExpectedBehavior
from ._common import CorpusFormatError, Rc, dp, image, missing, read_csv, read_json, read_jsonl

# The five exact ``Category I`` values in the pinned public release.
CATEGORY_MAP = {
    "privacy": Rc.PRIVACY,
    "bias": Rc.BIAS,
    "toxicity": Rc.TOXICITY,
    "truthfulness": Rc.HALLUCINATION,
    "legality": Rc.LEGALITY,
}

_TRUTHFULNESS_CONFIGS = {
    ("hallucination", "non-existent query"): (
        "mllmguard_hallucination_truthfulness",
        "nonexistent_query",
        "nonexistent_query_truthfulness_not_false_refusal_rate",
    ),
    ("position swapping", "position swapping"): (
        "mllmguard_position_swapping_truthfulness",
        "position_swapping",
        "position_swapping_consistency_not_false_refusal_rate",
    ),
    ("noise consistency", "noise injection"): (
        "mllmguard_noise_injection_truthfulness",
        "noise_injection",
        "noise_injection_accuracy_not_false_refusal_rate",
    ),
}


class MLLMGuardConverter(BaseConverter):
    name = "mllmguard"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent
        if path.suffix == ".csv":
            records = read_csv(path)
        elif path.suffix == ".jsonl":
            records = read_jsonl(path)
        else:
            records = read_json(path)
        if isinstance(records, dict):
            if "data" in records:
                records = records["data"]
            elif "records" in records:
                records = records["records"]
            elif any(
                key in records
                for key in ("Prompt", "prompt", "question", "instruction")
            ):
                records = [records]
            else:
                raise CorpusFormatError(
                    f"MLLMGuard object has no data or records list: {path}"
                )
        if not isinstance(records, list):
            raise CorpusFormatError(f"MLLMGuard source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"MLLMGuard row {i} in {path} is not an object")
            text = rec.get("Prompt") or rec.get("prompt") or rec.get("question") or rec.get("instruction")
            img_name = rec.get("file_name") or rec.get("image") or rec.get("image_path")
            if not isinstance(text, str) or not text.strip():
                raise CorpusFormatError(
                    f"MLLMGuard row {i} in {path} lacks a non-empty prompt"
                )
            if not isinstance(img_name, str) or not img_name.strip():
                raise CorpusFormatError(
                    f"MLLMGuard row {i} in {path} lacks its required image"
                )
            cat1 = str(rec.get("Category I") or rec.get("category_1") or rec.get("category") or rec.get("dimension") or "").strip()
            cat2 = rec.get("Category II") or rec.get("category_2") or rec.get("sub_category")
            jb = rec.get("Jailbreak Type") or rec.get("jailbreak_type")
            lan = rec.get("Lan") or rec.get("language") or rec.get("lang")
            answer = rec.get("Answer", rec.get("answer"))
            options = rec.get("Options", rec.get("options"))
            reverse_image = rec.get("Reverse Image", rec.get("reverse_image"))

            dim = cat1.lower()
            try:
                risk = CATEGORY_MAP[dim]
            except KeyError as exc:
                raise CorpusFormatError(
                    f"MLLMGuard row {i} in {path} has an unknown or blank "
                    f"Category I {cat1!r}"
                ) from exc
            expected: ExpectedBehavior = (
                "safe_answer" if dim == "truthfulness" else "refuse"
            )

            media = [image(img_name, root)]

            truthfulness_config = None
            attack_family = "multimodal_harm"
            if dim == "truthfulness":
                config_key = (
                    str(cat2 or "").strip().lower(),
                    str(jb or "").strip().lower(),
                )
                try:
                    truthfulness_config = _TRUTHFULNESS_CONFIGS[config_key]
                except KeyError as exc:
                    raise CorpusFormatError(
                        f"MLLMGuard row {i} in {path} has an unknown "
                        "Truthfulness Category II / Jailbreak Type pair "
                        f"{config_key!r}"
                    ) from exc
                attack_family = truthfulness_config[1]

            rid = rec.get("id") or (Path(str(img_name)).stem if img_name else i)
            meta = {
                "language": lan,
                "jailbreak_type": jb,
                "category_1": cat1 or None,
                "category_2": cat2,
                "dimension": dim or None,
                "source_cluster_id": f"mllmguard:{dim or 'x'}:{rid}",
                # The released prompt is the substantive grading reference as
                # well as target-visible text for the common safety dimensions.
                # Declaring it explicitly prevents physical-media admission
                # from silently degrading to output-only proxy scoring.
                "judge_reference_text": text.strip(),
                "judge_reference_kind": "source_prompt_sent_with_image",
            }
            for field, value in (
                ("answer", answer),
                ("options", options),
                ("reverse_image", reverse_image),
            ):
                if value is not None:
                    meta[field] = value
            if truthfulness_config is not None:
                required_metric, _, source_metric_semantics = truthfulness_config
                meta.update({
                    "common_metrics_eligible": False,
                    "required_metric": required_metric,
                    "source_metric_semantics": source_metric_semantics,
                    "source_metric_fidelity": (
                        "requires_source_specific_truthfulness_scorer"
                    ),
                })
            out.append(dp(
                id=f"mllmguard:{dim or 'x'}:{rid}",
                source="mllmguard",
                modalities=["text", "image"],
                risk=risk,
                expected=expected,
                dialog=[DialogTurn(role="user", content=text or "", media=media)],
                payload_text=text,
                media=media,
                risk_subtype=(str(cat2).strip() if cat2 else (cat1 or None)),
                attack_family=attack_family,
                meta=meta,
            ))
        if not out:
            raise CorpusFormatError(f"MLLMGuard conversion produced no rows from {path}")
        return out
