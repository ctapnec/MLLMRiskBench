"""MLLMGuard converter: multi-dimensional multimodal safety.

MLLMGuard (Gu et al., 2024; github.com/AI45Lab/MLLMGuard) is a
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

_PINNED_CODE_REVISION = "ef14fe44f34975e5c74f92d793536f0b0f2bc47f"
_PINNED_DATASET_REVISION = "4263487ca736c99292bac92d89f05eb744773450"

_PAIR_PROVENANCE = {
    "nonexistent_query": {
        "source_pair_implementation_location": "utils.py:48-62",
        "source_pair_branch_path_token": "non-existent",
        "source_launcher_dimension_name": "hallucination",
    },
    "position_swapping": {
        "source_pair_implementation_location": "utils.py:36-46",
        "source_pair_branch_path_token": "sequential",
        "source_launcher_dimension_name": "position-swapping",
    },
    "noise_injection": {
        "source_pair_implementation_location": "utils.py:64-79",
        "source_pair_branch_path_token": "noise-consistency",
        "source_launcher_dimension_name": "noise-injection",
    },
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
            cluster = f"mllmguard:{dim or 'x'}:{rid}"
            base_meta = {
                "language": lan,
                "jailbreak_type": jb,
                "category_1": cat1 or None,
                "category_2": cat2,
                "dimension": dim or None,
                "source_cluster_id": cluster,
                "source_record_index": i,
                "source_dataset_revision": _PINNED_DATASET_REVISION,
            }
            for field, value in (
                ("answer", answer),
                ("options", options),
                ("reverse_image", reverse_image),
            ):
                if value is not None:
                    base_meta[field] = value
            variants: list[tuple[str | None, str, str]] = [(None, text, img_name)]
            if truthfulness_config is not None:
                required_metric, _, source_metric_semantics = truthfulness_config
                pair_provenance = _PAIR_PROVENANCE[attack_family]
                base_meta.update({
                    "common_metrics_eligible": False,
                    "required_metric": required_metric,
                    "source_metric_semantics": source_metric_semantics,
                    "source_metric_fidelity": (
                        "requires_source_specific_truthfulness_scorer"
                    ),
                    "source_code_revision": _PINNED_CODE_REVISION,
                    **pair_provenance,
                    "source_pair_conversion_status": (
                        "pinned_intended_pair_static_conversion"
                    ),
                    "official_pair_builder_executed": False,
                    "official_native_launcher_executed": False,
                    "official_task_scorer_executed": False,
                    "source_native_launcher_limitation": (
                        "upstream_dimensions_use_hallucination_noise-injection_"
                        "position-swapping_but_utils_pair_branches_match_"
                        "non-existent_noise-consistency_sequential_path_tokens"
                    ),
                })
                if attack_family == "nonexistent_query":
                    if not isinstance(options, str) or not options.strip():
                        raise CorpusFormatError(
                            f"MLLMGuard hallucination row {i} lacks Options"
                        )
                    variants = [
                        ("open_question", text, img_name),
                        (
                            "multiple_choice",
                            f"{text}(Please answer me with options) {options}",
                            img_name,
                        ),
                    ]
                elif attack_family == "position_swapping":
                    if not isinstance(reverse_image, str) or not reverse_image.strip():
                        raise CorpusFormatError(
                            f"MLLMGuard position-swapping row {i} lacks Reverse Image"
                        )
                    variants = [
                        ("original_image", text, img_name),
                        ("reverse_image", text, reverse_image),
                    ]
                elif attack_family == "noise_injection":
                    if not isinstance(answer, str) or not answer.strip():
                        raise CorpusFormatError(
                            f"MLLMGuard noise-injection row {i} lacks Answer"
                        )
                    original_path = Path(img_name)
                    noise_path = original_path.with_name(
                        f"{original_path.stem}_noise{original_path.suffix}"
                    )
                    variants = [
                        ("original_image", text, img_name),
                        ("noise_image", text, str(noise_path)),
                    ]
                else:  # pragma: no cover - the exact map above is exhaustive
                    raise CorpusFormatError(
                        f"MLLMGuard truthfulness row {i} lacks a paired construct"
                    )

            for variant, variant_prompt, variant_image in variants:
                media = [image(variant_image, root)]
                meta = {
                    **base_meta,
                    # The released variant prompt is both the substantive grading
                    # reference and target-visible text. This keeps physical-media
                    # admission from degrading to output-only proxy scoring.
                    "judge_reference_text": variant_prompt.strip(),
                    "judge_reference_kind": "source_prompt_sent_with_image",
                }
                point_id = cluster
                if variant is not None:
                    point_id = f"{cluster}:{variant}"
                    meta.update({
                        "source_pair_kind": attack_family,
                        "source_pair_member": variant,
                        "source_pair_size": 2,
                    })
                out.append(dp(
                    id=point_id,
                    source="mllmguard",
                    modalities=["text", "image"],
                    risk=risk,
                    expected=expected,
                    dialog=[
                        DialogTurn(role="user", content=variant_prompt, media=media)
                    ],
                    payload_text=variant_prompt,
                    media=media,
                    risk_subtype=(str(cat2).strip() if cat2 else (cat1 or None)),
                    attack_family=attack_family,
                    meta=meta,
                ))
        if not out:
            raise CorpusFormatError(f"MLLMGuard conversion produced no rows from {path}")
        return out
