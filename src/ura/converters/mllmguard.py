"""MLLMGuard converter: multi-dimensional multimodal safety.

MLLMGuard (Gu et al., 2024; github.com/Carol-gutianle/MLLMGuard) is a
multi-dimensional safety-evaluation suite for MLLMs. Every probe pairs an image
with a (bilingual, zh/en) text prompt engineered to elicit an unsafe response
across seven dimensions: privacy, bias, toxicity, hallucination, legality, plus
two robustness perturbations - position-swapping and noise-injection.

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

# MLLMGuard dimension / "Category I" -> internal taxonomy (default TOXICITY).
CATEGORY_MAP = {
    "privacy": Rc.PRIVACY,
    "bias": Rc.BIAS,
    "toxicity": Rc.TOXICITY,
    "hallucination": Rc.HALLUCINATION,
    "legality": Rc.LEGALITY,
    # robustness perturbations wrap a harmful probe -> treat as jailbreak-style
    "position-swapping": Rc.JAILBREAK,
    "position_swapping": Rc.JAILBREAK,
    "position swapping": Rc.JAILBREAK,
    "noise-injection": Rc.JAILBREAK,
    "noise_injection": Rc.JAILBREAK,
    "noise injection": Rc.JAILBREAK,
}

# hallucination probes want a truthful (not refused) answer; everything else refuse.
EXPECTED_MAP: dict[str, ExpectedBehavior] = {
    "hallucination": "safe_answer",
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
        # the dimension is sometimes only recoverable from the per-dimension filename
        split = path.stem.lower().replace("_", "-")
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

            dim = cat1.lower() or split
            risk = CATEGORY_MAP.get(dim, CATEGORY_MAP.get(split, Rc.TOXICITY))
            expected: ExpectedBehavior = EXPECTED_MAP.get(dim, EXPECTED_MAP.get(split, "refuse"))

            media = [image(img_name, root)]

            tag = f"{dim} {split}"
            if "position" in tag:
                attack_family = "position_swapping"
            elif "noise" in tag:
                attack_family = "noise_injection"
            else:
                attack_family = "multimodal_harm"

            rid = rec.get("id") or (Path(str(img_name)).stem if img_name else i)
            meta = {
                "language": lan,
                "jailbreak_type": jb,
                "category_1": cat1 or None,
                "category_2": cat2,
                "dimension": dim or None,
                "source_cluster_id": f"mllmguard:{dim or 'x'}:{rid}",
            }
            if dim == "hallucination" or split == "hallucination":
                # Hallucination is a truthfulness construct, not a benign-utility
                # probe. Treating ``safe_answer`` rows as common-metric eligible
                # silently turns them into false-refusal observations. Keep the
                # prompts convertible, but require a substantive source scorer;
                # the scored Runner preflight then rejects them until one exists.
                meta.update({
                    "common_metrics_eligible": False,
                    "required_metric": "mllmguard_hallucination_truthfulness",
                    "source_metric_runtime": (
                        "upstream_GuardRank_RoBERTa-large_hallucination_classifier_"
                        "with_official_weights"
                    ),
                    "source_metric_semantics": (
                        "GuardRank_hallucination_component_not_false-refusal_rate"
                    ),
                    "source_metric_fidelity": "requires_upstream_GuardRank_checkpoint",
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
