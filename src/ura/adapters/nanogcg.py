"""Auditable nanoGCG precomputed-suffix replay.

Stage 1 intentionally admits only a supplied suffix.  Live optimization must
load nanoGCG, torch, transformers, and a managed surrogate in the same isolated
process that verifies the model seal.  That Stage 2 handshake does not exist yet,
so live mode fails before package import, model construction, or target use.  No
in-process fallback remains in this adapter.
"""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
    _attempt,
)
from .base import AttackBudget, BaseAttacker

PRECOMPUTED_SURROGATE_UNSPECIFIED = "precomputed-surrogate-unspecified"
LIVE_NANOGCG_DISABLED_MESSAGE = (
    "live nanoGCG optimization is disabled inside Runner; prepare one sealed "
    "suffix with experiments.nanogcg_capture and replay that artifact"
)


class NanoGCGAttacker(BaseAttacker):
    """Replay one explicitly supplied suffix without invoking nanoGCG."""

    name = "nanogcg"
    portable_config_exclude = (
        "device", "model_id", "model_revision", "num_steps", "search_width",
        "topk", "torch_dtype",
    )

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        return text_only_transfer_contract(self.name, datapoint, budget)

    def __init__(
        self,
        model_id: str = "meta-llama/Llama-2-7b-chat-hf",
        *,
        model_revision: str | None = None,
        suffix: str | None = None,
        suffix_source: str | None = None,
        captured_surrogate_id: str | None = None,
        captured_surrogate_revision: str | None = None,
        captured_source_id: str | None = None,
        captured_target: str | None = None,
        device: str = "cuda",
        torch_dtype: str = "float16",
        num_steps: int = 250,
        search_width: int = 512,
        topk: int = 256,
        model_runtime: Any = None,
    ) -> None:
        if suffix is None:
            raise RuntimeError(LIVE_NANOGCG_DISABLED_MESSAGE)
        if model_runtime is not None:
            raise ValueError("precomputed nanoGCG replay does not accept a model runtime")
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError("nanoGCG surrogate model_id must be non-blank")
        if model_revision is not None and (
            not isinstance(model_revision, str) or not model_revision.strip()
        ):
            raise ValueError("nanoGCG model_revision must be non-blank when supplied")
        if not isinstance(suffix, str) or not suffix.strip():
            raise ValueError("nanoGCG suffix must be non-blank when supplied")
        if suffix_source is not None and (
            not isinstance(suffix_source, str) or not suffix_source.strip()
        ):
            raise ValueError("nanoGCG suffix_source must be non-blank when supplied")
        if captured_surrogate_id is not None and (
            not isinstance(captured_surrogate_id, str)
            or not captured_surrogate_id.strip()
        ):
            raise ValueError("nanoGCG captured_surrogate_id must be non-blank")
        if captured_surrogate_revision is not None and (
            not isinstance(captured_surrogate_revision, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", captured_surrogate_revision.strip())
            is None
        ):
            raise ValueError(
                "nanoGCG captured_surrogate_revision must be 40-64 lowercase hex"
            )
        if (captured_surrogate_id is None) != (captured_surrogate_revision is None):
            raise ValueError(
                "nanoGCG captured surrogate ID and revision must be supplied together"
            )
        for field, value in (
            ("captured_source_id", captured_source_id),
            ("captured_target", captured_target),
        ):
            if value is not None and (
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
            ):
                raise ValueError(f"nanoGCG {field} must be non-blank")
        if (captured_source_id is None) != (captured_target is None):
            raise ValueError(
                "nanoGCG captured source ID and target must be supplied together"
            )
        if not isinstance(device, str) or not device.strip():
            raise ValueError("nanoGCG device must be non-blank")
        if torch_dtype not in {"float16", "bfloat16"}:
            raise ValueError("nanoGCG torch_dtype must be float16 or bfloat16")
        for field, value in {
            "num_steps": num_steps,
            "search_width": search_width,
            "topk": topk,
        }.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"nanoGCG {field} must be a positive integer")

        self.model_id = model_id.strip()
        self.model_revision = model_revision.strip().lower() if model_revision else None
        self.suffix = suffix
        self.suffix_source = suffix_source.strip() if suffix_source else None
        self.captured_surrogate_id = (
            captured_surrogate_id.strip() if captured_surrogate_id else None
        )
        self.captured_surrogate_revision = (
            captured_surrogate_revision.strip().lower()
            if captured_surrogate_revision
            else None
        )
        self.captured_source_id = (
            captured_source_id if captured_source_id else None
        )
        self.captured_target = captured_target if captured_target else None
        self.device = device.strip()
        self.torch_dtype = torch_dtype
        self.num_steps = num_steps
        self.search_width = search_width
        self.topk = topk

    def preflight(self) -> dict[str, Any]:
        surrogate = (
            self.captured_surrogate_id or PRECOMPUTED_SURROGATE_UNSPECIFIED
        )
        revision = self.captured_surrogate_revision
        return {
            "component": self.name,
            "mode": "precomputed_suffix_replay",
            "model": surrogate,
            "revision": revision,
            "source_id": self.captured_source_id,
            "framework_execution": "not_invoked",
        }

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        request = datapoint.payload_text or datapoint.payload_code or ""
        if not request.strip():
            raise ExternalEngineOutputError("nanoGCG received a blank attack request")
        if (
            self.captured_source_id is not None
            and datapoint.id != self.captured_source_id
        ):
            raise ExternalEngineConformanceError(
                "nanoGCG captured suffix source differs from the selected row"
            )
        prompt = f"{request} {self.suffix}".strip()
        if prompt == request:
            raise ExternalEngineOutputError("nanoGCG emitted the unchanged seed prompt")

        surrogate = (
            self.captured_surrogate_id or PRECOMPUTED_SURROGATE_UNSPECIFIED
        )
        revision = self.captured_surrogate_revision
        yield _attempt(
            datapoint,
            self.name,
            strategy=f"gcg:precomputed_suffix_replay:{surrogate}",
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={
                "surrogate_model_id": surrogate,
                "requested_surrogate_revision": revision,
                "suffix": self.suffix,
                "captured_source_id": self.captured_source_id,
                "target_continuation": self.captured_target,
                "num_steps": None,
                "search_width": None,
                "topk": None,
                "device": None,
                "torch_dtype": None,
                "mode": "precomputed",
                "attack_semantics": "precomputed_suffix_replay",
                "suffix_source": self.suffix_source,
                "resolved_surrogate_revision": revision,
                "nanogcg_version": None,
                "best_loss": None,
                "losses": [],
                "optimization_strings": [],
                "framework_execution": "not_invoked",
                "engine_runtime": None,
            },
        )


__all__ = [
    "LIVE_NANOGCG_DISABLED_MESSAGE",
    "NanoGCGAttacker",
    "PRECOMPUTED_SURROGATE_UNSPECIFIED",
]
