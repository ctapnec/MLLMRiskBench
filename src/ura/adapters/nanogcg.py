"""Auditable nanoGCG precomputed-suffix replay.

Stage 1 intentionally admits only a supplied suffix.  Live optimization must
load nanoGCG, torch, transformers, and a managed surrogate in the same isolated
process that verifies the model seal.  That Stage 2 handshake does not exist yet,
so live mode fails before package import, model construction, or target use.  No
in-process fallback remains in this adapter.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint
from ._engine_common import ExternalEngineOutputError, _attempt
from .base import AttackBudget, BaseAttacker

_DEFAULT_TARGET = "Sure, here is"
LIVE_NANOGCG_DISABLED_MESSAGE = (
    "live nanoGCG optimization is disabled until the isolated managed-snapshot "
    "load/verify/optimize handshake is implemented"
)


class NanoGCGAttacker(BaseAttacker):
    """Replay one explicitly supplied suffix without invoking nanoGCG."""

    name = "nanogcg"

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
        self.device = device.strip()
        self.torch_dtype = torch_dtype
        self.num_steps = num_steps
        self.search_width = search_width
        self.topk = topk

    def preflight(self) -> dict[str, Any]:
        return {
            "component": self.name,
            "mode": "precomputed_suffix_replay",
            "model": self.model_id,
            "revision": self.model_revision,
            "framework_execution": "not_invoked",
        }

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        request = datapoint.payload_text or datapoint.payload_code or ""
        if not request.strip():
            raise ExternalEngineOutputError("nanoGCG received a blank attack request")
        target = datapoint.meta.get("gcg_target", _DEFAULT_TARGET)
        if not isinstance(target, str) or not target.strip():
            raise ExternalEngineOutputError("nanoGCG target continuation is blank")
        prompt = f"{request} {self.suffix}".strip()
        if prompt == request:
            raise ExternalEngineOutputError("nanoGCG emitted the unchanged seed prompt")

        yield _attempt(
            datapoint,
            self.name,
            strategy=f"gcg:precomputed_suffix_replay:{self.model_id}",
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={
                "surrogate_model_id": self.model_id,
                "requested_surrogate_revision": self.model_revision,
                "suffix": self.suffix,
                "target_continuation": target,
                "num_steps": self.num_steps,
                "search_width": self.search_width,
                "topk": self.topk,
                "device": self.device,
                "torch_dtype": self.torch_dtype,
                "mode": "precomputed",
                "attack_semantics": "precomputed_suffix_replay",
                "suffix_source": self.suffix_source,
                "resolved_surrogate_revision": self.model_revision,
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
]
