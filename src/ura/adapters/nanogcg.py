"""nanoGCG engine adapter: white-box GCG adversarial-suffix optimization.

nanoGCG (GraySwanAI, MIT; ``pip install nanogcg``) is a lightweight implementation
of Greedy Coordinate Gradient (GCG; Zou et al. 2023, "Universal and Transferable
Adversarial Attacks on Aligned Language Models"). It optimizes an adversarial token
*suffix* that, appended to a harmful request, drives an aligned model toward an
affirmative target continuation. In URA-Bench it represents the white-box,
gradient-based jailbreak family (thesis II.4.x; OWASP LLM01 Prompt Injection /
jailbreak; RiskCategory.JAILBREAK).

Scope: GCG is a *white-box* attack. It applies only to open-weight targets whose
weights and tokenizer you control locally, and it needs a Hugging Face causal LM
plus a GPU to run the gradient search. It cannot be pointed at a closed API target.

Safety (thesis N5, III.2.4): this adapter operates in attack-*generation* mode. It
materialises the adversarial-suffix-appended prompt as an Attempt for the target to
be judged on; it never executes a live exploit against a deployed/third-party
system. When a precomputed suffix is supplied it runs fully offline (no model load,
no optimization). Otherwise the GCG search is performed against the local
open-weight model via a lazy import of nanogcg. Authorized use only.

The heavy dependencies (nanogcg + transformers + torch) are imported lazily via
``_require`` inside the call path, so this module imports with only stdlib +
pydantic present and raises a clear RuntimeError when they are absent.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt, _require

# Classic GCG affirmative target continuation (Zou et al. 2023). Overridable per
# DataPoint via meta['gcg_target'].
_DEFAULT_TARGET = "Sure, here is"


class NanoGCGAttacker(BaseAttacker):
    """Optimize a GCG adversarial suffix and emit the suffixed prompt as an Attempt.

    White-box only: requires an open-weight Hugging Face target model + GPU. Pass a
    precomputed ``suffix`` to run fully offline (seed mode); otherwise nanogcg runs
    the gradient search against ``model_id`` (lazy import). No live exploit is ever
    executed against a deployed system (thesis N5).
    """

    name = "nanogcg"

    def __init__(
        self,
        model_id: str = "meta-llama/Llama-2-7b-chat-hf",
        suffix: str | None = None,
        num_steps: int = 250,
        search_width: int = 512,
        topk: int = 256,
    ) -> None:
        # HF id of the white-box open-weight target the suffix is optimized against.
        self.model_id = model_id
        # Precomputed adversarial suffix; when set, generate() is fully offline.
        self.suffix = suffix
        self.num_steps = num_steps
        self.search_width = search_width
        self.topk = topk

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        request = datapoint.payload_text or datapoint.payload_code or ""
        target = datapoint.meta.get("gcg_target", _DEFAULT_TARGET)
        suffix, mode = self._suffix(request, target, budget)
        prompt = f"{request} {suffix}".strip()
        yield _attempt(
            datapoint,
            self.name,
            strategy=f"gcg:{self.model_id}",
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={
                "model_id": self.model_id,
                "suffix": suffix,
                "target": target,
                "num_steps": self.num_steps,
                "search_width": self.search_width,
                "topk": self.topk,
                "mode": mode,
            },
        )

    def _suffix(self, request: str, target: str, budget: AttackBudget) -> tuple[str, str]:
        """Return ``(adversarial_suffix, mode)``.

        Uses the precomputed suffix offline (mode ``"seed"``), or runs the white-box
        GCG search via nanogcg (mode ``"optimize"``; lazy import, needs an HF model +
        GPU). Never contacts a live/third-party target (thesis N5).
        """
        if self.suffix is not None:
            return self.suffix, "seed"
        nanogcg = _require("nanogcg", "NanoGCGAttacker")
        transformers = _require("transformers", "NanoGCGAttacker")
        model = transformers.AutoModelForCausalLM.from_pretrained(
            self.model_id, torch_dtype="auto"
        )
        tokenizer = transformers.AutoTokenizer.from_pretrained(self.model_id)
        config = nanogcg.GCGConfig(
            num_steps=self.num_steps,
            search_width=self.search_width,
            topk=self.topk,
            seed=budget.seed,
        )
        result = nanogcg.run(model, tokenizer, request, target, config)
        return result.best_string, "optimize"
