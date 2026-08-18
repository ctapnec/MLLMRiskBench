"""Auditable nanoGCG adversarial-suffix generation.

nanoGCG optimizes a suffix against a Hugging Face causal language model whose
weights are locally available.  In a URA run against a different target (for
example Fable or GPT-5.6 Sol), that is a *surrogate-transfer attack*, not a
white-box attack on the evaluated hosted model.  A supplied suffix is an exact
precomputed replay condition.  Both conditions are named in every Attempt.

The live optimization path preserves the upstream ``GCGResult`` fields
(``best_loss``, per-step ``losses`` and per-step ``strings``), the immutable
surrogate revision and package version.  Empty or malformed results fail closed.
Heavy GPU dependencies remain lazy imports.
"""
from __future__ import annotations

import math
import os
import re
from collections.abc import Iterable
from importlib import metadata
from typing import Any

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint
from ._engine_common import ExternalEngineOutputError, _attempt, _require
from .base import AttackBudget, BaseAttacker

_DEFAULT_TARGET = "Sure, here is"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")


class NanoGCGAttacker(BaseAttacker):
    """Generate a pinned nanoGCG suffix or replay an explicitly supplied one.

    ``model_revision`` is mandatory for optimization and should be an immutable
    Hugging Face commit.  ``suffix`` bypasses all model loading; callers should
    use ``suffix_source`` to identify the paper/artifact/run that produced it.
    """

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
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError("nanoGCG surrogate model_id must be non-blank")
        if model_revision is not None and (
            not isinstance(model_revision, str) or not model_revision.strip()
        ):
            raise ValueError("nanoGCG model_revision must be non-blank when supplied")
        if suffix is not None and (not isinstance(suffix, str) or not suffix.strip()):
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
        self._model_runtime = model_runtime
        self._model: Any = None
        self._tokenizer: Any = None
        self._nanogcg_module: Any = None
        self._resolved_model_revision: str | None = None
        self._nanogcg_version: str | None = None
        if self.suffix is None and (
            self.model_revision is None
            or _COMMIT_RE.fullmatch(self.model_revision) is None
        ):
            raise ValueError(
                "nanoGCG optimization requires immutable model_revision as a "
                "40-64 hex Hugging Face commit"
            )

    def preflight(self) -> dict[str, Any]:
        """Load and post-verify the surrogate without optimizing a suffix."""

        if self.suffix is not None:
            return {
                "component": self.name,
                "mode": "precomputed_suffix_replay",
                "model": self.model_id,
                "revision": self.model_revision,
            }
        self._ensure_surrogate_loaded()
        return {
            "component": self.name,
            "mode": "surrogate_transfer",
            "model": self.model_id,
            "revision": self._resolved_model_revision,
            "nanogcg_version": self._nanogcg_version,
        }

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        request = datapoint.payload_text or datapoint.payload_code or ""
        if not request.strip():
            raise ExternalEngineOutputError("nanoGCG received a blank attack request")
        target = datapoint.meta.get("gcg_target", _DEFAULT_TARGET)
        if not isinstance(target, str) or not target.strip():
            raise ExternalEngineOutputError("nanoGCG target continuation is blank")

        suffix, evidence = self._suffix(request, target, budget)
        prompt = f"{request} {suffix}".strip()
        if prompt == request:
            raise ExternalEngineOutputError("nanoGCG emitted the unchanged seed prompt")

        semantics = evidence["attack_semantics"]
        yield _attempt(
            datapoint,
            self.name,
            strategy=f"gcg:{semantics}:{self.model_id}",
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={
                "surrogate_model_id": self.model_id,
                "requested_surrogate_revision": self.model_revision,
                "suffix": suffix,
                "target_continuation": target,
                "num_steps": self.num_steps,
                "search_width": self.search_width,
                "topk": self.topk,
                "device": self.device,
                "torch_dtype": self.torch_dtype,
                **evidence,
            },
        )

    def _suffix(
        self, request: str, target: str, budget: AttackBudget
    ) -> tuple[str, dict[str, Any]]:
        if self.suffix is not None:
            return self.suffix, {
                "mode": "precomputed",
                "attack_semantics": "precomputed_suffix_replay",
                "suffix_source": self.suffix_source,
                "resolved_surrogate_revision": self.model_revision,
                "nanogcg_version": None,
                "best_loss": None,
                "losses": [],
                "optimization_strings": [],
            }

        (
            nanogcg,
            model,
            tokenizer,
            resolved_revision,
            package_version,
        ) = self._ensure_surrogate_loaded()

        config = nanogcg.GCGConfig(
            num_steps=self.num_steps,
            search_width=self.search_width,
            topk=self.topk,
            seed=budget.seed,
        )
        result = self._model_runtime.private_execution(
            "nanogcg_surrogate",
            lambda: nanogcg.run(model, tokenizer, request, target, config),
        )
        best_string, best_loss, losses, strings = self._validate_result(result)
        return best_string, {
            "mode": "optimize",
            "attack_semantics": "surrogate_transfer",
            "suffix_source": "nanogcg_optimization",
            "resolved_surrogate_revision": resolved_revision,
            "nanogcg_version": package_version,
            "best_loss": best_loss,
            "losses": losses,
            "optimization_strings": strings,
        }

    def _ensure_surrogate_loaded(
        self,
    ) -> tuple[Any, Any, Any, str, str]:
        if (
            self._model is not None
            and self._tokenizer is not None
            and self._nanogcg_module is not None
            and self._resolved_model_revision is not None
            and self._nanogcg_version is not None
        ):
            return (
                self._nanogcg_module,
                self._model,
                self._tokenizer,
                self._resolved_model_revision,
                self._nanogcg_version,
            )
        if self._model_runtime is None:
            raise RuntimeError(
                "nanoGCG optimization requires an admitted managed-model runtime; "
                "implicit Hugging Face downloads are disabled"
            )
        from ..model_acquisition_runtime import hf_offline_environment_overrides

        # Transformers and huggingface_hub may cache offline policy on import.
        os.environ.update(hf_offline_environment_overrides())

        nanogcg = _require("nanogcg", "NanoGCGAttacker")
        transformers = _require("transformers", "NanoGCGAttacker")
        torch = _require("torch", "NanoGCGAttacker")
        dtype = getattr(torch, self.torch_dtype, None)
        if dtype is None:
            raise RuntimeError(f"installed torch lacks dtype {self.torch_dtype!r}")
        if self.device.startswith("cuda") and not torch.cuda.is_available():
            raise RuntimeError("nanoGCG optimization requested CUDA but none is available")

        from ..model_acquisition import nanogcg_requirement
        from ..model_acquisition_runtime import (
            transformers_managed_snapshot_args,
        )

        requirement = nanogcg_requirement({
            "model_id": self.model_id,
            "model_revision": self.model_revision,
        })
        if requirement is None:  # pragma: no cover - suffix returned above
            raise RuntimeError("nanoGCG managed requirement is unexpectedly absent")

        def construct(snapshot: Any) -> tuple[Any, Any]:
            local_model, local_only = transformers_managed_snapshot_args(snapshot)
            model = transformers.AutoModelForCausalLM.from_pretrained(
                local_model,
                torch_dtype=dtype,
                trust_remote_code=False,
                **local_only,
            ).to(self.device)
            model.eval()
            tokenizer = transformers.AutoTokenizer.from_pretrained(
                local_model,
                trust_remote_code=False,
                **local_only,
            )
            return model, tokenizer

        def cleanup(loaded: tuple[Any, Any]) -> None:
            model, tokenizer = loaded
            operations = (
                getattr(tokenizer, "close", None),
                getattr(model, "close", None),
                (
                    (lambda: model.to("cpu"))
                    if callable(getattr(model, "to", None))
                    else None
                ),
                (
                    torch.cuda.empty_cache
                    if torch.cuda.is_available()
                    else None
                ),
            )
            for operation in operations:
                if callable(operation):
                    try:
                        operation()
                    except Exception:
                        pass

        model, tokenizer = self._model_runtime.construct(
            requirement,
            construct,
            cleanup=cleanup,
        )
        resolved_revision = self._resolved_revision(model, tokenizer)
        package_version = self._package_version(nanogcg)
        self._model = model
        self._tokenizer = tokenizer
        self._nanogcg_module = nanogcg
        self._resolved_model_revision = resolved_revision
        self._nanogcg_version = package_version
        return nanogcg, model, tokenizer, resolved_revision, package_version

    def _resolved_revision(self, model: Any, tokenizer: Any) -> str:
        model_commit = getattr(getattr(model, "config", None), "_commit_hash", None)
        tokenizer_commit = getattr(tokenizer, "init_kwargs", {}).get("_commit_hash")
        commits = {
            value
            for value in (model_commit, tokenizer_commit)
            if isinstance(value, str) and value.strip()
        }
        if len(commits) > 1:
            raise ExternalEngineOutputError(
                "nanoGCG model and tokenizer resolved to different revisions"
            )
        if commits:
            resolved = commits.pop()
        elif self.model_revision and _COMMIT_RE.fullmatch(self.model_revision):
            resolved = self.model_revision
        else:
            raise ExternalEngineOutputError(
                "nanoGCG could not resolve the surrogate model commit"
            )
        if (
            self.model_revision
            and _COMMIT_RE.fullmatch(self.model_revision)
            and resolved.lower() != self.model_revision.lower()
        ):
            raise ExternalEngineOutputError(
                "nanoGCG resolved surrogate revision differs from the requested commit"
            )
        return resolved

    @staticmethod
    def _package_version(nanogcg: Any) -> str:
        module_version = getattr(nanogcg, "__version__", None)
        if isinstance(module_version, str) and module_version.strip():
            return module_version.strip()
        try:
            return metadata.version("nanogcg")
        except metadata.PackageNotFoundError as exc:
            raise ExternalEngineOutputError(
                "nanoGCG package version cannot be established"
            ) from exc

    @staticmethod
    def _validate_result(result: Any) -> tuple[str, float, list[float], list[str]]:
        best_string = getattr(result, "best_string", None)
        best_loss = getattr(result, "best_loss", None)
        losses = getattr(result, "losses", None)
        strings = getattr(result, "strings", None)
        if not isinstance(best_string, str) or not best_string.strip():
            raise ExternalEngineOutputError("nanoGCG returned no best_string")
        if (
            not isinstance(best_loss, (int, float))
            or isinstance(best_loss, bool)
            or not math.isfinite(float(best_loss))
        ):
            raise ExternalEngineOutputError("nanoGCG returned an invalid best_loss")
        if not isinstance(losses, list) or not isinstance(strings, list) or not losses:
            raise ExternalEngineOutputError("nanoGCG returned no optimization trace")
        if len(losses) != len(strings):
            raise ExternalEngineOutputError(
                "nanoGCG loss and string traces have different lengths"
            )
        clean_losses: list[float] = []
        clean_strings: list[str] = []
        for index, (loss, string) in enumerate(zip(losses, strings, strict=True)):
            if (
                not isinstance(loss, (int, float))
                or isinstance(loss, bool)
                or not math.isfinite(float(loss))
            ):
                raise ExternalEngineOutputError(
                    f"nanoGCG trace contains invalid loss at step {index}"
                )
            if not isinstance(string, str) or not string.strip():
                raise ExternalEngineOutputError(
                    f"nanoGCG trace contains blank string at step {index}"
                )
            clean_losses.append(float(loss))
            clean_strings.append(string)
        if best_string not in clean_strings or float(best_loss) != min(clean_losses):
            raise ExternalEngineOutputError(
                "nanoGCG best result is inconsistent with its optimization trace"
            )
        best_index = clean_losses.index(min(clean_losses))
        if clean_strings[best_index] != best_string:
            raise ExternalEngineOutputError(
                "nanoGCG best_string does not match the minimum-loss step"
            )
        return best_string, float(best_loss), clean_losses, clean_strings
