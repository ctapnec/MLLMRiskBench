"""EasyJailbreak 0.1.3 native-result integration.

EasyJailbreak recipes are complete attack experiments: depending on the recipe,
they call an attack model, a target model and an evaluator, and they retain all
three roles in their result ``Instance`` objects.  They are not a documented
target-free prompt-export API.  URA therefore imports the exact JSONL written by
``JailbreakDataset.save_to_jsonl`` instead of making a second target call and
silently replacing EasyJailbreak's native evaluator.

Authoritative upstream contracts:

* https://github.com/EasyJailbreak/EasyJailbreak
* ``easyjailbreak/attacker/__init__.py`` (the exported recipe registry)
* ``easyjailbreak/datasets/jailbreak_datasets.py`` (``save_to_jsonl``)
* ``setup.py`` (package version 0.1.3 and GPL-3.0 license)

The import is deliberately strict.  It requires the exact upstream commit,
recipe and model roles, a predeclared record count, and optionally a preregistered
file digest.  Every response and native boolean evaluation is preserved.  The
result stays common-metric- and Runner-replay-ineligible because the upstream
evaluator is part of the native estimand.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from ..data_models import Attempt, DataPoint
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
)
from ._native_artifacts import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    NativeArtifactFile,
    NativeEngineCase,
    NativeEngineRun,
    json_sha256,
    read_utf8_artifact,
    require_expected_sha256,
    strict_json_loads,
)
from .base import AttackBudget, BaseAttacker


EASYJAILBREAK_REPOSITORY = "https://github.com/EasyJailbreak/EasyJailbreak"
EASYJAILBREAK_VERSION = "0.1.3"
EASYJAILBREAK_NATIVE_SCHEMA = "easyjailbreak:JailbreakDataset.save_to_jsonl/0.1.3"
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# Exact public exports in easyjailbreak/attacker/__init__.py.  This is a registry,
# not a fuzzy module/class search: a typo or future API drift must fail closed.
EASYJAILBREAK_RECIPES: dict[str, str] = {
    "AutoDAN": "easyjailbreak.attacker.AutoDAN_Liu_2023.AutoDAN",
    "Cipher": "easyjailbreak.attacker.Cipher_Yuan_2023.Cipher",
    "CodeChameleon": "easyjailbreak.attacker.CodeChameleon_2024.CodeChameleon",
    "DeepInception": "easyjailbreak.attacker.DeepInception_Li_2023.DeepInception",
    "GCG": "easyjailbreak.attacker.GCG_Zou_2023.GCG",
    "GPTFuzzer": "easyjailbreak.attacker.Gptfuzzer_yu_2023.GPTFuzzer",
    "ICA": "easyjailbreak.attacker.ICA_wei_2023.ICA",
    "Jailbroken": "easyjailbreak.attacker.Jailbroken_wei_2023.Jailbroken",
    "MJP": "easyjailbreak.attacker.MJP_Li_2023.MJP",
    "Multilingual": "easyjailbreak.attacker.Multilingual_Deng_2023.Multilingual",
    "PAIR": "easyjailbreak.attacker.PAIR_chao_2023.PAIR",
    "ReNeLLM": "easyjailbreak.attacker.ReNeLLM_ding_2023.ReNeLLM",
    "TAP": "easyjailbreak.attacker.TAP_Mehrotra_2023.TAP",
}


class _EasyJailbreakRecord(BaseModel):
    """Exact fields emitted by upstream ``save_to_jsonl``."""

    model_config = ConfigDict(extra="forbid", strict=True)

    jailbreak_prompt: str
    query: str
    target_responses: list[str]
    eval_results: list[bool | int]

    @field_validator("jailbreak_prompt", "query")
    @classmethod
    def _nonblank_prompt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("EasyJailbreak prompts and queries must not be blank")
        return value


def _validated_binary_results(values: list[bool | int], *, line_no: int) -> list[bool]:
    normalized: list[bool] = []
    for index, value in enumerate(values):
        if isinstance(value, bool):
            normalized.append(value)
        elif isinstance(value, int) and value in (0, 1):
            normalized.append(bool(value))
        else:
            raise ExternalEngineOutputError(
                "EasyJailbreak eval_results must contain only booleans/0/1 "
                f"(line {line_no}, index {index})"
            )
    return normalized


class EasyJailbreakAttacker(BaseAttacker):
    """Import a complete EasyJailbreak recipe run without changing its estimand.

    Execute one exact upstream recipe in a pinned EasyJailbreak 0.1.3 checkout,
    retain its complete ``attack_results`` dataset, and call upstream
    ``attack_results.save_to_jsonl(path)``.  Then configure this importer with
    the same recipe and model-role identities and call :meth:`import_run`.

    ``generate`` intentionally rejects use through ``Runner``.  EasyJailbreak's
    recipes own target calls and native evaluation; treating their saved prompt
    as a fresh URA attack would be a different transfer experiment.
    """

    name = "easyjailbreak"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        *,
        recipe: str = "ReNeLLM",
        target_model: str | None = None,
        attack_model: str | None = None,
        eval_model: str | None = None,
        upstream_version: str = EASYJAILBREAK_VERSION,
    ) -> None:
        if recipe not in EASYJAILBREAK_RECIPES:
            raise ValueError(
                "EasyJailbreak recipe must be an exact audited export: "
                + ", ".join(EASYJAILBREAK_RECIPES)
            )
        if upstream_version != EASYJAILBREAK_VERSION:
            raise ValueError(
                f"EasyJailbreak package must be pinned to {EASYJAILBREAK_VERSION}"
            )
        for role, model in (("target", target_model), ("evaluator", eval_model)):
            if model is not None and (
                not isinstance(model, str) or not model.strip()
            ):
                raise ValueError(f"EasyJailbreak {role} model identity must not be blank")
        if attack_model is not None and (
            not isinstance(attack_model, str) or not attack_model.strip()
        ):
            raise ValueError(
                "EasyJailbreak attack model must be nonblank or explicitly None"
            )
        self.recipe = recipe
        self.target_model = target_model
        self.attack_model = attack_model
        self.eval_model = eval_model
        self.upstream_version = upstream_version

    @property
    def upstream_recipe_class(self) -> str:
        return EASYJAILBREAK_RECIPES[self.recipe]

    def import_run(
        self,
        result_jsonl: str | Path,
        *,
        upstream_revision: str,
        expected_records: int,
        expected_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import the complete upstream ``save_to_jsonl`` output.

        ``expected_records`` is mandatory and must come from the frozen native
        run plan.  This prevents a truncated prefix from being accepted merely
        because every remaining JSON line happens to be valid.
        """

        if not _COMMIT_RE.fullmatch(upstream_revision):
            raise ValueError(
                "EasyJailbreak upstream_revision must be a full 40-hex Git commit"
            )
        if isinstance(expected_records, bool) or not isinstance(expected_records, int):
            raise ValueError("EasyJailbreak expected_records must be an integer")
        if expected_records < 1:
            raise ValueError("EasyJailbreak expected_records must be positive")
        if self.target_model is None or self.eval_model is None:
            raise ValueError(
                "EasyJailbreak import requires explicit target_model and eval_model identities"
            )

        path, file_bytes, text = read_utf8_artifact(
            Path(result_jsonl), max_bytes=max_artifact_bytes
        )
        file_digest = require_expected_sha256(
            file_bytes, expected_sha256, role="EasyJailbreak result JSONL"
        )

        records: list[tuple[dict[str, Any], _EasyJailbreakRecord, list[bool]]] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                raise ExternalEngineOutputError(
                    f"EasyJailbreak JSONL contains a blank record at line {line_no}"
                )
            try:
                value = strict_json_loads(line)
                record = _EasyJailbreakRecord.model_validate(value)
            except (json.JSONDecodeError, ValueError, ValidationError) as exc:
                raise ExternalEngineOutputError(
                    f"invalid EasyJailbreak JSONL record at line {line_no}: {exc}"
                ) from exc
            if not record.target_responses:
                raise ExternalEngineOutputError(
                    f"EasyJailbreak line {line_no} has no target response"
                )
            results = _validated_binary_results(record.eval_results, line_no=line_no)
            if len(results) != len(record.target_responses):
                raise ExternalEngineOutputError(
                    f"EasyJailbreak line {line_no} response/evaluation counts differ"
                )
            assert isinstance(value, dict)  # guaranteed by Pydantic validation
            records.append((value, record, results))

        if len(records) != expected_records:
            raise ExternalEngineOutputError(
                "EasyJailbreak result count mismatch: "
                f"expected {expected_records}, observed {len(records)}"
            )

        run_id = f"easyjailbreak:{self.recipe}:{file_digest[:20]}"
        cases: list[NativeEngineCase] = []
        successes = 0
        evaluations = 0
        blank_target_responses = 0
        for index, (raw, record, results) in enumerate(records, start=1):
            successes += sum(results)
            evaluations += len(results)
            blank_target_responses += sum(
                not response.strip() for response in record.target_responses
            )
            if all(results):
                outcome = "all_native_evaluations_jailbreak"
            elif any(results):
                outcome = "mixed_native_evaluations"
            else:
                outcome = "no_native_evaluation_jailbreak"
            cases.append(
                NativeEngineCase(
                    id=f"{run_id}:line{index}",
                    source_run_id=run_id,
                    target_model=self.target_model,
                    attack_method=f"easyjailbreak:{self.recipe}",
                    original_input=record.query,
                    adversarial_input=record.jailbreak_prompt,
                    target_outputs=record.target_responses,
                    native_outcome=outcome,
                    native_scores={
                        "native_jailbreak_count": sum(results),
                        "native_evaluation_count": len(results),
                        "native_success_fraction": sum(results) / len(results),
                    },
                    native_details={
                        "native_eval_results": results,
                        "target_output_states": [
                            "blank" if not response.strip() else "text"
                            for response in record.target_responses
                        ],
                        "jailbreak_prompt_may_be_template": "{query}"
                        in record.jailbreak_prompt,
                        "recipe_class": self.upstream_recipe_class,
                        "full_native_record": raw,
                    },
                    source_artifact_role="attack_results",
                    source_record=f"{path.name}:line{index}",
                    source_record_sha256=json_sha256(raw),
                )
            )

        roles = {"target": self.target_model, "evaluator": self.eval_model}
        if self.attack_model is not None:
            roles["attack"] = self.attack_model
        return NativeEngineRun(
            engine="easyjailbreak",
            native_schema=EASYJAILBREAK_NATIVE_SCHEMA,
            native_run_id=run_id,
            upstream_repository=EASYJAILBREAK_REPOSITORY,
            upstream_version=self.upstream_version,
            upstream_revision=upstream_revision.lower(),
            source_artifacts=[
                NativeArtifactFile(
                    role="attack_results",
                    path=str(path),
                    sha256=file_digest,
                    bytes=len(file_bytes),
                    records=len(records),
                )
            ],
            target_models=[self.target_model],
            model_roles=roles,
            cases=cases,
            native_aggregates={
                "recipe": self.recipe,
                "recipe_class": self.upstream_recipe_class,
                "native_jailbreak_count": successes,
                "native_evaluation_count": evaluations,
                "native_success_fraction": successes / evaluations,
            },
            import_accounting={
                "expected_records": expected_records,
                "imported_records": len(records),
                "target_responses": evaluations,
                "blank_target_responses": blank_target_responses,
                "native_evaluations": evaluations,
            },
            measurement_semantics=(
                "EasyJailbreak source-native recipe, target and evaluator results; "
                "not URA common ASR/FRR and not a prompt-only Runner replay"
            ),
        )

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "EasyJailbreak is supported through import_run(result_jsonl, ...). "
            "BaseAttacker.generate is inapplicable because the audited 0.1.3 recipes "
            "perform their own attack-model, target-model and evaluator calls."
        )


__all__ = [
    "EASYJAILBREAK_NATIVE_SCHEMA",
    "EASYJAILBREAK_RECIPES",
    "EASYJAILBREAK_REPOSITORY",
    "EASYJAILBREAK_VERSION",
    "EasyJailbreakAttacker",
]
