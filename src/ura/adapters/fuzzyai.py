"""CyberArk FuzzyAI native-run integration.

FuzzyAI is an end-to-end LLM fuzzer, not a target-free mutation library.  Its
official ``fuzzyai fuzz`` command attacks the model supplied with ``-m``, asks
its configured classifiers to evaluate the target responses, and writes a
timestamped result family containing ``raw.jsonl`` and ``report.json``.  The
upstream contract is defined by:

* https://github.com/cyberark/FuzzyAI
* https://github.com/cyberark/FuzzyAI/blob/main/src/fuzzyai/cli.py
* https://github.com/cyberark/FuzzyAI/blob/main/src/fuzzyai/handlers/attacks/models.py
* https://github.com/cyberark/FuzzyAI/blob/main/src/fuzzyai/models/fuzzer_result.py

URA imports that complete native result family.  It validates every raw row,
reconstructs the upstream report categorisation and counters, verifies the
configured attack modes/model, and records content-addressed provenance.  It
does not replay the mutated prompts through ``Runner``: doing so would discard
the measured FuzzyAI response/classification and make a second, different model
call.  FuzzyAI-native outcomes therefore remain source-specific and are not
silently relabelled as common ASR/FRR.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

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


FUZZYAI_REPOSITORY = "https://github.com/cyberark/FuzzyAI"
FUZZYAI_NATIVE_SCHEMA = "fuzzyai-cli-raw+report/main"
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class _RawEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    original_prompt: str
    current_prompt: str
    response: str
    classifications: dict[str, Any]
    extra: dict[str, Any]


class _RawSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_mode: str
    model: str
    system_prompt: str
    entries: list[_RawEntry]

    @field_validator("attack_mode", "model")
    @classmethod
    def _nonblank_identity(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("FuzzyAI attack mode/model must not be blank")
        return value


class _ReportPrompt(BaseModel):
    # Upstream PromptEntry explicitly permits extension fields.
    model_config = ConfigDict(extra="allow")

    original_prompt: str
    original_response: str
    harmful_prompt: str
    harmful_response: str
    classifications: dict[str, Any]


class _ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    harmful_prompts_count: int = Field(ge=0)
    failed_prompts_count: int = Field(ge=0)
    harmful_prompts: list[_ReportPrompt]
    failed_prompts: list[_ReportPrompt]


class _ReportTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_mode: str
    total_prompts_count: int = Field(ge=0)
    models: list[_ReportModel]
    success_rate: int = Field(ge=0, le=100)


class _Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    attacking_techniques: list[_ReportTechnique]

    @field_validator("attack_id")
    @classmethod
    def _nonblank_run_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("FuzzyAI report attack_id must not be blank")
        return value


def _report_prompt(entry: _RawEntry) -> dict[str, Any]:
    original_response = entry.extra.get("original_response", "")
    if not isinstance(original_response, str):
        raise ExternalEngineOutputError(
            "FuzzyAI raw entry extra.original_response must be a string"
        )
    return {
        "original_prompt": entry.original_prompt,
        "original_response": original_response,
        "harmful_prompt": entry.current_prompt,
        "harmful_response": entry.response,
        "classifications": entry.classifications,
    }


def _is_harmful(entry: _RawEntry) -> bool:
    return any(value == 1 for value in entry.classifications.values())


def _is_failed(entry: _RawEntry) -> bool:
    # This deliberately mirrors upstream FuzzerResult.from_attack_summary,
    # including Python's all([]) behaviour for an empty classification map.
    return all(value == 0 for value in entry.classifications.values())


def _expected_report(raw_rows: list[_RawSummary]) -> list[dict[str, Any]]:
    """Reconstruct the current upstream report algorithm exactly."""

    techniques: list[dict[str, Any]] = []
    for summary in raw_rows:
        harmful = [
            _report_prompt(entry) for entry in summary.entries if _is_harmful(entry)
        ]
        unique_failed: dict[str, _RawEntry] = {}
        for entry in summary.entries:
            if _is_failed(entry):
                unique_failed[entry.original_prompt] = entry
        failed = [_report_prompt(entry) for entry in unique_failed.values()]
        model = {
            "name": summary.model,
            "harmful_prompts_count": len(harmful),
            "failed_prompts_count": len(failed),
            "harmful_prompts": harmful,
            "failed_prompts": failed,
        }
        for technique in techniques:
            if technique["attack_mode"] == summary.attack_mode:
                technique["models"].append(model)
                break
        else:
            techniques.append({"attack_mode": summary.attack_mode, "models": [model]})

    for technique in techniques:
        total = sum(
            model["harmful_prompts_count"] + model["failed_prompts_count"]
            for model in technique["models"]
        )
        failed = sum(model["failed_prompts_count"] for model in technique["models"])
        technique["total_prompts_count"] = total
        technique["success_rate"] = int((total - failed) / total * 100) if total else 0
    return techniques


def _core_report(report: _Report) -> list[dict[str, Any]]:
    """Drop only PromptEntry extension fields before exact reconstruction check."""

    def prompt_core(prompt: _ReportPrompt) -> dict[str, Any]:
        return {
            "original_prompt": prompt.original_prompt,
            "original_response": prompt.original_response,
            "harmful_prompt": prompt.harmful_prompt,
            "harmful_response": prompt.harmful_response,
            "classifications": prompt.classifications,
        }

    techniques: list[dict[str, Any]] = []
    for technique in report.attacking_techniques:
        models: list[dict[str, Any]] = []
        for model in technique.models:
            models.append(
                {
                    "name": model.name,
                    "harmful_prompts_count": model.harmful_prompts_count,
                    "failed_prompts_count": model.failed_prompts_count,
                    "harmful_prompts": [
                        prompt_core(prompt) for prompt in model.harmful_prompts
                    ],
                    "failed_prompts": [
                        prompt_core(prompt) for prompt in model.failed_prompts
                    ],
                }
            )
        techniques.append(
            {
                "attack_mode": technique.attack_mode,
                "models": models,
                "total_prompts_count": technique.total_prompts_count,
                "success_rate": technique.success_rate,
            }
        )
    return techniques


class FuzzyAIAttacker(BaseAttacker):
    """Import complete FuzzyAI fuzzer results without changing their estimand.

    Run FuzzyAI separately with its official CLI, retaining the timestamped
    directory that contains ``raw.jsonl`` and ``report.json``.  Then call
    :meth:`import_run` on an adapter configured with the same target model and
    attack-mode codes.  Because upstream ``main`` does not put a version in these
    files, the exact 40-character Git commit is mandatory at import time.

    ``generate`` intentionally remains unavailable.  That method is Runner's
    target-free prompt-generation boundary, which FuzzyAI does not implement.
    """

    name = "fuzzyai"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        attacks: list[str] | None = None,
        model: str = "ollama/llama3",
        cli: str = "fuzzyai",
        credential_env: list[str] | tuple[str, ...] | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        selected = attacks or ["asc", "bon"]
        if not selected or any(
            not isinstance(mode, str) or not mode.strip() for mode in selected
        ):
            raise ValueError("FuzzyAI attacks must contain nonblank mode codes")
        if len(set(selected)) != len(selected):
            raise ValueError("FuzzyAI attack modes must be unique")
        if not isinstance(model, str) or not model.strip() or "/" not in model:
            raise ValueError("FuzzyAI model must use the upstream provider/model form")
        self.attacks = selected
        self.model = model
        self.cli = cli
        self.credential_env = tuple(credential_env or ())
        self.timeout_seconds = timeout_seconds

    def build_native_command(self, prompts_file: str | Path) -> list[str]:
        """Build (but never execute) the documented end-to-end CLI invocation."""

        prompts = Path(prompts_file)
        if not prompts.is_file():
            raise FileNotFoundError(f"FuzzyAI prompt file not found: {prompts}")
        command = [self.cli, "fuzz", "-m", self.model]
        for attack in self.attacks:
            command.extend(["-a", attack])
        command.extend(["-T", str(prompts.resolve())])
        return command

    def import_run(
        self,
        results_dir: str | Path,
        *,
        upstream_revision: str,
        expected_raw_sha256: str | None = None,
        expected_report_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import and cross-validate FuzzyAI's official result pair.

        ``upstream_revision`` is required because the native result format has
        no embedded version/revision field.  Optional expected hashes allow a
        preregistered run manifest to pin the returned files before import.
        """

        if not _COMMIT_RE.fullmatch(upstream_revision):
            raise ValueError(
                "FuzzyAI upstream_revision must be a full 40-hex Git commit"
            )
        root = Path(results_dir).resolve(strict=True)
        if not root.is_dir():
            raise ExternalEngineOutputError(
                f"FuzzyAI results path is not a directory: {root}"
            )
        raw_path, raw_bytes, raw_text = read_utf8_artifact(
            root / "raw.jsonl", max_bytes=max_artifact_bytes
        )
        report_path, report_bytes, report_text = read_utf8_artifact(
            root / "report.json", max_bytes=max_artifact_bytes
        )
        require_expected_sha256(
            raw_bytes, expected_raw_sha256, role="FuzzyAI raw.jsonl"
        )
        require_expected_sha256(
            report_bytes, expected_report_sha256, role="FuzzyAI report.json"
        )

        raw_rows: list[_RawSummary] = []
        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            if not line.strip():
                raise ExternalEngineOutputError(
                    f"FuzzyAI raw.jsonl contains a blank record at line {line_no}"
                )
            try:
                raw_value = strict_json_loads(line)
                summary = _RawSummary.model_validate(raw_value)
            except (json.JSONDecodeError, ValueError, ValidationError) as exc:
                raise ExternalEngineOutputError(
                    f"invalid FuzzyAI raw.jsonl record at line {line_no}: {exc}"
                ) from exc
            if not summary.entries:
                raise ExternalEngineOutputError(
                    f"FuzzyAI raw.jsonl line {line_no} contains no attack entries"
                )
            raw_rows.append(summary)
        if not raw_rows:
            raise ExternalEngineOutputError("FuzzyAI raw.jsonl contains no records")

        try:
            report_value = strict_json_loads(report_text)
            report = _Report.model_validate(report_value)
        except (json.JSONDecodeError, ValueError, ValidationError) as exc:
            raise ExternalEngineOutputError(
                f"invalid FuzzyAI report.json: {exc}"
            ) from exc
        if not report.attacking_techniques:
            raise ExternalEngineOutputError(
                "FuzzyAI report.json has no attacking techniques"
            )

        expected = _expected_report(raw_rows)
        observed = _core_report(report)
        if observed != expected:
            raise ExternalEngineOutputError(
                "FuzzyAI report.json does not reconstruct exactly from raw.jsonl"
            )

        observed_modes = {row.attack_mode for row in raw_rows}
        expected_modes = set(self.attacks)
        if observed_modes != expected_modes:
            raise ExternalEngineOutputError(
                "FuzzyAI attack-mode mismatch: "
                f"configured={sorted(expected_modes)!r}, artifact={sorted(observed_modes)!r}"
            )
        observed_models = {row.model for row in raw_rows}
        if observed_models != {self.model}:
            raise ExternalEngineOutputError(
                "FuzzyAI target-model mismatch: "
                f"configured={self.model!r}, artifact={sorted(observed_models)!r}"
            )

        cases: list[NativeEngineCase] = []
        outcome_counts = {"harmful": 0, "failed": 0, "uncategorized": 0}
        for raw_index, summary in enumerate(raw_rows, start=1):
            for entry_index, entry in enumerate(summary.entries):
                if not entry.original_prompt.strip():
                    raise ExternalEngineOutputError(
                        f"FuzzyAI raw.jsonl:{raw_index} entry {entry_index} has blank original_prompt"
                    )
                if not entry.current_prompt.strip():
                    raise ExternalEngineOutputError(
                        f"FuzzyAI raw.jsonl:{raw_index} entry {entry_index} has blank current_prompt"
                    )
                if not entry.response.strip():
                    raise ExternalEngineOutputError(
                        f"FuzzyAI raw.jsonl:{raw_index} entry {entry_index} has blank response"
                    )
                if _is_harmful(entry):
                    outcome = "harmful"
                elif _is_failed(entry):
                    outcome = "failed"
                else:
                    outcome = "uncategorized"
                outcome_counts[outcome] += 1
                raw_entry = entry.model_dump(mode="json")
                record_digest = json_sha256(raw_entry)
                cases.append(
                    NativeEngineCase(
                        id=f"fuzzyai:{report.attack_id}:{raw_index}:{entry_index}",
                        source_run_id=report.attack_id,
                        target_model=summary.model,
                        attack_method=summary.attack_mode,
                        original_input=entry.original_prompt,
                        adversarial_input=entry.current_prompt,
                        target_outputs=[entry.response],
                        native_outcome=outcome,
                        native_details={
                            "classifications": entry.classifications,
                            "original_response": entry.extra.get(
                                "original_response", ""
                            ),
                            "system_prompt": summary.system_prompt,
                            "raw_extra": entry.extra,
                        },
                        source_artifact_role="raw",
                        source_record=f"raw.jsonl:{raw_index}:entries[{entry_index}]",
                        source_record_sha256=record_digest,
                    )
                )

        artifacts = [
            NativeArtifactFile(
                role="raw",
                path=str(raw_path),
                sha256=require_expected_sha256(
                    raw_bytes, None, role="FuzzyAI raw.jsonl"
                ),
                bytes=len(raw_bytes),
                records=len(raw_rows),
            ),
            NativeArtifactFile(
                role="report",
                path=str(report_path),
                sha256=require_expected_sha256(
                    report_bytes, None, role="FuzzyAI report.json"
                ),
                bytes=len(report_bytes),
                records=1,
            ),
        ]
        report_categorized = sum(
            technique.total_prompts_count for technique in report.attacking_techniques
        )
        return NativeEngineRun(
            engine="fuzzyai",
            native_schema=FUZZYAI_NATIVE_SCHEMA,
            native_run_id=report.attack_id,
            upstream_repository=FUZZYAI_REPOSITORY,
            upstream_revision=upstream_revision.lower(),
            source_artifacts=artifacts,
            target_models=[self.model],
            model_roles={"target": self.model},
            cases=cases,
            native_aggregates={"report": report_value},
            import_accounting={
                "raw_summaries": len(raw_rows),
                "raw_cases": len(cases),
                "report_categorized_cases": report_categorized,
                **outcome_counts,
            },
            measurement_semantics=(
                "FuzzyAI source-native classifier outcomes over its own end-to-end "
                "target calls; not URA common ASR/FRR"
            ),
        )

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "FuzzyAI is supported through import_run(results_dir, upstream_revision=...). "
            "BaseAttacker.generate is inapplicable: upstream `fuzzyai fuzz -m` is an "
            "end-to-end target evaluation with no pinned, documented prompt-export "
            "contract. Replaying its prompts would discard native responses and labels."
        )


__all__ = [
    "FUZZYAI_NATIVE_SCHEMA",
    "FUZZYAI_REPOSITORY",
    "FuzzyAIAttacker",
]
