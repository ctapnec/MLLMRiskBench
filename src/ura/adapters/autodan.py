"""AutoDAN-Turbo complete-run artifact integration.

AutoDAN-Turbo is an end-to-end, target-conditioned optimisation pipeline.  Its
``AutoDANTurbo.test`` loop generates a prompt, calls the target, scores that
response, and retrieves the next strategy from the previous target response;
the official method returns only the final prompt.  It is therefore not a
target-free prompt generator and cannot be replayed through URA ``Runner``
without changing the experiment.

The supported boundary is the artifact family written by the pinned official
``main.py``/``main_r.py`` entrypoints.  URA imports the warm-up and lifelong
strategy libraries, attack logs and summarizer logs, and content-addresses the
two pickle checkpoints without ever deserializing them.  A small URA manifest
is mandatory because the native files omit the attacker, target, scorer,
summarizer and embedding-model identities.

Primary upstream contracts:

* https://github.com/SaFo-Lab/AutoDAN-Turbo
* https://github.com/SaFo-Lab/AutoDAN-Turbo/blob/main/pipeline.py
* https://github.com/SaFo-Lab/AutoDAN-Turbo/blob/main/main.py
* https://github.com/SaFo-Lab/AutoDAN-Turbo/blob/main/main_r.py
* https://github.com/SaFo-Lab/AutoDAN-Turbo/blob/main/framework/library.py
* https://github.com/SaFo-Lab/AutoDAN-Turbo/blob/main/framework/log.py
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

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
    canonical_json_bytes,
    json_sha256,
    read_binary_artifact,
    read_utf8_artifact,
    require_expected_sha256,
    strict_json_loads,
)
from .base import AttackBudget, BaseAttacker


AUTODAN_REPOSITORY = "https://github.com/SaFo-Lab/AutoDAN-Turbo"
AUTODAN_PINNED_REVISION = "389df844439888fc44ea7f5e8e95fd2b5c82ea64"
AUTODAN_MANIFEST_SCHEMA = "ura-autodan-turbo-run-manifest/1"
AUTODAN_NATIVE_SCHEMA = (
    "autodan-turbo-main-json+opaque-pickle/"
    f"{AUTODAN_PINNED_REVISION}"
)
AUTODAN_MANIFEST_FILE = "ura_autodan_run_manifest.json"

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ARTIFACT_ROLES = {
    "warm_up_strategy_library_json": "warm_up_strategy_library.json",
    "warm_up_strategy_library_pickle": "warm_up_strategy_library.pkl",
    "warm_up_attack_log": "warm_up_attack_log.json",
    "warm_up_summarizer_log": "warm_up_summarizer_log.json",
    "lifelong_strategy_library_json": "lifelong_strategy_library.json",
    "lifelong_strategy_library_pickle": "lifelong_strategy_library.pkl",
    "lifelong_attack_log": "lifelong_attack_log.json",
    "lifelong_summarizer_log": "lifelong_summarizer_log.json",
}


def _nonblank(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonblank string")
    return value


class _ManifestArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    filename: str
    sha256: str

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, value: str) -> str:
        _nonblank(value, field="AutoDAN manifest artifact filename")
        candidate = Path(value)
        if candidate.name != value or candidate.is_absolute():
            raise ValueError("AutoDAN artifacts must be simple filenames in the run directory")
        return value

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("AutoDAN artifact SHA-256 must contain 64 hex characters")
        return value.lower()


class _ModelRoles(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    attacker: str
    target: str
    scorer: str
    summarizer: str
    embedding: str

    @field_validator("attacker", "target", "scorer", "summarizer", "embedding")
    @classmethod
    def _role_identity(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN model role")


class _RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    epochs: int = Field(ge=1)
    warm_up_iterations: int = Field(ge=1)
    lifelong_iterations: int = Field(ge=1)
    warm_up_requests: int = Field(ge=1)
    lifelong_requests: int = Field(ge=1)
    break_score: float = Field(ge=1.0, le=10.0)
    dataset_sha256: str

    @field_validator("dataset_sha256")
    @classmethod
    def _dataset_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("AutoDAN dataset_sha256 must contain 64 hex characters")
        return value.lower()


class _RunManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, protected_namespaces=()
    )

    integration_schema: Literal["ura-autodan-turbo-run-manifest/1"]
    run_id: str
    completed: Literal[True]
    upstream_repository: Literal["https://github.com/SaFo-Lab/AutoDAN-Turbo"]
    upstream_revision: str
    variant: Literal["standard", "reasoning"]
    entrypoint: Literal["main.py", "main_r.py"]
    model_roles: _ModelRoles
    config: _RunConfig
    artifacts: dict[str, _ManifestArtifact]

    @field_validator("run_id")
    @classmethod
    def _run_identity(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN run_id")

    @field_validator("upstream_revision")
    @classmethod
    def _revision(cls, value: str) -> str:
        if not _COMMIT_RE.fullmatch(value):
            raise ValueError("AutoDAN upstream_revision must be a full 40-hex commit")
        if value.lower() != AUTODAN_PINNED_REVISION:
            raise ValueError(
                "AutoDAN importer supports only pinned revision "
                f"{AUTODAN_PINNED_REVISION}"
            )
        return value.lower()

    @model_validator(mode="after")
    def _complete_contract(self) -> "_RunManifest":
        expected_entrypoint = "main.py" if self.variant == "standard" else "main_r.py"
        if self.entrypoint != expected_entrypoint:
            raise ValueError(
                f"AutoDAN variant {self.variant!r} requires {expected_entrypoint!r}"
            )
        if set(self.artifacts) != set(_ARTIFACT_ROLES):
            raise ValueError(
                "AutoDAN manifest artifact roles must be exactly "
                f"{sorted(_ARTIFACT_ROLES)!r}"
            )
        filenames = [artifact.filename for artifact in self.artifacts.values()]
        if len(filenames) != len(set(filenames)):
            raise ValueError("AutoDAN manifest artifact filenames must be unique")
        for role, artifact in self.artifacts.items():
            suffix = ".pkl" if role.endswith("_pickle") else ".json"
            if not artifact.filename.endswith(suffix):
                raise ValueError(f"AutoDAN artifact {role!r} must use {suffix!r}")
        return self


class _Strategy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    Strategy: str
    Definition: str
    Example: list[str]

    @field_validator("Strategy", "Definition")
    @classmethod
    def _text(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN strategy field")

    @field_validator("Example")
    @classmethod
    def _examples(cls, value: list[str]) -> list[str]:
        if not value or any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError("AutoDAN strategy Example must contain nonblank strings")
        return value


class _WarmAttack(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    request: str
    prompt: str
    response: str
    assessment: str
    score: float
    attacker: str
    scorer: str
    iteration: int = Field(ge=0)
    epoch: int = Field(ge=0)
    request_id: int = Field(ge=0)
    stage: Literal["warm_up"]

    @field_validator("request", "prompt", "response", "assessment", "attacker", "scorer")
    @classmethod
    def _nonblank_fields(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN attack-log text")

    @field_validator("score")
    @classmethod
    def _score_range(cls, value: float) -> float:
        if not math.isfinite(value) or not 1.0 <= value <= 10.0:
            raise ValueError("AutoDAN source danger score must be finite and in [1, 10]")
        # Upstream casts a requested one-decimal answer to float.  It does not
        # enforce the prompt's suggested 0.5 increments, so neither do we.
        if not math.isclose(value, round(value, 1), abs_tol=1e-9):
            raise ValueError("AutoDAN source danger score must have one-decimal precision")
        return value


class _LifelongAttack(_WarmAttack):
    model_config = ConfigDict(extra="forbid", strict=True)

    retrival_strategy: str
    stage: Literal["lifelong"]


class _SummarizerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    request: str
    summarizer: str
    weak_prompt: str
    strong_prompt: str
    strategy: str
    score_difference: float
    stage: Literal["warm_up", "lifelong"]

    @field_validator("request", "summarizer", "weak_prompt", "strong_prompt", "strategy")
    @classmethod
    def _nonblank_fields(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN summarizer-log text")

    @field_validator("score_difference")
    @classmethod
    def _positive_delta(cls, value: float) -> float:
        if not math.isfinite(value) or not 0.0 < value <= 9.0:
            raise ValueError("AutoDAN score_difference must be finite and in (0, 9]")
        return value


class _SummarizedStrategy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    Strategy: str
    Definition: str

    @field_validator("Strategy", "Definition")
    @classmethod
    def _text(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN summarized strategy")


class _RetrievedStrategy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    Strategy: str
    Definition: str
    Example: str

    @field_validator("Strategy", "Definition", "Example")
    @classmethod
    def _text(cls, value: str) -> str:
        return _nonblank(value, field="AutoDAN retrieved strategy")


def _parse_model(model: type[BaseModel], value: Any, *, location: str) -> BaseModel:
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        raise ExternalEngineOutputError(f"invalid AutoDAN {location}: {exc}") from exc


def _load_json(path: Path, *, max_bytes: int) -> tuple[Path, bytes, Any]:
    resolved, data, text = read_utf8_artifact(path, max_bytes=max_bytes)
    try:
        value = strict_json_loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ExternalEngineOutputError(f"invalid AutoDAN JSON artifact {resolved}: {exc}") from exc
    return resolved, data, value


def _strategy_library(value: Any, *, role: str) -> dict[str, _Strategy]:
    if not isinstance(value, dict) or not value:
        raise ExternalEngineOutputError(f"AutoDAN {role} must be a non-empty object")
    parsed: dict[str, _Strategy] = {}
    for strategy_id, raw in value.items():
        if not isinstance(strategy_id, str) or not strategy_id.strip():
            raise ExternalEngineOutputError(f"AutoDAN {role} contains a blank strategy ID")
        strategy = _parse_model(_Strategy, raw, location=f"{role}[{strategy_id!r}]")
        assert isinstance(strategy, _Strategy)
        if strategy.Strategy != strategy_id:
            raise ExternalEngineOutputError(
                f"AutoDAN {role} key {strategy_id!r} differs from Strategy field "
                f"{strategy.Strategy!r}"
            )
        parsed[strategy_id] = strategy
    return parsed


def _json_list(value: Any, *, role: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ExternalEngineOutputError(f"AutoDAN {role} must be a non-empty array")
    return value


def _manifest_artifact(
    *, role: str, path: Path, data: bytes, records: int
) -> NativeArtifactFile:
    return NativeArtifactFile(
        role=role,
        path=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        records=records,
    )


class AutoDANTurboAttacker(BaseAttacker):
    """Import a complete pinned AutoDAN-Turbo run without target replay."""

    name = "autodan"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        *,
        target_model: str | None = None,
        variant: Literal["standard", "reasoning"] | None = None,
    ) -> None:
        if target_model is not None:
            _nonblank(target_model, field="AutoDAN configured target_model")
        if variant not in (None, "standard", "reasoning"):
            raise ValueError("AutoDAN variant must be 'standard' or 'reasoning'")
        self.target_model = target_model
        self.variant = variant

    @staticmethod
    def write_run_manifest(
        results_dir: str | Path,
        *,
        run_id: str,
        variant: Literal["standard", "reasoning"],
        model_roles: Mapping[str, str],
        epochs: int,
        warm_up_iterations: int,
        lifelong_iterations: int,
        warm_up_requests: int,
        lifelong_requests: int,
        dataset_sha256: str,
        break_score: float = 8.5,
        upstream_revision: str = AUTODAN_PINNED_REVISION,
        artifact_files: Mapping[str, str] | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> Path:
        """Write the missing provenance sidecar after an official full run.

        The eight upstream files must already exist.  Pickles are hashed as
        opaque bytes and are never loaded.  Existing manifests are never
        overwritten, allowing their digest to be preregistered independently.
        """

        root = Path(results_dir).resolve(strict=True)
        if not root.is_dir():
            raise ExternalEngineOutputError(f"AutoDAN results path is not a directory: {root}")
        manifest_path = root / AUTODAN_MANIFEST_FILE
        if manifest_path.exists():
            raise FileExistsError(f"AutoDAN manifest already exists: {manifest_path}")
        selected = dict(_ARTIFACT_ROLES if artifact_files is None else artifact_files)
        artifacts: dict[str, dict[str, str]] = {}
        if set(selected) != set(_ARTIFACT_ROLES):
            raise ValueError(
                "AutoDAN artifact_files roles must be exactly "
                f"{sorted(_ARTIFACT_ROLES)!r}"
            )
        for role, filename in selected.items():
            descriptor = _ManifestArtifact(filename=filename, sha256="0" * 64)
            file_path = (root / descriptor.filename).resolve(strict=True)
            if file_path.parent != root or not file_path.is_file():
                raise ExternalEngineOutputError(
                    f"AutoDAN artifact must be a file directly in the run directory: {file_path}"
                )
            _, data = read_binary_artifact(
                file_path, max_bytes=max_artifact_bytes
            )
            artifacts[role] = {
                "filename": descriptor.filename,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        manifest = _RunManifest(
            integration_schema=AUTODAN_MANIFEST_SCHEMA,
            run_id=run_id,
            completed=True,
            upstream_repository=AUTODAN_REPOSITORY,
            upstream_revision=upstream_revision,
            variant=variant,
            entrypoint="main.py" if variant == "standard" else "main_r.py",
            model_roles=_ModelRoles.model_validate(dict(model_roles)),
            config=_RunConfig(
                epochs=epochs,
                warm_up_iterations=warm_up_iterations,
                lifelong_iterations=lifelong_iterations,
                warm_up_requests=warm_up_requests,
                lifelong_requests=lifelong_requests,
                break_score=break_score,
                dataset_sha256=dataset_sha256,
            ),
            artifacts=artifacts,
        )
        manifest_path.write_bytes(canonical_json_bytes(manifest.model_dump(mode="json")))
        return manifest_path

    def import_run(
        self,
        results_dir: str | Path,
        *,
        expected_manifest_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import and cross-check the complete official AutoDAN artifact family."""

        root = Path(results_dir).resolve(strict=True)
        if not root.is_dir():
            raise ExternalEngineOutputError(f"AutoDAN results path is not a directory: {root}")
        manifest_path, manifest_bytes, manifest_text = read_utf8_artifact(
            root / AUTODAN_MANIFEST_FILE, max_bytes=max_artifact_bytes
        )
        require_expected_sha256(
            manifest_bytes,
            expected_manifest_sha256,
            role="AutoDAN run manifest",
        )
        try:
            manifest_value = strict_json_loads(manifest_text)
            manifest = _RunManifest.model_validate(manifest_value)
        except (json.JSONDecodeError, ValueError, ValidationError) as exc:
            raise ExternalEngineOutputError(f"invalid AutoDAN run manifest: {exc}") from exc
        if self.target_model is not None and manifest.model_roles.target != self.target_model:
            raise ExternalEngineOutputError(
                "AutoDAN target-model mismatch: "
                f"configured={self.target_model!r}, manifest={manifest.model_roles.target!r}"
            )
        if self.variant is not None and manifest.variant != self.variant:
            raise ExternalEngineOutputError(
                "AutoDAN variant mismatch: "
                f"configured={self.variant!r}, manifest={manifest.variant!r}"
            )

        raw_values: dict[str, Any] = {}
        artifact_data: dict[str, tuple[Path, bytes]] = {}
        for role, descriptor in manifest.artifacts.items():
            candidate = (root / descriptor.filename).resolve(strict=True)
            if candidate.parent != root:
                raise ExternalEngineOutputError(
                    f"AutoDAN artifact escapes its run directory: {candidate}"
                )
            if role.endswith("_pickle"):
                resolved, data = read_binary_artifact(
                    candidate, max_bytes=max_artifact_bytes
                )
            else:
                resolved, data, value = _load_json(
                    candidate, max_bytes=max_artifact_bytes
                )
                raw_values[role] = value
            require_expected_sha256(data, descriptor.sha256, role=f"AutoDAN {role}")
            artifact_data[role] = (resolved, data)

        warm_library = _strategy_library(
            raw_values["warm_up_strategy_library_json"],
            role="warm_up_strategy_library_json",
        )
        lifelong_library = _strategy_library(
            raw_values["lifelong_strategy_library_json"],
            role="lifelong_strategy_library_json",
        )
        if not set(warm_library).issubset(lifelong_library):
            raise ExternalEngineOutputError(
                "AutoDAN lifelong strategy library does not contain every warm-up strategy ID"
            )
        for strategy_id, warm in warm_library.items():
            lifelong = lifelong_library[strategy_id]
            if warm.Definition != lifelong.Definition or lifelong.Example[: len(warm.Example)] != warm.Example:
                raise ExternalEngineOutputError(
                    f"AutoDAN lifelong strategy {strategy_id!r} does not preserve its warm-up definition/examples"
                )

        warm_attack_raw = _json_list(
            raw_values["warm_up_attack_log"], role="warm_up_attack_log"
        )
        lifelong_attack_raw = _json_list(
            raw_values["lifelong_attack_log"], role="lifelong_attack_log"
        )
        warm_summary_raw = _json_list(
            raw_values["warm_up_summarizer_log"], role="warm_up_summarizer_log"
        )
        lifelong_summary_raw = _json_list(
            raw_values["lifelong_summarizer_log"], role="lifelong_summarizer_log"
        )
        if lifelong_attack_raw[: len(warm_attack_raw)] != warm_attack_raw:
            raise ExternalEngineOutputError(
                "AutoDAN warm-up attack log is not the exact prefix of the lifelong attack log"
            )
        if lifelong_summary_raw[: len(warm_summary_raw)] != warm_summary_raw:
            raise ExternalEngineOutputError(
                "AutoDAN warm-up summarizer log is not the exact prefix of the lifelong summarizer log"
            )

        warm_attacks: list[_WarmAttack] = []
        lifelong_attacks: list[_WarmAttack | _LifelongAttack] = []
        for index, raw in enumerate(warm_attack_raw):
            parsed = _parse_model(_WarmAttack, raw, location=f"warm_up_attack_log[{index}]")
            assert isinstance(parsed, _WarmAttack)
            warm_attacks.append(parsed)
        for index, raw in enumerate(lifelong_attack_raw):
            if not isinstance(raw, dict):
                raise ExternalEngineOutputError(
                    f"AutoDAN lifelong_attack_log[{index}] must be an object"
                )
            stage = raw.get("stage")
            model: type[BaseModel]
            if stage == "warm_up":
                model = _WarmAttack
            elif stage == "lifelong":
                model = _LifelongAttack
            else:
                raise ExternalEngineOutputError(
                    f"AutoDAN lifelong_attack_log[{index}] has invalid stage {stage!r}"
                )
            parsed = _parse_model(model, raw, location=f"lifelong_attack_log[{index}]")
            assert isinstance(parsed, (_WarmAttack, _LifelongAttack))
            lifelong_attacks.append(parsed)
        if not any(entry.stage == "lifelong" for entry in lifelong_attacks):
            raise ExternalEngineOutputError(
                "AutoDAN lifelong attack log contains no lifelong-stage records"
            )

        config = manifest.config
        observed_request_ids: dict[str, set[int]] = {"warm_up": set(), "lifelong": set()}
        retrieved_by_index: dict[int, list[_RetrievedStrategy]] = {}
        for index, entry in enumerate(lifelong_attacks):
            request_limit = (
                config.warm_up_requests
                if entry.stage == "warm_up"
                else config.lifelong_requests
            )
            if entry.request_id >= request_limit:
                raise ExternalEngineOutputError(
                    f"AutoDAN {entry.stage} request_id {entry.request_id} exceeds manifest request count"
                )
            if entry.epoch >= config.epochs:
                raise ExternalEngineOutputError(
                    f"AutoDAN {entry.stage} epoch {entry.epoch} exceeds manifest epochs"
                )
            if entry.stage == "warm_up":
                if entry.iteration >= config.warm_up_iterations:
                    raise ExternalEngineOutputError(
                        "AutoDAN warm-up iteration exceeds manifest warm_up_iterations"
                    )
            elif entry.iteration != 0:
                # Both official main entrypoints instantiate the inner pipeline
                # with lifelong_iterations=1 and repeat it in an outer save loop.
                raise ExternalEngineOutputError(
                    "AutoDAN lifelong log is inconsistent with the pinned main entrypoint (iteration must be 0)"
                )
            observed_request_ids[entry.stage].add(entry.request_id)
            if isinstance(entry, _LifelongAttack):
                try:
                    retrieved_raw = strict_json_loads(entry.retrival_strategy)
                except (json.JSONDecodeError, ValueError) as exc:
                    raise ExternalEngineOutputError(
                        f"invalid AutoDAN retrival_strategy at lifelong_attack_log[{index}]: {exc}"
                    ) from exc
                if not isinstance(retrieved_raw, list):
                    raise ExternalEngineOutputError(
                        f"AutoDAN retrival_strategy at lifelong_attack_log[{index}] must encode a list"
                    )
                retrieved: list[_RetrievedStrategy] = []
                for strategy_index, raw_strategy in enumerate(retrieved_raw):
                    parsed_strategy = _parse_model(
                        _RetrievedStrategy,
                        raw_strategy,
                        location=(
                            f"lifelong_attack_log[{index}].retrival_strategy[{strategy_index}]"
                        ),
                    )
                    assert isinstance(parsed_strategy, _RetrievedStrategy)
                    library_strategy = lifelong_library.get(parsed_strategy.Strategy)
                    if library_strategy is None:
                        raise ExternalEngineOutputError(
                            f"AutoDAN retrieved unknown strategy ID {parsed_strategy.Strategy!r}"
                        )
                    if (
                        parsed_strategy.Definition != library_strategy.Definition
                        or parsed_strategy.Example not in library_strategy.Example
                    ):
                        raise ExternalEngineOutputError(
                            f"AutoDAN retrieved strategy {parsed_strategy.Strategy!r} differs from the lifelong library"
                        )
                    retrieved.append(parsed_strategy)
                retrieved_by_index[index] = retrieved
        if observed_request_ids["warm_up"] != set(range(config.warm_up_requests)):
            raise ExternalEngineOutputError(
                "AutoDAN warm-up request IDs do not cover the manifest request count"
            )
        if observed_request_ids["lifelong"] != set(range(config.lifelong_requests)):
            raise ExternalEngineOutputError(
                "AutoDAN lifelong request IDs do not cover the manifest request count"
            )

        summaries: list[_SummarizerEntry] = []
        for index, raw in enumerate(lifelong_summary_raw):
            summary = _parse_model(
                _SummarizerEntry,
                raw,
                location=f"lifelong_summarizer_log[{index}]",
            )
            assert isinstance(summary, _SummarizerEntry)
            try:
                raw_strategy = strict_json_loads(summary.strategy)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ExternalEngineOutputError(
                    f"invalid AutoDAN summarized strategy at lifelong_summarizer_log[{index}]: {exc}"
                ) from exc
            parsed_strategy = _parse_model(
                _SummarizedStrategy,
                raw_strategy,
                location=f"lifelong_summarizer_log[{index}].strategy",
            )
            assert isinstance(parsed_strategy, _SummarizedStrategy)
            library = warm_library if summary.stage == "warm_up" else lifelong_library
            if parsed_strategy.Strategy not in library:
                raise ExternalEngineOutputError(
                    f"AutoDAN summarizer log references unknown {summary.stage} strategy ID "
                    f"{parsed_strategy.Strategy!r}"
                )
            summaries.append(summary)

        cases: list[NativeEngineCase] = []
        outcome_counts: Counter[str] = Counter()
        stage_counts: Counter[str] = Counter()
        all_scores: list[float] = []
        for index, (raw, entry) in enumerate(zip(lifelong_attack_raw, lifelong_attacks)):
            reached = entry.score >= config.break_score
            outcome = (
                "native_break_score_reached"
                if reached
                else "native_break_score_not_reached"
            )
            outcome_counts[outcome] += 1
            stage_counts[entry.stage] += 1
            all_scores.append(entry.score)
            retrieved = retrieved_by_index.get(index, [])
            cases.append(
                NativeEngineCase(
                    id=f"autodan:{manifest.run_id}:{index}",
                    source_run_id=manifest.run_id,
                    target_model=manifest.model_roles.target,
                    attack_method=f"autodan-turbo:{entry.stage}",
                    original_input=entry.request,
                    adversarial_input=entry.prompt,
                    target_outputs=[entry.response],
                    native_outcome=outcome,
                    native_scores={"danger_score_1_to_10": entry.score},
                    native_details={
                        "assessment": entry.assessment,
                        "attacker_system_prompt": entry.attacker,
                        "scorer_system_prompt": entry.scorer,
                        "iteration": entry.iteration,
                        "epoch": entry.epoch,
                        "request_id": entry.request_id,
                        "stage": entry.stage,
                        "variant": manifest.variant,
                        "break_score": config.break_score,
                        "retrieved_strategy_ids": [item.Strategy for item in retrieved],
                        "retrieved_strategies": [
                            item.model_dump(mode="json") for item in retrieved
                        ],
                    },
                    source_artifact_role="lifelong_attack_log",
                    source_record=f"lifelong_attack_log.json[{index}]",
                    source_record_sha256=json_sha256(raw),
                )
            )

        artifacts = [
            _manifest_artifact(
                role="manifest",
                path=manifest_path,
                data=manifest_bytes,
                records=1,
            )
        ]
        record_counts = {
            "warm_up_strategy_library_json": len(warm_library),
            "warm_up_strategy_library_pickle": 1,
            "warm_up_attack_log": len(warm_attack_raw),
            "warm_up_summarizer_log": len(warm_summary_raw),
            "lifelong_strategy_library_json": len(lifelong_library),
            "lifelong_strategy_library_pickle": 1,
            "lifelong_attack_log": len(lifelong_attack_raw),
            "lifelong_summarizer_log": len(lifelong_summary_raw),
        }
        for role in _ARTIFACT_ROLES:
            path, data = artifact_data[role]
            artifacts.append(
                _manifest_artifact(
                    role=role,
                    path=path,
                    data=data,
                    records=record_counts[role],
                )
            )

        return NativeEngineRun(
            engine="autodan_turbo",
            native_schema=AUTODAN_NATIVE_SCHEMA,
            native_run_id=manifest.run_id,
            upstream_repository=AUTODAN_REPOSITORY,
            upstream_revision=manifest.upstream_revision,
            source_artifacts=artifacts,
            target_models=[manifest.model_roles.target],
            model_roles=manifest.model_roles.model_dump(mode="json"),
            cases=cases,
            native_aggregates={
                "variant": manifest.variant,
                "entrypoint": manifest.entrypoint,
                "config": manifest.config.model_dump(mode="json"),
                "warm_up_strategy_ids": sorted(warm_library),
                "lifelong_strategy_ids": sorted(lifelong_library),
                "source_score": {
                    "scale": [1.0, 10.0],
                    "break_score": config.break_score,
                    "minimum": min(all_scores),
                    "maximum": max(all_scores),
                    "mean": sum(all_scores) / len(all_scores),
                },
                "native_outcome_counts": dict(outcome_counts),
            },
            import_accounting={
                "attack_records": len(lifelong_attacks),
                "warm_up_attack_records": stage_counts["warm_up"],
                "lifelong_attack_records": stage_counts["lifelong"],
                "summarizer_records": len(summaries),
                "warm_up_strategies": len(warm_library),
                "lifelong_strategies": len(lifelong_library),
                "retrieval_references": sum(len(items) for items in retrieved_by_index.values()),
            },
            measurement_semantics=(
                "AutoDAN-Turbo source-native 1-10 danger scores and native "
                "break-condition outcomes from its own target-conditioned optimisation "
                "loop; not URA common ASR/FRR"
            ),
        )

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "AutoDAN-Turbo is supported through import_run(results_dir). "
            "BaseAttacker.generate is inapplicable: official AutoDANTurbo.test() "
            "calls its target and scorer during retrieval and returns only the final "
            "prompt. The prior --max_prompts/--attacker_model/--output CLI did not "
            "exist upstream and has been removed."
        )


__all__ = [
    "AUTODAN_MANIFEST_FILE",
    "AUTODAN_MANIFEST_SCHEMA",
    "AUTODAN_NATIVE_SCHEMA",
    "AUTODAN_PINNED_REVISION",
    "AUTODAN_REPOSITORY",
    "AutoDANTurboAttacker",
]
