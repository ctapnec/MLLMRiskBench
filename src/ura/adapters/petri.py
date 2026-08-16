"""Petri v3 native Inspect-audit integration.

Petri is an end-to-end alignment auditor, not an attacker-style seed generator.
Its Inspect task binds distinct ``auditor``, ``target`` and ``judge`` model roles,
constructs multi-turn scenarios, supports simulated tools and rollback branches,
and scores the resulting target timeline on configurable 1-10 dimensions.  The
authoritative upstream contracts are:

* https://github.com/meridianlabs-ai/inspect_petri
* https://github.com/meridianlabs-ai/inspect_petri/blob/main/src/inspect_petri/_task/audit.py
* https://github.com/meridianlabs-ai/inspect_petri/blob/main/src/inspect_petri/_judge/judge.py
* https://inspect.aisi.org.uk/eval-logs.html
* https://inspect.aisi.org.uk/reference/inspect_ai.log.html

URA therefore imports the complete successful Inspect log (native ``.eval`` or
official JSON conversion), retains its task/model-role/sample/score lineage and
does not replay a selected message through ``Runner``.  Petri dimension scores
remain source-specific; no arbitrary threshold is used to turn them into common
ASR/FRR labels.
"""

from __future__ import annotations

import json
import io
import re
import stat
import tempfile
import zipfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ..data_models import Attempt, DataPoint
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
    _require,
)
from ._native_artifacts import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    NativeArtifactFile,
    NativeEngineCase,
    NativeEngineRun,
    json_sha256,
    read_binary_artifact,
    read_utf8_artifact,
    require_expected_sha256,
    strict_json_loads,
)
from .base import AttackBudget, BaseAttacker


PETRI_REPOSITORY = "https://github.com/meridianlabs-ai/inspect_petri"
PETRI_TASK = "inspect_petri/audit"
PETRI_NATIVE_SCHEMA = "inspect-eval-log/petri-v3"
_VERSION_3_RE = re.compile(r"^3(?:\.|$)")
_MAX_EVAL_ARCHIVE_MEMBERS = 10_000


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExternalEngineOutputError(f"Petri Inspect log {field} must be an object")
    return value


def _nonblank(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExternalEngineOutputError(
            f"Petri Inspect log {field} must be a nonblank string"
        )
    return value


def _package_version(packages: Mapping[str, Any], distribution: str) -> str:
    wanted = distribution.lower().replace("-", "_")
    matches = [
        value
        for name, value in packages.items()
        if isinstance(name, str) and name.lower().replace("-", "_") == wanted
    ]
    if len(matches) != 1:
        raise ExternalEngineOutputError(
            f"Petri Inspect log must record exactly one {distribution!r} package version"
        )
    return _nonblank(matches[0], field=f"eval.packages[{distribution!r}]")


def _role_model(role: str, value: Any) -> str:
    if isinstance(value, str):
        return _nonblank(value, field=f"eval.model_roles.{role}")
    role_config = _mapping(value, field=f"eval.model_roles.{role}")
    return _nonblank(role_config.get("model"), field=f"eval.model_roles.{role}.model")


def _read_eval_log(
    path: Path, *, max_artifact_bytes: int
) -> tuple[Path, bytes, dict[str, Any]]:
    """Read an Inspect JSON or binary eval log without triggering model calls."""

    if not isinstance(max_artifact_bytes, int) or max_artifact_bytes < 1:
        raise ValueError("max_artifact_bytes must be a positive integer")

    suffix = path.suffix.lower()
    if suffix == ".json":
        resolved, data, text = read_utf8_artifact(
            path, max_bytes=max_artifact_bytes
        )
        try:
            value = strict_json_loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ExternalEngineOutputError(
                f"invalid Petri Inspect JSON log: {exc}"
            ) from exc
    elif suffix == ".eval":
        resolved, data = read_binary_artifact(
            path, max_bytes=max_artifact_bytes
        )
        archive_stream = io.BytesIO(data)
        if zipfile.is_zipfile(archive_stream):
            archive_stream.seek(0)
            try:
                with zipfile.ZipFile(archive_stream) as archive:
                    members = archive.infolist()
                    if len(members) > _MAX_EVAL_ARCHIVE_MEMBERS:
                        raise ExternalEngineOutputError(
                            "Petri .eval archive exceeds the member-count limit"
                        )
                    total_uncompressed = 0
                    for member in members:
                        member_path = Path(member.filename.replace("\\", "/"))
                        parts = member_path.parts
                        if (
                            not parts
                            or member_path.is_absolute()
                            or member.filename.startswith(("/", "\\"))
                            or ".." in parts
                            or any(":" in part for part in parts)
                        ):
                            raise ExternalEngineOutputError(
                                "Petri .eval archive contains an unsafe member path"
                            )
                        mode = (member.external_attr >> 16) & 0xFFFF
                        if stat.S_ISLNK(mode):
                            raise ExternalEngineOutputError(
                                "Petri .eval archive contains a symbolic link"
                            )
                        total_uncompressed += member.file_size
                        if total_uncompressed > max_artifact_bytes:
                            raise ExternalEngineOutputError(
                                "Petri .eval archive exceeds the uncompressed byte limit"
                            )
            except (zipfile.BadZipFile, OSError) as exc:
                raise ExternalEngineOutputError(
                    "Petri .eval archive metadata is invalid"
                ) from exc
        inspect_log = _require(
            "inspect_ai.log",
            "Petri .eval artifact import",
            "inspect-ai>=0.3.236",
        )
        try:
            # Decode the exact stable bytes already admitted above.  Reopening
            # the caller-controlled source path would reintroduce a check/use
            # race between hashing and Inspect's parser.
            with tempfile.TemporaryDirectory(prefix="ura-petri-import-") as tmp:
                stable_copy = Path(tmp) / "captured.eval"
                stable_copy.write_bytes(data)
                loaded = inspect_log.read_eval_log(stable_copy, format="eval")
                value = loaded.model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - normalize optional backend errors
            raise ExternalEngineOutputError(
                f"Inspect could not decode Petri .eval log {resolved}: {exc}"
            ) from exc
    else:
        raise ExternalEngineOutputError(
            "Petri import accepts only native .eval logs or `inspect log convert --to json` output"
        )
    if not isinstance(value, dict):
        raise ExternalEngineOutputError("Petri Inspect log root must be a JSON object")
    return resolved, data, value


class PetriAttacker(BaseAttacker):
    """Import complete Petri v3 Inspect audit logs with native score semantics.

    The historical class name remains for registry compatibility.  This object
    is an audit-artifact adapter, not a ``Runner`` prompt generator.  Configure
    role identities and/or dimensions to assert them during import; leaving one
    unset accepts the value embedded in the authoritative Inspect log while
    still recording it in the returned provenance.
    """

    name = "petri"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        dimensions: list[str] | None = None,
        auditor_model: str | None = None,
        target_model: str | None = None,
        judge_model: str | None = None,
        cli: str = "inspect",
        credential_env: list[str] | tuple[str, ...] | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        if dimensions is not None:
            if not dimensions or any(
                not isinstance(dimension, str) or not dimension.strip()
                for dimension in dimensions
            ):
                raise ValueError("Petri dimensions must contain nonblank names")
            if len(set(dimensions)) != len(dimensions):
                raise ValueError("Petri dimensions must be unique")
        for role, model in (
            ("auditor", auditor_model),
            ("target", target_model),
            ("judge", judge_model),
        ):
            if model is not None and (not isinstance(model, str) or not model.strip()):
                raise ValueError(f"Petri {role}_model must be nonblank when supplied")
        if (
            target_model is not None
            and judge_model is not None
            and target_model.strip() == judge_model.strip()
        ):
            raise ValueError(
                "Petri target_model and judge_model must differ; the target must "
                "not grade its own output"
            )
        self.dimensions = dimensions
        self.auditor_model = auditor_model
        self.target_model = target_model
        self.judge_model = judge_model
        self.cli = cli
        self.credential_env = tuple(credential_env or ())
        self.timeout_seconds = timeout_seconds

    def build_native_command(self) -> list[str]:
        """Build (but never execute) the official three-role Inspect invocation."""

        roles = {
            "auditor": self.auditor_model,
            "target": self.target_model,
            "judge": self.judge_model,
        }
        missing = sorted(role for role, model in roles.items() if model is None)
        if missing:
            raise ValueError(
                "Petri native command requires configured model roles: "
                + ", ".join(missing)
            )
        command = [self.cli, "eval", PETRI_TASK]
        for role in ("auditor", "target", "judge"):
            command.extend(["--model-role", f"{role}={roles[role]}"])
        return command

    def import_run(
        self,
        log_path: str | Path,
        *,
        expected_log_sha256: str | None = None,
        expected_upstream_version: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import a completed Petri v3 Inspect log without re-running the audit."""

        resolved, log_bytes, log = _read_eval_log(
            Path(log_path), max_artifact_bytes=max_artifact_bytes
        )
        log_digest = require_expected_sha256(
            log_bytes, expected_log_sha256, role="Petri Inspect log"
        )

        required_top_level = {
            "version",
            "status",
            "eval",
            "plan",
            "results",
            "stats",
            "error",
            "invalidated",
            "samples",
        }
        missing_top_level = sorted(required_top_level - set(log))
        if missing_top_level:
            raise ExternalEngineOutputError(
                "Petri Inspect log lacks required top-level fields: "
                + ", ".join(missing_top_level)
            )
        version = log.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ExternalEngineOutputError(
                "Petri Inspect log version must be a positive integer"
            )
        if log.get("status") != "success":
            raise ExternalEngineOutputError(
                f"Petri Inspect log status must be 'success', observed {log.get('status')!r}"
            )
        if log.get("error") is not None:
            raise ExternalEngineOutputError(
                "Petri Inspect log marked successful but contains a top-level error"
            )
        if not isinstance(log.get("invalidated"), bool):
            raise ExternalEngineOutputError(
                "Petri Inspect log invalidated field must be boolean"
            )
        if log.get("invalidated") is True:
            raise ExternalEngineOutputError(
                "Petri Inspect log contains invalidated samples"
            )
        _mapping(log.get("plan"), field="plan")
        _mapping(log.get("results"), field="results")
        _mapping(log.get("stats"), field="stats")

        eval_spec = _mapping(log.get("eval"), field="eval")
        task = _nonblank(eval_spec.get("task"), field="eval.task")
        if task != PETRI_TASK:
            raise ExternalEngineOutputError(
                f"Inspect log task is {task!r}, not the Petri v3 task {PETRI_TASK!r}"
            )
        eval_id = _nonblank(eval_spec.get("eval_id"), field="eval.eval_id")
        inspect_run_id = _nonblank(eval_spec.get("run_id"), field="eval.run_id")

        packages = _mapping(eval_spec.get("packages"), field="eval.packages")
        petri_version = _package_version(packages, "inspect_petri")
        inspect_version = _package_version(packages, "inspect_ai")
        if not _VERSION_3_RE.match(petri_version):
            raise ExternalEngineOutputError(
                f"Petri v3 importer cannot admit inspect_petri version {petri_version!r}"
            )
        if (
            expected_upstream_version is not None
            and petri_version != expected_upstream_version
        ):
            raise ExternalEngineOutputError(
                "Petri package-version mismatch: "
                f"expected={expected_upstream_version!r}, observed={petri_version!r}"
            )

        role_values = _mapping(eval_spec.get("model_roles"), field="eval.model_roles")
        model_roles: dict[str, str] = {}
        for role in ("auditor", "target", "judge"):
            if role not in role_values:
                raise ExternalEngineOutputError(
                    f"Petri Inspect log lacks required {role!r} model role"
                )
            model_roles[role] = _role_model(role, role_values[role])
        if "realism" in role_values:
            model_roles["realism"] = _role_model("realism", role_values["realism"])
        if model_roles["target"] == model_roles["judge"]:
            raise ExternalEngineOutputError(
                "Petri target and judge model identities must differ"
            )
        configured = {
            "auditor": self.auditor_model,
            "target": self.target_model,
            "judge": self.judge_model,
        }
        for role, expected_model in configured.items():
            if expected_model is not None and model_roles[role] != expected_model:
                raise ExternalEngineOutputError(
                    f"Petri {role} model mismatch: configured={expected_model!r}, "
                    f"artifact={model_roles[role]!r}"
                )

        task_args = _mapping(eval_spec.get("task_args"), field="eval.task_args")
        max_turns = task_args.get("max_turns")
        if (
            isinstance(max_turns, bool)
            or not isinstance(max_turns, int)
            or max_turns < 1
        ):
            raise ExternalEngineOutputError(
                "Petri eval.task_args.max_turns must be a positive integer"
            )
        enable_rollback = task_args.get("enable_rollback")
        if not isinstance(enable_rollback, bool):
            raise ExternalEngineOutputError(
                "Petri eval.task_args.enable_rollback must be boolean"
            )
        target_tools = task_args.get("target_tools")
        if target_tools not in {"synthetic", "fixed", "none"}:
            raise ExternalEngineOutputError(
                "Petri eval.task_args.target_tools must be synthetic, fixed, or none"
            )

        samples = log.get("samples")
        if not isinstance(samples, list) or not samples:
            raise ExternalEngineOutputError(
                "successful Petri Inspect log must contain non-empty samples"
            )

        cases: list[NativeEngineCase] = []
        identities: set[tuple[str, int]] = set()
        scored_dimensions: set[str] | None = None
        scored = 0
        unscored = 0
        fallback_samples = 0
        for index, raw_sample in enumerate(samples):
            sample = _mapping(raw_sample, field=f"samples[{index}]")
            sample_id_value = sample.get("id")
            if isinstance(sample_id_value, bool) or not isinstance(
                sample_id_value, (str, int)
            ):
                raise ExternalEngineOutputError(
                    f"Petri samples[{index}].id must be a string or integer"
                )
            sample_id = str(sample_id_value)
            if not sample_id.strip():
                raise ExternalEngineOutputError(
                    f"Petri samples[{index}].id must not be blank"
                )
            epoch = sample.get("epoch")
            if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
                raise ExternalEngineOutputError(
                    f"Petri samples[{index}].epoch must be a positive integer"
                )
            identity = (sample_id, epoch)
            if identity in identities:
                raise ExternalEngineOutputError(
                    f"duplicate Petri sample identity {identity!r}"
                )
            identities.add(identity)

            if sample.get("error") is not None:
                raise ExternalEngineOutputError(
                    f"successful Petri sample {identity!r} contains an error"
                )
            transcript_fields = ("messages", "events", "timelines")
            if not any(
                isinstance(sample.get(field), list) and bool(sample.get(field))
                for field in transcript_fields
            ):
                raise ExternalEngineOutputError(
                    f"Petri sample {identity!r} contains no transcript messages/events/timelines"
                )

            scores = _mapping(sample.get("scores"), field=f"samples[{index}].scores")
            score = _mapping(
                scores.get("audit_judge"),
                field=f"samples[{index}].scores.audit_judge",
            )
            score_value = score.get("value")
            score_metadata = score.get("metadata")
            if score_metadata is None:
                score_metadata = {}
            score_metadata = _mapping(
                score_metadata,
                field=f"samples[{index}].scores.audit_judge.metadata",
            )
            native_scores: dict[str, int | float] = {}
            if score_value is None:
                if score_metadata.get("refusal") is not True:
                    raise ExternalEngineOutputError(
                        f"Petri sample {identity!r} is unscored without explicit judge refusal"
                    )
                explanation = score.get("explanation")
                if not isinstance(explanation, str) or not explanation.strip():
                    raise ExternalEngineOutputError(
                        f"Petri sample {identity!r} judge refusal lacks an explanation"
                    )
                native_outcome = "judge_refusal_unscored"
                unscored += 1
            else:
                value_map = _mapping(
                    score_value,
                    field=f"samples[{index}].scores.audit_judge.value",
                )
                if not value_map:
                    raise ExternalEngineOutputError(
                        f"Petri sample {identity!r} has an empty dimension-score map"
                    )
                for dimension, value in value_map.items():
                    if not isinstance(dimension, str) or not dimension.strip():
                        raise ExternalEngineOutputError(
                            f"Petri sample {identity!r} has a blank dimension name"
                        )
                    if isinstance(value, bool) or not isinstance(value, int):
                        raise ExternalEngineOutputError(
                            f"Petri dimension {dimension!r} for sample {identity!r} "
                            "must be an integer"
                        )
                    if value < 1 or value > 10:
                        raise ExternalEngineOutputError(
                            f"Petri dimension {dimension!r} for sample {identity!r} "
                            "must be in [1, 10]"
                        )
                    native_scores[dimension] = value
                dimensions = set(native_scores)
                if scored_dimensions is None:
                    scored_dimensions = dimensions
                elif dimensions != scored_dimensions:
                    raise ExternalEngineOutputError(
                        f"Petri sample {identity!r} dimension set differs from prior samples"
                    )
                native_outcome = "dimension_scores"
                scored += 1

            if (
                self.dimensions is not None
                and native_scores
                and set(self.dimensions) != set(native_scores)
            ):
                raise ExternalEngineOutputError(
                    f"Petri sample {identity!r} dimensions do not match configured dimensions"
                )
            model_fallbacks = sample.get("model_fallbacks")
            if isinstance(model_fallbacks, list) and model_fallbacks:
                fallback_samples += 1
            sample_digest = json_sha256(sample)
            uuid = sample.get("uuid")
            case_id = (
                f"petri:{uuid}"
                if isinstance(uuid, str) and uuid.strip()
                else f"petri:{eval_id}:{sample_id}:epoch{epoch}"
            )
            cases.append(
                NativeEngineCase(
                    id=case_id,
                    source_run_id=eval_id,
                    target_model=model_roles["target"],
                    attack_method="petri:audit",
                    original_input=sample.get("input"),
                    adversarial_input=None,
                    target_outputs=[],
                    native_outcome=native_outcome,
                    native_scores=native_scores,
                    native_details={
                        "epoch": epoch,
                        "sample_uuid": uuid,
                        "judge_explanation": score.get("explanation"),
                        "judge_metadata": score_metadata,
                        "model_fallbacks": model_fallbacks,
                        "transcript_fields": [
                            field
                            for field in transcript_fields
                            if isinstance(sample.get(field), list)
                            and bool(sample.get(field))
                        ],
                        "transcript_retained_in_source_artifact": True,
                    },
                    source_artifact_role="inspect_log",
                    source_record=f"samples[{index}] (id={sample_id!r}, epoch={epoch})",
                    source_record_sha256=sample_digest,
                )
            )

        if self.dimensions is not None and scored_dimensions is None:
            # All-refusal runs are valid native artifacts, but there is no evidence
            # that the configured dimensions were actually returned.
            raise ExternalEngineOutputError(
                "Petri log contains no scored sample with which to verify configured dimensions"
            )

        artifact = NativeArtifactFile(
            role="inspect_log",
            path=str(resolved),
            sha256=log_digest,
            bytes=len(log_bytes),
            records=len(samples),
        )
        return NativeEngineRun(
            engine="petri",
            native_schema=f"{PETRI_NATIVE_SCHEMA};inspect_log_version={version}",
            native_run_id=eval_id,
            upstream_repository=PETRI_REPOSITORY,
            upstream_version=petri_version,
            source_artifacts=[artifact],
            target_models=[model_roles["target"]],
            model_roles=model_roles,
            cases=cases,
            native_aggregates={
                "inspect_run_id": inspect_run_id,
                "inspect_results": log.get("results"),
                "inspect_packages": packages,
                "inspect_ai_version": inspect_version,
                "task": task,
                "task_args": task_args,
                "eval_revision": eval_spec.get("revision"),
                "score_dimensions": sorted(scored_dimensions or []),
            },
            import_accounting={
                "samples": len(samples),
                "scored_samples": scored,
                "judge_refusal_unscored_samples": unscored,
                "samples_with_model_fallbacks": fallback_samples,
                "native_score_coverage": scored / len(samples),
            },
            measurement_semantics=(
                "Petri source-native 1-10 alignment dimension scores over complete "
                "auditor-target transcripts; judge refusals remain unscored and no "
                "common ASR/FRR threshold is imputed"
            ),
        )

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "Petri is supported through import_run(log_path). BaseAttacker.generate "
            "is inapplicable because Petri is a complete Inspect auditor/target/judge "
            "task, not a seed-only probes.json exporter. Replaying one message would "
            "discard its multi-turn timeline, branches, tools and native scores."
        )


__all__ = [
    "PETRI_NATIVE_SCHEMA",
    "PETRI_REPOSITORY",
    "PETRI_TASK",
    "PetriAttacker",
]
