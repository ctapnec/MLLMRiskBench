"""Giskard v2 Scan and RAGET native-run integration.

Giskard v2 is a complete evaluator.  Its documented LLM flow wraps a target in
``giskard.Model``, calls ``giskard.scan(model, dataset)`` and returns a
``ScanReport``.  RAGET similarly calls ``giskard.rag.evaluate`` and returns a
``RAGReport`` whose official ``save`` method writes the testset, target answers,
per-question metrics, recommendation, optional knowledge base and HTML report.
Neither surface is a prompt-only attacker.

This module pins the stable v2 contract to 2.19.2, executes those real APIs only
through explicit ``run_scan``/``run_raget`` methods, and imports their native
artifacts without replaying target calls.  Giskard v3 is intentionally excluded:
the official v3 repository states that v2 Scan and RAGET are not available in
the rewrite; ``giskard-scan`` remains a separate pre-release line.

Primary upstream contracts:

* https://github.com/Giskard-AI/giskard-oss/tree/v2.19.2
* https://github.com/Giskard-AI/giskard-oss/blob/v2.19.2/giskard/scanner/report.py
* https://github.com/Giskard-AI/giskard-oss/blob/v2.19.2/giskard/rag/evaluate.py
* https://github.com/Giskard-AI/giskard-oss/blob/v2.19.2/giskard/rag/report.py
* https://github.com/Giskard-AI/giskard-oss/blob/v2.19.2/giskard/rag/testset.py
* https://docs.giskard.ai/en/stable/getting_started/index.html
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    field_validator,
    model_validator,
)

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
    canonical_json_bytes,
    json_sha256,
    read_binary_artifact,
    read_utf8_artifact,
    require_expected_sha256,
    strict_json_loads,
)
from .base import AttackBudget, BaseAttacker


GISKARD_REPOSITORY = "https://github.com/Giskard-AI/giskard-oss"
GISKARD_V2_VERSION = "2.19.2"
GISKARD_V2_REVISION = "86512399daf097358422e1f30d19abbacbe5ce9a"
GISKARD_MANIFEST_SCHEMA = "ura-giskard-v2-run-manifest/1"
GISKARD_MANIFEST_FILE = "ura_giskard_v2_run_manifest.json"
GISKARD_SCAN_SCHEMA = "giskard-v2-ScanReport.to_json+to_html/2.19.2"
GISKARD_RAGET_SCHEMA = "giskard-v2-RAGReport.save/2.19.2"

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SCAN_ARTIFACTS = {
    "scan_report_json": "scan_report.json",
    "scan_report_html": "scan_report.html",
}
_RAGET_REQUIRED_ARTIFACTS = {
    "raget_report_html": "report.html",
    "raget_testset_jsonl": "testset.jsonl",
    "raget_agent_answers_json": "agent_answer.json",
    "raget_report_details_json": "report_details.json",
    "raget_metrics_results_json": "metrics_results.json",
}
_RAGET_KB_ARTIFACTS = {
    "raget_knowledge_base_jsonl": "knowledge_base.jsonl",
    "raget_knowledge_base_meta_json": "knowledge_base_meta.json",
}
_ISSUE_LEVELS = {"major", "medium", "minor"}
_QUESTION_ATTRIBUTION = {
    "GENERATOR": ["simple", "complex", "distracting element", "situational", "double"],
    "RETRIEVER": ["simple", "distracting element", "multi-context"],
    "REWRITER": ["distracting element", "double", "conversational", "multi-context"],
    "ROUTING": ["out of scope"],
    "KNOWLEDGE_BASE": ["out of scope"],
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
        _nonblank(value, field="Giskard manifest artifact filename")
        candidate = Path(value)
        if candidate.name != value or candidate.is_absolute():
            raise ValueError("Giskard artifacts must be simple filenames in the run directory")
        return value

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("Giskard artifact SHA-256 must contain 64 hex characters")
        return value.lower()


class _Invocation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    api: Literal["giskard.scan", "giskard.rag.evaluate"]
    report_export: Literal[
        "ScanReport.to_json+to_html",
        "RAGReport.save",
    ]
    parameters: dict[str, Any]


class _RunManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, protected_namespaces=()
    )

    integration_schema: Literal["ura-giskard-v2-run-manifest/1"]
    run_id: str
    completed: Literal[True]
    upstream_repository: Literal["https://github.com/Giskard-AI/giskard-oss"]
    giskard_version: Literal["2.19.2"]
    upstream_revision: Literal["86512399daf097358422e1f30d19abbacbe5ce9a"]
    mode: Literal["scan", "raget"]
    model_roles: dict[str, str]
    dataset_id: str
    dataset_sha256: str
    invocation: _Invocation
    artifacts: dict[str, _ManifestArtifact]

    @field_validator("run_id", "dataset_id")
    @classmethod
    def _identity(cls, value: str) -> str:
        return _nonblank(value, field="Giskard run/dataset identity")

    @field_validator("dataset_sha256")
    @classmethod
    def _dataset_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("Giskard dataset_sha256 must contain 64 hex characters")
        return value.lower()

    @field_validator("model_roles")
    @classmethod
    def _roles(cls, value: dict[str, str]) -> dict[str, str]:
        for role, identity in value.items():
            _nonblank(role, field="Giskard model role name")
            _nonblank(identity, field=f"Giskard model role {role!r}")
        return value

    @model_validator(mode="after")
    def _mode_contract(self) -> "_RunManifest":
        filenames = [item.filename for item in self.artifacts.values()]
        if len(filenames) != len(set(filenames)):
            raise ValueError("Giskard artifact filenames must be unique")
        if self.mode == "scan":
            if self.invocation.api != "giskard.scan" or self.invocation.report_export != "ScanReport.to_json+to_html":
                raise ValueError("Giskard scan manifest names the wrong native API/export")
            if set(self.artifacts) != set(_SCAN_ARTIFACTS):
                raise ValueError(
                    f"Giskard scan artifact roles must be exactly {sorted(_SCAN_ARTIFACTS)!r}"
                )
            required_roles = {"target", "scanner_llm"}
        else:
            if self.invocation.api != "giskard.rag.evaluate" or self.invocation.report_export != "RAGReport.save":
                raise ValueError("Giskard RAGET manifest names the wrong native API/export")
            roles = set(self.artifacts)
            required = set(_RAGET_REQUIRED_ARTIFACTS)
            optional = set(_RAGET_KB_ARTIFACTS)
            if not required.issubset(roles) or not roles.issubset(required | optional):
                raise ValueError(
                    "Giskard RAGET artifact roles must contain the complete RAGReport.save family"
                )
            if bool(roles & optional) and not optional.issubset(roles):
                raise ValueError("Giskard RAGET knowledge-base artifacts must occur as a pair")
            required_roles = {"target", "evaluator_llm"}
        if not required_roles.issubset(self.model_roles):
            raise ValueError(
                f"Giskard {self.mode} manifest lacks model roles {sorted(required_roles - set(self.model_roles))!r}"
            )
        allowed_roles = required_roles | {"embedding"}
        if not set(self.model_roles).issubset(allowed_roles):
            raise ValueError(
                f"Giskard {self.mode} manifest has unsupported model roles "
                f"{sorted(set(self.model_roles) - allowed_roles)!r}"
            )
        # Fail at manifest creation/import, rather than after a live run, if a
        # parameter cannot be represented reproducibly as canonical JSON.
        canonical_json_bytes(self.invocation.parameters)
        return self


class _QuestionSample(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str
    question: str
    reference_answer: str
    reference_context: str
    conversation_history: list[dict[str, str]]
    metadata: dict[str, Any]
    agent_answer: str | None = None
    correctness: bool | None = None

    @field_validator("id", "question", "reference_answer", "reference_context")
    @classmethod
    def _required_text(cls, value: str) -> str:
        return _nonblank(value, field="Giskard RAGET testset field")

    @field_validator("conversation_history")
    @classmethod
    def _history(cls, value: list[dict[str, str]]) -> list[dict[str, str]]:
        for index, message in enumerate(value):
            if not message or any(
                not isinstance(key, str)
                or not key.strip()
                or not isinstance(item, str)
                for key, item in message.items()
            ):
                raise ValueError(f"invalid RAGET conversation_history message {index}")
        return value

    @field_validator("metadata")
    @classmethod
    def _report_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        for name in ("question_type", "topic"):
            item = value.get(name)
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"RAGET report metadata requires nonblank string {name!r}"
                )
        return value


class _AgentAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    message: str
    documents: list[str] | None = None


class _ReportDetails(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    recommendation: str


def _require_giskard_v2():
    package = _require(
        "giskard",
        "GiskardAttacker native v2 execution",
        "giskard[llm]==2.19.2",
    )
    version = getattr(package, "__version__", None)
    if not isinstance(version, str):
        try:
            version = importlib.metadata.version("giskard")
        except importlib.metadata.PackageNotFoundError as exc:
            raise ExternalEngineConformanceError(
                "cannot establish the installed Giskard distribution version"
            ) from exc
    if version != GISKARD_V2_VERSION:
        raise ExternalEngineConformanceError(
            "Giskard native bridge requires giskard[llm]==2.19.2; "
            f"observed {version!r}. Giskard v3 Checks/Scan is a separate contract."
        )
    return package


def _prepare_output_dir(path: str | Path) -> Path:
    output = Path(path).resolve()
    if output.exists():
        if not output.is_dir():
            raise FileExistsError(f"Giskard output path is not a directory: {output}")
        if any(output.iterdir()):
            raise FileExistsError(f"Giskard output directory must be empty: {output}")
    else:
        output.mkdir(parents=True)
    return output


def _artifact_descriptors(
    root: Path,
    files: Mapping[str, str],
    *,
    max_artifact_bytes: int,
) -> dict[str, dict[str, str]]:
    descriptors: dict[str, dict[str, str]] = {}
    for role, filename in files.items():
        safe = _ManifestArtifact(filename=filename, sha256="0" * 64)
        path = (root / safe.filename).resolve(strict=True)
        if path.parent != root or not path.is_file():
            raise ExternalEngineOutputError(
                f"Giskard artifact must be a file directly in the run directory: {path}"
            )
        _, data = read_binary_artifact(path, max_bytes=max_artifact_bytes)
        descriptors[role] = {
            "filename": safe.filename,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return descriptors


def _write_manifest(
    root: Path,
    *,
    run_id: str,
    mode: Literal["scan", "raget"],
    model_roles: Mapping[str, str],
    dataset_id: str,
    dataset_sha256: str,
    parameters: Mapping[str, Any],
    files: Mapping[str, str],
    max_artifact_bytes: int,
) -> Path:
    manifest_path = root / GISKARD_MANIFEST_FILE
    if manifest_path.exists():
        raise FileExistsError(f"Giskard manifest already exists: {manifest_path}")
    invocation = (
        _Invocation(
            api="giskard.scan",
            report_export="ScanReport.to_json+to_html",
            parameters=dict(parameters),
        )
        if mode == "scan"
        else _Invocation(
            api="giskard.rag.evaluate",
            report_export="RAGReport.save",
            parameters=dict(parameters),
        )
    )
    manifest = _RunManifest(
        integration_schema=GISKARD_MANIFEST_SCHEMA,
        run_id=run_id,
        completed=True,
        upstream_repository=GISKARD_REPOSITORY,
        giskard_version=GISKARD_V2_VERSION,
        upstream_revision=GISKARD_V2_REVISION,
        mode=mode,
        model_roles=dict(model_roles),
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        invocation=invocation,
        artifacts=_artifact_descriptors(
            root, files, max_artifact_bytes=max_artifact_bytes
        ),
    )
    manifest_path.write_bytes(canonical_json_bytes(manifest.model_dump(mode="json")))
    return manifest_path


def _read_json_artifact(
    path: Path,
    *,
    max_bytes: int,
) -> tuple[Path, bytes, Any]:
    resolved, data, text = read_utf8_artifact(path, max_bytes=max_bytes)
    try:
        value = strict_json_loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ExternalEngineOutputError(f"invalid Giskard JSON artifact {resolved}: {exc}") from exc
    return resolved, data, value


def _source_artifact(
    *, role: str, path: Path, data: bytes, records: int
) -> NativeArtifactFile:
    return NativeArtifactFile(
        role=role,
        path=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        records=records,
    )


def _grouped_correctness(
    samples: Sequence[_QuestionSample],
    correctness: Mapping[str, bool],
    metadata_name: str,
) -> dict[str, float]:
    groups: dict[str, list[bool]] = defaultdict(list)
    for sample in samples:
        groups[str(sample.metadata[metadata_name])].append(correctness[sample.id])
    return {
        name: sum(values) / len(values)
        for name, values in sorted(groups.items())
    }


def _component_scores(
    by_question_type: Mapping[str, float],
    by_topic: Mapping[str, float],
) -> dict[str, float]:
    scores: dict[str, float] = {}
    for component, attribution in _QUESTION_ATTRIBUTION.items():
        available = [name for name in attribution if name in by_question_type]
        scores[component] = (
            sum(by_question_type[name] for name in available) / len(available)
            if available
            else 1.0
        )
    topic_values = list(by_topic.values())
    scores["KNOWLEDGE_BASE"] = 1.0 - (max(topic_values) - min(topic_values))
    return scores


class GiskardAttacker(BaseAttacker):
    """Execute or import Giskard v2's real Scan/RAGET evaluator contracts."""

    name = "giskard"
    supported_integration_mode = "native_v2_scan_or_raget"
    runner_replay_eligible = False

    def __init__(self, *, target_model: str | None = None) -> None:
        if target_model is not None:
            _nonblank(target_model, field="Giskard configured target_model")
        self.target_model = target_model

    def _target_identity(self) -> str:
        if self.target_model is None:
            raise ValueError(
                "Giskard native execution requires an explicit target_model identity"
            )
        return self.target_model

    @staticmethod
    def write_scan_manifest(
        results_dir: str | Path,
        *,
        run_id: str,
        target_model: str,
        scanner_model: str,
        dataset_id: str,
        dataset_sha256: str,
        embedding_model: str | None = None,
        scan_parameters: Mapping[str, Any] | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> Path:
        """Attach model/dataset provenance to official ScanReport exports."""

        root = Path(results_dir).resolve(strict=True)
        roles = {"target": target_model, "scanner_llm": scanner_model}
        if embedding_model is not None:
            roles["embedding"] = embedding_model
        return _write_manifest(
            root,
            run_id=run_id,
            mode="scan",
            model_roles=roles,
            dataset_id=dataset_id,
            dataset_sha256=dataset_sha256,
            parameters=dict(scan_parameters or {}),
            files=_SCAN_ARTIFACTS,
            max_artifact_bytes=max_artifact_bytes,
        )

    @staticmethod
    def write_raget_manifest(
        results_dir: str | Path,
        *,
        run_id: str,
        target_model: str,
        evaluator_model: str,
        dataset_id: str,
        dataset_sha256: str,
        embedding_model: str | None = None,
        evaluate_parameters: Mapping[str, Any] | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> Path:
        """Attach model/dataset provenance to an official RAGReport.save folder."""

        root = Path(results_dir).resolve(strict=True)
        roles = {"target": target_model, "evaluator_llm": evaluator_model}
        if embedding_model is not None:
            roles["embedding"] = embedding_model
        files = dict(_RAGET_REQUIRED_ARTIFACTS)
        kb_present = {
            role: (root / filename).exists()
            for role, filename in _RAGET_KB_ARTIFACTS.items()
        }
        if any(kb_present.values()) and not all(kb_present.values()):
            raise ExternalEngineOutputError(
                "Giskard RAGReport.save knowledge-base artifacts are incomplete"
            )
        if all(kb_present.values()):
            files.update(_RAGET_KB_ARTIFACTS)
        return _write_manifest(
            root,
            run_id=run_id,
            mode="raget",
            model_roles=roles,
            dataset_id=dataset_id,
            dataset_sha256=dataset_sha256,
            parameters=dict(evaluate_parameters or {}),
            files=files,
            max_artifact_bytes=max_artifact_bytes,
        )

    def run_scan(
        self,
        model: Any,
        dataset: Any,
        output_dir: str | Path,
        *,
        run_id: str,
        scanner_model: str,
        dataset_id: str,
        dataset_sha256: str,
        embedding_model: str | None = None,
        scan_kwargs: Mapping[str, Any] | None = None,
    ) -> NativeEngineRun:
        """Call the documented synchronous v2 ``giskard.scan`` API and import it.

        ``model`` must be the caller's real ``giskard.Model`` wrapper and
        ``dataset`` its real ``giskard.Dataset``.  This method can make target and
        evaluator calls; it is never invoked by ``generate`` or during import.
        """

        target_model = self._target_identity()
        package = _require_giskard_v2()
        scan = getattr(package, "scan", None)
        if not callable(scan):
            raise ExternalEngineConformanceError(
                "giskard==2.19.2 lacks the documented top-level giskard.scan API"
            )
        kwargs = dict(scan_kwargs or {})
        canonical_json_bytes(kwargs)
        output = _prepare_output_dir(output_dir)
        report = scan(model, dataset, **kwargs)
        to_json = getattr(report, "to_json", None)
        to_html = getattr(report, "to_html", None)
        if not callable(to_json) or not callable(to_html):
            raise ExternalEngineConformanceError(
                "giskard.scan did not return a v2 ScanReport with to_json/to_html"
            )
        to_json(output / _SCAN_ARTIFACTS["scan_report_json"])
        to_html(output / _SCAN_ARTIFACTS["scan_report_html"])
        self.write_scan_manifest(
            output,
            run_id=run_id,
            target_model=target_model,
            scanner_model=scanner_model,
            embedding_model=embedding_model,
            dataset_id=dataset_id,
            dataset_sha256=dataset_sha256,
            scan_parameters=kwargs,
        )
        return self.import_scan_run(output)

    def run_raget(
        self,
        answer_fn: Callable[..., str] | Sequence[Any],
        output_dir: str | Path,
        *,
        run_id: str,
        evaluator_model: str,
        dataset_id: str,
        dataset_sha256: str,
        testset: Any | None = None,
        knowledge_base: Any | None = None,
        llm_client: Any | None = None,
        agent_description: str = "This agent is a chatbot that answers question from users.",
        metrics: Sequence[Callable[..., Any]] | None = None,
        embedding_model: str | None = None,
    ) -> NativeEngineRun:
        """Call the documented v2 ``giskard.rag.evaluate``/``RAGReport.save`` API."""

        target_model = self._target_identity()
        _require_giskard_v2()
        rag = _require(
            "giskard.rag",
            "GiskardAttacker RAGET execution",
            "giskard[llm]==2.19.2",
        )
        evaluate = getattr(rag, "evaluate", None)
        if not callable(evaluate):
            raise ExternalEngineConformanceError(
                "giskard.rag lacks the documented v2 evaluate API"
            )
        output = _prepare_output_dir(output_dir)
        report = evaluate(
            answer_fn,
            testset=testset,
            knowledge_base=knowledge_base,
            llm_client=llm_client,
            agent_description=agent_description,
            metrics=metrics,
        )
        save = getattr(report, "save", None)
        if not callable(save):
            raise ExternalEngineConformanceError(
                "giskard.rag.evaluate did not return a v2 RAGReport with save"
            )
        save(output)
        metric_names = [
            getattr(metric, "name", getattr(metric, "__name__", type(metric).__name__))
            for metric in (metrics or ())
        ]
        self.write_raget_manifest(
            output,
            run_id=run_id,
            target_model=target_model,
            evaluator_model=evaluator_model,
            embedding_model=embedding_model,
            dataset_id=dataset_id,
            dataset_sha256=dataset_sha256,
            evaluate_parameters={
                "agent_description": agent_description,
                "metric_names": metric_names,
                "testset_supplied": testset is not None,
                "knowledge_base_supplied": knowledge_base is not None,
            },
        )
        return self.import_raget_run(output)

    def _read_manifest(
        self,
        results_dir: str | Path,
        *,
        expected_manifest_sha256: str | None,
        max_artifact_bytes: int,
    ) -> tuple[Path, bytes, _RunManifest]:
        root = Path(results_dir).resolve(strict=True)
        if not root.is_dir():
            raise ExternalEngineOutputError(f"Giskard results path is not a directory: {root}")
        path, data, text = read_utf8_artifact(
            root / GISKARD_MANIFEST_FILE, max_bytes=max_artifact_bytes
        )
        require_expected_sha256(
            data, expected_manifest_sha256, role="Giskard v2 run manifest"
        )
        try:
            value = strict_json_loads(text)
            manifest = _RunManifest.model_validate(value)
        except (json.JSONDecodeError, ValueError, ValidationError) as exc:
            raise ExternalEngineOutputError(f"invalid Giskard v2 run manifest: {exc}") from exc
        if self.target_model is not None and manifest.model_roles["target"] != self.target_model:
            raise ExternalEngineOutputError(
                "Giskard target-model mismatch: "
                f"configured={self.target_model!r}, manifest={manifest.model_roles['target']!r}"
            )
        return path, data, manifest

    def import_run(
        self,
        results_dir: str | Path,
        *,
        expected_manifest_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Dispatch to the scan or RAGET importer named by the strict manifest."""

        _, _, manifest = self._read_manifest(
            results_dir,
            expected_manifest_sha256=expected_manifest_sha256,
            max_artifact_bytes=max_artifact_bytes,
        )
        if manifest.mode == "scan":
            return self.import_scan_run(
                results_dir,
                expected_manifest_sha256=expected_manifest_sha256,
                max_artifact_bytes=max_artifact_bytes,
            )
        return self.import_raget_run(
            results_dir,
            expected_manifest_sha256=expected_manifest_sha256,
            max_artifact_bytes=max_artifact_bytes,
        )

    def import_scan_run(
        self,
        results_dir: str | Path,
        *,
        expected_manifest_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import official ``ScanReport.to_json`` and ``to_html`` exports."""

        manifest_path, manifest_data, manifest = self._read_manifest(
            results_dir,
            expected_manifest_sha256=expected_manifest_sha256,
            max_artifact_bytes=max_artifact_bytes,
        )
        if manifest.mode != "scan":
            raise ExternalEngineOutputError(
                f"Giskard manifest mode is {manifest.mode!r}, not 'scan'"
            )
        root = manifest_path.parent
        artifact_values: dict[str, tuple[Path, bytes, Any | None]] = {}
        for role, descriptor in manifest.artifacts.items():
            path = (root / descriptor.filename).resolve(strict=True)
            if path.parent != root:
                raise ExternalEngineOutputError(f"Giskard artifact escapes its run directory: {path}")
            if role == "scan_report_json":
                resolved, data, value = _read_json_artifact(
                    path, max_bytes=max_artifact_bytes
                )
            else:
                resolved, data, _ = read_utf8_artifact(
                    path, max_bytes=max_artifact_bytes
                )
                value = None
            require_expected_sha256(data, descriptor.sha256, role=f"Giskard {role}")
            artifact_values[role] = (resolved, data, value)
        report = artifact_values["scan_report_json"][2]
        if not isinstance(report, dict):
            raise ExternalEngineOutputError("Giskard ScanReport JSON must be an object")

        cases: list[NativeEngineCase] = []
        severity_counts = {level: 0 for level in sorted(_ISSUE_LEVELS)}
        issue_index = 0
        for detector, levels in report.items():
            if not isinstance(detector, str) or not detector.strip():
                raise ExternalEngineOutputError("Giskard ScanReport has a blank detector name")
            if not isinstance(levels, dict):
                raise ExternalEngineOutputError(
                    f"Giskard ScanReport detector {detector!r} must map levels to descriptions"
                )
            for level, descriptions in levels.items():
                if level not in _ISSUE_LEVELS:
                    raise ExternalEngineOutputError(
                        f"Giskard ScanReport detector {detector!r} has unknown issue level {level!r}"
                    )
                if not isinstance(descriptions, list) or any(
                    not isinstance(item, str) or not item.strip() for item in descriptions
                ):
                    raise ExternalEngineOutputError(
                        f"Giskard ScanReport {detector!r}/{level!r} descriptions must be nonblank strings"
                    )
                for description_index, description in enumerate(descriptions):
                    record = {
                        "detector": detector,
                        "level": level,
                        "description": description,
                    }
                    cases.append(
                        NativeEngineCase(
                            id=f"giskard-scan:{manifest.run_id}:{issue_index}",
                            source_run_id=manifest.run_id,
                            target_model=manifest.model_roles["target"],
                            attack_method=f"giskard-v2-scan:{detector}",
                            original_input={
                                "dataset_id": manifest.dataset_id,
                                "issue_description": description,
                            },
                            target_outputs=[],
                            native_outcome=f"reported_issue:{level}",
                            native_details={
                                "detector_name": detector,
                                "issue_level": level,
                                "description": description,
                                "html_report_retained": True,
                            },
                            source_artifact_role="scan_report_json",
                            source_record=(
                                f"scan_report.json[{detector!r}][{level!r}]"
                                f"[{description_index}]"
                            ),
                            source_record_sha256=json_sha256(record),
                        )
                    )
                    severity_counts[level] += 1
                    issue_index += 1
        if not cases:
            no_issue_record = {
                "dataset_id": manifest.dataset_id,
                "detectors": list(report),
                "outcome": "no_issues_in_native_report",
            }
            cases.append(
                NativeEngineCase(
                    id=f"giskard-scan:{manifest.run_id}:no-issues",
                    source_run_id=manifest.run_id,
                    target_model=manifest.model_roles["target"],
                    attack_method="giskard-v2-scan",
                    original_input={"dataset_id": manifest.dataset_id},
                    target_outputs=[],
                    native_outcome="no_issues_in_native_report",
                    native_details={
                        "detectors": list(report),
                        "html_report_retained": True,
                        "not_a_safety_certification": True,
                    },
                    source_artifact_role="scan_report_json",
                    source_record="scan_report.json",
                    source_record_sha256=json_sha256(no_issue_record),
                )
            )

        source_artifacts = [
            _source_artifact(
                role="manifest",
                path=manifest_path,
                data=manifest_data,
                records=1,
            )
        ]
        for role in _SCAN_ARTIFACTS:
            path, data, _ = artifact_values[role]
            source_artifacts.append(
                _source_artifact(
                    role=role,
                    path=path,
                    data=data,
                    records=max(1, issue_index) if role == "scan_report_json" else 1,
                )
            )
        return NativeEngineRun(
            engine="giskard_v2_scan",
            native_schema=GISKARD_SCAN_SCHEMA,
            native_run_id=manifest.run_id,
            upstream_repository=GISKARD_REPOSITORY,
            upstream_version=GISKARD_V2_VERSION,
            upstream_revision=GISKARD_V2_REVISION,
            source_artifacts=source_artifacts,
            target_models=[manifest.model_roles["target"]],
            model_roles=manifest.model_roles,
            cases=cases,
            native_aggregates={
                "dataset_id": manifest.dataset_id,
                "dataset_sha256": manifest.dataset_sha256,
                "scan_report": report,
                "detectors": list(report),
                "reported_issue_counts": severity_counts,
                "reported_issue_total": issue_index,
                "invocation": manifest.invocation.model_dump(mode="json"),
            },
            import_accounting={
                "detectors": len(report),
                "reported_issues": issue_index,
                "native_cases": len(cases),
            },
            measurement_semantics=(
                "Giskard v2 ScanReport detector/severity findings from its own "
                "model+dataset scan; absence of reported issues is not a safety "
                "certification and findings are not URA common ASR/FRR"
            ),
        )

    def import_raget_run(
        self,
        results_dir: str | Path,
        *,
        expected_manifest_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import the complete official ``RAGReport.save`` artifact folder."""

        manifest_path, manifest_data, manifest = self._read_manifest(
            results_dir,
            expected_manifest_sha256=expected_manifest_sha256,
            max_artifact_bytes=max_artifact_bytes,
        )
        if manifest.mode != "raget":
            raise ExternalEngineOutputError(
                f"Giskard manifest mode is {manifest.mode!r}, not 'raget'"
            )
        root = manifest_path.parent
        loaded: dict[str, tuple[Path, bytes, Any | None, int]] = {}
        for role, descriptor in manifest.artifacts.items():
            path = (root / descriptor.filename).resolve(strict=True)
            if path.parent != root:
                raise ExternalEngineOutputError(f"Giskard artifact escapes its run directory: {path}")
            if role.endswith("_html"):
                resolved, data, _ = read_utf8_artifact(
                    path, max_bytes=max_artifact_bytes
                )
                value = None
                records = 1
            elif role.endswith("_jsonl"):
                resolved, data, text = read_utf8_artifact(
                    path, max_bytes=max_artifact_bytes
                )
                rows: list[Any] = []
                for line_no, line in enumerate(text.splitlines(), start=1):
                    if not line.strip():
                        raise ExternalEngineOutputError(
                            f"Giskard {role} contains a blank record at line {line_no}"
                        )
                    try:
                        rows.append(strict_json_loads(line))
                    except (json.JSONDecodeError, ValueError) as exc:
                        raise ExternalEngineOutputError(
                            f"invalid Giskard {role} line {line_no}: {exc}"
                        ) from exc
                if not rows:
                    raise ExternalEngineOutputError(f"Giskard {role} contains no records")
                value = rows
                records = len(rows)
            else:
                resolved, data, value = _read_json_artifact(
                    path, max_bytes=max_artifact_bytes
                )
                records = len(value) if isinstance(value, (list, dict)) and value else 1
            require_expected_sha256(data, descriptor.sha256, role=f"Giskard {role}")
            loaded[role] = (resolved, data, value, records)

        raw_samples = loaded["raget_testset_jsonl"][2]
        raw_answers = loaded["raget_agent_answers_json"][2]
        raw_metrics = loaded["raget_metrics_results_json"][2]
        raw_details = loaded["raget_report_details_json"][2]
        assert isinstance(raw_samples, list)
        if not isinstance(raw_answers, list) or not raw_answers:
            raise ExternalEngineOutputError("Giskard RAGET agent_answer.json must be a non-empty array")
        if not isinstance(raw_metrics, dict) or not raw_metrics:
            raise ExternalEngineOutputError("Giskard RAGET metrics_results.json must be a non-empty object")
        try:
            samples = [_QuestionSample.model_validate(item) for item in raw_samples]
            answers = [_AgentAnswer.model_validate(item) for item in raw_answers]
            details = _ReportDetails.model_validate(raw_details)
        except ValidationError as exc:
            raise ExternalEngineOutputError(f"invalid Giskard RAGET saved report: {exc}") from exc
        if len(samples) != len(answers):
            raise ExternalEngineOutputError(
                "Giskard RAGET testset and agent-answer counts differ"
            )
        ids = [sample.id for sample in samples]
        if len(ids) != len(set(ids)):
            raise ExternalEngineOutputError("Giskard RAGET testset IDs must be unique")
        if set(raw_metrics) != set(ids):
            raise ExternalEngineOutputError(
                "Giskard RAGET metric-result IDs do not exactly match the testset"
            )

        correctness: dict[str, bool] = {}
        additional_metric_names: set[str] = set()
        cases: list[NativeEngineCase] = []
        for index, (sample, answer) in enumerate(zip(samples, answers)):
            metric_values = raw_metrics[sample.id]
            if not isinstance(metric_values, dict):
                raise ExternalEngineOutputError(
                    f"Giskard RAGET metrics for {sample.id!r} must be an object"
                )
            correct = metric_values.get("correctness")
            if not isinstance(correct, bool):
                raise ExternalEngineOutputError(
                    f"Giskard RAGET metrics for {sample.id!r} lack boolean correctness"
                )
            reason = metric_values.get("correctness_reason")
            if reason is not None and not isinstance(reason, str):
                raise ExternalEngineOutputError(
                    f"Giskard RAGET correctness_reason for {sample.id!r} must be a string"
                )
            correctness[sample.id] = correct
            native_scores: dict[str, int | float] = {}
            for metric_name, value in metric_values.items():
                if metric_name not in {"correctness", "correctness_reason"}:
                    additional_metric_names.add(metric_name)
                if (
                    metric_name not in {"correctness", "correctness_reason"}
                    and not isinstance(value, bool)
                    and isinstance(value, (int, float))
                ):
                    if not math.isfinite(float(value)):
                        raise ExternalEngineOutputError(
                            f"Giskard RAGET metric {metric_name!r} for {sample.id!r} is non-finite"
                        )
                    native_scores[metric_name] = value
            cases.append(
                NativeEngineCase(
                    id=f"giskard-raget:{manifest.run_id}:{sample.id}",
                    source_run_id=manifest.run_id,
                    target_model=manifest.model_roles["target"],
                    attack_method="giskard-v2-raget",
                    original_input={
                        "question": sample.question,
                        "reference_answer": sample.reference_answer,
                        "reference_context": sample.reference_context,
                        "conversation_history": sample.conversation_history,
                        "metadata": sample.metadata,
                    },
                    target_outputs=[answer.message],
                    native_outcome="correct" if correct else "incorrect",
                    native_scores=native_scores,
                    native_details={
                        "question_id": sample.id,
                        "metrics": metric_values,
                        "retrieved_documents": answer.documents,
                        "correctness_judge": manifest.model_roles["evaluator_llm"],
                    },
                    source_artifact_role="raget_metrics_results_json",
                    source_record=f"metrics_results.json[{sample.id!r}]",
                    source_record_sha256=json_sha256(metric_values),
                )
            )

        by_question_type = _grouped_correctness(
            samples, correctness, "question_type"
        )
        by_topic = _grouped_correctness(samples, correctness, "topic")
        component_scores = _component_scores(by_question_type, by_topic)
        overall_correctness = sum(correctness.values()) / len(correctness)

        source_artifacts = [
            _source_artifact(
                role="manifest",
                path=manifest_path,
                data=manifest_data,
                records=1,
            )
        ]
        for role in manifest.artifacts:
            path, data, _, records = loaded[role]
            source_artifacts.append(
                _source_artifact(
                    role=role,
                    path=path,
                    data=data,
                    records=records,
                )
            )
        return NativeEngineRun(
            engine="giskard_v2_raget",
            native_schema=GISKARD_RAGET_SCHEMA,
            native_run_id=manifest.run_id,
            upstream_repository=GISKARD_REPOSITORY,
            upstream_version=GISKARD_V2_VERSION,
            upstream_revision=GISKARD_V2_REVISION,
            source_artifacts=source_artifacts,
            target_models=[manifest.model_roles["target"]],
            model_roles=manifest.model_roles,
            cases=cases,
            native_aggregates={
                "dataset_id": manifest.dataset_id,
                "dataset_sha256": manifest.dataset_sha256,
                "correctness": overall_correctness,
                "correctness_by_question_type": by_question_type,
                "correctness_by_topic": by_topic,
                "component_scores_0_to_1": component_scores,
                "additional_metric_names": sorted(additional_metric_names),
                "recommendation": details.recommendation,
                "metrics_results": raw_metrics,
                "invocation": manifest.invocation.model_dump(mode="json"),
            },
            import_accounting={
                "questions": len(samples),
                "correct": sum(correctness.values()),
                "incorrect": len(samples) - sum(correctness.values()),
                "knowledge_base_retained": int(
                    "raget_knowledge_base_jsonl" in manifest.artifacts
                ),
            },
            measurement_semantics=(
                "Giskard v2 RAGET source-native LLM-judged correctness and "
                "0-to-1 component scores over the saved testset/agent answers; "
                "these business-correctness metrics are not URA common ASR/FRR"
            ),
        )

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "Giskard is supported through run_scan/import_scan_run and "
            "run_raget/import_raget_run using giskard[llm]==2.19.2. "
            "BaseAttacker.generate is inapplicable: v2 Scan and RAGET are complete "
            "model/dataset evaluators, while the removed v3 generate_suite prompt "
            "exporter was not a real Giskard API."
        )


__all__ = [
    "GISKARD_MANIFEST_FILE",
    "GISKARD_MANIFEST_SCHEMA",
    "GISKARD_RAGET_SCHEMA",
    "GISKARD_REPOSITORY",
    "GISKARD_SCAN_SCHEMA",
    "GISKARD_V2_REVISION",
    "GISKARD_V2_VERSION",
    "GiskardAttacker",
]
