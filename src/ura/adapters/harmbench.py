"""Pinned HarmBench test-case generation with transfer-safe provenance.

HarmBench's generation scripts create adversarial test cases under a named
experiment/model configuration.  URA may replay those cases against another
target, but that is a transfer condition; it is not HarmBench's native
completion/classifier evaluation.  This adapter therefore preserves the exact
method, experiment, checkout commit and generated artifact tree, and never
substitutes URA common metrics for HarmBench's native classifier.

The supported bridge is text-only.  ``MultiModal*`` methods and any image-bearing
output fail closed until their generated image artifacts can be represented.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..data_models import Attempt, DataPoint
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
    _attempt,
    run_engine_command,
)
from ._native_artifacts import read_binary_artifact, read_utf8_artifact
from .base import AttackBudget, BaseAttacker

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPLAY_FORMAT = "ura-harmbench-transfer-replay/1"
_METHOD_SPECS: dict[str, tuple[str, str | None]] = {
    # logical HarmBench paper/pipeline name: (upstream class, fixed experiment).
    # A null experiment uses this adapter's configured target-model experiment.
    "PEZ": ("PEZ", None),
    "GBDA": ("GBDA", None),
    "UAT": ("UAT", None),
    "AutoPrompt": ("AutoPrompt", None),
    "PAP-top5": ("PAP", "top_5"),
    "GCG": ("GCG", None),
    "GCG-Multi": ("EnsembleGCG", None),
    "GCG-Transfer": (
        "EnsembleGCG",
        "llama2_7b_vicuna_7b_llama2_13b_vicuna_13b_multibehavior_1000steps",
    ),
    "AutoDAN": ("AutoDAN", None),
    "PAIR": ("PAIR", None),
    "TAP": ("TAP", None),
    "DirectRequest": ("DirectRequest", "default"),
    "HumanJailbreaks": ("HumanJailbreaks", "random_subset_5"),
    "ZeroShot": ("ZeroShot", "mixtral_attacker_llm"),
}
_SUPPORTED_METHODS = frozenset(_METHOD_SPECS)
_IDENTITY_METHODS = frozenset({"DirectRequest"})
_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_BEHAVIOR_CSV_BYTES = 1024 * 1024
_MAX_TREE_BYTES = 512 * 1024 * 1024
_MAX_TREE_FILES = 10_000
_MAX_REPLAY_BYTES = 64 * 1024 * 1024
_MAX_REPLAY_CASES = 100_000
_MAX_REPLAY_REQUESTS = 10_000


def _canonical_sha256(value: Any) -> str:
    data = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _behavior_text(datapoint: DataPoint) -> str:
    value = datapoint.payload_text or datapoint.payload_code or ""
    if not value.strip():
        raise ExternalEngineOutputError("HarmBench received a blank behavior")
    return value


def _source_request(datapoint: DataPoint) -> dict[str, str]:
    """Return the exact converted-request identity bound into a replay bundle."""

    behavior = _behavior_text(datapoint)
    return {
        "datapoint_id": datapoint.id,
        "source": datapoint.source,
        "datapoint_sha256": _canonical_sha256(datapoint.model_dump(mode="json")),
        "behavior_sha256": hashlib.sha256(behavior.encode("utf-8")).hexdigest(),
    }


def _upstream_execution(method: str, experiment: str) -> tuple[str, str]:
    upstream_method, fixed_experiment = _METHOD_SPECS[method]
    return upstream_method, fixed_experiment or experiment


class HarmBenchAttacker(BaseAttacker):
    """Run every configured HarmBench method at one immutable checkout.

    A full 40-hex ``upstream_revision`` is required and is checked against a
    clean Git worktree.  ``max_queries`` must permit at least one generated case
    from every configured method, preventing a budget from silently dropping a
    treatment arm.
    """

    name = "harmbench"

    def __init__(
        self,
        methods: list[str] | None = None,
        experiment: str = "llama2_7b",
        repo: str | None = None,
        *,
        upstream_revision: str | None = None,
        script: str = "generate_test_cases.py",
        merge_script: str = "merge_test_cases.py",
        python: str | None = None,
        credential_env: list[str] | tuple[str, ...] | None = None,
        timeout_seconds: float | None = None,
        replay_artifact: str | Path | None = None,
        replay_artifact_sha256: str | None = None,
    ) -> None:
        selected = ["PEZ", "PAP-top5"] if methods is None else list(methods)
        if not selected or any(not isinstance(method, str) for method in selected):
            raise ValueError("HarmBench methods must be a non-empty string list")
        multimodal = [
            method for method in selected if method.lower().startswith("multimodal")
        ]
        if multimodal:
            raise ValueError(
                "HarmBench MultiModal* methods are not supported by this bridge: "
                "generated image bytes cannot be discarded or represented as "
                f"text-only attempts ({', '.join(multimodal)})"
            )
        unknown = sorted(set(selected) - _SUPPORTED_METHODS)
        if unknown:
            raise ValueError("unsupported HarmBench methods: " + ", ".join(unknown))
        if len(set(selected)) != len(selected):
            raise ValueError("HarmBench methods must be unique")
        if not isinstance(experiment, str) or not experiment.strip():
            raise ValueError("HarmBench experiment must be non-blank")
        for label, value in {"script": script, "merge_script": merge_script}.items():
            path = Path(value)
            if path.is_absolute() or ".." in path.parts or not value.strip():
                raise ValueError(f"HarmBench {label} must be a safe repo-relative path")
        if upstream_revision is not None and not _COMMIT_RE.fullmatch(upstream_revision):
            raise ValueError("HarmBench upstream_revision must be a full 40-hex commit")
        if replay_artifact is None and replay_artifact_sha256 is not None:
            raise ValueError(
                "HarmBench replay_artifact_sha256 requires replay_artifact"
            )
        if replay_artifact is not None:
            if upstream_revision is None:
                raise ValueError(
                    "HarmBench replay requires an explicit upstream_revision"
                )
            if (
                not isinstance(replay_artifact_sha256, str)
                or not _SHA256_RE.fullmatch(replay_artifact_sha256.lower())
            ):
                raise ValueError(
                    "HarmBench replay_artifact_sha256 must be a full SHA-256"
                )

        self.methods = selected
        self.experiment = experiment.strip()
        self.repo = repo
        self.upstream_revision = (
            upstream_revision.lower() if upstream_revision is not None else None
        )
        self.script = script
        self.merge_script = merge_script
        self.python = python
        self.credential_env = tuple(credential_env or ())
        self.timeout_seconds = timeout_seconds
        # The operator-local path is deliberately private so Runner manifests
        # retain only the validated, portable content identity below.
        self._replay_artifact = (
            Path(replay_artifact) if replay_artifact is not None else None
        )
        self.replay_artifact_sha256 = (
            replay_artifact_sha256.lower()
            if replay_artifact_sha256 is not None
            else None
        )
        self.replay_artifact_identity: dict[str, object] | None = None
        self._replay_cases: dict[str, list[dict[str, Any]]] | None = None
        self._replay_cases_per_method: int | None = None

    def validate_measured_run(self, corpus: Iterable[DataPoint] = ()) -> None:
        """Admit only a complete capture matching the exact measured corpus."""

        if self._replay_artifact is None:
            raise ExternalEngineConformanceError(
                "measured HarmBench runs require replay_artifact: run "
                "experiments.harmbench_capture before the measured grid"
            )
        prepared = list(corpus)
        if any(
            datapoint.media
            or any(turn.media for turn in datapoint.dialog_history)
            for datapoint in prepared
        ):
            raise ExternalEngineConformanceError(
                "the text-only HarmBench replay cannot admit DataPoint media"
            )
        bundle, identity = self._read_replay_artifact(prepared)
        cases: dict[str, list[dict[str, Any]]] = {}
        for case in bundle["cases"]:
            cases.setdefault(case["datapoint_id"], []).append(case)
        self._replay_cases = cases
        self._replay_cases_per_method = bundle["cases_per_method"]
        self.replay_artifact_identity = identity

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        required_queries = len(self.methods)
        if self._replay_artifact is not None and self._replay_cases_per_method is not None:
            required_queries *= self._replay_cases_per_method
        if min(budget.max_queries, budget.max_turns) < required_queries:
            raise ExternalEngineConformanceError(
                "HarmBench max_queries and max_turns must cover every captured "
                "case and method"
                if self._replay_artifact is not None
                else "HarmBench max_queries and max_turns must allow at least "
                "one case per configured method"
            )
        if datapoint.media or any(turn.media for turn in datapoint.dialog_history):
            raise ExternalEngineConformanceError(
                "the text-only HarmBench bridge cannot drop DataPoint media"
            )
        seed = _behavior_text(datapoint)

        if self._replay_artifact is not None:
            if self._replay_cases is None or self.replay_artifact_identity is None:
                raise ExternalEngineConformanceError(
                    "HarmBench replay must be validated against the complete corpus "
                    "before generation"
                )
            generated = self._replay_cases.get(datapoint.id)
            if generated is None:
                raise ExternalEngineConformanceError(
                    f"HarmBench replay has no captured cases for {datapoint.id!r}"
                )
            yield from self._attempts(
                datapoint,
                generated[: budget.max_queries],
                budget,
                replay_identity=self.replay_artifact_identity,
            )
            return

        generated = self._generate_test_cases(datapoint, seed, budget.max_queries)
        yield from self._attempts(datapoint, generated, budget)

    def _attempts(
        self,
        datapoint: DataPoint,
        generated: list[dict[str, Any]],
        budget: AttackBudget,
        *,
        replay_identity: dict[str, object] | None = None,
    ) -> Iterable[Attempt]:
        for index, item in enumerate(generated):
            method = item["method"]
            params = {
                "method": method,
                "upstream_method": item.get(
                    "upstream_method", _upstream_execution(method, self.experiment)[0]
                ),
                "upstream_experiment": item.get(
                    "upstream_experiment", _upstream_execution(method, self.experiment)[1]
                ),
                "experiment": self.experiment,
                "upstream_revision": self.upstream_revision,
                "attack_semantics": "harmbench_generated_case_transfer",
                "source_experiment_conditioned": True,
                "native_completions_executed": False,
                "native_harmbench_classifier_executed": False,
                "common_judge_is_not_native_harmbench_classifier": True,
                "behavior_csv_sha256": item["behavior_csv_sha256"],
                "generated_case_index": item["case_index"],
                "generated_case_sha256": item.get(
                    "prompt_sha256",
                    hashlib.sha256(item["prompt"].encode("utf-8")).hexdigest(),
                ),
                "source_request_sha256": item.get("datapoint_sha256"),
                "method_output_artifacts": item["artifacts"],
                "method_output_manifest_sha256": item["artifact_manifest_sha256"],
            }
            if replay_identity is not None:
                params["replay_artifact_identity"] = replay_identity
            yield _attempt(
                datapoint,
                self.name,
                strategy=f"harmbench:{method}:{self.experiment}:transfer",
                turn_index=index,
                prompt=item["prompt"],
                seed=budget.seed,
                params=params,
            )

    def _read_replay_artifact(
        self, corpus: list[DataPoint]
    ) -> tuple[dict[str, Any], dict[str, object]]:
        assert self._replay_artifact is not None
        assert self.replay_artifact_sha256 is not None
        try:
            path, raw = read_binary_artifact(
                self._replay_artifact.expanduser(), max_bytes=_MAX_REPLAY_BYTES
            )
        except ExternalEngineOutputError as exc:
            raise ExternalEngineConformanceError(
                f"cannot read HarmBench replay artifact: {self._replay_artifact}"
            ) from exc
        file_sha256 = hashlib.sha256(raw).hexdigest()
        if file_sha256 != self.replay_artifact_sha256:
            raise ExternalEngineConformanceError(
                "HarmBench replay artifact does not match replay_artifact_sha256"
            )
        try:
            bundle = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise ExternalEngineOutputError(
                "HarmBench replay artifact is not valid UTF-8 JSON"
            ) from exc
        if not isinstance(bundle, dict):
            raise ExternalEngineOutputError("HarmBench replay artifact must be an object")
        expected_top = {
            "format_version",
            "upstream_revision",
            "experiment",
            "methods",
            "cases_per_method",
            "selection",
            "source_artifact",
            "source_requests",
            "cases",
            "content_sha256",
        }
        if set(bundle) != expected_top:
            raise ExternalEngineOutputError(
                "HarmBench replay artifact is incomplete or has unknown fields"
            )
        if bundle["format_version"] != _REPLAY_FORMAT:
            raise ExternalEngineOutputError(
                f"HarmBench replay artifact must use {_REPLAY_FORMAT}"
            )
        content_sha256 = bundle["content_sha256"]
        unsigned = {key: value for key, value in bundle.items() if key != "content_sha256"}
        if (
            not isinstance(content_sha256, str)
            or not _SHA256_RE.fullmatch(content_sha256)
            or _canonical_sha256(unsigned) != content_sha256
        ):
            raise ExternalEngineConformanceError(
                "HarmBench replay artifact content digest is invalid"
            )
        if bundle["upstream_revision"] != self.upstream_revision:
            raise ExternalEngineConformanceError(
                "HarmBench replay upstream revision does not match configuration"
            )
        if bundle["experiment"] != self.experiment:
            raise ExternalEngineConformanceError(
                "HarmBench replay experiment does not match configuration"
            )
        if bundle["methods"] != self.methods:
            raise ExternalEngineConformanceError(
                "HarmBench replay methods do not match configuration"
            )
        cases_per_method = bundle["cases_per_method"]
        if (
            isinstance(cases_per_method, bool)
            or not isinstance(cases_per_method, int)
            or not 1 <= cases_per_method <= 1000
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay cases_per_method must be in [1, 1000]"
            )
        self._validate_capture_metadata(bundle["selection"], bundle["source_artifact"])

        requests = bundle["source_requests"]
        if (
            not isinstance(requests, list)
            or not requests
            or len(requests) > _MAX_REPLAY_REQUESTS
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay must contain a bounded non-empty source request list"
            )
        expected_requests = [_source_request(datapoint) for datapoint in corpus]
        if requests != expected_requests:
            raise ExternalEngineConformanceError(
                "HarmBench replay source requests do not exactly match the measured corpus"
            )
        request_by_id: dict[str, dict[str, str]] = {}
        for request in requests:
            if not isinstance(request, dict) or set(request) != {
                "datapoint_id", "source", "datapoint_sha256", "behavior_sha256"
            }:
                raise ExternalEngineOutputError(
                    "HarmBench replay contains an invalid source request identity"
                )
            datapoint_id = request.get("datapoint_id")
            source = request.get("source")
            if (
                not isinstance(datapoint_id, str)
                or not datapoint_id.strip()
                or not isinstance(source, str)
                or not source.strip()
                or not isinstance(request.get("datapoint_sha256"), str)
                or not _SHA256_RE.fullmatch(request["datapoint_sha256"])
                or not isinstance(request.get("behavior_sha256"), str)
                or not _SHA256_RE.fullmatch(request["behavior_sha256"])
                or datapoint_id in request_by_id
            ):
                raise ExternalEngineOutputError(
                    "HarmBench replay source request identities are invalid or duplicated"
                )
            request_by_id[datapoint_id] = request

        cases = bundle["cases"]
        expected_case_count = len(requests) * len(self.methods) * cases_per_method
        if (
            not isinstance(cases, list)
            or len(cases) != expected_case_count
            or len(cases) > _MAX_REPLAY_CASES
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay is partial or exceeds the case-count limit"
            )
        observed: dict[tuple[str, str], set[int]] = {}
        for case in cases:
            self._validate_replay_case(case, request_by_id)
            key = (case["datapoint_id"], case["method"])
            indexes = observed.setdefault(key, set())
            if case["case_index"] in indexes:
                raise ExternalEngineOutputError(
                    "HarmBench replay contains duplicate generated case indexes"
                )
            indexes.add(case["case_index"])
        required_indexes = set(range(cases_per_method))
        required_groups = {
            (request["datapoint_id"], method)
            for request in requests
            for method in self.methods
        }
        if set(observed) != required_groups or any(
            indexes != required_indexes for indexes in observed.values()
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay does not contain every requested method/case"
            )
        return bundle, {
            "format_version": _REPLAY_FORMAT,
            "sha256": file_sha256,
            "bytes": len(raw),
            "content_sha256": content_sha256,
            "source_requests": len(requests),
            "generated_cases": len(cases),
        }

    @staticmethod
    def _validate_capture_metadata(selection: object, source_artifact: object) -> None:
        if not isinstance(selection, dict) or set(selection) != {
            "corpus_name", "limit", "sample_seed"
        }:
            raise ExternalEngineOutputError("HarmBench replay selection is invalid")
        if (
            not isinstance(selection.get("corpus_name"), str)
            or not selection["corpus_name"].strip()
            or isinstance(selection.get("limit"), bool)
            or not isinstance(selection.get("limit"), int)
            or selection["limit"] < 0
            or isinstance(selection.get("sample_seed"), bool)
            or not isinstance(selection.get("sample_seed"), int)
        ):
            raise ExternalEngineOutputError("HarmBench replay selection is invalid")
        if not isinstance(source_artifact, dict) or set(source_artifact) != {
            "file", "sha256", "bytes"
        }:
            raise ExternalEngineOutputError(
                "HarmBench replay source artifact identity is invalid"
            )
        filename = source_artifact.get("file")
        size = source_artifact.get("bytes")
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or not isinstance(source_artifact.get("sha256"), str)
            or not _SHA256_RE.fullmatch(source_artifact["sha256"])
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay source artifact identity is invalid"
            )

    def _validate_replay_case(
        self,
        case: object,
        request_by_id: dict[str, dict[str, str]],
    ) -> None:
        expected = {
            "datapoint_id",
            "datapoint_sha256",
            "method",
            "upstream_method",
            "upstream_experiment",
            "case_index",
            "prompt",
            "prompt_sha256",
            "behavior_csv_sha256",
            "artifacts",
            "artifact_manifest_sha256",
        }
        if not isinstance(case, dict) or set(case) != expected:
            raise ExternalEngineOutputError(
                "HarmBench replay contains an invalid generated case"
            )
        request = request_by_id.get(case.get("datapoint_id"))
        method = case.get("method")
        expected_execution = (
            _upstream_execution(method, self.experiment)
            if method in self.methods
            else None
        )
        index = case.get("case_index")
        prompt = case.get("prompt")
        if (
            request is None
            or case.get("datapoint_sha256") != request["datapoint_sha256"]
            or method not in self.methods
            or expected_execution is None
            or (case.get("upstream_method"), case.get("upstream_experiment"))
            != expected_execution
            or isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or not isinstance(prompt, str)
            or not prompt.strip()
            or not isinstance(case.get("prompt_sha256"), str)
            or hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            != case["prompt_sha256"]
            or not isinstance(case.get("behavior_csv_sha256"), str)
            or not _SHA256_RE.fullmatch(case["behavior_csv_sha256"])
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay generated case identity is invalid"
            )
        if method not in _IDENTITY_METHODS and (
            case["prompt_sha256"] == request["behavior_sha256"]
        ):
            raise ExternalEngineOutputError(
                f"HarmBench {method} replay contains the unchanged behavior"
            )
        artifacts = case.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ExternalEngineOutputError(
                "HarmBench replay generated case lacks output artifacts"
            )
        files: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {
                "file", "sha256", "bytes"
            }:
                raise ExternalEngineOutputError(
                    "HarmBench replay has an invalid output artifact descriptor"
                )
            filename = artifact.get("file")
            size = artifact.get("bytes")
            if (
                not isinstance(filename, str)
                or not filename
                or Path(filename).is_absolute()
                or ".." in Path(filename).parts
                or filename in files
                or not isinstance(artifact.get("sha256"), str)
                or not _SHA256_RE.fullmatch(artifact["sha256"])
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size <= 0
            ):
                raise ExternalEngineOutputError(
                    "HarmBench replay has an invalid output artifact descriptor"
                )
            files.add(filename)
        if (
            not isinstance(case.get("artifact_manifest_sha256"), str)
            or _canonical_sha256(artifacts) != case["artifact_manifest_sha256"]
        ):
            raise ExternalEngineOutputError(
                "HarmBench replay output artifact manifest digest is invalid"
            )

    def _checkout(self) -> tuple[Path, Path, Path]:
        configured = self.repo or os.environ.get("HARMBENCH_HOME")
        if not configured:
            raise ExternalEngineConformanceError(
                "HarmBench requires repo=... or HARMBENCH_HOME"
            )
        try:
            root = Path(configured).resolve(strict=True)
        except OSError as exc:
            raise ExternalEngineConformanceError(
                f"HarmBench checkout cannot be resolved: {configured}"
            ) from exc
        if not root.is_dir():
            raise ExternalEngineConformanceError("HarmBench checkout is not a directory")
        entries: list[Path] = []
        for relative in (self.script, self.merge_script):
            try:
                entry = (root / relative).resolve(strict=True)
                entry.relative_to(root)
            except (OSError, ValueError) as exc:
                raise ExternalEngineConformanceError(
                    f"HarmBench entry script is missing or escapes checkout: {relative}"
                ) from exc
            if not entry.is_file():
                raise ExternalEngineConformanceError(
                    f"HarmBench entry is not a file: {entry}"
                )
            entries.append(entry)
        return root, entries[0], entries[1]

    def _verify_checkout(self, root: Path) -> str:
        if self.upstream_revision is None:
            raise ExternalEngineConformanceError(
                "HarmBench execution requires an immutable upstream_revision"
            )
        git = shutil.which("git")
        if git is None:
            raise ExternalEngineConformanceError(
                "Git is required to verify the HarmBench checkout revision"
            )
        head = run_engine_command(
            [git, "-C", str(root), "rev-parse", "HEAD"],
            feature="HarmBench checkout revision",
            timeout_seconds=self.timeout_seconds,
        ).stdout.strip()
        if head.lower() != self.upstream_revision:
            raise ExternalEngineConformanceError(
                "HarmBench checkout HEAD does not match upstream_revision"
            )
        status = run_engine_command(
            [
                git, "-C", str(root), "status", "--porcelain=v1",
                "--untracked-files=all", "--ignored=matching",
            ],
            feature="HarmBench checkout cleanliness",
            timeout_seconds=self.timeout_seconds,
        ).stdout
        if status.strip():
            raise ExternalEngineConformanceError(
                "HarmBench checkout has tracked modifications, untracked files, "
                "or ignored files"
            )
        return head.lower()

    def _generate_test_cases(
        self, datapoint: DataPoint, seed: str, limit: int
    ) -> list[dict[str, Any]]:
        root, entry, merge = self._checkout()
        self._verify_checkout(root)
        datapoint_sha256 = _source_request(datapoint)["datapoint_sha256"]
        python = self.python or sys.executable

        by_method: dict[str, list[dict[str, Any]]] = {}
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            behaviors_csv = tmp_root / "behaviors.csv"
            behavior_id = self._write_behaviors_csv(datapoint, seed, behaviors_csv)
            _, behavior_csv_bytes = read_binary_artifact(
                behaviors_csv, max_bytes=_MAX_BEHAVIOR_CSV_BYTES
            )
            behavior_csv_sha256 = hashlib.sha256(
                behavior_csv_bytes
            ).hexdigest()

            for method in self.methods:
                upstream_method, upstream_experiment = _upstream_execution(
                    method, self.experiment
                )
                save_dir = tmp_root / method
                run_engine_command(
                    [
                        python,
                        str(entry),
                        "--method_name",
                        upstream_method,
                        "--experiment_name",
                        upstream_experiment,
                        "--behaviors_path",
                        str(behaviors_csv),
                        "--save_dir",
                        str(save_dir),
                        "--behavior_start_idx",
                        "0",
                        "--behavior_end_idx",
                        "1",
                        "--overwrite",
                    ],
                    feature=f"HarmBench {method} generation",
                    cwd=root,
                    allow_credentials=self.credential_env,
                    env_overrides={"PYTHONDONTWRITEBYTECODE": "1"},
                    timeout_seconds=self.timeout_seconds,
                )
                run_engine_command(
                    [
                        python,
                        str(merge),
                        "--method_name",
                        upstream_method,
                        "--save_dir",
                        str(save_dir),
                    ],
                    feature=f"HarmBench {method} merge",
                    cwd=root,
                    allow_credentials=self.credential_env,
                    env_overrides={"PYTHONDONTWRITEBYTECODE": "1"},
                    timeout_seconds=self.timeout_seconds,
                )
                prompts = self._read_test_cases(
                    save_dir / "test_cases.json", behavior_id
                )
                if method not in _IDENTITY_METHODS and any(prompt == seed for prompt in prompts):
                    raise ExternalEngineOutputError(
                        f"HarmBench {method} emitted the unchanged behavior"
                    )
                artifacts = self._describe_tree(save_dir)
                manifest_sha256 = _canonical_sha256(artifacts)
                by_method[method] = [
                    {
                        "method": method,
                        "upstream_method": upstream_method,
                        "upstream_experiment": upstream_experiment,
                        "prompt": prompt,
                        "prompt_sha256": hashlib.sha256(
                            prompt.encode("utf-8")
                        ).hexdigest(),
                        "datapoint_sha256": datapoint_sha256,
                        "case_index": case_index,
                        "behavior_csv_sha256": behavior_csv_sha256,
                        "artifacts": artifacts,
                        "artifact_manifest_sha256": manifest_sha256,
                    }
                    for case_index, prompt in enumerate(prompts)
                ]

            selected = [by_method[method][0] for method in self.methods]
            offsets = {method: 1 for method in self.methods}
            while len(selected) < limit:
                progressed = False
                for method in self.methods:
                    offset = offsets[method]
                    rows = by_method[method]
                    if offset < len(rows):
                        selected.append(rows[offset])
                        offsets[method] += 1
                        progressed = True
                        if len(selected) == limit:
                            break
                if not progressed:
                    break
        return selected

    @staticmethod
    def _write_behaviors_csv(datapoint: DataPoint, seed: str, path: Path) -> str:
        import csv

        behavior_id = "".join(
            char if char.isalnum() else "_" for char in (datapoint.id or "seed")
        )[:64] or "seed"
        fields = [
            "Behavior",
            "FunctionalCategory",
            "SemanticCategory",
            "Tags",
            "ContextString",
            "BehaviorID",
        ]
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerow({
                "Behavior": seed,
                "FunctionalCategory": "standard",
                "SemanticCategory": datapoint.risk_subtype or "",
                "Tags": "",
                "ContextString": "",
                "BehaviorID": behavior_id,
            })
        return behavior_id

    @staticmethod
    def _read_test_cases(path: Path, behavior_id: str) -> list[str]:
        try:
            _, _, raw = read_utf8_artifact(path, max_bytes=_MAX_FILE_BYTES)
            data = json.loads(
                raw,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant {value}")
                ),
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ExternalEngineOutputError(
                f"HarmBench merged output is missing or invalid: {path}"
            ) from exc
        if not isinstance(data, dict) or set(data) != {behavior_id}:
            raise ExternalEngineOutputError(
                "HarmBench test_cases.json must contain exactly the requested BehaviorID"
            )
        items = data[behavior_id]
        if not isinstance(items, list) or not items:
            raise ExternalEngineOutputError(
                "HarmBench emitted no test cases for the requested BehaviorID"
            )
        prompts: list[str] = []
        for case_index, case in enumerate(items):
            if isinstance(case, (list, tuple)) or (
                isinstance(case, dict)
                and any(key in case for key in ("image", "image_path", "image_file", "media"))
            ):
                raise ExternalEngineOutputError(
                    "HarmBench emitted a multimodal test case, but this bridge "
                    "cannot preserve its generated image artifact"
                )
            if not isinstance(case, str) or not case.strip():
                raise ExternalEngineOutputError(
                    f"HarmBench test case {case_index} is not a non-blank string"
                )
            prompts.append(case)
        return prompts

    @staticmethod
    def _describe_tree(root: Path) -> list[dict[str, Any]]:
        if not root.is_dir():
            raise ExternalEngineOutputError("HarmBench method output directory is missing")
        descriptors: list[dict[str, Any]] = []
        total = 0
        file_count = 0
        entry_count = 0
        for path in sorted(root.rglob("*")):
            entry_count += 1
            if entry_count > _MAX_TREE_FILES * 4:
                raise ExternalEngineOutputError(
                    "HarmBench output tree contains too many filesystem entries"
                )
            if path.is_symlink():
                raise ExternalEngineOutputError(
                    "HarmBench output tree contains a symbolic link"
                )
            if not path.is_file():
                continue
            file_count += 1
            if file_count > _MAX_TREE_FILES:
                raise ExternalEngineOutputError(
                    f"HarmBench output tree exceeds {_MAX_TREE_FILES} files"
                )
            resolved, payload = read_binary_artifact(
                path, max_bytes=_MAX_FILE_BYTES
            )
            total += len(payload)
            if total > _MAX_TREE_BYTES:
                raise ExternalEngineOutputError(
                    f"HarmBench output tree exceeds {_MAX_TREE_BYTES} bytes"
                )
            descriptors.append({
                "file": resolved.relative_to(root.resolve(strict=True)).as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            })
        if not descriptors:
            raise ExternalEngineOutputError("HarmBench emitted no output artifacts")
        return descriptors


__all__ = ["HarmBenchAttacker"]
