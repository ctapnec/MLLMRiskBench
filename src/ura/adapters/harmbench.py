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
_SUPPORTED_METHODS = frozenset({
    "PEZ", "GBDA", "UAT", "AutoPrompt", "PAP-top5", "GCG", "GCG-Multi",
    "GCG-Transfer", "AutoDAN", "PAIR", "TAP", "DirectRequest",
    "HumanJailbreaks", "ZeroShot",
})
_IDENTITY_METHODS = frozenset({"DirectRequest"})
_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_BEHAVIOR_CSV_BYTES = 1024 * 1024
_MAX_TREE_BYTES = 512 * 1024 * 1024
_MAX_TREE_FILES = 10_000


def _canonical_sha256(value: Any) -> str:
    data = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


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

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        if budget.max_queries < len(self.methods):
            raise ExternalEngineConformanceError(
                "HarmBench max_queries must allow at least one case per configured method"
            )
        if datapoint.media or any(turn.media for turn in datapoint.dialog_history):
            raise ExternalEngineConformanceError(
                "the text-only HarmBench bridge cannot drop DataPoint media"
            )
        seed = datapoint.payload_text or datapoint.payload_code or ""
        if not seed.strip():
            raise ExternalEngineOutputError("HarmBench received a blank behavior")

        generated = self._generate_test_cases(datapoint, seed, budget.max_queries)
        for index, item in enumerate(generated):
            method = item["method"]
            yield _attempt(
                datapoint,
                self.name,
                strategy=f"harmbench:{method}:{self.experiment}:transfer",
                turn_index=index,
                prompt=item["prompt"],
                seed=budget.seed,
                params={
                    "method": method,
                    "experiment": self.experiment,
                    "upstream_revision": self.upstream_revision,
                    "attack_semantics": "harmbench_generated_case_transfer",
                    "source_experiment_conditioned": True,
                    "native_completions_executed": False,
                    "native_harmbench_classifier_executed": False,
                    "common_judge_is_not_native_harmbench_classifier": True,
                    "behavior_csv_sha256": item["behavior_csv_sha256"],
                    "generated_case_index": item["case_index"],
                    "method_output_artifacts": item["artifacts"],
                    "method_output_manifest_sha256": item["artifact_manifest_sha256"],
                },
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
                save_dir = tmp_root / method
                run_engine_command(
                    [
                        python,
                        str(entry),
                        "--method_name",
                        method,
                        "--experiment_name",
                        self.experiment,
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
                    timeout_seconds=self.timeout_seconds,
                )
                run_engine_command(
                    [
                        python,
                        str(merge),
                        "--method_name",
                        method,
                        "--save_dir",
                        str(save_dir),
                    ],
                    feature=f"HarmBench {method} merge",
                    cwd=root,
                    allow_credentials=self.credential_env,
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
                        "prompt": prompt,
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
