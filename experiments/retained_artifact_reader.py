"""Read completed historical grids with their exact retained source validators.

This is analysis-only: no target, judge or installer is constructed. One private
temporary worktree is reused across revision partitions and removed afterwards.
The current media exporter only decodes locators; historical integrity checks
remain those of the source revision that produced each grid.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

from ura.strict_json import strict_json_loads


_COMMIT = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = Path(__file__).resolve().parents[1]
# IPC contains many already source-validated artifacts, not one persisted JSON
# artifact. Keep its aggregate transport finite without changing any source
# validator's per-artifact node/depth limits or strict JSON ambiguity checks.
_MAX_VALIDATOR_IPC_BYTES = 512 * 1024 * 1024
_MAX_VALIDATOR_IPC_NODES = 32_000_000

_WORKER = r'''
import hashlib, inspect, json, sys
from pathlib import Path
from experiments import figure_results
from experiments.figure_results import _load_cells
from experiments.suite_summary import _load_eligibility_plan
from experiments import human_audit
from ura.runner import _harness_source_identity

request = json.load(sys.stdin)
root = Path(request["results"])
# Older figure readers routed eligibility through their generic 4 MiB loader.
# Reuse THIS exact source revision's existing typed 16 MiB eligibility loader;
# no parser limit, artifact bytes or source semantic validator is changed.
original_read_object = figure_results._read_object
def read_typed_object(path):
    if path.name.endswith(".eligibility.json"):
        return _load_eligibility_plan(path)[0]
    return original_read_object(path)
figure_results._read_object = read_typed_object
cells = _load_cells(root)
harness = _harness_source_identity()["sha256"]
driver = hashlib.sha256(Path("experiments/run_matrix.py").read_bytes()).hexdigest()
for cell in cells:
    revision = cell["manifest"]["config"]["run"]["project_revision"]
    if (revision["expected_commit"] != request["commit"]
        or revision["observed_commit"] != request["commit"]
        or revision["head_tree"] != request["tree"]
        or revision["harness_source_sha256"] != harness
        or revision["driver_source_sha256"] != driver):
        raise ValueError("retained source does not match its exact validator checkout")
result = {"cells": cells, "validator_commit": request["commit"]}
if request["joined"]:
    frame = request.get("frame", "common")
    if frame not in {"common", "source_task"}:
        raise ValueError(f"unknown human-audit frame {frame!r}")
    # The source is supplied by this reader, never by the retained artifacts.
    exec(request["media_export_source"], human_audit.__dict__)
    rows = [row["raw"] for cell in cells for row in cell["judgments"]]
    eligible = any(
        raw.get("common_metrics_eligible") is True if frame == "common"
        else (raw.get("common_metrics_eligible") is False
              and raw.get("policy_evaluable_turn") is True)
        for raw in rows
    )
    if request.get("separate_judge_configurations", False):
        if frame != "common":
            raise ValueError("judge configuration separation requires the common frame")
        # Validate the WHOLE original grid, including orphan/source/grid checks,
        # before taking an in-memory view of any configuration's actual cells.
        original_inventory = human_audit._validated_artifacts
        original_completed_cell = human_audit._completed_cell
        try:
            zero_result_runs = [cell["run_id"] for cell in cells
                                if cell.get("aggregate_results") == []]
            if zero_result_runs:
                original_source = inspect.getsource(original_completed_cell)
                legacy_guard = "if not attempts or not responses or not judgments or not aggregate_results:"
                if original_source.count(legacy_guard) == 1:
                    # The ORIGINAL figure/grid validator has already admitted
                    # these exact typed nondecisions. Correct only its older
                    # auxiliary transfer reader's nonempty-Result assumption.
                    bridge = request.get("audit_join_bridge")
                    if not isinstance(bridge, dict):
                        raise ValueError("audit-join compatibility lacks bridge provenance")
                    corrected_guard = (
                        "if not attempts or not responses or not judgments or "
                        "(not aggregate_results and not "
                        "_source_zero_result_population(parsed_judgments)):"
                    )
                    namespace = dict(original_completed_cell.__globals__)
                    namespace["_source_zero_result_population"] = (
                        figure_results._zero_result_guardrail_abstention_population
                    )
                    exec(original_source.replace(legacy_guard, corrected_guard), namespace)
                    human_audit._completed_cell = namespace[original_completed_cell.__name__]
                    result["audit_join_compatibility"] = {
                        "kind": "original_typed_zero_result_population_in_auxiliary_audit_join",
                        "original_source_commit": request["commit"],
                        "original_figure_grid_validation": "passed_before_compatibility",
                        "original_transfer_function_sha256": hashlib.sha256(
                            original_source.encode("utf-8")).hexdigest(),
                        "original_source_predicate": "figure_results._zero_result_guardrail_abstention_population",
                        "zero_result_run_ids": sorted(zero_result_runs),
                        "bridge": bridge,
                        "unchanged_original_transfer_validator_claimed": False,
                    }
            all_roles, validated_cells = original_inventory(root)
        finally:
            human_audit._completed_cell = original_completed_cell
        original_by_run = {cell["run_id"]: cell for cell in cells}
        validated_by_run = {cell["run_id"]: cell for cell in validated_cells}
        if (len(original_by_run) != len(cells)
            or len(validated_by_run) != len(validated_cells)
            or original_by_run.keys() != validated_by_run.keys()):
            raise ValueError("human-audit full-grid inventory differs")
        for run_id, cell in validated_by_run.items():
            original = original_by_run[run_id]
            if (cell["manifest"] != original["manifest"]
                or cell["artifacts"] != original["artifacts"]):
                raise ValueError("human-audit validated cell identity differs")
        groups = {}
        expected_keys = set()
        for cell in validated_cells:
            common_rows = [row for row in original_by_run[cell["run_id"]]["judgments"]
                           if row["raw"].get("common_metrics_eligible") is True
                           and row["raw"].get("policy_evaluable_turn") is True]
            if not common_rows:
                continue
            binding = human_audit._judge_configuration_binding([cell])
            groups.setdefault(binding["sha256"], []).append(cell)
            for row in common_rows:
                key = human_audit._record_key(row)
                if key in expected_keys:
                    raise ValueError("duplicate common-frame identity across validated cells")
                expected_keys.add(key)
        result["joined_by_configuration"] = {}
        observed_keys = set()
        try:
            for fingerprint, selected_cells in sorted(groups.items()):
                selected_roles = {
                    role: [Path(cell["artifacts"][role]) for cell in selected_cells]
                    for role in all_roles
                }
                def scoped_inventory(requested_root):
                    if requested_root != root:
                        raise ValueError("scoped human-audit root differs")
                    return selected_roles, selected_cells
                human_audit._validated_artifacts = scoped_inventory
                joined = human_audit._joined_artifacts(root, frame="common")
                predictors, metadata, judgments, audit = joined
                if (metadata.keys() != judgments.keys()
                    or observed_keys.intersection(metadata)
                    or audit["judge_configuration_binding"]["sha256"] != fingerprint
                    or any(set(labels) - metadata.keys() for labels in predictors.values())):
                    raise ValueError("configuration-scoped human-audit join differs")
                observed_keys.update(metadata)
                result["joined_by_configuration"][fingerprint] = joined
        finally:
            human_audit._validated_artifacts = original_inventory
        if observed_keys != expected_keys:
            raise ValueError("configuration-scoped joins omit or add common-frame rows")
    elif eligible:
        result["joined"] = human_audit._joined_artifacts(root, frame=frame)
    elif frame == "common":
        result["joined"] = [{}, {}, {}, {
            "policy_evaluable_samples": 0,
            "common_ineligible_evaluable_rows_excluded": sum(
                len(cell["judgments"]) for cell in cells),
        }]
    else:
        result["joined"] = [{}, {}, {}, {
            "policy_evaluable_samples": 0,
            "common_eligible_rows_excluded_from_source_task_frame": sum(
                raw.get("common_metrics_eligible") is True
                and raw.get("policy_evaluable_turn") is True for raw in rows),
        }]
def json_default(value):
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)
print(json.dumps(result, default=json_default, allow_nan=False))
'''

_LEVEL1_WORKER = r'''
import hashlib, json, sys
from pathlib import Path
from experiments import level1_evidence as source
from ura.runner import _harness_source_identity

request = json.load(sys.stdin)
roots = [Path(path) for path in request["results"]]
paths = [Path(path) for path in request["eligibility_paths"]]
artifacts = [source._plan_artifact(path) for path in paths]
envelopes = source._discover_request_envelopes(paths, artifacts, roots)
if json.loads(json.dumps(artifacts)) != request["plans"]:
    raise ValueError("retained Level-1 eligibility inputs changed during validation")
if envelopes != request["envelopes"]:
    raise ValueError("retained Level-1 request envelopes changed during validation")
harness = _harness_source_identity()["sha256"]
driver = hashlib.sha256(Path("experiments/run_matrix.py").read_bytes()).hexdigest()
def require_source(revision):
    if (revision["expected_commit"] != request["commit"]
        or revision["observed_commit"] != request["commit"]
        or revision["head_tree"] != request["tree"]
        or revision["harness_source_sha256"] != harness
        or revision["driver_source_sha256"] != driver):
        raise ValueError("retained source does not match its exact validator checkout")
for artifact in artifacts:
    require_source(artifact[0]["bindings"]["project_revision"])
for artifact in envelopes:
    require_source(artifact["envelope"]["bindings"]["project_revision"])
plans = {artifact[0]["plan_id"]: artifact for artifact in artifacts}
grids, errors = source._load_results(roots, plans)
# Validate request-only failure bindings too; these are not completed cells.
source._bind_request_lifecycle(envelopes, plans, errors)
for grid in grids.values():
    require_source(grid["request"]["project_revision"])
    for cell in grid["cells"].values():
        if "validated_cell" in cell:
            require_source(cell["validated_cell"]["manifest"]["config"]["run"]["project_revision"])
    grid["cells"] = [[list(key), cell] for key, cell in grid["cells"].items()]
def json_default(value):
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)
print(json.dumps({"validator_commit": request["commit"], "grids": grids,
                  "request_errors": errors}, default=json_default, allow_nan=False))
'''


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments], check=False,
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    if result.returncode:
        raise ValueError(f"retained analysis git {arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _restore_cell_paths(cell: dict[str, Any]) -> None:
    for field in ("manifest_path", "complete_path"):
        cell[field] = Path(cell[field])
    cell["artifacts"] = {key: Path(path) for key, path in cell["artifacts"].items()}


def _decode_validator_ipc(payload: str) -> Any:
    """Decode only successful trusted-validator aggregate stdout, not artifacts."""
    if (len(payload) > _MAX_VALIDATOR_IPC_BYTES
            or len(payload.encode("utf-8")) > _MAX_VALIDATOR_IPC_BYTES):
        raise ValueError("retained validator IPC exceeds its aggregate byte limit")
    return strict_json_loads(payload, max_nodes=_MAX_VALIDATOR_IPC_NODES)


def load_level1_results(
    roots: Sequence[Path],
    plans: Mapping[str, tuple[dict[str, Any], str, str, int, int]],
    envelopes: list[dict[str, Any]],
    *, eligibility_paths: Sequence[Path], code_repository: Path = _REPOSITORY,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Validate one exact historical stratum, leaving accounting to current code.

    Unlike the success-only Level-2 reader, the source Level-1 reader preserves
    final partial grids and request errors. Mixed revisions must be supplied as
    separate strata; one source checkout validates the entire stratum at once.
    """
    revisions = [artifact[0]["bindings"]["project_revision"] for artifact in plans.values()]
    revisions.extend(item["envelope"]["bindings"]["project_revision"] for item in envelopes)
    identities = set()
    for revision in revisions:
        commit, tree = revision.get("expected_commit"), revision.get("head_tree")
        if (not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None
            or not isinstance(tree, str) or _COMMIT.fullmatch(tree) is None
            or revision.get("observed_commit") != commit):
            raise ValueError("retained Level-1 inputs lack an exact verified source revision")
        identities.add((commit, tree))
    if len(identities) != 1:
        raise ValueError("retained Level-1 inputs must have one exact source revision")
    commit, tree = identities.pop()
    repository = Path(code_repository).resolve(strict=True)
    trusted_head = _git(repository, "rev-parse", "HEAD")
    _git(repository, "merge-base", "--is-ancestor", commit, trusted_head)
    if _git(repository, "rev-parse", f"{commit}^{{tree}}") != tree:
        raise ValueError("retained revision tree does not match trusted Git history")
    with tempfile.TemporaryDirectory(prefix="ura-retained-level1-") as scratch:
        worktree = Path(scratch).resolve() / "source"
        installed = False
        try:
            _git(repository, "worktree", "add", "--quiet", "--detach", str(worktree), commit)
            installed = True
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(worktree / "src")
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            for key in list(environment):
                if key.endswith(("_API_KEY", "_TOKEN")):
                    environment.pop(key)
            request = {
                "results": [str(Path(root).resolve(strict=True)) for root in roots],
                "eligibility_paths": [str(Path(path).resolve()) for path in eligibility_paths],
                "plans": list(plans.values()), "envelopes": envelopes,
                "commit": commit, "tree": tree,
            }
            result = subprocess.run(
                [sys.executable, "-c", _LEVEL1_WORKER], cwd=worktree, env=environment,
                input=json.dumps(request), text=True, encoding="utf-8",
                capture_output=True, timeout=600,
            )
            if result.returncode:
                raise ValueError(
                    f"retained Level-1 validator {commit[:12]} failed: " + result.stderr[-4000:]
                )
            value = _decode_validator_ipc(result.stdout)
            if (not isinstance(value, dict) or value.get("validator_commit") != commit
                or not isinstance(value.get("grids"), dict)
                or not isinstance(value.get("request_errors"), list)):
                raise ValueError("retained Level-1 validator returned an invalid inventory")
            for grid in value["grids"].values():
                cells = {}
                for raw_key, cell in grid["cells"]:
                    key = tuple(raw_key)
                    if len(key) != 3 or key in cells:
                        raise ValueError("retained Level-1 validator returned duplicate cell keys")
                    if "validated_cell" in cell:
                        _restore_cell_paths(cell["validated_cell"])
                    cells[key] = cell
                grid["cells"] = cells
            return value["grids"], value["request_errors"]
        finally:
            if installed:
                _git(repository, "worktree", "remove", "--force", str(worktree))


def grid_partitions(root: Path) -> list[tuple[Path, str, str]]:
    """Find exact grid roots, rejecting orphan manifests and mixed revisions."""
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("retained analysis requires a directory")
    for pattern in ("*.grid.lock", "*.cell.lock", "*.error.json"):
        if any(root.rglob(pattern)):
            raise ValueError("retained analysis refuses running or failed result trees")
    roots = sorted({path.parent for path in root.rglob("*.grid.json")})
    if not roots:
        return []
    for pattern in ("*.attempts.jsonl", "*.responses.jsonl", "*.complete.json"):
        if any(path.parent not in roots for path in root.rglob(pattern)):
            raise ValueError("retained view contains orphan artifacts outside its grids")
    manifests = sorted(root.rglob("*.manifest.json"))
    if any(path.parent not in roots for path in manifests):
        raise ValueError("retained view contains an orphan manifest outside its grids")
    partitions = []
    for grid_root in roots:
        if any(parent in roots for parent in grid_root.parents):
            raise ValueError("retained grid roots must not overlap")
        revisions = set()
        for path in manifests:
            if path.parent != grid_root:
                continue
            if path.is_symlink():
                raise ValueError("retained manifest must not be a symlink")
            value = strict_json_loads(path.read_text(encoding="utf-8"))
            revision = value.get("config", {}).get("run", {}).get("project_revision", {})
            commit = revision.get("expected_commit")
            tree = revision.get("head_tree")
            if (not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None
                or not isinstance(tree, str) or _COMMIT.fullmatch(tree) is None
                or revision.get("observed_commit") != commit):
                raise ValueError("retained grid lacks an exact verified source revision")
            revisions.add((commit, tree))
        if len(revisions) != 1:
            raise ValueError("each retained grid must have one exact source revision")
        commit, tree = revisions.pop()
        partitions.append((grid_root, commit, tree))
    return partitions


def read_partitions(
    root: Path, *, joined: bool, frame: str = "common",
    code_repository: Path = _REPOSITORY,
    separate_judge_configurations: bool = False,
) -> list[dict[str, Any]]:
    """Validate each grid without changing the caller's code or result files."""
    if frame not in {"common", "source_task"}:
        raise ValueError(f"unknown human-audit frame {frame!r}")
    if type(separate_judge_configurations) is not bool:
        raise ValueError("judge configuration separation must be boolean")
    if separate_judge_configurations and (not joined or frame != "common"):
        raise ValueError("judge configuration separation requires a joined common frame")
    from experiments.human_audit import _portable_media_references

    partitions = grid_partitions(root)
    if not partitions:
        raise ValueError("retained view contains no completed grid manifests")
    repository = Path(code_repository).resolve(strict=True)
    trusted_head = _git(repository, "rev-parse", "HEAD")
    for _root, commit, tree in partitions:
        _git(repository, "merge-base", "--is-ancestor", commit, trusted_head)
        if _git(repository, "rev-parse", f"{commit}^{{tree}}") != tree:
            raise ValueError("retained revision tree does not match trusted Git history")
    export_source = inspect.getsource(_portable_media_references)
    results = []
    with tempfile.TemporaryDirectory(prefix="ura-retained-reader-") as scratch:
        worktree = Path(scratch).resolve() / "source"
        installed = False
        try:
            _git(repository, "worktree", "add", "--quiet", "--detach",
                 str(worktree), partitions[0][1])
            installed = True
            for grid_root, commit, tree in partitions:
                _git(worktree, "switch", "--quiet", "--detach", commit)
                environment = dict(os.environ)
                environment["PYTHONPATH"] = str(worktree / "src")
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                # This reader needs neither provider credentials nor HF access.
                for key in list(environment):
                    if key.endswith(("_API_KEY", "_TOKEN")):
                        environment.pop(key)
                request = {
                    "results": str(grid_root), "commit": commit, "tree": tree,
                    "joined": joined, "media_export_source": export_source,
                    "frame": frame,
                }
                if separate_judge_configurations:
                    request["separate_judge_configurations"] = True
                    request["audit_join_bridge"] = {
                        "commit": _git(_REPOSITORY, "rev-parse", "HEAD"),
                        "module": "experiments/retained_artifact_reader.py",
                        "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    }
                result = subprocess.run(
                    [sys.executable, "-c", _WORKER], cwd=worktree,
                    env=environment, input=json.dumps(request), text=True,
                    encoding="utf-8", capture_output=True, timeout=300,
                )
                if result.returncode:
                    raise ValueError(
                        f"retained validator {commit[:12]} failed for {grid_root}: "
                        + result.stderr[-4000:]
                    )
                value = _decode_validator_ipc(result.stdout)
                if (not isinstance(value, dict) or value.get("validator_commit") != commit
                    or not isinstance(value.get("cells"), list) or not value["cells"]):
                    raise ValueError("retained validator returned an invalid cell inventory")
                for cell in value["cells"]:
                    _restore_cell_paths(cell)
                results.append(value)
        finally:
            if installed:
                # Only this newly created private worktree is removed. Source
                # revisions remain recoverable from the shared Git object store.
                _git(repository, "worktree", "remove", "--force", str(worktree))
    return results


def load_cells(root: Path, *, code_repository: Path = _REPOSITORY) -> list[dict[str, Any]]:
    cells = []
    seen = set()
    for partition in read_partitions(root, joined=False, code_repository=code_repository):
        for cell in partition["cells"]:
            if cell["run_id"] in seen:
                raise ValueError("retained view contains a duplicate completed run")
            seen.add(cell["run_id"])
            cells.append(cell)
    return cells


def load_joined(
    root: Path, *, frame: str = "common", code_repository: Path = _REPOSITORY,
) -> tuple[list[dict[str, Any]], dict, dict, dict]:
    """Merge identities for selection, never pool rates or discard strata."""
    cells, metadata, judgments = [], {}, {}
    excluded = ("common_ineligible_evaluable_rows_excluded" if frame == "common"
                else "common_eligible_rows_excluded_from_source_task_frame")
    audit = {"policy_evaluable_samples": 0, excluded: 0}
    seen_runs = set()
    for partition in read_partitions(
        root, joined=True, frame=frame, code_repository=code_repository,
    ):
        _predictors, part_metadata, part_judgments, part_audit = partition["joined"]
        if metadata.keys() & part_metadata.keys() or judgments.keys() & part_judgments.keys():
            raise ValueError("retained view contains duplicate joined identities")
        if part_metadata.keys() != part_judgments.keys():
            raise ValueError("retained partition has an incomplete response/judgment join")
        for cell in partition["cells"]:
            if cell["run_id"] in seen_runs:
                raise ValueError("retained view contains a duplicate completed run")
            seen_runs.add(cell["run_id"])
        cells.extend(partition["cells"])
        metadata.update(part_metadata)
        judgments.update(part_judgments)
        for field in audit:
            audit[field] += part_audit[field]
    return cells, metadata, judgments, audit
