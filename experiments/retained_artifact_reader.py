"""Read completed historical grids with their exact retained source validators.

This is analysis-only: no target, judge or installer is constructed. One private
temporary worktree is reused across revision partitions and removed afterwards.
The current media exporter only decodes locators; historical integrity checks
remain those of the source revision that produced each grid.
"""

from __future__ import annotations

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

_WORKER = r'''
import hashlib, json, sys
from pathlib import Path
from experiments.figure_results import _load_cells
from experiments import human_audit
from ura.runner import _harness_source_identity

request = json.load(sys.stdin)
root = Path(request["results"])
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
    # The source is supplied by this reader, never by the retained artifacts.
    exec(request["media_export_source"], human_audit.__dict__)
    eligible = any(row["raw"].get("common_metrics_eligible") is True
                   for cell in cells for row in cell["judgments"])
    if eligible:
        result["joined"] = human_audit._joined_artifacts(root, frame="common")
    else:
        result["joined"] = [{}, {}, {}, {
            "policy_evaluable_samples": 0,
            "common_ineligible_evaluable_rows_excluded": sum(
                len(cell["judgments"]) for cell in cells),
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
            value = strict_json_loads(result.stdout)
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
    root: Path, *, joined: bool, code_repository: Path = _REPOSITORY,
) -> list[dict[str, Any]]:
    """Validate each grid without changing the caller's code or result files."""
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
                value = strict_json_loads(result.stdout)
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


def load_joined(root: Path) -> tuple[list[dict[str, Any]], dict, dict, dict]:
    """Merge identities for selection, never pool rates or discard strata."""
    cells, metadata, judgments = [], {}, {}
    audit = {"policy_evaluable_samples": 0, "common_ineligible_evaluable_rows_excluded": 0}
    seen_runs = set()
    for partition in read_partitions(root, joined=True):
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
