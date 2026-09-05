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
from typing import Any

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


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments], check=False,
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    if result.returncode:
        raise ValueError(f"retained analysis git {arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


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
                    for field in ("manifest_path", "complete_path"):
                        cell[field] = Path(cell[field])
                    cell["artifacts"] = {
                        key: Path(path) for key, path in cell["artifacts"].items()
                    }
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
