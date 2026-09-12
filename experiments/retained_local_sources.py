"""Select completed local runs for input-matched follow-on preparation.

Explicit source directories work for ordinary Runner jobs, without a particular
campaign controller or analysis layout. No model, evaluator or network is used.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from collections.abc import Sequence

from experiments.retained_artifact_reader import load_cells
from experiments.hosted_retained_inputs import candidates_from_cells
from experiments.hosted_campaign_budget import _write_new
from ura.artifact_checks import artifact_verification_cli


SCHEMA = "ura-retained-local-sources/1"


def read_sources(roots: Sequence[Path], run_ids: Sequence[str] = ()) -> list[dict]:
    """Read only named roots and reject accidentally duplicated source runs."""
    paths = [Path(root).resolve(strict=True) for root in roots]
    if not paths or any(not path.is_dir() for path in paths):
        raise ValueError("Select at least one existing local results directory")
    if any(left.is_relative_to(right) or right.is_relative_to(left)
           for index, left in enumerate(paths) for right in paths[index + 1:]):
        raise ValueError("Source directories overlap; select each run only once")
    requested = set(run_ids)
    if len(requested) != len(run_ids) or any(not isinstance(key, str) or not key for key in run_ids):
        raise ValueError("Select each exact run ID only once")
    cells, seen = [], set()
    for path in paths:
        for cell in load_cells(path):
            if requested and cell["run_id"] not in requested:
                continue
            if cell["run_id"] in seen:
                raise ValueError("A local run occurs in several source directories")
            seen.add(cell["run_id"])
            cells.append(cell)
    if requested - seen:
        raise ValueError("A selected run is absent from the completed source directories")
    # Source admission and local-provider checks belong to the existing reader
    # and selector. Do not infer eligibility from a saved response or label.
    return sorted(cells, key=lambda cell: cell["run_id"])


def describe_sources(roots: Sequence[Path], cells: list[dict]) -> dict:
    candidates = candidates_from_cells(cells)
    return {
        "schema": SCHEMA,
        "status": "prepared_inputs_only",
        "source_roots": sorted(str(Path(root).resolve(strict=True)) for root in roots),
        "run_ids": sorted(cell["run_id"] for cell in cells),
        "runs": [{"run_id": cell["run_id"], "model": cell["model"],
                  "corpus": cell["manifest"]["config"]["run"]["corpus"],
                  "attempts": len(cell["attempts"])} for cell in cells],
        "inputs": [{"input_identity_sha256": row["input_identity_sha256"],
                    "memberships": [{"run_id": source["run_id"], "attempt_id": source["attempt_id"]}
                                    for source in row["local_sources"]]} for row in candidates],
        "unique_inputs": len(candidates),
        "model_input_assignments": sum(len(cell["attempts"]) for cell in cells),
        "target_calls": 0, "judge_calls": 0, "model_loads": 0,
    }


def prepare_sources(roots: Sequence[Path], run_ids: Sequence[str] = ()) -> dict:
    return describe_sources(roots, read_sources(roots, run_ids))


def load_sources(inventory: dict) -> list[dict]:
    """Resolve the recorded selection, never all runs subsequently added to it."""
    if inventory.get("schema") != SCHEMA:
        raise ValueError("Unsupported retained local source inventory")
    roots = [Path(value) for value in inventory["source_roots"]]
    cells = read_sources(roots, inventory["run_ids"])
    if describe_sources(roots, cells) != inventory:
        raise ValueError("Selected local input population differs from its saved inventory")
    return cells


@artifact_verification_cli
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, action="append", required=True,
                        help="Completed Runner results directory; repeat for additional directories")
    parser.add_argument("--run-id", action="append", default=[],
                        help="Optional exact run IDs; blank selects all completed runs in the named directories")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verify-artifact-sha256", action="store_true",
                        help="Opt in to full retained-artifact checksum revalidation")
    args = parser.parse_args(argv)
    result = prepare_sources(args.source_root, args.run_id)
    _write_new(args.out, result)
    print(json.dumps({key: result[key] for key in
                      ("status", "unique_inputs", "model_input_assignments", "target_calls", "judge_calls", "model_loads")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
