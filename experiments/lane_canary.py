"""Summarize one completed diagnostic canary without making external calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from experiments.figure_results import _load_cells
from experiments.level1_evidence import (
    _condition_from_plan,
    _grid_condition,
    _grid_id,
    _validate_grid_plan_bindings,
)
from ura.eligibility import canonical_json_sha256, validate_eligibility_plan
from ura.lane_canary import (
    artifact_descriptor,
    build_lane_canary_summary,
    write_lane_canary,
)
from ura.lane_projection import validate_lane_projection_binding


_MAX_JSON_BYTES = 16 * 1024 * 1024


def _read_object(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"expected regular non-symlink JSON file: {path}")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact exceeds {_MAX_JSON_BYTES} bytes: {path}")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r} is forbidden")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON object key {key!r} is forbidden")
            output[key] = item
        return output

    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _bound_descriptor(
    descriptor: object, path: Path, *, label: str,
) -> dict[str, Any]:
    if not isinstance(descriptor, dict):
        raise ValueError(f"{label} descriptor is missing")
    expected = artifact_descriptor(path)
    for field in ("file", "sha256", "bytes", "records"):
        if field not in descriptor:
            raise ValueError(f"{label} descriptor lacks {field}")
    projected = {key: descriptor.get(key) for key in ("file", "sha256", "bytes")}
    observed = {key: expected[key] for key in projected}
    if projected != observed:
        raise ValueError(f"{label} descriptor does not match supplied artifact")
    records = descriptor.get("records")
    if isinstance(records, bool) or not isinstance(records, int) or records <= 0:
        raise ValueError(f"{label} descriptor records must be a positive integer")
    return {
        "file": descriptor["file"],
        "sha256": descriptor["sha256"],
        "bytes": descriptor["bytes"],
        "records": records,
    }


def summarize_canary(
    *, results: Path, eligibility_path: Path, out_dir: Path,
) -> tuple[dict[str, Any], Path]:
    """Strictly load one diagnostic grid and persist its immutable summary."""

    cells = _load_cells(results, _allow_diagnostic_canary=True)
    if len(cells) != 1:
        raise ValueError(
            f"lane-canary summary requires exactly one completed cell; found {len(cells)}"
        )
    grid_paths = sorted(results.rglob("*.grid.json"))
    if len(grid_paths) != 1:
        raise ValueError(
            f"lane-canary summary requires exactly one completed grid; found {len(grid_paths)}"
        )
    grid_path = grid_paths[0]
    grid = _read_object(grid_path)
    if grid.get("request", {}).get("execution_purpose") != "diagnostic_canary":
        raise ValueError("grid is not typed as a diagnostic canary")
    if grid.get("grid_id") != _grid_id(grid):
        raise ValueError("grid request identity does not match its grid_id")

    eligibility = validate_eligibility_plan(_read_object(eligibility_path))
    eligibility_descriptor = _bound_descriptor(
        grid["request"].get("eligibility_plan"),
        eligibility_path,
        label="eligibility",
    )
    if grid["request"]["eligibility_plan"].get("plan_id") != eligibility["plan_id"]:
        raise ValueError("grid/eligibility plan identity mismatch")
    condition = _condition_from_plan(eligibility)
    if _grid_condition(grid["request"]) != condition:
        raise ValueError("grid/eligibility experiment-condition mismatch")
    _validate_grid_plan_bindings(grid["request"], eligibility)

    projection_binding = grid["request"].get("lane_projection")
    if not isinstance(projection_binding, dict):
        raise ValueError("grid lacks a lane-projection binding")
    projection_name = projection_binding.get("file")
    if (
        not isinstance(projection_name, str)
        or not projection_name
        or Path(projection_name).name != projection_name
    ):
        raise ValueError("grid lane-projection filename is unsafe")
    projection_path = grid_path.parent / projection_name
    projection_descriptor = _bound_descriptor(
        projection_binding, projection_path, label="lane projection"
    )
    projection = validate_lane_projection_binding(
        _read_object(projection_path),
        eligibility_plan=eligibility,
        eligibility_artifact=eligibility_descriptor,
    )
    if projection_binding.get("projection_id") != projection["projection_id"]:
        raise ValueError("grid/lane-projection identity mismatch")
    if projection.get("call_projection") != grid["request"].get("call_projection"):
        raise ValueError("grid/lane-projection call-accounting mismatch")
    if projection.get("selection", {}).get("arms") is None:
        raise ValueError("lane projection lacks selected-arm evidence")

    cell = cells[0]
    run = cell["manifest"]["config"]["run"]
    manifest = cell["manifest"]
    request = grid["request"]
    exact_run_fields = {
        "execution_purpose": request.get("execution_purpose"),
        "project_revision": request.get("project_revision"),
        "limit": request.get("limit"),
        "sample_seed": request.get("sample_seed"),
        "attacker": request.get("attackers", [None])[0],
        "judge_names": request.get("judges"),
        "judge_model": request.get("judge_model"),
        "guardrail_model": request.get("guardrail_model"),
        "guardrail_revision": request.get("guardrail_revision"),
        "guardrail_device": request.get("guardrail_device"),
        "defense_guardrail_model": request.get("defense_guardrail_model"),
        "defense_guardrail_revision": request.get("defense_guardrail_revision"),
        "defense_guardrail_device": request.get("defense_guardrail_device"),
        "group_keys": request.get("group_keys"),
        "defense": request.get("defense"),
        "defense_guard": request.get("defense_guard"),
        "quantization": request.get("quantization"),
        "dtype": request.get("dtype"),
        "dry_run": request.get("dry_run"),
        "attestation_probe": request.get("attestation_probe"),
        "live_attestation": request.get("live_attestation"),
        "driver_source": request.get("driver_source"),
        "global_call_budget": request.get("global_call_budget"),
    }
    if "sampling_policy" in request:
        exact_run_fields["sampling_policy"] = request["sampling_policy"]
    if ("sampling_policy" in run) != ("sampling_policy" in request):
        raise ValueError("canary cell/grid sampling policy presence mismatch")
    if any(run.get(field) != expected for field, expected in exact_run_fields.items()):
        raise ValueError("canary cell/grid exact run-condition mismatch")
    expected_budget = {
        "max_queries": request.get("max_queries"),
        "max_turns": request.get("max_turns"),
        "seed": request.get("seeds", [None])[0],
    }
    if manifest.get("config", {}).get("budget") != expected_budget:
        raise ValueError("canary cell/grid attack-budget mismatch")
    if manifest.get("seeds") != request.get("seeds"):
        raise ValueError("canary cell/grid seed inventory mismatch")
    arms = projection["selection"]["arms"]
    if len(arms) != 1 or arms[0].get("logical_source_arm") != run.get("corpus"):
        raise ValueError("canary cell/lane-projection source-arm mismatch")
    audit = run.get("sampling_audit")
    if not isinstance(audit, dict):
        raise ValueError("canary cell lacks sampling audit")
    if (
        ("sampling_policy" in audit) != ("sampling_policy" in request)
        or audit.get("sampling_policy") != request.get("sampling_policy")
    ):
        raise ValueError("canary sampling audit/request policy mismatch")
    expected_arm_evidence = {
        "selected_records": audit.get("selected_records"),
        "selected_clusters": audit.get("selected_clusters"),
        "selected_converted_corpus_sha256": audit.get(
            "selected_converted_corpus_sha256"
        ),
        "selected_datapoint_ids_sha256": canonical_json_sha256(
            sorted(audit.get("selected_ids") or [])
        ),
        "selected_cluster_ids_sha256": canonical_json_sha256(
            sorted(audit.get("selected_cluster_ids") or [])
        ),
    }
    if any(arms[0].get(key) != value for key, value in expected_arm_evidence.items()):
        raise ValueError("canary cell/lane-projection selected-workload mismatch")
    complete_path = Path(cell["complete_path"])
    marker = _read_object(complete_path)
    summary = build_lane_canary_summary(
        cell=cell,
        grid=grid,
        grid_descriptor=artifact_descriptor(grid_path),
        eligibility_plan=eligibility,
        eligibility_descriptor=eligibility_descriptor,
        lane_projection=projection,
        lane_projection_descriptor=projection_descriptor,
        completion_descriptor=artifact_descriptor(complete_path),
        completion_marker=marker,
    )
    return summary, write_lane_canary(out_dir, summary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create a strict offline ura-lane-canary/1 diagnostic summary. "
            "The artifact is neither campaign authorization nor empirical evidence."
        )
    )
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--eligibility", type=Path, required=True)
    parser.add_argument(
        "--out-dir", type=Path, default=None,
        help="output directory (default: the diagnostic results directory)",
    )
    args = parser.parse_args(argv)
    try:
        summary, path = summarize_canary(
            results=args.results,
            eligibility_path=args.eligibility,
            out_dir=args.out_dir or args.results,
        )
    except (FileExistsError, OSError, TypeError, ValueError) as exc:
        print(f"lane-canary summary failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "artifact": str(path),
        "canary_id": summary["canary_id"],
        "evidence_class": summary["evidence_class"],
        "campaign_authorized": False,
        "empirical_benchmark_evidence": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
