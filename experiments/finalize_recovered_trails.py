"""Finalize a fully executed cell blocked only by retry-trail projection.

This is a zero-call recovery path for a narrow persistence failure.  It copies
an immutable failed result root, repairs only the retained response-quality
fields in judge-trail projections, creates a normal content-addressed cell
marker, and records the old and new project revisions in a separate receipt.
It never queries a target or judge and never edits the failed source root.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Mapping, Sequence

from experiments import figure_results, run_matrix
from ura.data_models import Attempt, Judgment, Response, RunManifest
from ura.project_revision import load_project_revision_file
from ura.runner import validate_persisted_judgment_trails


SCHEMA = "ura-recovered-trail-finalization/1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOME_FIELDS = (
    "model_stability_status",
    "model_stability_category",
    "model_stability_error_type",
    "model_stability_retry_count",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _descriptor(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact is not one regular file: {path}")
    return {
        "path": str(path.resolve(strict=True)),
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _one(root: Path, pattern: str, *, label: str) -> Path:
    matches = sorted(root.glob(pattern))
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError(f"{label} requires exactly one {pattern}")
    return matches[0]


def _read_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not one JSON object")
    return value


def _read_rows(path: Path, *, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} has invalid JSON at line {line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{label} row {line_number} is not an object")
        rows.append(value)
    if not rows:
        raise ValueError(f"{label} is empty")
    return rows


def repair_recovered_trail_rows(
    trails: Sequence[Mapping[str, Any]],
    responses: Mapping[str, Response],
    judgments: Mapping[str, Judgment],
) -> tuple[list[dict[str, Any]], int]:
    """Copy retry outcome fields onto every stage of its exact response."""

    corrected: list[dict[str, Any]] = []
    repaired_attempts: set[str] = set()
    for raw_row in trails:
        row = dict(raw_row)
        attempt_id = row.get("attempt_id")
        if not isinstance(attempt_id, str) or attempt_id not in responses:
            raise ValueError("judge trail lacks exact response lineage")
        if attempt_id not in judgments:
            raise ValueError("judge trail lacks exact final-judgment lineage")
        response = responses[attempt_id]
        judgment = judgments[attempt_id]
        response_status = response.raw.get("model_stability_status")
        judgment_status = judgment.raw.get("model_stability_status")
        if response_status == "recovered_after_retry":
            if judgment_status != response_status:
                raise ValueError("recovered response/final judgment status differs")
            retry_count = response.raw.get("model_stability_retry_count")
            if (
                isinstance(retry_count, bool)
                or not isinstance(retry_count, int)
                or retry_count < 1
            ):
                raise ValueError("recovered response lacks a positive retry count")
            for field in _OUTCOME_FIELDS:
                expected = response.raw.get(field)
                if judgment.raw.get(field) != expected:
                    raise ValueError(
                        f"recovered response/final judgment {field} differs"
                    )
                observed = row.get(field)
                if observed not in {None, expected}:
                    raise ValueError(
                        f"retained trail contains a conflicting {field}"
                    )
                row[field] = expected
            repaired_attempts.add(attempt_id)
        corrected.append(row)
    if not repaired_attempts:
        raise ValueError("failed cell contains no recovered retry projection to repair")
    return corrected, len(repaired_attempts)


def repair_recovered_judgments(
    responses: Mapping[str, Response],
    judgments: Mapping[str, Judgment],
) -> tuple[dict[str, Judgment], int]:
    """Repair the final record's embedded projections for recovered retries."""

    corrected: dict[str, Judgment] = {}
    repaired = 0
    for attempt_id, judgment in judgments.items():
        if attempt_id not in responses:
            raise ValueError("final judgment lacks exact response lineage")
        response = responses[attempt_id]
        if response.raw.get("model_stability_status") != "recovered_after_retry":
            corrected[attempt_id] = judgment
            continue
        outcome = {field: response.raw.get(field) for field in _OUTCOME_FIELDS}
        if any(judgment.raw.get(field) != value for field, value in outcome.items()):
            raise ValueError("recovered response/final judgment outcome differs")
        raw = dict(judgment.raw)
        bindings = raw.get("judge_stage_bindings")
        if not isinstance(bindings, list) or not bindings or any(
            not isinstance(binding, dict) for binding in bindings
        ):
            raise ValueError("recovered final judgment lacks ordered stage bindings")
        raw["judge_stage_bindings"] = [
            {**binding, **outcome} for binding in bindings
        ]
        strongreject = raw.get("strongreject_stage_binding")
        if strongreject is not None:
            if not isinstance(strongreject, dict):
                raise ValueError("recovered final judgment has invalid rubric binding")
            raw["strongreject_stage_binding"] = {**strongreject, **outcome}
        corrected[attempt_id] = judgment.model_copy(update={"raw": raw})
        repaired += 1
    if repaired < 1:
        raise ValueError("failed cell contains no recovered retry judgment to repair")
    return corrected, repaired


def _write_json_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(
            value,
            handle,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        handle.write("\n")


def _write_rows(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    dict(row),
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n"
            )


def _copy_regular_tree(source: Path, destination: Path) -> None:
    """Copy a supporting artifact tree without following any link."""

    for candidate in (source, *source.rglob("*")):
        if candidate.is_symlink() or (
            not candidate.is_dir() and not candidate.is_file()
        ):
            raise ValueError(
                f"failed root contains a non-regular supporting entry: {candidate}"
            )
    shutil.copytree(source, destination, symlinks=False)


def finalize(
    *,
    source_root: Path,
    out_root: Path,
    finalizer_project_revision: Path,
    finalizer_project_revision_sha256: str,
) -> dict[str, Any]:
    source_root = source_root.resolve(strict=True)
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("failed result root must be one canonical directory")
    if out_root.exists() or out_root.is_symlink():
        raise FileExistsError("fresh finalization output root already exists")
    if not out_root.is_absolute() or out_root.parent.resolve(strict=True) != out_root.parent:
        raise ValueError("finalization output parent must already be canonical")
    if _HEX64.fullmatch(finalizer_project_revision_sha256) is None:
        raise ValueError("finalizer project-revision SHA-256 is invalid")
    _revision, finalizer_revision_descriptor = load_project_revision_file(
        finalizer_project_revision,
        finalizer_project_revision_sha256,
        Path(run_matrix.__file__).resolve(),
    )

    grid_path = _one(source_root, "*.grid.json", label="failed grid")
    manifest_path = _one(source_root, "*.manifest.json", label="failed manifest")
    stem = manifest_path.name.removesuffix(".manifest.json")
    source_paths = {
        "attempts": source_root / f"{stem}.attempts.jsonl",
        "responses": source_root / f"{stem}.responses.jsonl",
        "judgments": source_root / f"{stem}.jsonl",
        "trails": source_root / f"{stem}.trails.jsonl",
        "results": source_root / f"{stem}.results.jsonl",
        "manifest": manifest_path,
        "error": source_root / f"{stem}.error.json",
    }
    if any(path.is_symlink() or not path.is_file() for path in source_paths.values()):
        raise ValueError("failed cell artifact inventory is incomplete")
    if (source_root / f"{stem}.complete.json").exists():
        raise ValueError("failed source cell already has a completion marker")
    error = _read_object(source_paths["error"], label="failed cell error")
    if (
        error.get("status") != "error"
        or error.get("exception_type") != "ValueError"
        or "model_stability_status differs from its retained stage projection"
        not in str(error.get("message", ""))
    ):
        raise ValueError("cell did not fail only at recovered retry-trail projection")
    grid = _read_object(grid_path, label="failed grid")
    cells = grid.get("cells")
    if (
        grid.get("status") != "partial"
        or grid.get("n_errors") != 1
        or not isinstance(cells, list)
        or len(cells) != 1
        or not isinstance(cells[0], dict)
        or cells[0].get("status") != "error"
        or cells[0].get("run_id") != error.get("run_id")
    ):
        raise ValueError("failed grid is not one exact post-execution cell failure")

    manifest = RunManifest.model_validate(
        _read_object(source_paths["manifest"], label="failed manifest"),
        strict=True,
    )
    attempt_rows = _read_rows(source_paths["attempts"], label="failed attempts")
    response_rows = _read_rows(source_paths["responses"], label="failed responses")
    judgment_rows = _read_rows(source_paths["judgments"], label="failed judgments")
    trail_rows = _read_rows(source_paths["trails"], label="failed trails")
    attempts = [Attempt.model_validate(row, strict=True) for row in attempt_rows]
    responses = [Response.model_validate(row, strict=True) for row in response_rows]
    judgments = [Judgment.model_validate(row, strict=True) for row in judgment_rows]
    attempts_by_id = {row.id: row for row in attempts}
    responses_by_id = {row.attempt_id: row for row in responses}
    judgments_by_id = {row.attempt_id: row for row in judgments}
    if (
        len(attempts_by_id) != len(attempts)
        or set(attempts_by_id) != set(responses_by_id)
        or set(attempts_by_id) != set(judgments_by_id)
        or any(row.run_id != manifest.run_id for row in attempts)
        or any(row.run_id != manifest.run_id for row in responses)
        or any(row.run_id != manifest.run_id for row in judgments)
    ):
        raise ValueError("failed cell Attempt/Response/Judgment lineage changed")
    try:
        validate_persisted_judgment_trails(
            attempts_by_id,
            responses_by_id,
            judgments_by_id,
            trail_rows,
            manifest.config,
            manifest.judges,
        )
    except ValueError as exc:
        if "model_stability_status differs" not in str(exc):
            raise ValueError("failed trail has an unrelated validation error") from exc
    else:
        raise ValueError("failed trail no longer reproduces its retained error")
    corrected_judgments, repaired_judgments = repair_recovered_judgments(
        responses_by_id, judgments_by_id
    )
    corrected_trails, repaired_attempts = repair_recovered_trail_rows(
        trail_rows, responses_by_id, corrected_judgments
    )
    if repaired_judgments != repaired_attempts:
        raise ValueError("recovered judgment/trail repair populations differ")
    validate_persisted_judgment_trails(
        attempts_by_id,
        responses_by_id,
        corrected_judgments,
        corrected_trails,
        manifest.config,
        manifest.judges,
    )

    out_root.mkdir(mode=0o700)
    try:
        for source in source_root.iterdir():
            if source.is_symlink():
                raise ValueError(f"failed root contains a symlink: {source}")
            if source.is_dir():
                _copy_regular_tree(source, out_root / source.name)
                continue
            if not source.is_file():
                raise ValueError(f"failed root contains a non-regular entry: {source}")
            if (
                source.name.endswith(".error.json")
                or source.name.endswith(".checkpoint.jsonl")
                or source.name.endswith(".complete.json")
                or source.name.endswith(".lock")
                or source.name.endswith(".parquet")
            ):
                continue
            shutil.copyfile(source, out_root / source.name)
        repaired_trail_path = out_root / source_paths["trails"].name
        _write_rows(repaired_trail_path, corrected_trails)
        repaired_judgment_path = out_root / source_paths["judgments"].name
        _write_rows(
            repaired_judgment_path,
            [
                corrected_judgments[row.attempt_id].model_dump(mode="json")
                for row in judgments
            ],
        )

        out_paths = {
            name: out_root / path.name
            for name, path in source_paths.items()
            if name not in {"error"}
        }
        required = (
            "attempts", "responses", "judgments", "trails", "results", "manifest"
        )
        completion = {
            "status": "complete",
            "format_version": 2,
            "completed_at": datetime.now(timezone.utc).timestamp(),
            "run_id": manifest.run_id,
            "code_version": manifest.code_version,
            "schema_version": manifest.schema_version,
            "n_attempts": len(attempts),
            "n_responses": len(responses),
            "n_judgments": len(judgments),
            "n_results": len(_read_rows(out_paths["results"], label="results")),
            "realized_identities_sha256": manifest.config[
                "realized_identities_sha256"
            ],
            "engine_runtime_close": None,
            "call_budget_snapshot": manifest.config["call_budget_snapshot"],
            "artifacts": {
                name: run_matrix._artifact_descriptor(out_paths[name])
                for name in required
            },
            "post_execution_finalization": {
                "schema": SCHEMA,
                "target_calls": 0,
                "judge_calls": 0,
                "repaired_attempts": repaired_attempts,
                "repaired_fields": list(_OUTCOME_FIELDS),
                "source_error_sha256": _sha256_file(source_paths["error"]),
                "finalizer_project_revision_sha256": (
                    finalizer_project_revision_sha256
                ),
            },
        }
        completion_path = out_root / f"{stem}.complete.json"
        _write_json_new(completion_path, completion)
        run_matrix._validate_completion_marker(
            {**out_paths, "complete": completion_path},
            manifest,
            required,
            grid["request"]["model_acquisition_execution"],
        )

        repaired_cell = {
            key: value
            for key, value in cells[0].items()
            if key not in {"error_artifact", "execution_started", "phase"}
        }
        repaired_cell.update({
            "status": "complete",
            "completion_marker": completion_path.name,
        })
        grid.update({
            "status": "complete",
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "n_new_complete": 1,
            "n_existing_complete": 0,
            "n_errors": 0,
            "cells": [repaired_cell],
        })
        repaired_grid_path = out_root / grid_path.name
        _write_json_new(repaired_grid_path.with_suffix(".repaired.tmp"), grid)
        repaired_grid_path.unlink()
        repaired_grid_path.with_suffix(".repaired.tmp").replace(repaired_grid_path)
        loaded = figure_results._load_cells(out_root)
        if len(loaded) != 1 or loaded[0]["run_id"] != manifest.run_id:
            raise ValueError("finalized cell did not pass the measured figure loader")

        receipt = {
            "schema": SCHEMA,
            "status": "complete",
            "completed_at_utc": _utc_now(),
            "source_root": str(source_root),
            "output_root": str(out_root),
            "source_error": _descriptor(source_paths["error"]),
            "source_grid": _descriptor(grid_path),
            "finalizer_project_revision": {
                **finalizer_revision_descriptor,
                "path": str(finalizer_project_revision.resolve(strict=True)),
            },
            "run_id": manifest.run_id,
            "target_calls": 0,
            "judge_calls": 0,
            "attempts": len(attempts),
            "responses": len(responses),
            "judgments": len(judgments),
            "repaired_attempts": repaired_attempts,
            "repaired_fields": list(_OUTCOME_FIELDS),
            "completion_marker": _descriptor(completion_path),
            "repaired_grid": _descriptor(repaired_grid_path),
        }
        receipt_path = out_root / f"finalization-{manifest.run_id}.json"
        _write_json_new(receipt_path, receipt)
        return {**receipt, "receipt": _descriptor(receipt_path)}
    except Exception:
        # The output is a fresh staging root.  Keep it for diagnosis; no source
        # evidence was changed and no completion is returned to the controller.
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--finalizer-project-revision", type=Path, required=True)
    parser.add_argument("--finalizer-project-revision-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = finalize(
            source_root=args.source_root,
            out_root=args.out,
            finalizer_project_revision=args.finalizer_project_revision,
            finalizer_project_revision_sha256=(
                args.finalizer_project_revision_sha256
            ),
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"recovered-trail finalization failed: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
