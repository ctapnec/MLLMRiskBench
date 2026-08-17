"""Capture pinned HarmBench generations for measured transfer replay.

Generation stays outside Runner because several HarmBench methods are
source/model-conditioned.  This command binds the selected converted behaviors,
method configuration, checkout revision, and generated cases into one
content-addressed artifact.  The emitted attacker config lets ``run_matrix``
replay that artifact through the normal HarmBench adapter without regenerating
anything inside the measured grid.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ura.adapters.base import AttackBudget  # noqa: E402
from ura.adapters.harmbench import (  # noqa: E402
    HarmBenchAttacker,
    _MAX_REPLAY_BYTES,
    _MAX_REPLAY_CASES,
    _MAX_REPLAY_REQUESTS,
    _REPLAY_FORMAT,
    _canonical_sha256,
    _source_request,
)
from ura.adapters._native_artifacts import read_binary_artifact  # noqa: E402
from ura.converters.harmbench import HarmBenchConverter  # noqa: E402

from .run_matrix import _select_corpus  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture a pinned, text-only HarmBench transfer artifact."
    )
    parser.add_argument("--repo", required=True, help="clean HarmBench checkout")
    parser.add_argument(
        "--revision", required=True, help="exact 40-hex HarmBench Git commit"
    )
    parser.add_argument(
        "--source", required=True, help="official HarmBench text behavior CSV"
    )
    parser.add_argument(
        "--corpus-name",
        default="harmbench_text",
        help="logical run_matrix corpus arm (default: harmbench_text)",
    )
    parser.add_argument(
        "--method", action="append", required=True, help="repeat for each method"
    )
    parser.add_argument("--experiment", default="llama2_7b")
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="same prompt/intent-cluster limit passed to run_matrix (0 = all)",
    )
    parser.add_argument(
        "--sample-seed",
        type=int,
        default=0,
        help="same deterministic source-sampling seed passed to run_matrix",
    )
    parser.add_argument(
        "--cases-per-method",
        type=int,
        default=1,
        help="required generated cases per behavior and method (default: 1)",
    )
    parser.add_argument("--artifact-out", required=True)
    parser.add_argument("--attacker-config-out", required=True)
    parser.add_argument("--python", default=None, help="HarmBench Python executable")
    parser.add_argument(
        "--credential-env",
        action="append",
        default=[],
        help="repeat for each credential environment variable forwarded upstream",
    )
    parser.add_argument("--timeout-seconds", type=float, default=None)
    return parser


def _case_record(attempt, request: dict[str, str]) -> dict[str, Any]:
    if len(attempt.rendered_input) != 1:
        raise ValueError("HarmBench capture produced a non-single-turn case")
    prompt = attempt.rendered_input[0].content
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("HarmBench capture produced a blank case")
    params = attempt.params
    return {
        "datapoint_id": request["datapoint_id"],
        "datapoint_sha256": request["datapoint_sha256"],
        "method": params["method"],
        "upstream_method": params["upstream_method"],
        "upstream_experiment": params["upstream_experiment"],
        "case_index": params["generated_case_index"],
        "prompt": prompt,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "behavior_csv_sha256": params["behavior_csv_sha256"],
        "artifacts": params["method_output_artifacts"],
        "artifact_manifest_sha256": params["method_output_manifest_sha256"],
    }


def _atomic_exclusive_write(path: Path, payload: bytes) -> None:
    """Publish a complete file without overwriting or exposing partial bytes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # A hard-link publish is atomic and create-only: unlike replace(), it
        # cannot overwrite a file created after the preflight existence check.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _canonical_output_target(path: Path) -> Path:
    """Resolve the output parent once and reject an occupied final name."""

    requested = path.expanduser()
    requested.parent.mkdir(parents=True, exist_ok=True)
    target = requested.parent.resolve(strict=True) / requested.name
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing output: {target}")
    return target


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 0:
        raise ValueError("--limit must be non-negative")
    if not 1 <= args.cases_per_method <= 1000:
        raise ValueError("--cases-per-method must be in [1, 1000]")
    if not args.corpus_name.strip():
        raise ValueError("--corpus-name must be non-blank")
    artifact_out = _canonical_output_target(Path(args.artifact_out))
    config_out = _canonical_output_target(Path(args.attacker_config_out))
    if artifact_out == config_out:
        raise ValueError("artifact and attacker config outputs must differ")

    source_path = Path(args.source)
    source_resolved, source_bytes = read_binary_artifact(source_path)
    converted = HarmBenchConverter().parse(source_resolved)
    selected, _, _, _ = _select_corpus(
        args.corpus_name.strip(), converted, args.limit, args.sample_seed
    )
    if not selected:
        raise ValueError("HarmBench capture selected no behaviors")
    selected_ids = [datapoint.id for datapoint in selected]
    if len(set(selected_ids)) != len(selected_ids):
        raise ValueError("HarmBench capture selected duplicate DataPoint ids")
    if len(selected) > _MAX_REPLAY_REQUESTS:
        raise ValueError(
            f"HarmBench capture exceeds the {_MAX_REPLAY_REQUESTS}-request limit"
        )
    expected_case_count = (
        len(selected) * len(args.method) * args.cases_per_method
    )
    if expected_case_count > _MAX_REPLAY_CASES:
        raise ValueError(
            f"HarmBench capture exceeds the {_MAX_REPLAY_CASES}-case limit"
        )
    if any(
        datapoint.media or any(turn.media for turn in datapoint.dialog_history)
        for datapoint in selected
    ):
        raise ValueError(
            "HarmBench capture currently supports text behaviors only"
        )

    attacker = HarmBenchAttacker(
        methods=args.method,
        experiment=args.experiment,
        repo=args.repo,
        upstream_revision=args.revision,
        python=args.python,
        credential_env=args.credential_env,
        timeout_seconds=args.timeout_seconds,
    )
    root, _, _ = attacker._checkout()
    attacker._verify_checkout(root)
    source_requests = [_source_request(datapoint) for datapoint in selected]
    cases: list[dict[str, Any]] = []
    requested_per_behavior = len(attacker.methods) * args.cases_per_method
    budget = AttackBudget(
        max_queries=requested_per_behavior,
        max_turns=requested_per_behavior,
        seed=args.sample_seed,
    )
    for datapoint, request in zip(selected, source_requests):
        attempts = list(attacker.generate(datapoint, budget))
        if len(attempts) != requested_per_behavior:
            raise ValueError(
                f"HarmBench produced {len(attempts)} cases for {datapoint.id!r}; "
                f"expected {requested_per_behavior}"
            )
        cases.extend(_case_record(attempt, request) for attempt in attempts)
    # A generation script that mutated even an ignored checkout path invalidates
    # the capture, just as a dirty checkout does before the first method call.
    attacker._verify_checkout(root)

    unsigned: dict[str, Any] = {
        "format_version": _REPLAY_FORMAT,
        "upstream_revision": attacker.upstream_revision,
        "experiment": attacker.experiment,
        "methods": attacker.methods,
        "cases_per_method": args.cases_per_method,
        "selection": {
            "corpus_name": args.corpus_name.strip(),
            "limit": args.limit,
            "sample_seed": args.sample_seed,
        },
        "source_artifact": {
            "file": source_resolved.name,
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
            "bytes": len(source_bytes),
        },
        "source_requests": source_requests,
        "cases": cases,
    }
    bundle = {**unsigned, "content_sha256": _canonical_sha256(unsigned)}
    artifact_bytes = (
        json.dumps(
            bundle,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(artifact_bytes) > _MAX_REPLAY_BYTES:
        raise ValueError(
            f"HarmBench capture artifact exceeds {_MAX_REPLAY_BYTES} bytes"
        )
    artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    _atomic_exclusive_write(artifact_out, artifact_bytes)
    config = {
        "harmbench": {
            "methods": attacker.methods,
            "experiment": attacker.experiment,
            "upstream_revision": attacker.upstream_revision,
            "replay_artifact": str(artifact_out),
            "replay_artifact_sha256": artifact_sha256,
        }
    }
    config_bytes = (
        json.dumps(config, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    _atomic_exclusive_write(config_out, config_bytes)
    print(
        f"captured {len(cases)} HarmBench cases for {len(selected)} behaviors "
        f"-> {artifact_out} (sha256:{artifact_sha256})"
    )
    print(f"attacker config -> {config_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
