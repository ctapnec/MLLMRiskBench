"""Derive typed live-transport receipts from strict completed probe artifacts.

This command performs no provider call.  It revalidates an already completed
``run_matrix --attestation-probe`` grid and emits one content-addressed
``ura-live-attestation/2`` JSON receipt.  The receipt proves only the historical
route/identity/byte-backed transport prerequisite named by each record.
``--validate PATH --sha256 HEX`` instead revalidates an existing receipt
through the same strict loader/validator the measured-grid admission uses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from experiments.level1_evidence import (  # noqa: E402
    _load_results,
    _plan_artifact,
)
from experiments.local_campaign.target_execution import (  # noqa: E402
    target_execution_counts,
)
from ura.data_models import Attempt  # noqa: E402
from ura.live_attestation import (  # noqa: E402
    build_live_attestation_manifest,
    canonical_json_sha256,
    load_live_attestation_file,
    route_config_from_grid_request,
    route_config_sha256,
)
from ura.modality_coverage import canonical_modality_combination  # noqa: E402
from ura.project_revision import validate_project_revision_binding  # noqa: E402


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _descriptor(path: Path) -> dict[str, object]:
    return {
        "file": path.name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _conservative_probe_observed_at(value: object) -> str:
    """Return the completion-bound probe start as a strict UTC timestamp.

    A run manifest has no completion timestamp.  Its content-addressed
    ``started_at`` is nevertheless a sound conservative lower bound for the
    later target observation and cannot be refreshed by editing grid metadata.
    """

    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or not value.endswith(("Z", "+00:00"))
    ):
        raise ValueError("probe manifest started_at must be an unpadded UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("probe manifest started_at is not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("probe manifest started_at must use UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _attempt_combination(value: dict[str, Any]) -> tuple[str, ...]:
    attempt = Attempt.model_validate(value, strict=True)
    physical = {
        ref.modality
        for turn in attempt.rendered_input
        for ref in turn.media
    }
    has_text = any(
        bool((turn.content or "").strip())
        or turn.tool_call is not None
        or bool((turn.tool_result or "").strip())
        for turn in attempt.rendered_input
    )
    return canonical_modality_combination(
        modality
        for modality in ("text", "image", "audio", "video")
        if modality in physical or (modality == "text" and has_text)
    )


def _build_from_probe_root_with_target_execution(
    root: Path, *, execution_scope_id: str
) -> tuple[dict[str, Any], tuple[int, int]]:
    """Strictly load one completed probe grid and derive exact receipt records."""

    if root.is_symlink():
        raise ValueError("probe root must not be a symlink")
    root = root.resolve(strict=True)
    plans = list(root.glob("eligibility-*.eligibility.json"))
    if len(plans) != 1:
        raise ValueError("probe root must contain exactly one eligibility plan")
    artifact = _plan_artifact(plans[0])
    grids, request_errors = _load_results([root], {artifact[0]["plan_id"]: artifact})
    if request_errors or len(grids) != 1:
        raise ValueError("probe root must contain one error-free final grid")
    grid = next(iter(grids.values()))
    request = grid["request"]
    if request.get("attestation_probe") is not True or request.get("dry_run") is not False:
        raise ValueError(
            "live receipt requires a non-dry-run grid explicitly marked "
            "attestation_probe=true"
        )
    projection = request.get("live_attestation")
    if projection != {
        "mode": "probe",
        "execution_scope_id": execution_scope_id,
        "max_age_hours": None,
        "artifacts": [],
    }:
        raise ValueError(
            "probe grid does not bind the exact requested execution scope"
        )
    if request.get("defense") != "none":
        raise ValueError("live transport probe must exercise the unwrapped base target")
    if grid["grid_status"] != "complete" or len(grid["cells"]) != 1:
        raise ValueError("live transport probe must complete exactly one Runner cell")
    cell = next(iter(grid["cells"].values()))
    validated = cell.get("validated_cell")
    if not isinstance(validated, dict):
        raise ValueError("live transport probe lacks a validated completion bundle")
    requested_specs = artifact[0]["request"]["requested_target_specs"]
    if len(requested_specs) != 1:
        raise ValueError("live transport probe must request exactly one target")
    requested = requested_specs[0]
    resolved_target = validated["model"]
    identity = validated["realized_identities"]["target"]
    if identity.get("observations", 0) < 1 or not identity.get("snapshot"):
        raise ValueError("probe lacks a realized target identity observation")
    route_kind = "local_runtime" if requested.startswith(("vllm:", "ollama:")) else "hosted_api"
    route_config = route_config_from_grid_request(
        request,
        route_kind=route_kind,
        requested_target_spec=requested,
        resolved_target=resolved_target,
    )
    route_digest = route_config_sha256(
        route_kind=route_kind,
        requested_target_spec=requested,
        resolved_target=resolved_target,
        route_config=route_config,
    )
    attempts = validated["attempts"]
    judgments = validated["judgments"]
    combinations: set[tuple[str, ...]] = set()
    media_hashes_by_combination: dict[tuple[str, ...], dict[str, str]] = {}
    for judgment in judgments:
        if judgment.get("raw", {}).get("policy_evaluable_turn") is not True:
            continue
        attempt = attempts.get(judgment.get("attempt_id"))
        if not isinstance(attempt, dict):
            raise ValueError("probe Judgment lacks its validated Attempt")
        if judgment["raw"].get("target_input_delivered") is not True:
            continue
        combination = _attempt_combination(attempt)
        if list(combination) != judgment["raw"].get(
            "planning_exact_modality_combination"
        ):
            raise ValueError("probe planned/delivered exact modality mismatch")
        combinations.add(combination)
        media_hashes = media_hashes_by_combination.setdefault(combination, {})
        params = attempt.get("params", {})
        hashes = params.get("attempt_media_hashes", {})
        if not isinstance(hashes, dict):
            raise ValueError("probe Attempt lacks media-hash provenance")
        for key, digest in hashes.items():
            if key in media_hashes and media_hashes[key] != digest:
                raise ValueError("probe contains conflicting attempt-media hashes")
            media_hashes[key] = digest
    if not combinations:
        raise ValueError("probe has no policy-evaluable delivered input evidence")
    grid_path = root / grid["grid_locator"]
    marker_path = validated["complete_path"]
    # The grid's finished_at is operator-package metadata outside the completed
    # cell's content-addressed artifact set.  Use the manifest's hashed start
    # timestamp as the conservative observation time so editing the grid cannot
    # manufacture a fresh receipt.
    observed_at = _conservative_probe_observed_at(
        validated["manifest"].get("started_at")
    )
    harness_source = validated["manifest"]["config"].get("harness_source")
    driver_source = validated["manifest"]["config"]["run"].get("driver_source")
    project_revision = validate_project_revision_binding(
        validated["manifest"]["config"]["run"].get("project_revision"),
        allow_not_required=False,
    )
    if not isinstance(harness_source, dict) or not isinstance(driver_source, dict):
        raise ValueError("probe lacks harness/experiment-driver source identity")
    harness_source_sha256 = harness_source.get("sha256")
    driver_source_sha256 = driver_source.get("sha256")
    if project_revision != validate_project_revision_binding(
        request.get("project_revision"), allow_not_required=False
    ):
        raise ValueError("probe grid/execution project-revision mismatch")
    if project_revision["harness_source_sha256"] != harness_source_sha256:
        raise ValueError("probe project-revision/harness-source mismatch")
    if project_revision["driver_source_sha256"] != driver_source_sha256:
        raise ValueError("probe project-revision/experiment-driver mismatch")
    records = []
    for combination in sorted(combinations):
        records.append({
            "execution_scope_id": execution_scope_id,
            "requested_target_spec": requested,
            "resolved_target": resolved_target,
            "route_kind": route_kind,
            "route_config_sha256": route_digest,
            "exact_input_modalities": list(combination),
            "realized_target_identity": identity["snapshot"],
            "observed_at_utc": observed_at,
            "probe": {
                "evidence_kind": (
                    "synthetic_live_transport_probe"
                    if set(request.get("corpora", [])) == {"synth"}
                    else "real_source_live_transport_probe"
                ),
                "grid_id": grid["grid_id"],
                "run_id": validated["run_id"],
                "grid_artifact": _descriptor(grid_path),
                "completion_artifact": _descriptor(marker_path),
                "realized_identities_sha256": validated["manifest"]["config"]
                ["realized_identities_sha256"],
                "attempt_media_hashes_sha256": canonical_json_sha256(
                    dict(sorted(media_hashes_by_combination[combination].items()))
                ),
                "harness_source_sha256": harness_source_sha256,
                "driver_source_sha256": driver_source_sha256,
                "project_revision": project_revision,
            },
        })
    responses = validated.get("responses")
    if not isinstance(responses, dict):
        raise ValueError("probe completion lacks validated target responses")
    execution = target_execution_counts(len(responses), len(responses))
    return build_live_attestation_manifest(records), execution


def build_from_probe_root(
    root: Path, *, execution_scope_id: str
) -> dict[str, Any]:
    """Strictly derive a receipt while retaining the historical public API."""

    return _build_from_probe_root_with_target_execution(
        root, execution_scope_id=execution_scope_id
    )[0]


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Derive a typed live-transport receipt from one completed probe, "
            "or revalidate an existing receipt against its exact byte digest"
        )
    )
    parser.add_argument("--probe-root", type=Path, default=None)
    parser.add_argument("--execution-scope-id", default="")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--validate", type=Path, default=None,
        help=(
            "existing ura-live-attestation/2 receipt to revalidate (with "
            "--sha256) through the strict loader instead of deriving one"
        ),
    )
    parser.add_argument(
        "--sha256", default="",
        help="exact byte digest required alongside --validate",
    )
    args = parser.parse_args(argv)
    if args.validate is not None:
        if args.probe_root or args.execution_scope_id or args.out:
            parser.error(
                "--validate requires --sha256 and cannot be combined with "
                "--probe-root, --execution-scope-id, or --out"
            )
        if not args.sha256:
            parser.error("--validate requires --sha256")
        try:
            manifest, artifact = load_live_attestation_file(
                args.validate, args.sha256
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            print(f"live attestation validation failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({
            "status": "attestation_validated",
            "attestation_id": manifest["attestation_id"],
            "records": len(manifest["records"]),
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
            "validity_claim": "target_route_and_byte_backed_transport_only",
        }, sort_keys=True))
        return 0
    if args.sha256:
        parser.error("--sha256 is valid only with --validate")
    if args.probe_root is None or not args.execution_scope_id or args.out is None:
        parser.error(
            "derivation requires --probe-root, --execution-scope-id, and --out"
        )
    try:
        receipt, (target_attempts, successful_target_generations) = (
            _build_from_probe_root_with_target_execution(
                args.probe_root, execution_scope_id=args.execution_scope_id
            )
        )
        _write_new(args.out, receipt)
        receipt_sha256 = _sha256_file(args.out)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"live attestation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "written",
        "attestation_id": receipt["attestation_id"],
        "records": len(receipt["records"]),
        "sha256": receipt_sha256,
        "successful_target_generations": successful_target_generations,
        "target_attempts": target_attempts,
        "out": str(args.out.resolve()),
        "validity_claim": "target_route_and_byte_backed_transport_only",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
