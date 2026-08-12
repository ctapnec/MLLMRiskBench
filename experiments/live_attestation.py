"""Derive typed live-transport receipts from strict completed probe artifacts.

This command performs no provider call.  It revalidates an already completed
``run_matrix --attestation-probe`` grid and emits one content-addressed
``ura-live-attestation/1`` JSON receipt.  The receipt proves only the historical
route/identity/byte-backed transport prerequisite named by each record.
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
from ura.data_models import Attempt  # noqa: E402
from ura.live_attestation import (  # noqa: E402
    build_live_attestation_manifest,
    canonical_json_sha256,
    route_config_from_grid_request,
    route_config_sha256,
)
from ura.modality_coverage import canonical_modality_combination  # noqa: E402


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


def build_from_probe_root(
    root: Path, *, execution_scope_id: str
) -> dict[str, Any]:
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
    if not isinstance(harness_source, dict) or not isinstance(driver_source, dict):
        raise ValueError("probe lacks harness/experiment-driver source identity")
    harness_source_sha256 = harness_source.get("sha256")
    driver_source_sha256 = driver_source.get("sha256")
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
            },
        })
    return build_live_attestation_manifest(records)


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive a typed live-transport receipt from one completed probe"
    )
    parser.add_argument("--probe-root", type=Path, required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = build_from_probe_root(
            args.probe_root, execution_scope_id=args.execution_scope_id
        )
        _write_new(args.out, receipt)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"live attestation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "written",
        "attestation_id": receipt["attestation_id"],
        "records": len(receipt["records"]),
        "out": str(args.out.resolve()),
        "validity_claim": "target_route_and_byte_backed_transport_only",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
