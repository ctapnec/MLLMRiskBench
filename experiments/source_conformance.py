"""Validate one compact, operator-authored source acquisition receipt.

This command performs no download, model call, or scientific validation.  The
matrix driver adds and binds machine-derived converted/policy/media evidence.

The optional ``--scaffold`` mode pre-fills only the mechanical receipt fields
(registry identity, consumed-input digests, and the semantic-review corpus
digest/cluster IDs from a bounded dry-run observation).  Every operator
judgment field is written as an ``OPERATOR_TODO`` placeholder, the scaffold
carries a non-receipt schema name, and receipt validation rejects any
surviving placeholder, so a scaffold can never be admitted without the
operator actually supplying the license/access decision, raw-record
reconciliation, and semantic review.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.source_conformance import (  # noqa: E402
    SCAFFOLD_SENTINEL,
    validate_source_conformance_manifest,
    verify_manifest_components,
)


_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
SCAFFOLD_SCHEMA = "ura-source-conformance-scaffold/1"


def _read_regular(path: Path, *, label: str, max_bytes: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} must be a regular file")
    size = resolved.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"{label} must be 1..{max_bytes} bytes")
    payload = resolved.read_bytes()
    if len(payload) != size:
        raise ValueError(f"{label} changed while being read")
    return payload


def _loads_strict(payload: bytes, *, label: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains non-finite JSON number {value!r}")

    try:
        return json.loads(payload.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label} JSON: {exc}") from exc


def _scaffold_consumed_input(path_env: str) -> tuple[dict[str, Any] | None, str]:
    configured = os.environ.get(path_env)
    if configured is None or not configured.strip():
        return None, f"environment {path_env} unset; set it and re-run the scaffold"
    unresolved = Path(configured).expanduser()
    if unresolved.is_symlink():
        raise ValueError(f"scaffold input {path_env} must not be a symlink")
    path = unresolved.resolve(strict=True)
    if path.is_file():
        payload = path.read_bytes()
        return (
            {
                "kind": "file",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            },
            "hashed_from_environment",
        )
    if path.is_dir():
        return (
            {"kind": "directory"},
            "directory input; declare the exact-file release component(s)",
        )
    raise ValueError(f"scaffold input {path_env} is neither file nor directory")


def _scaffold_semantic_review(
    arm_id: str, observation: Path | None,
) -> tuple[dict[str, Any], str]:
    review: dict[str, Any] = {
        "status": "pending",
        "reviewer": SCAFFOLD_SENTINEL,
        "reviewed_at": SCAFFOLD_SENTINEL,
        "selection_rule": SCAFFOLD_SENTINEL,
        "reviewed_cluster_ids": [],
        "reviewed_converted_corpus_sha256": SCAFFOLD_SENTINEL,
        "notes": SCAFFOLD_SENTINEL,
    }
    if observation is None:
        return review, "no observation supplied; run the runbook one-arm dry run"
    manifests = sorted(observation.glob("*.manifest.json"))
    if len(manifests) != 1:
        raise ValueError(
            f"observation for {arm_id!r} must contain exactly one manifest, "
            f"found {len(manifests)}: {observation}"
        )
    manifest = _loads_strict(
        _read_regular(
            manifests[0], label="observation manifest",
            max_bytes=_MAX_MANIFEST_BYTES,
        ),
        label="observation manifest",
    )
    if not isinstance(manifest, dict):
        raise ValueError("observation manifest is not an object")
    run = ((manifest.get("config") or {}).get("run") or {})
    if run.get("corpus") != arm_id:
        raise ValueError(
            f"observation manifest corpus {run.get('corpus')!r} does not match "
            f"scaffolded arm {arm_id!r}"
        )
    audit = run.get("sampling_audit")
    if not isinstance(audit, dict):
        raise ValueError("observation manifest lacks its sampling audit")
    digest = audit.get("full_converted_corpus_sha256")
    selected = audit.get("selected_cluster_ids")
    if not isinstance(digest, str) or not isinstance(selected, list):
        raise ValueError("observation sampling audit lacks digest/cluster fields")
    review["reviewed_converted_corpus_sha256"] = digest
    review["reviewed_cluster_ids"] = [str(item) for item in selected]
    return review, "corpus digest and selected clusters copied from observation"


def _write_scaffold(
    arms: list[str],
    observations: dict[str, Path],
    source_config: Path,
    out: Path,
) -> dict[str, Any]:
    unknown = sorted(set(observations) - set(arms))
    if unknown:
        raise ValueError(f"--observation names unscaffolded arm(s): {unknown}")

    # Reuse the matrix's strict registry parser so scaffold identity and
    # paid-run admission cannot disagree about selected configuration.
    from experiments.run_matrix import _load_source_config

    instances, _ = _load_source_config(str(source_config), arms)
    scaffold_arms: list[dict[str, Any]] = []
    prefill: dict[str, dict[str, str]] = {}
    for arm_id in arms:
        instance = instances[arm_id]
        consumed, consumed_note = _scaffold_consumed_input(
            str(instance["path_env"])
        )
        review, review_note = _scaffold_semantic_review(
            arm_id, observations.get(arm_id)
        )
        prefill[arm_id] = {
            "consumed_input": consumed_note,
            "semantic_review": review_note,
        }
        scaffold_arms.append({
            "arm_id": arm_id,
            "converter": instance["converter"],
            "path_env": instance["path_env"],
            "source_label": instance.get("source_label"),
            "split": instance.get("split"),
            "disposition": "admitted",
            "reason": f"{SCAFFOLD_SENTINEL}: why this arm is selected",
            "upstream_uri": f"https://{SCAFFOLD_SENTINEL}.invalid/",
            "requested_revision": f"{SCAFFOLD_SENTINEL.lower()}0",
            "observed_revision": f"{SCAFFOLD_SENTINEL.lower()}0",
            "consumed_input": consumed,
            "components": [],
            "operator_decision": {
                "decision": "pending",
                "access_status": "pending",
                "license_identifier_or_notice": SCAFFOLD_SENTINEL,
                "reviewer": SCAFFOLD_SENTINEL,
                "reviewed_at": SCAFFOLD_SENTINEL,
                "evidence_sha256": SCAFFOLD_SENTINEL,
                "notes": SCAFFOLD_SENTINEL,
            },
            "raw_records": {
                "discovered": 0,
                "accepted": 0,
                "excluded_by_design": 0,
                "rejected_invalid": 0,
                "reasons": {},
            },
            "semantic_review": review,
        })
    scaffold = {
        "schema": SCAFFOLD_SCHEMA,
        "claim_scope": "acquisition_and_conversion_traceability_only",
        "instructions": [
            "This scaffold is NOT a receipt and is rejected by validation "
            "until completed and renamed.",
            "Replace every OPERATOR_TODO value with the actual judgment: "
            "upstream URI/revisions, license/access decision with evidence "
            "digest, raw-record reconciliation against the raw release, and "
            "the attributed semantic review (set status passed only after "
            "actually comparing the observed clusters with the raw source).",
            "For a blocked or not-selected arm, keep only arm identity, "
            "disposition, and reason; delete the other fields.",
            "Directory-backed arms must declare exact-file release "
            "component(s) with role/path_env/sha256/bytes.",
            "When complete, change schema to 'ura-source-conformance/1' and "
            "validate: python -m experiments.source_conformance --manifest "
            "<file> --sha256 <sha256> --source-config <registry>.",
        ],
        "arms": scaffold_arms,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8", newline="") as stream:
        stream.write(json.dumps(
            scaffold, ensure_ascii=False, indent=2, sort_keys=True,
        ) + "\n")
    return {
        "status": "scaffold_written",
        "not_a_receipt": True,
        "schema": SCAFFOLD_SCHEMA,
        "output": str(out.resolve()),
        "arms": len(scaffold_arms),
        "prefill": prefill,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a compact URA source acquisition receipt, or scaffold "
            "one with only its mechanical fields pre-filled"
        )
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--source-config", type=Path, required=True)
    parser.add_argument(
        "--scaffold", action="store_true",
        help="write a pre-filled non-receipt scaffold instead of validating",
    )
    parser.add_argument(
        "--arm", action="append", default=[],
        help="scaffold mode: registry arm to scaffold; repeatable",
    )
    parser.add_argument(
        "--observation", action="append", default=[],
        metavar="ARM=DIR",
        help=(
            "scaffold mode: bounded one-arm dry-run observation directory "
            "whose corpus digest and selected clusters pre-fill the semantic "
            "review; repeatable"
        ),
    )
    parser.add_argument(
        "--out", type=Path,
        help="scaffold mode: output path (create-only)",
    )
    args = parser.parse_args(argv)
    try:
        if args.scaffold:
            if args.manifest is not None or args.sha256 is not None:
                parser.error("--scaffold does not take --manifest/--sha256")
            if not args.arm or args.out is None:
                parser.error("--scaffold requires at least one --arm and --out")
            observations: dict[str, Path] = {}
            for item in args.observation:
                arm_id, separator, directory = item.partition("=")
                if not separator or not arm_id.strip() or not directory.strip():
                    raise ValueError(
                        f"--observation must be ARM=DIR, got {item!r}"
                    )
                if arm_id in observations:
                    raise ValueError(f"duplicate --observation for {arm_id!r}")
                observations[arm_id] = Path(directory).expanduser().resolve(
                    strict=True
                )
            summary = _write_scaffold(
                list(dict.fromkeys(args.arm)), observations,
                args.source_config, args.out,
            )
            print(json.dumps(summary, sort_keys=True))
            return 0
        if args.manifest is None or args.sha256 is None:
            parser.error("validation requires --manifest and --sha256")
        expected = args.sha256.lower()
        if len(expected) != 64 or any(
            char not in "0123456789abcdef" for char in expected
        ):
            raise ValueError("--sha256 must be exactly 64 lowercase hex digits")
        payload = _read_regular(
            args.manifest,
            label="source receipt",
            max_bytes=_MAX_MANIFEST_BYTES,
        )
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise ValueError(
                f"source receipt sha256 mismatch: expected {expected}, got {actual}"
            )
        receipt = validate_source_conformance_manifest(
            _loads_strict(payload, label="source receipt")
        )
        arm_ids = [str(arm["arm_id"]) for arm in receipt["arms"]]

        # Reuse the matrix's strict registry parser so this command and paid-run
        # admission cannot disagree about selected configuration identity.
        from experiments.run_matrix import _load_source_config

        instances, artifact = _load_source_config(str(args.source_config), arm_ids)
        if artifact is None:  # pragma: no cover - explicit path above
            raise ValueError("source receipt requires source-config provenance")
        for arm_id, instance in instances.items():
            arm = next(item for item in receipt["arms"] if item["arm_id"] == arm_id)
            for field in ("converter", "path_env", "source_label", "split"):
                if arm.get(field) != instance.get(field):
                    raise ValueError(f"source receipt arm {arm_id!r} {field} mismatch")
        verified = verify_manifest_components(receipt)
        print(json.dumps({
            "status": "receipt_validated",
            "schema": receipt["schema"],
            "sha256": actual,
            "arms": len(receipt["arms"]),
            "verified_admitted_arms": verified,
            "source_config_selected_sha256": artifact[
                "normalized_selected_sha256"
            ],
            "claim_scope": receipt["claim_scope"],
            "runtime_conversion_binding": "pending_run_matrix_preflight",
        }, sort_keys=True))
        return 0
    except (OSError, KeyError, ValueError) as exc:
        print(f"source receipt validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
