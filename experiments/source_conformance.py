"""Validate one compact, operator-authored source acquisition receipt.

This command performs no download, model call, or scientific validation.  The
matrix driver adds and binds machine-derived converted/policy/media evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.source_conformance import (
    validate_source_conformance_manifest,
    verify_manifest_components,
)


_MAX_MANIFEST_BYTES = 4 * 1024 * 1024


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a compact URA source acquisition receipt"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source-config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
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
