"""Create the next workspace binding by explicitly rebinding a prior one."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
from typing import Sequence

from .generate import (
    BINDINGS_SCHEMA,
    EXTERNAL_BINDINGS,
    LEGACY_A05_EXTERNAL_BINDINGS,
    PHASE3_BINDINGS_ADDED_AFTER_A05,
    PRE_RR_EXTERNAL_BINDINGS,
    RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719,
    ControllerGenerationError,
    validate_binding_document,
)


NAME = re.compile(r"[A-Z][A-Z0-9_]*")
MIGRATION_REVISION_BINDINGS = frozenset({
    "EXPECTED_COMMIT",
    "PROJECT_RECEIPT_PATH",
    "PROJECT_RECEIPT_SHA256",
    "PROJECT_RECEIPT_BYTES",
})
LEGACY_A05_REQUIRED_REPLACEMENTS = PHASE3_BINDINGS_ADDED_AFTER_A05 | {
    "CONTROLLER_INSTALL_ROOT"
} | RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719 | MIGRATION_REVISION_BINDINGS
PRE_RR_REQUIRED_REPLACEMENTS = (
    RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719 | MIGRATION_REVISION_BINDINGS
)


def _assignment(value: str) -> tuple[str, str]:
    name, separator, replacement = value.partition("=")
    if not separator or NAME.fullmatch(name) is None or not replacement:
        raise argparse.ArgumentTypeError("--set requires NAME=non-empty-value")
    return name, replacement


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--project-receipt-path")
    parser.add_argument("--project-receipt-sha256")
    parser.add_argument("--phase3-guard-tag")
    parser.add_argument("--phase5-sequence-tag")
    parser.add_argument("--gate5-sequence-tag")
    parser.add_argument("--phase6-sequence-tag")
    parser.add_argument("--phase7-watcher-tag")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        type=_assignment,
        metavar="NAME=VALUE",
        help="explicitly replace a less-common receipt or Phase 3 evidence binding",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = json.loads(args.base.resolve(strict=True).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("values"), dict):
            raise ControllerGenerationError("base binding is not one binding document")
        if any(not isinstance(key, str) for key in raw["values"]):
            raise ControllerGenerationError("base binding names must be strings")
        base_keys = set(raw["values"])
        if base_keys == EXTERNAL_BINDINGS:
            values = validate_binding_document(raw)
            required_migration_replacements: frozenset[str] = frozenset()
            migration_label = ""
        elif base_keys == PRE_RR_EXTERNAL_BINDINGS:
            values = validate_binding_document(
                raw,
                expected_keys=PRE_RR_EXTERNAL_BINDINGS,
            )
            required_migration_replacements = PRE_RR_REQUIRED_REPLACEMENTS
            migration_label = "pre-RR migration"
        elif base_keys == LEGACY_A05_EXTERNAL_BINDINGS:
            values = validate_binding_document(
                raw,
                expected_keys=LEGACY_A05_EXTERNAL_BINDINGS,
            )
            values.pop("PHASE3_GPU_INVENTORY_SHA256")
            required_migration_replacements = LEGACY_A05_REQUIRED_REPLACEMENTS
            migration_label = "legacy a05 migration"
        else:
            allowed = EXTERNAL_BINDINGS | {"PHASE3_GPU_INVENTORY_SHA256"}
            unknown = sorted(base_keys - allowed)
            missing_current = sorted(EXTERNAL_BINDINGS - base_keys)
            raise ControllerGenerationError(
                "base binding key inventory is neither current nor the exact "
                "pre-RR or legacy a05 inventory: "
                f"missing_current={missing_current}, unknown={unknown}"
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ControllerGenerationError) as exc:
        raise SystemExit(f"cannot load base controller binding: {exc}") from exc

    convenience = {
        "EXPECTED_COMMIT": args.expected_commit,
        "PROJECT_RECEIPT_PATH": args.project_receipt_path,
        "PROJECT_RECEIPT_SHA256": args.project_receipt_sha256,
        "PHASE3_GUARD_TAG": args.phase3_guard_tag,
        "PHASE5_SEQUENCE_TAG": args.phase5_sequence_tag,
        "GATE5_SEQUENCE_TAG": args.gate5_sequence_tag,
        "PHASE6_SEQUENCE_TAG": args.phase6_sequence_tag,
        "PHASE7_WATCHER_TAG": args.phase7_watcher_tag,
    }
    replacements = {name: value for name, value in convenience.items() if value is not None}
    for name, value in args.set:
        if name not in EXTERNAL_BINDINGS:
            raise SystemExit(f"--set names no reviewed external binding: {name}")
        if name in replacements:
            raise SystemExit(f"binding was replaced more than once: {name}")
        replacements[name] = value
    if not replacements:
        raise SystemExit("at least one binding replacement is required")
    if required_migration_replacements:
        explicitly_added = set(replacements) & required_migration_replacements
        missing_migration = sorted(
            required_migration_replacements - explicitly_added
        )
        if missing_migration:
            raise SystemExit(
                f"{migration_label} requires an explicit replacement for every new "
                f"or changed controller binding: {missing_migration}"
            )
    values.update(replacements)
    document = {"schema": BINDINGS_SCHEMA, "values": values}
    try:
        validate_binding_document(document)
    except ControllerGenerationError as exc:
        raise SystemExit(str(exc)) from exc

    output = args.out.resolve()
    if output.exists() or output.is_symlink():
        raise SystemExit(f"binding output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"out": str(output), "replaced": sorted(replacements)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
