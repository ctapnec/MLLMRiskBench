"""Run every whole execution cell's no-call plan and retain its eligibility ledger."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from experiments import run_matrix


def _requested_output(arguments: list[str]) -> Path:
    destination = Path("runs/exp")
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item == "--out" and index + 1 < len(arguments):
            destination = Path(arguments[index + 1])
            index += 2
            continue
        if item.startswith("--out="):
            destination = Path(item.split("=", 1)[1])
        index += 1
    return destination


def _persist_eligibility_artifacts(scratch: Path, destination: Path) -> list[Path]:
    """Copy only content-addressed planning ledgers out of temporary preflight."""

    sources = sorted(scratch.glob("eligibility-*.eligibility.json"))
    if not sources:
        return []
    if destination.is_symlink():
        raise ValueError("rig-check --out must not be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for source in sources:
        payload = source.read_bytes()
        target = destination / source.name
        if target.exists():
            if not target.is_file() or target.is_symlink():
                raise ValueError(f"eligibility destination is not a regular file: {target}")
            if target.read_bytes() != payload:
                raise ValueError(
                    f"content-addressed eligibility artifact collision: {target}"
                )
        else:
            with target.open("xb") as handle:
                handle.write(payload)
        copied.append(target)
    return copied


def main(argv: list[str] | None = None) -> int:
    forwarded = list(sys.argv[1:] if argv is None else argv)
    destination = _requested_output(forwarded)
    with TemporaryDirectory(prefix="ura-rig-check-") as scratch:
        try:
            result = run_matrix.main([
                *forwarded,
                "--preflight-only",
                "--out", scratch,
            ])
        except BaseException:
            # argparse/SystemExit failures late enough to have a ledger should
            # not erase it when the temporary preflight directory is removed.
            _persist_eligibility_artifacts(Path(scratch), destination)
            raise
        try:
            copied = _persist_eligibility_artifacts(Path(scratch), destination)
        except (OSError, ValueError) as exc:
            print(f"rig-check eligibility persistence failed: {exc}", file=sys.stderr)
            return 1
        if result == 0 and not copied:
            print(
                "rig-check passed without emitting the required eligibility artifact",
                file=sys.stderr,
            )
            return 1
        if copied:
            print(json.dumps({
                "status": "eligibility_persisted",
                "artifacts": [str(path.resolve()) for path in copied],
            }, sort_keys=True))
        return result


if __name__ == "__main__":
    raise SystemExit(main())
