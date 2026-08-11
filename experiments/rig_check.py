"""Run the experiment driver's complete no-call preflight in temporary storage."""
from __future__ import annotations

import sys
from tempfile import TemporaryDirectory

from experiments import run_matrix


def main(argv: list[str] | None = None) -> int:
    forwarded = list(sys.argv[1:] if argv is None else argv)
    with TemporaryDirectory(prefix="ura-rig-check-") as scratch:
        return run_matrix.main([
            *forwarded,
            "--preflight-only",
            "--out", scratch,
        ])


if __name__ == "__main__":
    raise SystemExit(main())
