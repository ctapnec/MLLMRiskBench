"""Create or validate a content-addressed URA project-revision receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.project_revision import (  # noqa: E402
    create_project_revision,
    load_project_revision_file,
    write_project_revision,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create a ura-project-revision/1 receipt from an exact clean Git "
            "checkout, or validate an existing receipt against this checkout."
        )
    )
    parser.add_argument("--expected-revision", default="")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--sha256", default="")
    args = parser.parse_args(argv)
    driver = Path(__file__).with_name("run_matrix.py")
    try:
        if args.validate is not None:
            if args.expected_revision or args.out is not None or not args.sha256:
                parser.error(
                    "--validate requires --sha256 and cannot be combined with "
                    "--expected-revision or --out"
                )
            receipt, descriptor = load_project_revision_file(
                args.validate, args.sha256, driver
            )
            print(json.dumps({
                "status": "valid",
                "revision_id": receipt["revision_id"],
                **descriptor,
            }, sort_keys=True, separators=(",", ":")))
            return 0
        if not args.expected_revision or args.out is None or args.sha256:
            parser.error(
                "creation requires --expected-revision and --out; --sha256 is "
                "valid only with --validate"
            )
        receipt = create_project_revision(args.expected_revision, driver)
        path = write_project_revision(args.out, receipt)
        print(json.dumps({
            "status": "complete",
            "revision_id": receipt["revision_id"],
            "artifact": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (FileExistsError, OSError, TypeError, ValueError) as exc:
        print(f"project-revision failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
