"""Build one private, content-addressed isolated-engine runtime config.

Interpreter locators are read from named environment variables so they do not
appear in this controller's argv.  Standard output contains only path-free
content identities; the create-only output document is private operational
state consumed by ``run_matrix`` with its exact SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from ura.adapters._engine_runtime import (
    ENGINE_RUNTIME_CONFIG_SCHEMA,
    ENGINE_RUNTIME_REQUIREMENTS,
    inspect_engine_runtime,
)


_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _parse_runtime_binding(value: str) -> tuple[str, str]:
    engine, separator, environment_name = value.partition("=")
    engine = engine.strip().lower()
    environment_name = environment_name.strip()
    if (
        separator != "="
        or engine not in ENGINE_RUNTIME_REQUIREMENTS
        or _ENVIRONMENT_NAME.fullmatch(environment_name) is None
    ):
        raise argparse.ArgumentTypeError(
            "--runtime must be ENGINE=ENVIRONMENT_NAME for pyrit, deepteam, "
            "h4rm3l, or spikee"
        )
    return engine, environment_name


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_private_create_only(path_value: str, payload: bytes) -> None:
    if not isinstance(path_value, str) or not path_value.strip() or "\0" in path_value:
        raise ValueError("--out must name a non-blank output file")
    unresolved = Path(path_value).expanduser()
    if unresolved.name in {"", ".", ".."}:
        raise ValueError("--out must name a file")
    parent = unresolved.parent.resolve(strict=True)
    if not parent.is_dir() or parent.is_symlink() or parent.is_junction():
        raise ValueError("--out parent must be one existing regular directory")
    path = parent / unresolved.name
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect isolated framework venvs and write a private runtime config."
    )
    parser.add_argument(
        "--runtime",
        action="append",
        required=True,
        type=_parse_runtime_binding,
        metavar="ENGINE=ENVIRONMENT_NAME",
        help="read one absolute venv interpreter path from the named environment variable",
    )
    parser.add_argument("--out", required=True, help="create-only private JSON output")
    parser.add_argument("--timeout-seconds", type=float, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    bindings: list[tuple[str, str]] = args.runtime
    engines = [engine for engine, _name in bindings]
    if len(set(engines)) != len(engines):
        raise ValueError("each engine may be selected only once")

    runtimes: dict[str, dict[str, object]] = {}
    public_runtimes: dict[str, str] = {}
    for engine, environment_name in sorted(bindings):
        interpreter = os.environ.get(environment_name, "")
        if not interpreter.strip() or "\0" in interpreter:
            raise ValueError(
                f"environment variable {environment_name!r} must contain one "
                "absolute venv interpreter path"
            )
        receipt = inspect_engine_runtime(
            interpreter,
            engine,
            timeout_seconds=args.timeout_seconds,
        )
        runtimes[engine] = {
            "interpreter": interpreter,
            "receipt": receipt,
        }
        public_runtimes[engine] = str(receipt["runtime_id"])

    payload = _canonical_json({
        "schema": ENGINE_RUNTIME_CONFIG_SCHEMA,
        "runtimes": runtimes,
    })
    _write_private_create_only(args.out, payload)
    print(json.dumps(
        {
            "schema": "ura-engine-runtime-config-build/1",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "runtimes": public_runtimes,
        },
        sort_keys=True,
        separators=(",", ":"),
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
