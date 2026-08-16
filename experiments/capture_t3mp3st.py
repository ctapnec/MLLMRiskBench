"""Capture planning-only T3MP3ST responses for an exact corpus selection.

This is deliberately an out-of-band preparation command.  It contacts only a
prestarted literal-loopback ``POST /api/general/plan`` endpoint and writes one
content-addressed replay bundle for later measured runs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ura.adapters.t3mp3st import (  # noqa: E402
    T3MP3STAttacker,
    build_plan_bundle,
)
from ura.data_models import DataPoint  # noqa: E402


_FORMAT_VERSION = "ura-t3mp3st-plan-bundle/1"
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024 * 1024
_MAX_RECORDS = 10_000


def _strict_json(text: str) -> object:
    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key {key!r}")
            value[key] = item
        return value

    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant {constant}")
        ),
    )


def load_input_list(path_value: str | Path) -> list[DataPoint]:
    """Load a bounded JSON array containing only declared DataPoint fields."""

    unresolved = Path(path_value).expanduser()
    if unresolved.is_symlink():
        raise ValueError("--input must not be a symlink")
    path = unresolved.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("--input must be a regular non-symlink JSON file")
    size = path.stat().st_size
    if not 0 < size <= _MAX_INPUT_BYTES:
        raise ValueError(f"--input must be non-empty and at most {_MAX_INPUT_BYTES} bytes")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError("--input changed while being read")
    try:
        value = _strict_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("--input must contain valid UTF-8 JSON") from exc
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_RECORDS:
        raise ValueError(f"--input must contain a JSON array of 1..{_MAX_RECORDS} rows")
    allowed_fields = set(DataPoint.model_fields)
    datapoints: list[DataPoint] = []
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            raise ValueError(f"--input row {index} must be an object")
        unknown = sorted(set(row) - allowed_fields)
        if unknown:
            raise ValueError(
                f"--input row {index} has unsupported DataPoint fields: "
                + ", ".join(unknown)
            )
        datapoints.append(DataPoint.model_validate(row))
    return datapoints


def load_corpus_selection(
    corpus: str,
    *,
    source_config: str = "",
    limit: int = 50,
    sample_seed: int = 0,
) -> list[DataPoint]:
    """Use run_matrix's exact converter and deterministic selection path."""

    if not isinstance(corpus, str) or not corpus.strip() or corpus != corpus.strip():
        raise ValueError("--corpus must be one non-blank, unpadded arm id")
    if "," in corpus:
        raise ValueError("capture one --corpus arm per bundle")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("--limit must be a non-negative integer")
    if isinstance(sample_seed, bool) or not isinstance(sample_seed, int):
        raise ValueError("--sample-seed must be an integer")
    from experiments.run_matrix import (  # noqa: PLC0415
        _load_source_config,
        load_corpus_with_audit,
    )

    source_instances, _artifact = _load_source_config(source_config, [corpus])
    datapoints, _audit = load_corpus_with_audit(
        corpus,
        limit,
        sample_seed,
        source_instance=source_instances[corpus],
    )
    if not datapoints:
        raise ValueError("selected corpus converted to zero DataPoints")
    return datapoints


def write_content_addressed_bundle(
    bundle: dict[str, object], output_directory: str | Path
) -> dict[str, object]:
    """Atomically publish canonical bytes under their complete SHA-256 name."""

    encoded = (
        json.dumps(
            bundle,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if not 0 < len(encoded) <= _MAX_OUTPUT_BYTES:
        raise ValueError(
            f"T3MP3ST plan bundle must be at most {_MAX_OUTPUT_BYTES} bytes"
        )
    digest = hashlib.sha256(encoded).hexdigest()
    unresolved = Path(output_directory).expanduser()
    if unresolved.exists() and unresolved.is_symlink():
        raise ValueError("--out must not be a symlink")
    unresolved.mkdir(parents=True, exist_ok=True)
    directory = unresolved.resolve(strict=True)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("--out must be a regular non-symlink directory")
    destination = directory / f"t3mp3st-plan-bundle-{digest}.json"
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError("content-addressed bundle destination is not a regular file")
        if destination.stat().st_size != len(encoded):
            raise ValueError("content-addressed bundle destination has conflicting bytes")
        if destination.read_bytes() != encoded:
            raise ValueError("content-addressed bundle destination has conflicting bytes")
    else:
        temporary = directory / (
            f".{destination.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if destination.is_symlink() or not destination.is_file():
                    raise ValueError(
                        "content-addressed bundle destination is not a regular file"
                    )
                if destination.stat().st_size != len(encoded):
                    raise ValueError(
                        "content-addressed bundle destination has conflicting bytes"
                    )
                if destination.read_bytes() != encoded:
                    raise ValueError(
                        "content-addressed bundle destination has conflicting bytes"
                    )
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
    return {
        "artifact": str(destination),
        "sha256": digest,
        "bytes": len(encoded),
        "records": bundle["corpus"]["records"],  # type: ignore[index]
        "format_version": _FORMAT_VERSION,
    }


def capture_bundle(
    datapoints: Sequence[DataPoint],
    *,
    endpoint: str,
    upstream_revision: str,
    source_provider: str,
    source_model: str,
    output_directory: str | Path,
    timeout_seconds: float = 120.0,
) -> dict[str, object]:
    """Capture every selected plan, validate it, then atomically publish once."""

    selected = list(datapoints)
    attacker = T3MP3STAttacker(
        endpoint=endpoint,
        upstream_revision=upstream_revision,
        source_provider=source_provider,
        source_model=source_model,
        timeout_seconds=timeout_seconds,
    )
    attacker.validate_capture_selection(selected)
    responses: list[dict[str, object]] = []
    captured_bytes = 0
    for datapoint in selected:
        response = attacker.capture_plan_response(datapoint)
        captured_bytes += len(
            json.dumps(
                response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        if captured_bytes > _MAX_OUTPUT_BYTES:
            raise ValueError(
                f"captured T3MP3ST responses exceed {_MAX_OUTPUT_BYTES} bytes"
            )
        responses.append(response)
    bundle = build_plan_bundle(
        selected,
        responses,
        upstream_revision=upstream_revision,
        source_provider=source_provider,
        source_model=source_model,
    )
    return write_content_addressed_bundle(bundle, output_directory)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture planning-only T3MP3ST responses for measured replay"
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--corpus", help="one run_matrix corpus arm id")
    selection.add_argument("--input", help="strict JSON array of DataPoint objects")
    parser.add_argument("--source-config", default="", help="run_matrix source config JSON")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--sample-seed", type=int, default=0)
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:3333/api/general/plan",
        help="prestarted literal-loopback T3MP3ST planning endpoint",
    )
    parser.add_argument("--upstream-revision", required=True)
    parser.add_argument("--source-provider", required=True)
    parser.add_argument("--source-model", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--out", required=True, help="output directory")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.input and args.source_config:
        parser.error("--source-config is valid only with --corpus")
    try:
        datapoints = (
            load_input_list(args.input)
            if args.input
            else load_corpus_selection(
                args.corpus,
                source_config=args.source_config,
                limit=args.limit,
                sample_seed=args.sample_seed,
            )
        )
        result = capture_bundle(
            datapoints,
            endpoint=args.endpoint,
            upstream_revision=args.upstream_revision,
            source_provider=args.source_provider,
            source_model=args.source_model,
            output_directory=args.out,
            timeout_seconds=args.timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001 - concise CLI boundary
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
