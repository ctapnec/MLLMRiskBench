"""Shared, fail-closed helpers for source-corpus converters.

Converters are part of the measurement boundary.  A missing corpus, malformed
source file, escaped media path, or absent media asset must therefore abort the
conversion instead of silently changing the evaluation denominator.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import mimetypes
import os
from pathlib import Path
from typing import Any, Optional

from ..data_models import (
    DataPoint,
    DialogTurn,
    ExpectedBehavior,
    MediaRef,
    RiskCategory,
    SourceEvaluationPolicy,
)
from ..taxonomy import refs_for

Rc = RiskCategory


class ConverterError(RuntimeError):
    """Base class for errors at the corpus-conversion trust boundary."""


class CorpusNotFoundError(ConverterError):
    """The declared corpus path (or a required companion file) is absent."""


class CorpusFormatError(ConverterError):
    """A source artifact exists but does not match the released schema."""


class MediaAssetError(ConverterError):
    """A media reference is missing, unsafe, or inconsistent with its modality."""


DEFAULT_MAX_CORPUS_FILE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_CORPUS_RECORDS = 1_000_000
DEFAULT_MAX_CORPUS_JSON_NODES = 2_000_000
DEFAULT_MAX_CORPUS_JSON_DEPTH = 64
DEFAULT_MAX_CSV_FIELD_CHARS = 16 * 1024 * 1024
DEFAULT_MAX_MEDIA_ASSET_BYTES = 25 * 1024 * 1024


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _strict_json_loads(text: str) -> Any:
    """Parse finite JSON and cap its aggregate structure before conversion."""

    def parse_float(number: str) -> float:
        value = float(number)
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value

    value = json.loads(
        text,
        object_pairs_hook=_object_without_duplicates,
        parse_float=parse_float,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"non-standard JSON constant {constant!r}")
        ),
    )
    nodes = 0
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > DEFAULT_MAX_CORPUS_JSON_NODES:
            raise ValueError(
                f"JSON exceeds {DEFAULT_MAX_CORPUS_JSON_NODES} value nodes"
            )
        if depth > DEFAULT_MAX_CORPUS_JSON_DEPTH:
            raise ValueError(
                f"JSON nesting exceeds {DEFAULT_MAX_CORPUS_JSON_DEPTH}"
            )
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _bounded_regular_file(path: Path, *, max_bytes: int) -> tuple[Path, int]:
    """Resolve a corpus file without symlinks and validate its declared size."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    candidate = Path(path).expanduser()
    try:
        absolute = candidate.absolute()
        # Reject every existing symlink component before resolution.  Corpus
        # paths are experiment inputs; accepting a mutable indirection here would
        # make their recorded identity raceable.
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            if current.is_symlink():
                raise CorpusFormatError(f"corpus file path contains a symlink: {current}")
        resolved = absolute.resolve(strict=True)
        stat = resolved.stat()
    except CorpusFormatError:
        raise
    except OSError as exc:
        raise CorpusNotFoundError(f"cannot read corpus file: {path}") from exc
    if not resolved.is_file():
        raise CorpusFormatError(f"corpus input is not a regular file: {resolved}")
    if stat.st_size > max_bytes:
        raise CorpusFormatError(
            f"corpus file exceeds the {max_bytes}-byte parser limit: {resolved}"
        )
    return resolved, stat.st_size


def _read_bounded_bytes(
    path: Path, *, max_bytes: int = DEFAULT_MAX_CORPUS_FILE_BYTES
) -> tuple[Path, bytes]:
    """Read a regular file through one descriptor and detect concurrent change."""

    resolved, expected_size = _bounded_regular_file(path, max_bytes=max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(resolved, flags)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = handle.read(min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise CorpusFormatError(
                        f"corpus file exceeds the {max_bytes}-byte parser limit: {resolved}"
                    )
                chunks.append(chunk)
            after = os.fstat(handle.fileno())
    except CorpusFormatError:
        raise
    except OSError as exc:
        raise CorpusNotFoundError(f"cannot read corpus file: {resolved}") from exc
    stable = (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size == expected_size == total
        and before.st_mtime_ns == after.st_mtime_ns
    )
    if not stable:
        raise CorpusFormatError(f"corpus file changed while being read: {resolved}")
    return resolved, b"".join(chunks)


def read_json(path: Path) -> Any:
    try:
        _, payload = _read_bounded_bytes(path)
        value = _strict_json_loads(payload.decode("utf-8"))
        if isinstance(value, (list, dict)) and len(value) > DEFAULT_MAX_CORPUS_RECORDS:
            raise ValueError(
                f"top-level JSON collection exceeds {DEFAULT_MAX_CORPUS_RECORDS} records"
            )
        return value
    except UnicodeDecodeError as exc:
        raise CorpusFormatError(f"corpus JSON is not valid UTF-8: {path}") from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        line = getattr(exc, "lineno", "?")
        column = getattr(exc, "colno", "?")
        raise CorpusFormatError(
            f"invalid JSON in {path} at line {line}, column {column}"
        ) from exc


def read_jsonl(path: Path) -> list[dict]:
    try:
        _, payload = _read_bounded_bytes(path)
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CorpusFormatError(f"corpus JSONL is not valid UTF-8: {path}") from exc
    rows: list[dict] = []
    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            row = _strict_json_loads(line)
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise CorpusFormatError(
                f"invalid JSONL record in {path} at line {line_number}"
            ) from exc
        if not isinstance(row, dict):
            raise CorpusFormatError(
                f"JSONL record in {path} at line {line_number} is not an object"
            )
        rows.append(row)
        if len(rows) > DEFAULT_MAX_CORPUS_RECORDS:
            raise CorpusFormatError(
                f"JSONL corpus exceeds the {DEFAULT_MAX_CORPUS_RECORDS}-record limit: {path}"
            )
    return rows


def read_csv(path: Path) -> list[dict]:
    try:
        _, payload = _read_bounded_bytes(path)
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusFormatError(f"corpus CSV is not valid UTF-8: {path}") from exc
    try:
        # StringIO preserves embedded newlines in quoted fields (the official
        # MOSSBench information.csv uses them extensively).
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if reader.fieldnames is None:
            return []
        if any(not name.strip() for name in reader.fieldnames) or len(
            set(reader.fieldnames)
        ) != len(reader.fieldnames):
            raise CorpusFormatError(
                f"CSV header contains blank or duplicate column names: {path}"
            )
        rows: list[dict] = []
        for row in reader:
            if any(
                isinstance(value, str) and len(value) > DEFAULT_MAX_CSV_FIELD_CHARS
                for value in row.values()
            ):
                raise CorpusFormatError(
                    f"CSV field exceeds the {DEFAULT_MAX_CSV_FIELD_CHARS}-character limit: {path}"
                )
            rows.append(row)
            if len(rows) > DEFAULT_MAX_CORPUS_RECORDS:
                raise CorpusFormatError(
                    f"CSV corpus exceeds the {DEFAULT_MAX_CORPUS_RECORDS}-record limit: {path}"
                )
        return rows
    except csv.Error as exc:
        raise CorpusFormatError(f"invalid CSV in {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a local asset without loading it at once."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_normalized_text_file(path: Path) -> str:
    """Hash pinned UTF-8 source text with Git-safe LF normalization."""

    _, payload = _read_bounded_bytes(path)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusFormatError(f"pinned source is not valid UTF-8: {path}") from exc
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def local_media(
    path: str | Path,
    root: Path,
    *,
    modality: str,
    max_bytes: int = DEFAULT_MAX_MEDIA_ASSET_BYTES,
) -> MediaRef:
    """Resolve, confine, verify, hash, and type a local media asset.

    ``root`` is the declared corpus/media root, not merely a path prefix.  Both
    paths are resolved (including symlinks), then containment is checked on the
    resolved paths.  This prevents ``..`` and symlink traversal while still
    accepting source manifests that use paths such as ``../images/x.jpg`` when
    the caller declares the enclosing split directory as the root.
    """
    if not str(path).strip():
        raise MediaAssetError("empty media path")
    try:
        resolved_root = Path(root).expanduser().resolve(strict=True)
    except OSError as exc:
        raise CorpusNotFoundError(f"declared media root does not exist: {root}") from exc
    if not resolved_root.is_dir():
        raise MediaAssetError(f"declared media root is not a directory: {resolved_root}")

    raw = Path(path).expanduser()
    candidate = raw if raw.is_absolute() else resolved_root / raw
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise MediaAssetError(f"media asset does not exist: {candidate}") from exc
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise MediaAssetError(
            f"media path escapes declared root {resolved_root}: {resolved}"
        ) from exc
    if not resolved.is_file():
        raise MediaAssetError(f"media asset is not a file: {resolved}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise MediaAssetError(
            f"media asset exceeds the {max_bytes}-byte scored-input limit: {resolved}"
        )

    mime = mimetypes.guess_type(resolved.name)[0]
    expected_prefix = {
        "image": "image/",
        "audio": "audio/",
        "video": "video/",
    }.get(modality)
    if mime is None:
        raise MediaAssetError(f"cannot determine MIME type for {resolved}")
    if expected_prefix is not None and not mime.startswith(expected_prefix):
        raise MediaAssetError(
            f"{resolved} has MIME {mime!r}, incompatible with {modality!r}"
        )
    return MediaRef(
        modality=modality,  # type: ignore[arg-type]
        path=str(resolved),
        sha256=sha256_file(resolved),
        mime=mime,
    )


def image(path: str | Path, root: Path) -> MediaRef:
    """Build a verified, content-addressed local image reference."""
    return local_media(path, root, modality="image")


def _validated_refs(risk: RiskCategory, extra_refs: Optional[list[str]]) -> list[str]:
    """Category defaults plus any converter-supplied narrow ``STANDARD:ID`` refs.

    The category default is deliberately conservative (see ``taxonomy.py``): it
    carries only standards that hold for every member of the category. A
    converter that can establish a narrower construct at the source/subtype level
    (for example unexpected code execution, memory poisoning, or a specific
    catastrophic hazard) passes it through ``extra_refs``. Each extra ref must be
    a ``STANDARD:ID`` string; duplicates are dropped while preserving order.
    """
    refs = list(refs_for(risk))
    for ref in extra_refs or []:
        if not isinstance(ref, str):
            raise ValueError(f"taxonomy ref must be a string, got {type(ref).__name__}")
        parts = ref.split(":")
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ValueError(f"taxonomy ref must be 'STANDARD:ID', got {ref!r}")
        if ref not in refs:
            refs.append(ref)
    return refs


def dp(
    *,
    id: str,
    source: str,
    modalities: list[str],
    risk: RiskCategory,
    expected: ExpectedBehavior,
    dialog: list[DialogTurn],
    payload_text: Optional[str] = None,
    payload_code: Optional[str] = None,
    media: Optional[list[MediaRef]] = None,
    risk_subtype: Optional[str] = None,
    attack_family: Optional[str] = None,
    turns: int = 1,
    is_agentic: bool = False,
    meta: Optional[dict] = None,
    extra_refs: Optional[list[str]] = None,
    source_policy: Optional[SourceEvaluationPolicy] = None,
) -> DataPoint:
    """Construct a DataPoint with taxonomy references filled consistently.

    ``extra_refs`` lets a converter attach narrow, source-justified standard ids
    (``STANDARD:ID``) beyond the conservative category default; see
    :func:`_validated_refs`.
    """
    return DataPoint(
        id=id,
        source=source,
        modalities=modalities,
        dialog_history=dialog,
        payload_text=payload_text,
        payload_code=payload_code,
        media=media or [],
        risk_category=risk,
        risk_subtype=risk_subtype,
        expected_behavior=expected,
        taxonomy_refs=_validated_refs(risk, extra_refs),
        attack_family=attack_family,
        turns=turns,
        is_agentic=is_agentic,
        meta=meta or {},
        source_policy=source_policy,
    )


def missing(name: str, path: Path) -> list[DataPoint]:
    """Raise a typed error; retained as a small migration helper for modules."""
    raise CorpusNotFoundError(f"{name}: corpus path not found: {path}")


__all__ = [
    "ConverterError",
    "CorpusNotFoundError",
    "CorpusFormatError",
    "MediaAssetError",
    "DEFAULT_MAX_CORPUS_FILE_BYTES",
    "DEFAULT_MAX_CORPUS_JSON_DEPTH",
    "DEFAULT_MAX_CORPUS_JSON_NODES",
    "DEFAULT_MAX_CORPUS_RECORDS",
    "DEFAULT_MAX_MEDIA_ASSET_BYTES",
    "DataPoint",
    "DialogTurn",
    "MediaRef",
    "Rc",
    "dp",
    "image",
    "local_media",
    "missing",
    "read_csv",
    "read_json",
    "read_jsonl",
    "sha256_file",
    "sha256_normalized_text_file",
]
