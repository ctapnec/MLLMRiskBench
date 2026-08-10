"""Shared, fail-closed helpers for source-corpus converters.

Converters are part of the measurement boundary.  A missing corpus, malformed
source file, escaped media path, or absent media asset must therefore abort the
conversion instead of silently changing the evaluation denominator.
"""
from __future__ import annotations

import csv
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any, Optional

from ..data_models import DataPoint, DialogTurn, ExpectedBehavior, MediaRef, RiskCategory
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


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CorpusNotFoundError(f"cannot read corpus file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CorpusFormatError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}"
        ) from exc


def read_jsonl(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CorpusNotFoundError(f"cannot read corpus file: {path}") from exc
    rows: list[dict] = []
    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CorpusFormatError(
                f"invalid JSONL record in {path} at line {line_number}"
            ) from exc
        if not isinstance(row, dict):
            raise CorpusFormatError(
                f"JSONL record in {path} at line {line_number} is not an object"
            )
        rows.append(row)
    return rows


def read_csv(path: Path) -> list[dict]:
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except OSError as exc:
        raise CorpusNotFoundError(f"cannot read corpus file: {path}") from exc


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a local asset without loading it at once."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_media(
    path: str | Path,
    root: Path,
    *,
    modality: str,
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
    )


def missing(name: str, path: Path) -> list[DataPoint]:
    """Raise a typed error; retained as a small migration helper for modules."""
    raise CorpusNotFoundError(f"{name}: corpus path not found: {path}")


__all__ = [
    "ConverterError",
    "CorpusNotFoundError",
    "CorpusFormatError",
    "MediaAssetError",
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
]
