"""Export the official VLSBench Parquet release for the URA converter.

The Hugging Face release embeds image bytes in Parquet.  URA deliberately
converts ordinary content-addressed media files, so this bounded offline bridge
writes those bytes plus a JSONL manifest.  It makes no model or evaluator calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.converters._common import media_signature_matches  # noqa: E402


SCHEMA_VERSION = "ura-vlsbench-parquet-export/1"
_IMAGE_MIMES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
}
_MAX_IMAGE_BYTES = 25 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parquet_files(source: Path) -> tuple[Path, list[Path]]:
    if source.is_symlink():
        raise ValueError("VLSBench source must not be a symlink")
    resolved = source.resolve(strict=True)
    if resolved.is_file():
        if resolved.suffix.lower() != ".parquet":
            raise ValueError("VLSBench source file must be Parquet")
        return resolved.parent, [resolved]
    if not resolved.is_dir():
        raise ValueError("VLSBench source must be a Parquet file or directory")
    files = sorted(resolved.rglob("*.parquet"))
    if not files:
        raise ValueError("VLSBench source contains no Parquet files")
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("VLSBench Parquet members must be regular non-symlink files")
    return resolved, files


def _rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - optional analysis dependency
        raise RuntimeError(
            "VLSBench Parquet export requires pyarrow; install .[analysis]"
        ) from exc
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches(batch_size=128):
        for row in batch.to_pylist():
            if not isinstance(row, dict):
                raise ValueError(f"non-object Parquet row in {path}")
            yield row


def _image_bytes(row: dict[str, Any]) -> bytes:
    image = row.get("image")
    payload: Any = image.get("bytes") if isinstance(image, dict) else image
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    if isinstance(payload, bytearray):
        payload = bytes(payload)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("VLSBench image field lacks embedded bytes")
    if len(payload) > _MAX_IMAGE_BYTES:
        raise ValueError("VLSBench image sample exceeds the 25 MiB runtime bound")
    return payload


def _mime_and_suffix(payload: bytes) -> tuple[str, str]:
    for mime, suffix in _IMAGE_MIMES.items():
        if media_signature_matches(payload, mime):
            return mime, suffix
    raise ValueError("VLSBench image bytes have no supported image signature")


def _safe_name(value: object) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-._")
    return (safe or "row")[:80]


def export_release(
    source: Path,
    out: Path,
    *,
    max_records: int = 10_000,
    max_total_bytes: int = 100_000_000_000,
) -> dict[str, Any]:
    if max_records < 1 or max_total_bytes < 1:
        raise ValueError("export bounds must be positive")
    root, files = _parquet_files(source)
    if out.exists():
        raise ValueError("VLSBench export destination must not already exist")
    out.mkdir(parents=True)
    manifest = out / "vlsbench.jsonl"
    image_root = out / "images"
    image_root.mkdir()

    record_count = 0
    total_image_bytes = 0
    source_files: list[dict[str, Any]] = []
    with manifest.open("x", encoding="utf-8", newline="\n") as handle:
        for parquet_path in files:
            relative = parquet_path.relative_to(root).as_posix()
            source_rows = 0
            for row_index, row in enumerate(_rows(parquet_path)):
                source_rows += 1
                payload = _image_bytes(row)
                record_count += 1
                total_image_bytes += len(payload)
                if record_count > max_records or total_image_bytes > max_total_bytes:
                    raise ValueError("VLSBench export exceeds configured bounds")
                mime, suffix = _mime_and_suffix(payload)
                digest = hashlib.sha256(payload).hexdigest()
                source_id = row.get("instruction_id", row.get("id", row_index))
                filename = f"{_safe_name(source_id)}-{digest[:16]}{suffix}"
                image_path = image_root / filename
                with image_path.open("xb") as image_handle:
                    image_handle.write(payload)
                exported = {
                    key: value
                    for key, value in row.items()
                    if key not in {"image", "image_path"}
                    and isinstance(value, (str, int, float, bool, type(None)))
                }
                exported.update({
                    "image_path": image_path.relative_to(out).as_posix(),
                    "image_mime": mime,
                    "image_sha256": digest,
                    "source_parquet": relative,
                    "source_row_index": row_index,
                })
                handle.write(
                    json.dumps(exported, ensure_ascii=False, sort_keys=True, allow_nan=False)
                    + "\n"
                )
            source_files.append({
                "file": relative,
                "sha256": _sha256(parquet_path),
                "bytes": parquet_path.stat().st_size,
                "rows": source_rows,
            })
    if record_count == 0:
        raise ValueError("VLSBench export found no image-bearing rows")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "records": record_count,
        "image_bytes": total_image_bytes,
        "manifest": {
            "file": manifest.name,
            "sha256": _sha256(manifest),
            "bytes": manifest.stat().st_size,
        },
        "source_files": source_files,
    }
    with (out / "export-summary.json").open(
        "x", encoding="utf-8", newline="\n"
    ) as handle:
        json.dump(summary, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export official VLSBench Parquet images into a URA manifest"
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-records", type=int, default=10_000)
    parser.add_argument("--max-total-bytes", type=int, default=100_000_000_000)
    args = parser.parse_args(argv)
    try:
        summary = export_release(
            args.source,
            args.out,
            max_records=args.max_records,
            max_total_bytes=args.max_total_bytes,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"VLSBench export failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "written", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
