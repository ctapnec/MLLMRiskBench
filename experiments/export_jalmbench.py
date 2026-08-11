"""Stream the official JALMBench Parquet release into URA's file manifest.

The upstream Hugging Face release stores audio bytes inside Parquet rows.  The
runtime converter intentionally uses ordinary content-addressed files, so this
one-time, offline preparation step extracts only audio-bearing rows and records
their exact source fields.  It makes no model or evaluator calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from ura.converters._common import media_signature_matches


SCHEMA_VERSION = "ura-jalmbench-parquet-export/1"
_AUDIO_MIMES = {
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/mpeg": ".mp3",
    "audio/flac": ".flac",
    "audio/ogg": ".ogg",
    "audio/mp4": ".m4a",
    "audio/x-m4a": ".m4a",
    "audio/aac": ".aac",
}
_MAX_AUDIO_BYTES = 25 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parquet_files(source: Path) -> tuple[Path, list[Path]]:
    if source.is_symlink():
        raise ValueError("JALMBench source must not be a symlink")
    resolved = source.resolve(strict=True)
    if resolved.is_file():
        if resolved.suffix.lower() != ".parquet":
            raise ValueError("JALMBench source file must be Parquet")
        return resolved.parent, [resolved]
    if not resolved.is_dir():
        raise ValueError("JALMBench source must be a Parquet file or directory")
    files = sorted(resolved.rglob("*.parquet"))
    if not files:
        raise ValueError("JALMBench source contains no Parquet files")
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("JALMBench Parquet members must be regular non-symlink files")
    return resolved, files


def _rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - optional analysis dependency
        raise RuntimeError(
            "JALMBench Parquet export requires pyarrow; install .[analysis]"
        ) from exc
    parquet = pq.ParquetFile(path)
    # A row group may be very large in an upstream release.  Iterate in small
    # record batches so the offline bridge does not materialize it wholesale.
    for batch in parquet.iter_batches(batch_size=128):
        for row in batch.to_pylist():
            if not isinstance(row, dict):
                raise ValueError(f"non-object Parquet row in {path}")
            yield row


def _audio_bytes(row: dict[str, Any]) -> tuple[bytes, str | None] | None:
    audio = row.get("audio")
    name: str | None = None
    payload: Any = audio
    if isinstance(audio, dict):
        payload = audio.get("bytes")
        source_name = audio.get("path")
        name = source_name if isinstance(source_name, str) else None
    if payload is None:
        return None
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    if isinstance(payload, bytearray):
        payload = bytes(payload)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("JALMBench audio field is neither bytes nor a supported struct")
    if len(payload) > _MAX_AUDIO_BYTES:
        raise ValueError("JALMBench audio sample exceeds the 25 MiB runtime bound")
    return payload, name


def _mime_and_suffix(payload: bytes, source_name: str | None) -> tuple[str, str]:
    guessed = mimetypes.guess_type(source_name or "")[0]
    candidates = ([guessed] if guessed in _AUDIO_MIMES else []) + list(_AUDIO_MIMES)
    for mime in candidates:
        if media_signature_matches(payload, mime):
            return mime, _AUDIO_MIMES[mime]
    raise ValueError("JALMBench audio bytes have no supported audio signature")


def _safe_name(value: object) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-._")
    return (safe or "row")[:80]


def export_release(
    source: Path,
    out: Path,
    *,
    max_records: int = 300_000,
    max_total_bytes: int = 600_000_000_000,
) -> dict[str, Any]:
    if max_records < 1 or max_total_bytes < 1:
        raise ValueError("export bounds must be positive")
    root, files = _parquet_files(source)
    if out.exists():
        raise ValueError("JALMBench export destination must not already exist")
    out.mkdir(parents=True)
    manifest = out / "jalmbench.jsonl"
    audio_root = out / "audio"
    audio_root.mkdir()

    record_count = 0
    skipped_text_only = 0
    total_audio_bytes = 0
    source_files: list[dict[str, Any]] = []
    with manifest.open("x", encoding="utf-8", newline="\n") as handle:
        for parquet_path in files:
            relative = parquet_path.relative_to(root).as_posix()
            subset = parquet_path.stem
            source_row_count = 0
            for row_index, row in enumerate(_rows(parquet_path)):
                source_row_count += 1
                extracted = _audio_bytes(row)
                if extracted is None:
                    skipped_text_only += 1
                    continue
                payload, source_name = extracted
                record_count += 1
                total_audio_bytes += len(payload)
                if record_count > max_records or total_audio_bytes > max_total_bytes:
                    raise ValueError("JALMBench export exceeds configured bounds")
                mime, suffix = _mime_and_suffix(payload, source_name)
                digest = hashlib.sha256(payload).hexdigest()
                source_id = row.get("id", row_index)
                filename = f"{_safe_name(source_id)}-{digest[:16]}{suffix}"
                subset_dir = audio_root / _safe_name(relative.rsplit("/", 1)[0] or subset)
                subset_dir.mkdir(parents=True, exist_ok=True)
                audio_path = subset_dir / filename
                with audio_path.open("xb") as audio_handle:
                    audio_handle.write(payload)
                exported = {
                    key: value
                    for key, value in row.items()
                    if key != "audio" and isinstance(value, (str, int, float, bool, type(None)))
                }
                exported.update({
                    "id": f"{subset}:{source_id}:{row_index}",
                    "audio_path": audio_path.relative_to(out).as_posix(),
                    "audio_mime": mime,
                    "audio_sha256": digest,
                    "subset": subset,
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
                "rows": source_row_count,
            })
    if record_count == 0:
        raise ValueError("JALMBench export found no audio-bearing rows")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "records": record_count,
        "skipped_text_only_rows": skipped_text_only,
        "audio_bytes": total_audio_bytes,
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
        description="Export official JALMBench Parquet audio into a URA manifest"
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-records", type=int, default=300_000)
    parser.add_argument("--max-total-bytes", type=int, default=600_000_000_000)
    args = parser.parse_args(argv)
    try:
        summary = export_release(
            args.source,
            args.out,
            max_records=args.max_records,
            max_total_bytes=args.max_total_bytes,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"JALMBench export failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "written", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
