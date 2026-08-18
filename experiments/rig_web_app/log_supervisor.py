"""Detached, bounded, privacy-preserving job-log capture.

The Web console must be able to exit while a job keeps running.  A controller
thread reading ``Popen.PIPE`` cannot provide that contract: closing the console
either strands the child's writer or blocks while the reader waits for EOF.
This tiny helper is instead launched as an independent process for each stream.
It owns the read end until the measured child exits, redacts in flight, and
writes only bounded bytes to the durable log.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Any, Mapping, Sequence


MAX_DURABLE_JOB_LOG_BYTES = 16 * 1024 * 1024
LOG_PIPE_READ_BYTES = 64 * 1024
LOG_TRUNCATED_MARKER = b"\n[durable job log truncated at the configured byte limit]\n"
_PATTERNS_ENV = "URA_PRIVATE_LOG_REDACTIONS_B64"
_MAX_PATTERN_ENV_BYTES = 24 * 1024
_MAX_DECODED_PATTERN_BYTES = 512 * 1024

# Capture the real constructor when this module is imported.  Lifecycle tests
# replace ``lifecycle.subprocess.Popen`` with a fake measured child; the
# detached privacy supervisor must remain a real, independent process.
_DETACHED_POPEN = subprocess.Popen


def redact_stream_prefix(
    data: bytes,
    patterns: tuple[bytes, ...],
    *,
    eof: bool,
) -> tuple[bytes, bytes]:
    """Redact one safe stream prefix, retaining cross-chunk match tails."""

    max_pattern = max((len(item) for item in patterns), default=1)
    safe_end = len(data) if eof else max(0, len(data) - max_pattern + 1)
    folded_data = data.lower()
    folded_patterns = tuple((item, item.lower()) for item in patterns)
    output = bytearray()
    offset = 0
    while offset < safe_end:
        match = next(
            (
                item
                for item, folded in folded_patterns
                if folded_data.startswith(folded, offset)
            ),
            None,
        )
        if match is not None:
            output.extend(b"<redacted-private>")
            offset += len(match)
        else:
            output.append(data[offset])
            offset += 1
    return bytes(output), data[offset:]


def bounded_log_write(
    sink: Any,
    payload: bytes,
    *,
    written: int,
    truncated: bool,
    max_bytes: int = MAX_DURABLE_JOB_LOG_BYTES,
) -> tuple[int, bool]:
    """Write at most ``max_bytes``, appending one deterministic marker."""

    if truncated or not payload:
        return written, truncated
    payload_limit = max(0, max_bytes - len(LOG_TRUNCATED_MARKER))
    remaining = max(0, payload_limit - written)
    if len(payload) <= remaining:
        sink.write(payload)
        return written + len(payload), False
    if remaining:
        sink.write(payload[:remaining])
        written += remaining
    sink.write(LOG_TRUNCATED_MARKER)
    return written + len(LOG_TRUNCATED_MARKER), True


def capture_stream(
    source: Any,
    sink: Any,
    patterns: tuple[bytes, ...],
    *,
    max_bytes: int = MAX_DURABLE_JOB_LOG_BYTES,
) -> None:
    """Drain one stream to EOF without ever writing unredacted durable bytes."""

    pending = b""
    written = 0
    truncated = False
    while True:
        chunk = source.read(LOG_PIPE_READ_BYTES)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        output, pending = redact_stream_prefix(
            pending + bytes(chunk), patterns, eof=False
        )
        written, truncated = bounded_log_write(
            sink,
            output,
            written=written,
            truncated=truncated,
            max_bytes=max_bytes,
        )
    output, pending = redact_stream_prefix(pending, patterns, eof=True)
    if pending:  # pragma: no cover - EOF consumes the complete buffer
        output += pending
    bounded_log_write(
        sink,
        output,
        written=written,
        truncated=truncated,
        max_bytes=max_bytes,
    )
    sink.flush()


def _encoded_patterns(patterns: Sequence[bytes]) -> str:
    payload = json.dumps(
        [base64.b64encode(item).decode("ascii") for item in patterns],
        separators=(",", ":"),
    ).encode("ascii")
    encoded = base64.b64encode(zlib.compress(payload, level=9)).decode("ascii")
    if len(encoded) > _MAX_PATTERN_ENV_BYTES:
        raise ValueError("private log redaction set exceeds the safe launch bound")
    return encoded


def _decoded_patterns() -> tuple[bytes, ...]:
    encoded = os.environ.pop(_PATTERNS_ENV, "")
    if not encoded or len(encoded) > _MAX_PATTERN_ENV_BYTES:
        raise ValueError("private log redaction set is missing or oversized")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        decoder = zlib.decompressobj()
        payload = decoder.decompress(
            compressed,
            _MAX_DECODED_PATTERN_BYTES + 1,
        )
        if (
            len(payload) > _MAX_DECODED_PATTERN_BYTES
            or decoder.unconsumed_tail
            or not decoder.eof
        ):
            raise ValueError
        values = json.loads(payload.decode("ascii"))
        if not isinstance(values, list):
            raise ValueError
        patterns = tuple(
            base64.b64decode(value, validate=True)
            for value in values
            if isinstance(value, str)
        )
    except (UnicodeError, ValueError, TypeError, zlib.error) as exc:
        raise ValueError("private log redaction set is malformed") from exc
    if len(patterns) != len(values) or any(not item for item in patterns):
        raise ValueError("private log redaction set is malformed")
    return patterns


def _supervisor_environment(
    base_env: Mapping[str, str],
    patterns: tuple[bytes, ...],
) -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
    by_upper = {str(name).upper(): str(value) for name, value in base_env.items()}
    child = {
        name: by_upper[name]
        for name in sorted(allowed)
        if name in by_upper and "\0" not in by_upper[name]
    }
    child[_PATTERNS_ENV] = _encoded_patterns(patterns)
    child["PYTHONUNBUFFERED"] = "1"
    return child


def start_detached_redactors(
    *,
    stdout_path: Path,
    stderr_path: Path,
    patterns: tuple[bytes, ...],
    base_env: Mapping[str, str],
    cwd: Path,
) -> tuple[tuple[Any, Any], tuple[Any, ...]]:
    """Launch independent stdout/stderr drains and return their write ends."""

    if not stdout_path.is_absolute() or not stderr_path.is_absolute():
        raise ValueError("durable log paths must be absolute")
    env = _supervisor_environment(base_env, patterns)
    processes: list[Any] = []
    writers: list[Any] = []
    try:
        for sink in (stdout_path, stderr_path):
            kwargs: dict[str, Any] = {}
            if os.name == "nt":
                kwargs["creationflags"] = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
            else:
                kwargs["start_new_session"] = True
            process = _DETACHED_POPEN(  # noqa: S603 - fixed local module argv
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--sink",
                    str(sink),
                    "--max-bytes",
                    str(MAX_DURABLE_JOB_LOG_BYTES),
                ],
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                **kwargs,
            )
            if process.stdin is None:  # pragma: no cover - PIPE invariant
                raise OSError("detached log supervisor has no input pipe")
            processes.append(process)
            writers.append(process.stdin)
        return (writers[0], writers[1]), tuple(processes)
    except BaseException:
        for writer in writers:
            try:
                writer.close()
            except (AttributeError, OSError, ValueError):
                pass
        for process in processes:
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        raise


def _open_safe_sink(raw: str) -> Any:
    """Open one direct log inode once, without a check/open link race."""

    path = Path(raw)
    if not path.is_absolute() or path.name not in {"stdout.log", "stderr.log"}:
        raise ValueError("durable log sink is invalid")
    descriptor: int | None = None
    try:
        parent = path.parent
        parent_info = parent.lstat()
        if (
            parent.is_symlink()
            or parent.is_junction()
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent.resolve(strict=True) != parent
        ):
            raise ValueError("durable log parent must be one resolved directory")
        info = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or path.resolve(strict=True) != path
        ):
            raise ValueError("durable log sink must be one direct regular file")
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = path.lstat()
        identity = (info.st_dev, info.st_ino, info.st_mode)
        if (
            not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
            or path.is_junction()
            or opened.st_nlink != 1
            or after.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_mode) != identity
            or (after.st_dev, after.st_ino, after.st_mode) != identity
        ):
            raise ValueError("durable log sink changed while being opened")
        stream = os.fdopen(descriptor, "ab", buffering=0, closefd=True)
        descriptor = None
        return stream
    except OSError as exc:
        raise ValueError("durable log sink cannot be opened safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detached Rig Web log redactor")
    parser.add_argument("--sink", required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    if not 1024 <= args.max_bytes <= MAX_DURABLE_JOB_LOG_BYTES:
        raise SystemExit("invalid durable log byte bound")
    try:
        patterns = _decoded_patterns()
        with _open_safe_sink(args.sink) as output:
            capture_stream(
                sys.stdin.buffer,
                output,
                patterns,
                max_bytes=args.max_bytes,
            )
    except (OSError, TypeError, ValueError):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
