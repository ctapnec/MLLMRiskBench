#!/usr/bin/env python3
"""Pull one exact Ollama tag through the fixed local daemon.

This is the console's job subprocess: it emits bounded, normalized JSONL
progress and never accepts a remote endpoint or invokes a shell.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os.path
import shutil
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from experiments.rig_web_app.ollama_service import (
    validate_ollama_base_url,
    validate_ollama_pull_storage,
    validate_ollama_tag,
)
from ura.ollama_security import (
    DEFAULT_OLLAMA_URL,
    NoRedirect,
    OllamaProcessLock,
    literal_loopback_listener_owner,
    open_with_deadline,
    process_start_identity,
    remaining_seconds,
    set_response_timeout,
)


_MAX_EVENT_BYTES = 64 * 1024
_MAX_RUNTIME_SECONDS = 24 * 60 * 60

# Ollama currently reports ordinary layer progress roughly once per 64 KiB.
# Keep the raw-frame ceiling high enough for a 256 GiB model at that cadence,
# while bounding even a hostile loopback stream independently of the wall-clock
# deadline and per-frame byte cap. Persisted UI output has a much smaller bound
# and is coalesced below.
_NORMAL_PROGRESS_FRAME_BYTES = 64 * 1024
_MAX_NORMAL_MODEL_BYTES = 256 * 1024**3
# Leave bounded headroom for manifest/status frames and layers that report more
# frequently than the ordinary cadence.  The stream is still independently
# constrained by the 24-hour wall and per-frame byte ceiling.
_RAW_EVENT_OVERHEAD = 65_536
_MAX_RAW_EVENTS = (
    _MAX_NORMAL_MODEL_BYTES // _NORMAL_PROGRESS_FRAME_BYTES
    + _RAW_EVENT_OVERHEAD
)
_MAX_STALLED_RAW_EVENTS = 4_096
_MAX_EMITTED_EVENTS = 10_000
_PROGRESS_EMIT_BYTES = 32 * 1024**2
_PROGRESS_EMIT_PERCENT = 0.5
_PROGRESS_HEARTBEAT_SECONDS = 15.0


@dataclass
class _EmissionState:
    emitted: int = 0
    last_at: float | None = None
    last_status: str = ""
    last_digest: str = ""
    last_completed: int | None = None
    last_percent: float | None = None


def _emit_progress(
    progress: dict[str, object],
    state: _EmissionState,
    *,
    now: float,
    terminal: bool = False,
) -> bool:
    """Emit one bounded, coalesced UI row and reserve space for termination."""

    if terminal:
        if state.emitted >= _MAX_EMITTED_EVENTS:
            return False
    elif state.emitted >= _MAX_EMITTED_EVENTS - 1:
        return False

    status = str(progress.get("status", ""))
    digest = str(progress.get("digest", ""))
    completed = progress.get("completed")
    completed = completed if isinstance(completed, int) else None
    percent = progress.get("percent")
    percent = float(percent) if isinstance(percent, (int, float)) else None

    status_changed = status != state.last_status
    digest_changed = bool(digest) and digest != state.last_digest
    byte_advance = bool(
        completed is not None
        and (
            state.last_completed is None
            or completed - state.last_completed >= _PROGRESS_EMIT_BYTES
        )
    )
    percent_advance = bool(
        percent is not None
        and (
            state.last_percent is None
            or percent - state.last_percent >= _PROGRESS_EMIT_PERCENT
        )
    )
    heartbeat = bool(
        state.last_at is not None
        and now - state.last_at >= _PROGRESS_HEARTBEAT_SECONDS
    )
    complete_progress = percent is not None and percent >= 100.0
    if not (
        terminal
        or state.emitted == 0
        or status_changed
        or digest_changed
        or byte_advance
        or percent_advance
        or heartbeat
        or complete_progress
    ):
        return False

    print(
        json.dumps(progress, sort_keys=True, separators=(",", ":")),
        flush=True,
    )
    state.emitted += 1
    state.last_at = now
    state.last_status = status
    state.last_digest = digest
    if completed is not None:
        state.last_completed = completed
    if percent is not None:
        state.last_percent = percent
    return True


def _terminal_error(model: str, message: str) -> dict[str, object]:
    bounded = str(message).strip()
    if not bounded or len(bounded) > 1000 or any(ord(char) < 32 for char in bounded):
        bounded = "Ollama pull failed"
    return {
        "activity": "model_download",
        "at": _timestamp(),
        "error": bounded,
        "event": "ollama_pull_progress",
        "model": model,
        "status": "error",
    }


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _strict_event(raw: bytes) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite value {value!r}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except RecursionError as exc:
        raise ValueError("progress JSON nesting exceeds the parser limit") from exc
    if not isinstance(value, dict):
        raise ValueError("progress row is not an object")
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            raise ValueError("progress JSON nesting exceeds the limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _bounded_string(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        return ""
    return text


def _count(value: object) -> int | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 2**63 - 1
    ):
        return None
    return value


def _normalize_progress(model: str, row: dict[str, Any]) -> dict[str, object]:
    error = _bounded_string(row.get("error"), maximum=1000)
    status = _bounded_string(row.get("status"), maximum=256)
    if (
        "error" in row
        and row["error"] is not None
        and row["error"] != ""
        and not error
    ):
        raise ValueError("progress error is invalid")
    if error:
        raise RuntimeError(error)
    if not status:
        raise ValueError("progress row has no bounded status")
    completed = _count(row.get("completed"))
    total = _count(row.get("total"))
    if "completed" in row and completed is None:
        raise ValueError("progress completed bytes are invalid")
    if "total" in row and total is None:
        raise ValueError("progress total bytes are invalid")
    if completed is not None and total is not None and completed > total:
        raise ValueError("progress completed bytes exceed total bytes")
    output: dict[str, object] = {
        "activity": "model_download",
        "at": _timestamp(),
        "event": "ollama_pull_progress",
        "model": model,
        "status": status,
    }
    if completed is not None:
        output["completed"] = completed
    if total is not None:
        output["total"] = total
    if completed is not None and total:
        output["percent"] = round(completed * 100.0 / total, 2)
    digest = _bounded_string(row.get("digest"), maximum=256)
    if "digest" in row and not digest:
        raise ValueError("progress digest is invalid")
    if digest:
        output["digest"] = digest
    return output


def _verified_models_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("models-path must be a bounded absolute directory")
    path = Path(value.strip())
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("models-path must be a non-symlink absolute directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("models-path must already exist") from exc
    if not resolved.is_dir() or os.path.normcase(str(path)) != os.path.normcase(
        str(resolved)
    ):
        raise ValueError("models-path must be one exact resolved directory")
    return str(resolved)


def _progress_lines(
    response,
    *,
    deadline: float,
    socket_timeout: float,
    monotonic,
):
    """Yield bounded JSONL rows under one hard monotonic wall deadline."""

    reader = getattr(response, "read1", None)
    use_line_reader = not callable(reader)
    if use_line_reader:
        reader = response.readline
    pending = bytearray()
    while True:
        remaining = remaining_seconds(deadline, monotonic, label="Ollama pull")
        set_response_timeout(response, min(socket_timeout, remaining))
        chunk = reader(8192)
        remaining_seconds(deadline, monotonic, label="Ollama pull")
        if not isinstance(chunk, bytes):
            raise ValueError("progress stream returned non-byte data")
        if not chunk:
            break
        pending.extend(chunk)
        while b"\n" in pending:
            raw, _, remainder = pending.partition(b"\n")
            pending = bytearray(remainder)
            if len(raw) > _MAX_EVENT_BYTES:
                raise ValueError("progress row exceeds the byte limit")
            yield bytes(raw)
        if len(pending) > _MAX_EVENT_BYTES:
            raise ValueError("progress row exceeds the byte limit")
        # A fallback readline already returns one logical line. Keeping this
        # branch explicit makes injected test transports obey the same bound.
        if use_line_reader and pending:
            yield bytes(pending)
            pending.clear()
    if pending:
        yield bytes(pending)


def pull(
    model: str,
    *,
    models_path: str,
    owned_pid: int,
    owned_process_identity: str,
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout_seconds: float = 120.0,
    open_request=None,
    monotonic=time.monotonic,
    disk_usage=shutil.disk_usage,
    process_identity=process_start_identity,
    listener_owner=literal_loopback_listener_owner,
) -> int:
    """Stream one bounded local pull; return a process-style exit code."""

    tag = validate_ollama_tag(model)
    endpoint = validate_ollama_base_url(base_url)
    if not 1.0 <= float(timeout_seconds) <= 600.0:
        raise ValueError("timeout-seconds must be in [1, 600]")
    frozen_models_path = _verified_models_path(models_path)
    if isinstance(owned_pid, bool) or not isinstance(owned_pid, int) or owned_pid <= 0:
        raise ValueError("owned-pid must be a positive integer")
    if (
        not isinstance(owned_process_identity, str)
        or len(owned_process_identity) > 256
        or not owned_process_identity.startswith("linux-proc-v1:")
        or any(ord(char) < 33 or ord(char) > 126 for char in owned_process_identity)
    ):
        raise ValueError("owned-process-identity is invalid")
    body = json.dumps(
        {"model": tag, "stream": True}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/api/pull",
        data=body,
        headers={
            "Accept": "application/x-ndjson, application/json",
            "Content-Type": "application/json",
            "User-Agent": "ura-rig-web/ollama-pull",
        },
        method="POST",
    )
    if open_request is None:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        )
        open_request = opener.open
    started = monotonic()
    deadline = started + _MAX_RUNTIME_SECONDS
    success = False
    raw_events = 0
    stalled_events = 0
    last_raw_signature: tuple[object, ...] | None = None
    emission = _EmissionState()
    try:
        with OllamaProcessLock(
            base_url=endpoint,
            exclusive=True,
            deadline=deadline,
            monotonic=monotonic,
        ):
            if process_identity(owned_pid) != owned_process_identity:
                raise RuntimeError(
                    "owned Ollama process identity changed before pull admission"
                )
            parsed = urlsplit(endpoint)
            if listener_owner(
                owned_pid,
                parsed.hostname or "127.0.0.1",
                parsed.port or 11434,
            ) is not True:
                raise RuntimeError(
                    "owned Ollama process no longer owns the loopback listener"
                )
            validate_ollama_pull_storage(
                {"OLLAMA_MODELS": frozen_models_path},
                disk_usage=disk_usage,
            )
            response = open_with_deadline(
                open_request,
                request,
                deadline=deadline,
                monotonic=monotonic,
                maximum_timeout=min(
                    float(timeout_seconds),
                    float(_MAX_RUNTIME_SECONDS),
                ),
                label="Ollama pull",
            )
            with response:
                for raw in _progress_lines(
                    response,
                    deadline=deadline,
                    socket_timeout=float(timeout_seconds),
                    monotonic=monotonic,
                ):
                    if not raw.strip():
                        continue
                    raw_events += 1
                    if raw_events > _MAX_RAW_EVENTS:
                        raise ValueError("pull exceeded the raw progress frame limit")
                    progress = _normalize_progress(tag, _strict_event(raw))
                    completed = progress.get("completed")
                    total = progress.get("total")
                    if isinstance(completed, int) and isinstance(total, int):
                        validate_ollama_pull_storage(
                            {"OLLAMA_MODELS": frozen_models_path},
                            required_bytes=total - completed,
                            disk_usage=disk_usage,
                        )
                    signature = (
                        progress.get("status"),
                        progress.get("digest"),
                        completed,
                        total,
                    )
                    if signature == last_raw_signature:
                        stalled_events += 1
                        if stalled_events > _MAX_STALLED_RAW_EVENTS:
                            raise ValueError(
                                "pull progress stalled across too many raw frames"
                            )
                    else:
                        stalled_events = 0
                        last_raw_signature = signature
                    terminal = str(progress["status"]).strip().lower() == "success"
                    _emit_progress(
                        progress,
                        emission,
                        now=monotonic(),
                        terminal=terminal,
                    )
                    if terminal:
                        success = True
                        break
    except urllib.error.URLError:
        message = "loopback daemon unavailable"
        _emit_progress(
            _terminal_error(tag, message),
            emission,
            now=monotonic(),
            terminal=True,
        )
        print(f"ollama pull failed: {message}", file=sys.stderr)
        return 1
    except (TimeoutError, OSError, UnicodeError, ValueError, RuntimeError) as exc:
        _emit_progress(
            _terminal_error(tag, str(exc)),
            emission,
            now=monotonic(),
            terminal=True,
        )
        print(f"ollama pull failed: {exc}", file=sys.stderr)
        return 1
    if not success:
        message = "stream ended without success"
        _emit_progress(
            _terminal_error(tag, message),
            emission,
            now=monotonic(),
            terminal=True,
        )
        print(f"ollama pull failed: {message}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pull one model through the loopback Ollama daemon"
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--models-path", required=True)
    parser.add_argument("--owned-pid", type=int, required=True)
    parser.add_argument("--owned-process-identity", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return pull(
            args.model,
            models_path=args.models_path,
            owned_pid=args.owned_pid,
            owned_process_identity=args.owned_process_identity,
            base_url=args.base_url,
            timeout_seconds=args.timeout_seconds,
        )
    except ValueError as exc:
        print(f"ollama pull rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
