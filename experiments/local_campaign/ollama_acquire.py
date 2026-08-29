#!/usr/bin/env python3
"""Resumably acquire and load-smoke an explicit Ollama model roster."""

from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Iterable
import urllib.error
import urllib.request

from experiments.rig_web_app.ollama_service import (
    validate_ollama_base_url,
    validate_ollama_tag,
)
from ura.ollama_security import DEFAULT_OLLAMA_URL
from ura.strict_json import strict_json_loads


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_FAILURE_SCHEMA = "ura-ollama-acquisition-failure/1"
_RETRY_ERRORS = (
    http.client.HTTPException,
    OSError,
    TimeoutError,
    UnicodeError,
    ValueError,
    urllib.error.URLError,
)
_PULL_RETRY_ERRORS = (*_RETRY_ERRORS, RuntimeError)
_PULL_STALL_SECONDS = 15 * 60


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def request(
    base_url: str,
    path: str,
    payload: object | None = None,
    *,
    timeout: float,
):
    data = None if payload is None else canonical(payload)
    req = urllib.request.Request(
        base_url + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="GET" if data is None else "POST",
    )
    return OPENER.open(req, timeout=timeout)


def append(path: Path, value: object) -> None:
    with path.open("ab") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def _write_create_only(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _event_rows(path: Path) -> list[dict[str, Any]]:
    payload = path.read_bytes()
    if not payload.endswith(b"\n") or b"\r" in payload or b"\0" in payload:
        raise ValueError("existing acquisition events are not canonical JSONL")
    rows: list[dict[str, Any]] = []
    for raw in payload[:-1].split(b"\n"):
        value = strict_json_loads(raw)
        if not isinstance(value, dict):
            raise ValueError("existing acquisition event is not an object")
        rows.append(value)
    if not rows:
        raise ValueError("existing acquisition event ledger is empty")
    return rows


def _safe_reason(exc: BaseException) -> str:
    text = str(exc).lower()
    if "max retries exceeded" in text:
        return "ollama_internal_retry_exhausted"
    if "connection refused" in text or "temporary failure" in text:
        return "network_unavailable"
    if isinstance(exc, (TimeoutError, urllib.error.URLError)):
        return "transport_unavailable"
    return "pull_attempt_failed"


def _publish_terminal_failure(
    out_dir: Path,
    models: Iterable[str],
    exc: BaseException,
) -> bool:
    """Publish a terminal only for an acquisition ledger owned by this request."""

    if not out_dir.is_absolute() or out_dir.is_symlink() or not out_dir.is_dir():
        return False
    try:
        selected = [validate_ollama_tag(model) for model in models]
        rows = _event_rows(out_dir / "events.jsonl")
    except (OSError, UnicodeError, ValueError):
        return False
    if (
        not rows
        or rows[0].get("event") != "start"
        or rows[0].get("models") != selected
        or (out_dir / ".exit").exists()
    ):
        return False
    _write_create_only(
        out_dir / "failure.json",
        canonical(
            {
                "error_type": type(exc).__name__,
                "reason_code": _safe_reason(exc),
                "schema": _FAILURE_SCHEMA,
                "status": "failed",
            }
        ),
    )
    _write_create_only(out_dir / ".exit", b"1\n")
    return True


def _json_response(response: Any) -> dict[str, Any]:
    with response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("Ollama response is not an object")
    return value


def _pull_once(
    response: Any,
    *,
    model: str,
    monotonic: Callable[[], float] = time.monotonic,
    stall_seconds: float = _PULL_STALL_SECONDS,
) -> None:
    final: dict[str, Any] | None = None
    last_progress_at = monotonic()
    last_progress: tuple[object, object] | None = None
    with response:
        for raw in response:
            value = strict_json_loads(raw)
            if not isinstance(value, dict):
                raise ValueError("Ollama pull event is not an object")
            final = value
            error = value.get("error")
            if isinstance(error, str) and error:
                raise RuntimeError(f"{model}: {error}")
            progress = (value.get("status"), value.get("completed"))
            now = monotonic()
            if progress != last_progress:
                last_progress = progress
                last_progress_at = now
            elif now - last_progress_at >= stall_seconds:
                raise TimeoutError(f"{model}: pull stream made no progress")
    if final is None or final.get("status") != "success":
        raise ValueError(f"{model}: pull did not finish successfully")


def _tags(
    base_url: str,
    request_fn: Callable[..., Any],
    *,
    timeout: float,
) -> dict[str, dict[str, Any]]:
    value = _json_response(request_fn(base_url, "/api/tags", timeout=timeout))
    rows = value.get("models")
    if not isinstance(rows, list):
        raise ValueError("Ollama tags response is malformed")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ValueError("Ollama tags row is malformed")
        name = str(row["name"])
        if name in result:
            raise ValueError("Ollama tags response contains a duplicate model")
        result[name] = row
    return result


def _sleep_delay(
    *,
    attempt: int,
    initial: float,
    maximum: float,
) -> float:
    return min(maximum, initial * (2 ** min(attempt - 1, 4)))


def _retry_call(
    action: Callable[[], Any],
    *,
    label: str,
    deadline: float,
    retry_delay_seconds: float,
    max_retry_delay_seconds: float,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    on_retry: Callable[[int, float, BaseException], None] | None = None,
) -> Any:
    attempt = 0
    while True:
        if monotonic() >= deadline:
            raise TimeoutError(f"{label}: acquisition deadline expired")
        attempt += 1
        try:
            return action()
        except _RETRY_ERRORS as exc:
            delay = _sleep_delay(
                attempt=attempt,
                initial=retry_delay_seconds,
                maximum=max_retry_delay_seconds,
            )
            if monotonic() + delay >= deadline:
                raise TimeoutError(f"{label}: acquisition deadline expired") from exc
            if on_retry is not None:
                on_retry(attempt, delay, exc)
            sleep(delay)


def acquire(
    *,
    out_dir: Path,
    models: Iterable[str],
    resume: bool,
    base_url: str = DEFAULT_OLLAMA_URL,
    retry_delay_seconds: float = 30.0,
    max_retry_delay_seconds: float = 300.0,
    deadline_seconds: float = 7 * 24 * 60 * 60,
    request_fn: Callable[..., Any] = request,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    endpoint = validate_ollama_base_url(base_url)
    selected = [validate_ollama_tag(model) for model in models]
    if not selected or len(selected) > 16 or len(set(selected)) != len(selected):
        raise ValueError("models must contain 1 to 16 unique Ollama tags")
    if not 0 < retry_delay_seconds <= max_retry_delay_seconds <= 3600:
        raise ValueError("retry delays are invalid")
    if not 60 <= deadline_seconds <= 30 * 24 * 60 * 60:
        raise ValueError("deadline-seconds must be in [60, 2592000]")
    if not out_dir.is_absolute() or out_dir.is_symlink():
        raise ValueError("out-dir must be one absolute non-symlink path")

    events = out_dir / "events.jsonl"
    deadline = monotonic() + deadline_seconds
    if resume:
        if not out_dir.is_dir() or not events.is_file() or events.is_symlink():
            raise ValueError("resume requires an existing acquisition event ledger")
        if (out_dir / ".exit").exists() or (out_dir / "selected-roster.json").exists():
            raise ValueError("a terminal acquisition cannot be resumed")
        rows = _event_rows(events)
        start = rows[0]
        if start.get("event") != "start" or start.get("models") != selected:
            raise ValueError("resume model roster differs from the retained ledger")
        completed = {
            str(row.get("model"))
            for row in rows
            if row.get("event") == "load_smoke_complete" and row.get("model") in selected
        }
        append(
            events,
            {
                "completed_models": [model for model in selected if model in completed],
                "event": "resume",
                "models": selected,
            },
        )
    else:
        if out_dir.exists():
            raise ValueError("new acquisition out-dir must be absent")
        version = _retry_call(
            lambda: _json_response(request_fn(endpoint, "/api/version", timeout=30.0)),
            label="Ollama version discovery",
            deadline=deadline,
            retry_delay_seconds=retry_delay_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
            sleep=sleep,
            monotonic=monotonic,
        )
        out_dir.mkdir(mode=0o700, parents=False)
        append(events, {"event": "start", "models": selected, "version": version})
        completed = set()

    for model in selected:
        if model in completed:
            continue
        append(events, {"event": "pull_start", "model": model})
        attempt = 0
        while True:
            if monotonic() >= deadline:
                raise TimeoutError(f"{model}: acquisition deadline expired")
            attempt += 1
            append(events, {"attempt": attempt, "event": "pull_attempt", "model": model})
            try:
                installed = _tags(endpoint, request_fn, timeout=30.0)
                if model in installed:
                    append(events, {"event": "pull_already_present", "model": model})
                    break
                _pull_once(
                    request_fn(
                        endpoint,
                        "/api/pull",
                        {"model": model, "stream": True},
                        timeout=600.0,
                    ),
                    model=model,
                    monotonic=monotonic,
                )
                append(events, {"event": "pull_complete", "model": model})
                break
            except _PULL_RETRY_ERRORS as exc:
                delay = _sleep_delay(
                    attempt=attempt,
                    initial=retry_delay_seconds,
                    maximum=max_retry_delay_seconds,
                )
                if monotonic() + delay >= deadline:
                    raise TimeoutError(f"{model}: acquisition deadline expired") from exc
                append(
                    events,
                    {
                        "attempt": attempt,
                        "delay_seconds": delay,
                        "event": "pull_retry",
                        "model": model,
                        "reason_code": _safe_reason(exc),
                    },
                )
                sleep(delay)

        started = monotonic()
        generated = _retry_call(
            lambda: _json_response(
                request_fn(
                    endpoint,
                    "/api/generate",
                    {
                        "model": model,
                        "prompt": "Reply with exactly OK.",
                        "stream": False,
                        "keep_alive": "0s",
                        "options": {"temperature": 0, "num_predict": 32},
                    },
                    timeout=600.0,
                )
            ),
            label=f"{model} load smoke",
            deadline=deadline,
            retry_delay_seconds=retry_delay_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
            sleep=sleep,
            monotonic=monotonic,
            on_retry=lambda attempt, delay, exc: append(
                events,
                {
                    "attempt": attempt,
                    "delay_seconds": delay,
                    "event": "load_smoke_retry",
                    "model": model,
                    "reason_code": _safe_reason(exc),
                },
            ),
        )
        if generated.get("done") is not True:
            raise RuntimeError(f"{model}: load smoke did not finish")
        append(
            events,
            {
                "done_reason": generated.get("done_reason"),
                "elapsed_seconds": round(monotonic() - started, 3),
                "event": "load_smoke_complete",
                "model": model,
                "response": str(generated.get("response", ""))[:500],
            },
        )

    roster = _retry_call(
        lambda: _tags(endpoint, request_fn, timeout=30.0),
        label="final Ollama roster",
        deadline=deadline,
        retry_delay_seconds=retry_delay_seconds,
        max_retry_delay_seconds=max_retry_delay_seconds,
        sleep=sleep,
        monotonic=monotonic,
        on_retry=lambda attempt, delay, exc: append(
            events,
            {
                "attempt": attempt,
                "delay_seconds": delay,
                "event": "roster_retry",
                "reason_code": _safe_reason(exc),
            },
        ),
    )
    if any(model not in roster for model in selected):
        raise RuntimeError("the acquired roster is incomplete")
    (out_dir / "selected-roster.json").write_bytes(
        canonical({"models": [roster[model] for model in selected]})
    )
    append(events, {"event": "complete", "models": selected})
    (out_dir / ".exit").write_text("0\n", encoding="ascii")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--base-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--retry-delay-seconds", type=float, default=30.0)
    parser.add_argument("--max-retry-delay-seconds", type=float, default=300.0)
    parser.add_argument("--deadline-seconds", type=float, default=7 * 24 * 60 * 60)
    parser.add_argument("models", nargs="+")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return acquire(
            out_dir=args.out_dir,
            models=args.models,
            resume=args.resume,
            base_url=args.base_url,
            retry_delay_seconds=args.retry_delay_seconds,
            max_retry_delay_seconds=args.max_retry_delay_seconds,
            deadline_seconds=args.deadline_seconds,
        )
    except (OSError, TimeoutError, UnicodeError, ValueError, RuntimeError) as exc:
        try:
            _publish_terminal_failure(args.out_dir, args.models, exc)
        except OSError as publish_exc:
            print(
                "Ollama roster acquisition terminal publication failed: "
                f"{type(publish_exc).__name__}",
            )
        print(f"Ollama roster acquisition failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
