"""Shared fail-closed Ollama transport, identity, and process-lock primitives."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import os
import re
import stat
import tempfile
import threading
import time
import urllib.request
from queue import Empty, Queue
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
_IDENTITY_SUFFIXES = {"base", "chat", "gguf", "hf", "instruct", "it"}
_GENERIC_BASE_FAMILIES = {"base", "chat", "code", "instruct", "model", "vision"}
_SHORT_BASE_FAMILIES = {"aya", "phi", "yi"}
_OPEN_WORKERS = threading.BoundedSemaphore(8)
_READ_WORKERS = threading.BoundedSemaphore(8)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject every redirect so a loopback request cannot leave loopback."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


def canonicalize_ollama_url(value: str) -> str:
    """Return an unauthenticated literal-loopback HTTP origin."""

    parsed = urlsplit(value.strip())
    if parsed.scheme != "http" or parsed.username or parsed.password:
        raise ValueError("Ollama API must use an unauthenticated loopback HTTP URL")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Ollama API URL must be an origin without a path/query/fragment")
    host = parsed.hostname or ""
    if host.lower() == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
        port = parsed.port or 11434
    except ValueError as exc:
        raise ValueError("Ollama API must use a valid literal loopback address") from exc
    if not address.is_loopback or not 1 <= port <= 65535:
        raise ValueError("Ollama API must use a valid literal loopback address")
    rendered = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{rendered}:{port}"


def remaining_seconds(
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
    *,
    label: str = "Ollama operation",
) -> float:
    """Return positive time remaining under one hard monotonic deadline."""

    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError(f"{label} exceeded its hard wall-clock deadline")
    return remaining


def open_with_deadline(
    open_request: Callable[..., Any],
    request: urllib.request.Request,
    *,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
    maximum_timeout: float,
    label: str,
) -> Any:
    """Open one URL without letting a drip-fed header block past a hard wall.

    ``urllib`` socket timeouts are inactivity timers. A loopback peer can keep
    an HTTP header alive indefinitely by sending one byte before each timeout.
    The bounded daemon worker makes the caller's deadline authoritative; at
    most eight stuck openers may exist in one process, after which calls fail
    closed instead of creating unbounded threads.
    """

    remaining = remaining_seconds(deadline, monotonic, label=label)
    acquired = _OPEN_WORKERS.acquire(timeout=min(remaining, maximum_timeout))
    if not acquired:
        raise TimeoutError(f"{label} exceeded its hard wall-clock deadline")
    result: Queue[tuple[bool, Any]] = Queue(maxsize=1)
    cancelled = threading.Event()

    def worker() -> None:
        try:
            value = open_request(
                request,
                timeout=min(
                    maximum_timeout,
                    remaining_seconds(deadline, monotonic, label=label),
                ),
            )
            if cancelled.is_set():
                try:
                    value.close()
                except (AttributeError, OSError):
                    pass
                return
            result.put_nowait((True, value))
        except BaseException as exc:  # relayed in the requesting thread
            if not cancelled.is_set():
                try:
                    result.put_nowait((False, exc))
                except Exception:
                    pass
        finally:
            _OPEN_WORKERS.release()

    thread = threading.Thread(target=worker, name="ollama-http-open", daemon=True)
    thread.start()
    try:
        wait_timeout = remaining_seconds(deadline, monotonic, label=label)
        ok, value = result.get(timeout=wait_timeout)
        remaining_seconds(deadline, monotonic, label=label)
    except (Empty, TimeoutError) as exc:
        cancelled.set()
        try:
            queued_ok, queued_value = result.get_nowait()
        except Empty:
            pass
        else:
            if queued_ok:
                try:
                    queued_value.close()
                except (AttributeError, OSError):
                    pass
        raise TimeoutError(f"{label} exceeded its hard wall-clock deadline") from exc
    if ok:
        return value
    raise value


def process_start_identity(pid: int) -> str | None:
    """Return a PID-reuse-resistant Linux process identity when provable."""

    if os.name != "posix" or isinstance(pid, bool) or pid <= 0:
        return None
    try:
        stat_line = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
        closing = stat_line.rfind(")")
        suffix = stat_line[closing + 2 :].split() if closing >= 0 else []
        # suffix[0] is field 3 (state); Linux field 22 is process start ticks.
        start_ticks = suffix[19]
        if not start_ticks.isdecimal():
            return None
    except (IndexError, OSError, UnicodeError):
        return None
    return f"linux-proc-v1:{pid}:{start_ticks}"


def literal_loopback_listener_owner(pid: int, host: str, port: int) -> bool | None:
    """Prove that a Linux PID or descendant owns the exact loopback listener."""

    if os.name != "posix" or not Path("/proc").is_dir():
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not address.is_loopback or not 1 <= port <= 65535:
        return None
    proc = Path("/proc")
    encoded_address = (
        "0100007F"
        if address.version == 4 and address.compressed == "127.0.0.1"
        else "00000000000000000000000001000000"
        if address.version == 6 and address.compressed == "::1"
        else None
    )
    # The contract permits any literal 127/8 address. /proc encodes IPv4 in
    # little-endian bytes, so compute non-default loopbacks exactly.
    if address.version == 4 and encoded_address is None:
        encoded_address = address.packed[::-1].hex().upper()
    if encoded_address is None:
        return None
    listener_inodes: set[str] = set()
    try:
        tables = (proc / "net" / "tcp",) if address.version == 4 else (proc / "net" / "tcp6",)
        for table in tables:
            if not table.is_file():
                continue
            for line in table.read_text(encoding="ascii").splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10 or fields[3] != "0A":
                    continue
                encoded_host, encoded_port = fields[1].rsplit(":", 1)
                if encoded_host == encoded_address and int(encoded_port, 16) == port:
                    listener_inodes.add(fields[9])
    except (OSError, UnicodeError, ValueError):
        return None
    if not listener_inodes:
        return False
    descendants = {pid}
    for _generation in range(8):
        added = False
        try:
            entries = list(proc.iterdir())[:65536]
        except OSError:
            return None
        for entry in entries:
            if not entry.name.isdecimal() or int(entry.name) in descendants:
                continue
            try:
                status = (entry / "status").read_text(encoding="ascii")
                parent_line = next(
                    line for line in status.splitlines() if line.startswith("PPid:")
                )
                parent = int(parent_line.split(":", 1)[1].strip())
            except (OSError, StopIteration, UnicodeError, ValueError):
                continue
            if parent in descendants:
                descendants.add(int(entry.name))
                added = True
        if not added:
            break
    for candidate in descendants:
        try:
            descriptors = (proc / str(candidate) / "fd").iterdir()
            for descriptor in descriptors:
                try:
                    link = os.readlink(descriptor)
                except OSError:
                    continue
                if link.startswith("socket:[") and link[8:-1] in listener_inodes:
                    return True
        except OSError:
            continue
    return False


def set_response_timeout(response: Any, timeout: float) -> None:
    """Best-effort tighten the live socket timeout to the remaining deadline."""

    candidates = [response]
    for _depth in range(5):
        next_candidates: list[Any] = []
        for candidate in candidates:
            if hasattr(candidate, "settimeout"):
                try:
                    candidate.settimeout(timeout)
                    return
                except (OSError, TypeError, ValueError):
                    pass
            for attribute in ("fp", "raw", "_sock", "sock"):
                child = getattr(candidate, attribute, None)
                if child is not None and child is not candidate:
                    next_candidates.append(child)
        candidates = next_candidates


def _read_bounded_response_inline(
    response: Any,
    *,
    maximum: int,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
    label: str,
) -> bytes:
    """Read one response body in the caller-selected worker."""

    declared = getattr(response, "headers", {}).get("Content-Length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} has invalid Content-Length") from exc
        if declared_size < 0 or declared_size > maximum:
            raise ValueError(f"{label} exceeds the byte limit")
    reader = getattr(response, "read1", None)
    if not callable(reader):
        remaining = remaining_seconds(deadline, monotonic, label=label)
        set_response_timeout(response, remaining)
        body = response.read(maximum + 1)
        remaining_seconds(deadline, monotonic, label=label)
        if not isinstance(body, bytes):
            raise ValueError(f"{label} returned a non-byte body")
        if len(body) > maximum:
            raise ValueError(f"{label} exceeds the byte limit")
        return body
    body = bytearray()
    while True:
        remaining = remaining_seconds(deadline, monotonic, label=label)
        set_response_timeout(response, remaining)
        chunk = reader(min(64 * 1024, maximum + 1 - len(body)))
        remaining_seconds(deadline, monotonic, label=label)
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise ValueError(f"{label} returned a non-byte body")
        body.extend(chunk)
        if len(body) > maximum:
            raise ValueError(f"{label} exceeds the byte limit")
    return bytes(body)


def read_bounded_response(
    response: Any,
    *,
    maximum: int,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
    label: str,
) -> bytes:
    """Read a response under a hard deadline even if its socket never wakes.

    Setting a socket timeout is insufficient when a response wrapper cannot
    expose its actual socket, or when a blocking ``read1`` implementation does
    not honor a concurrent timeout update. Keep the bounded byte reader in a
    daemon worker and make the requesting thread's monotonic deadline
    authoritative. The semaphore prevents repeated stuck peers from creating
    an unbounded number of workers.
    """

    remaining = remaining_seconds(deadline, monotonic, label=label)
    acquired = _READ_WORKERS.acquire(timeout=remaining)
    if not acquired:
        raise TimeoutError(f"{label} exceeded its hard wall-clock deadline")
    result: Queue[tuple[bool, Any]] = Queue(maxsize=1)
    cancelled = threading.Event()

    def worker() -> None:
        try:
            value = _read_bounded_response_inline(
                response,
                maximum=maximum,
                deadline=deadline,
                monotonic=monotonic,
                label=label,
            )
            if not cancelled.is_set():
                result.put_nowait((True, value))
        except BaseException as exc:  # relayed in the requesting thread
            if not cancelled.is_set():
                try:
                    result.put_nowait((False, exc))
                except Exception:
                    pass
        finally:
            _READ_WORKERS.release()

    thread = threading.Thread(target=worker, name="ollama-http-read", daemon=True)
    thread.start()
    try:
        wait_timeout = remaining_seconds(deadline, monotonic, label=label)
        ok, value = result.get(timeout=wait_timeout)
        remaining_seconds(deadline, monotonic, label=label)
    except (Empty, TimeoutError) as exc:
        cancelled.set()
        try:
            response.close()
        except (AttributeError, OSError):
            pass
        try:
            result.get_nowait()
        except Empty:
            pass
        raise TimeoutError(f"{label} exceeded its hard wall-clock deadline") from exc
    if ok:
        return value
    raise value


def _bounded_identity_text(value: object, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        return ""
    return text


def model_identity_keys(*values: str) -> set[str]:
    """Build exact normalized name/version-family and base-family aliases."""

    keys: set[str] = set()
    for original in values:
        value = re.sub(r"^(?:vllm|ollama):", "", original.strip().lower())
        if not value:
            continue
        if value.endswith(":latest"):
            value = value[: -len(":latest")]
        basename = value.rsplit("/", 1)[-1]
        for candidate in (value, basename):
            tokens = [token for token in re.split(r"[^a-z0-9]+", candidate) if token]
            while tokens and tokens[-1] in _IDENTITY_SUFFIXES:
                tokens.pop()
            normalized = "".join(tokens)
            if len(normalized) >= 4:
                keys.add(f"name:{normalized}")
        family_tokens = [
            token for token in re.split(r"[^a-z0-9]+", basename) if token
        ]
        if not family_tokens:
            continue
        family = family_tokens[0]
        base_match = re.match(r"[a-z]+", family)
        base = base_match.group(0) if base_match else ""
        if (
            len(base) >= 4 or base in _SHORT_BASE_FAMILIES
        ) and base not in _GENERIC_BASE_FAMILIES:
            keys.add(f"base-family:{base}")
        for token in family_tokens[1:]:
            if re.fullmatch(r"\d+(?:b|m|k|t)", token):
                break
            version = re.fullmatch(r"(\d+)", token)
            if version is None:
                if re.search(r"\d", family):
                    version = re.match(r"(\d+)", token)
                if version is None:
                    break
            family += version.group(1)
        if len(family) >= 4 and family not in _IDENTITY_SUFFIXES:
            keys.add(f"family:{family}")
    return keys


def vllm_identity_index(
    entries: Mapping[str, Mapping[str, object]],
) -> dict[str, tuple[str, ...]]:
    index: dict[str, set[str]] = {}
    for spec, entry in entries.items():
        if not str(spec).startswith("vllm:"):
            continue
        details: list[str] = []
        for key in (
            "architecture",
            "family",
            "model_family",
            "upstream_identity",
            "name",
        ):
            text = _bounded_identity_text(entry.get(key))
            if text:
                details.append(text)
        for key in model_identity_keys(str(spec), *details):
            index.setdefault(key, set()).add(str(spec))
    return {key: tuple(sorted(values)) for key, values in index.items()}


def ollama_overlap_specs(
    tag: str,
    details: Mapping[str, object],
    vllm_index: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    values = [tag]
    architecture = _bounded_identity_text(details.get("architecture"), maximum=128)
    if architecture:
        values.append(architecture)
    family = _bounded_identity_text(details.get("family"), maximum=128)
    if family:
        values.append(family)
    families = details.get("families")
    if isinstance(families, list):
        values.extend(str(value) for value in families if isinstance(value, str))
    overlaps: set[str] = set()
    for key in model_identity_keys(*values):
        overlaps.update(vllm_index.get(key, ()))
    return tuple(sorted(overlaps))


def ollama_lock_path(
    base_url: str = DEFAULT_OLLAMA_URL,
    *,
    namespace: str = "endpoint",
) -> Path:
    """Return one per-endpoint, per-user cross-process lock path."""

    canonical = canonicalize_ollama_url(base_url)
    if namespace not in {"endpoint", "inference"}:
        raise ValueError("Ollama lock namespace must be endpoint or inference")
    # POSIX gives every uid its own directory.  Windows has no getuid, and a
    # shared literal would put every account on ONE directory created with
    # mode 0o700 - which Windows honours as a DACL carrying no user ACE, so
    # the first creator permanently locks out every other account, and the
    # workstation itself once that entry goes stale.  Derive a per-account
    # suffix instead; the POSIX branch is byte-identical to before.
    if hasattr(os, "getuid"):
        user = str(os.getuid())
    else:
        account = "\\".join(
            (os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", ""))
        )
        user = hashlib.sha256(account.encode("utf-8", "replace")).hexdigest()[:16]
    directory = Path(tempfile.gettempdir()) / f"ura-ollama-lock-{user}"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("Ollama lock directory is not a trusted directory")
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    digest = hashlib.sha256(canonical.encode("ascii")).hexdigest()[:24]
    suffix = "" if namespace == "endpoint" else ".inference"
    return directory / f"{digest}{suffix}.lock"


class OllamaProcessLock:
    """Bounded endpoint lock with a separate inference/mutation gate.

    An exclusive endpoint operation first takes the inference gate. A target
    can therefore retain that gate across its loaded-model lifetime, blocking
    pull/start/stop while endpoint readers remain independently available.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_OLLAMA_URL,
        exclusive: bool,
        deadline: float,
        namespace: str = "endpoint",
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url
        self.namespace = namespace
        self.path = ollama_lock_path(base_url, namespace=namespace)
        self.exclusive = exclusive
        self.deadline = deadline
        self.monotonic = monotonic
        self.sleep = sleep
        self._fd: int | None = None
        self._inference_gate: OllamaProcessLock | None = None

    def __enter__(self) -> "OllamaProcessLock":
        if self.namespace == "endpoint" and self.exclusive:
            inference_gate = OllamaProcessLock(
                base_url=self.base_url,
                exclusive=True,
                deadline=self.deadline,
                namespace="inference",
                monotonic=self.monotonic,
                sleep=self.sleep,
            )
            inference_gate.__enter__()
            self._inference_gate = inference_gate
        try:
            return self._enter_own_lock()
        except BaseException:
            self._release_inference_gate()
            raise

    def _enter_own_lock(self) -> "OllamaProcessLock":
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise RuntimeError("Ollama process lock is not a regular file")
        if info.st_size == 0:
            os.write(fd, b"\0")
        self._fd = fd
        while True:
            try:
                if os.name == "nt":
                    import msvcrt  # noqa: PLC0415

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl  # noqa: PLC0415

                    operation = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
                    fcntl.flock(fd, operation | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    self._close_fd()
                    raise
                try:
                    remaining = remaining_seconds(
                        self.deadline,
                        self.monotonic,
                        label="Ollama cross-process lock acquisition",
                    )
                except TimeoutError:
                    self._close_fd()
                    raise
                self.sleep(min(0.05, remaining))

    def _close_fd(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _release_inference_gate(self) -> None:
        inference_gate = self._inference_gate
        self._inference_gate = None
        if inference_gate is not None:
            inference_gate.__exit__(None, None, None)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        fd = self._fd
        try:
            if fd is not None:
                if os.name == "nt":
                    import msvcrt  # noqa: PLC0415

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl  # noqa: PLC0415

                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            try:
                self._close_fd()
            finally:
                self._release_inference_gate()


__all__ = [
    "DEFAULT_OLLAMA_URL",
    "NoRedirect",
    "OllamaProcessLock",
    "canonicalize_ollama_url",
    "literal_loopback_listener_owner",
    "model_identity_keys",
    "ollama_lock_path",
    "ollama_overlap_specs",
    "open_with_deadline",
    "process_start_identity",
    "read_bounded_response",
    "remaining_seconds",
    "set_response_timeout",
    "vllm_identity_index",
]
