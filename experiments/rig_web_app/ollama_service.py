"""Secure lifecycle and read-only discovery for a rig-local Ollama daemon.

The console talks only to a literal loopback endpoint and owns only the
``ollama serve`` process handle it created in this process.  A daemon found on
the endpoint is useful for discovery, but is always classified as external and
is never stopped by the console.
"""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from ura.ollama_security import (
    DEFAULT_OLLAMA_URL,
    NoRedirect as _NoRedirect,
    OllamaProcessLock,
    canonicalize_ollama_url,
    literal_loopback_listener_owner,
    model_identity_keys,
    ollama_overlap_specs as _shared_ollama_overlap_specs,
    open_with_deadline,
    process_start_identity,
    read_bounded_response,
    remaining_seconds,
    vllm_identity_index as _shared_vllm_identity_index,
)

from .artifacts import (
    _win_assign_job,
    _win_close_handle,
    _win_managed_job,
    _win_terminate_job,
)


_MAX_TAGS_BYTES = 4 * 1024 * 1024
_MAX_PS_BYTES = 4 * 1024 * 1024
_MAX_SHOW_BYTES = 1024 * 1024
_MAX_MODELS = 512
_MAX_DISCOVERY_MODELS = 64
_MAX_JSON_DEPTH = 64
_MIN_PULL_FREE_BYTES = 5 * 1024**3
_DIGEST = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})\Z")
_TAG = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    r"(?::[A-Za-z0-9][A-Za-z0-9._-]*)?\Z"
)
_PROXY_ENV_NAMES = {"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"}
_PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
_RUNTIME_ENV_ALLOWLIST = {
    "COMSPEC",
    "CUDA_HOME",
    "CUDA_PATH",
    "CUDA_VISIBLE_DEVICES",
    "DYLD_LIBRARY_PATH",
    "HIP_VISIBLE_DEVICES",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "HSA_OVERRIDE_GFX_VERSION",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "LIBRARY_PATH",
    "LOCALAPPDATA",
    "NVIDIA_DRIVER_CAPABILITIES",
    "NVIDIA_VISIBLE_DEVICES",
    "ONEAPI_DEVICE_SELECTOR",
    "PATH",
    "PATHEXT",
    "PROGRAMDATA",
    "REQUESTS_CA_BUNDLE",
    "ROCR_VISIBLE_DEVICES",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "USERPROFILE",
    "WINDIR",
    "XDG_CACHE_HOME",
}
_OLLAMA_ENV_ALLOWLIST = {
    "OLLAMA_CONTEXT_LENGTH",
    "OLLAMA_DEBUG",
    "OLLAMA_FLASH_ATTENTION",
    "OLLAMA_KEEP_ALIVE",
    "OLLAMA_KV_CACHE_TYPE",
    "OLLAMA_LLM_LIBRARY",
    "OLLAMA_LOAD_TIMEOUT",
    "OLLAMA_MAX_LOADED_MODELS",
    "OLLAMA_MAX_QUEUE",
    "OLLAMA_MULTIUSER_CACHE",
    "OLLAMA_NOPRUNE",
    "OLLAMA_NUM_PARALLEL",
    "OLLAMA_SCHED_SPREAD",
}
_SIGTERM = getattr(signal, "SIGTERM", 15)
_SIGKILL = getattr(signal, "SIGKILL", 9)


class OllamaError(RuntimeError):
    """Base class for bounded local Ollama failures."""


class OllamaUnavailable(OllamaError):
    """The fixed loopback API is not reachable."""


class OllamaProtocolError(OllamaError):
    """The daemon returned malformed or ambiguous data."""


def _proxy_without_embedded_credentials(value: str) -> bool:
    """Return whether a proxy origin is usable without disclosing credentials."""

    try:
        parsed = urlsplit(value.strip())
        # Accessing ``port`` also rejects malformed/out-of-range ports.
        _port = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme.lower() in _PROXY_SCHEMES
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _ollama_child_environment(
    source: Mapping[str, str], *, host: str, models_path: Path
) -> dict[str, str]:
    """Build an explicit runtime/GPU/Ollama/safe-proxy child environment."""

    environment: dict[str, str] = {}
    for name, value in source.items():
        normalized = name.upper()
        if normalized in _RUNTIME_ENV_ALLOWLIST or normalized in _OLLAMA_ENV_ALLOWLIST:
            environment[name] = value
        elif normalized in _PROXY_ENV_NAMES:
            if _proxy_without_embedded_credentials(value):
                environment[name] = value
        elif normalized == "NO_PROXY":
            environment[name] = value
    environment["OLLAMA_HOST"] = host
    environment["OLLAMA_MODELS"] = str(models_path)
    return environment


def validate_ollama_pull_storage(
    environment: Mapping[str, str] | None = None,
    *,
    required_bytes: int = 0,
    disk_usage: Callable[[str], Any] = shutil.disk_usage,
) -> dict[str, int]:
    """Fail closed unless the likely Ollama model volume has safe headroom."""

    if (
        isinstance(required_bytes, bool)
        or not isinstance(required_bytes, int)
        or not 0 <= required_bytes <= 2**63 - 1
    ):
        raise ValueError("Ollama pull required bytes are invalid")
    source = os.environ if environment is None else environment
    configured = str(source.get("OLLAMA_MODELS", "")).strip()
    if configured:
        if len(configured) > 4096 or any(ord(char) < 32 for char in configured):
            raise OllamaUnavailable("Ollama model storage path is invalid")
        storage = Path(configured)
        if not storage.is_absolute():
            raise OllamaUnavailable(
                "OLLAMA_MODELS must be absolute so pull free space can be verified"
            )
    else:
        storage = Path.home() / ".ollama" / "models"
    probe = storage
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        free = int(disk_usage(str(probe)).free)
    except (OSError, TypeError, ValueError) as exc:
        raise OllamaUnavailable(
            "could not verify free space for Ollama model storage"
        ) from exc
    minimum = _MIN_PULL_FREE_BYTES + required_bytes
    if free < minimum:
        raise OllamaUnavailable(
            "Ollama pull requires five GiB of free model-storage headroom "
            "plus the reported remaining download"
        )
    return {
        "free_bytes": free,
        "minimum_free_bytes": minimum,
    }


def validate_ollama_base_url(value: str) -> str:
    """Return a canonical literal-loopback HTTP origin or reject it."""

    return canonicalize_ollama_url(value)


def validate_ollama_tag(value: str) -> str:
    """Validate an Ollama tag before it enters JSON, argv, or a local spec."""

    tag = value.strip()
    if not tag or len(tag) > 256 or _TAG.fullmatch(tag) is None:
        raise ValueError("model tag must be a valid Ollama name[:tag] (max 256 chars)")
    if any(part in {".", ".."} for part in tag.split(":", 1)[0].split("/")):
        raise ValueError("model tag must not contain dot path segments")
    return tag


def normalize_ollama_digest(value: object) -> str:
    """Normalize the daemon's digest to the Runner's exact lowercase 64-hex form."""

    if not isinstance(value, str):
        raise ValueError("model digest must be a string")
    match = _DIGEST.fullmatch(value.strip().lower())
    if match is None:
        raise ValueError("model digest must be exact SHA-256")
    return match.group(1).lower()


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
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
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OllamaProtocolError(f"{label} returned invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise OllamaProtocolError(f"{label} must return one JSON object")
    # json's parser already bounds recursion using Python's recursion limit;
    # this explicit walk gives the protocol a much tighter, deterministic cap.
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            raise OllamaProtocolError(f"{label} JSON nesting exceeds the limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


class OllamaAPI:
    """Small stdlib-only client for the fixed loopback Ollama API."""

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        *,
        timeout: float = 1.0,
        open_request: Callable[..., Any] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = validate_ollama_base_url(base_url)
        if not 0.1 <= float(timeout) <= 30.0:
            raise ValueError("Ollama API timeout must be in [0.1, 30] seconds")
        self.timeout = float(timeout)
        self._monotonic = monotonic
        if open_request is None:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _NoRedirect(),
            )
            self._open_request = opener.open
        else:
            self._open_request = open_request

    def _request_json(
        self,
        path: str,
        *,
        max_bytes: int,
        payload: Mapping[str, object] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if path not in {"/api/tags", "/api/ps", "/api/show"}:
            raise ValueError("Ollama API path is not allowlisted")
        body = None
        headers = {"Accept": "application/json", "User-Agent": "ura-rig-web/ollama"}
        if payload is not None:
            body = json.dumps(
                dict(payload), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            if len(body) > 4096:
                raise ValueError("Ollama request body exceeds the limit")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method="POST" if payload is not None else "GET",
        )
        request_timeout = self.timeout if timeout is None else float(timeout)
        if not 0.05 <= request_timeout <= self.timeout:
            raise ValueError("Ollama request timeout override is outside its bound")
        try:
            deadline = self._monotonic() + request_timeout
            response = open_with_deadline(
                self._open_request,
                request,
                deadline=deadline,
                monotonic=self._monotonic,
                maximum_timeout=request_timeout,
                label=f"Ollama {path}",
            )
            with response:
                raw = read_bounded_response(
                    response,
                    maximum=max_bytes,
                    deadline=deadline,
                    monotonic=self._monotonic,
                    label=f"Ollama {path}",
                )
        except ValueError as exc:
            raise OllamaProtocolError(str(exc)) from exc
        except (TimeoutError, OSError, urllib.error.URLError) as exc:
            raise OllamaUnavailable(f"Ollama loopback API unavailable at {path}") from exc
        return _strict_json(raw, label=path)

    def tags(self, *, timeout: float | None = None) -> dict[str, Any]:
        return self._request_json(
            "/api/tags", max_bytes=_MAX_TAGS_BYTES, timeout=timeout
        )

    def ps(self, *, timeout: float | None = None) -> dict[str, Any]:
        return self._request_json("/api/ps", max_bytes=_MAX_PS_BYTES, timeout=timeout)

    def show(self, model: str, *, timeout: float | None = None) -> dict[str, Any]:
        return self._request_json(
            "/api/show",
            max_bytes=_MAX_SHOW_BYTES,
            payload={"model": validate_ollama_tag(model)},
            timeout=timeout,
        )


def _bounded_text(value: object, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        return ""
    return text


def _details(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("details must be an object")
    output: dict[str, object] = {}
    for key in (
        "family",
        "format",
        "parameter_size",
        "parent_model",
        "quantization_level",
    ):
        if key not in value or value[key] is None or value[key] == "":
            continue
        text = _bounded_text(value[key], maximum=128)
        if not text:
            raise ValueError(f"details {key} must be bounded text")
        output[key] = text
    families = value.get("families")
    if families is not None:
        if not isinstance(families, list) or len(families) > 32:
            raise ValueError("details families must be a bounded list")
        normalized = [
            text
            for item in families
            if (text := _bounded_text(item, maximum=128))
        ]
        if len(normalized) != len(families) or len(set(normalized)) != len(normalized):
            raise ValueError("details families must contain unique bounded text")
        output["families"] = normalized
    family = output.get("family")
    normalized_families = output.get("families")
    if isinstance(family, str) and isinstance(normalized_families, list):
        if _credible_family_keys((family,)).isdisjoint(
            _credible_family_keys(tuple(str(value) for value in normalized_families))
        ):
            raise ValueError("details family/families identity mismatch")
    return output


def _show_architecture(document: Mapping[str, object]) -> str:
    """Return a strictly bounded architecture asserted by ``/api/show``."""

    model_info = document.get("model_info")
    if model_info is None:
        return ""
    if not isinstance(model_info, dict) or len(model_info) > 4096:
        raise ValueError("model_info must be a bounded object")
    if "general.architecture" not in model_info:
        return ""
    architecture = _bounded_text(
        model_info.get("general.architecture"), maximum=128
    )
    if not architecture:
        raise ValueError(
            "model_info general.architecture must be bounded non-empty text"
        )
    return architecture


def _family_evidence(details: Mapping[str, object]) -> tuple[str, ...]:
    values: list[str] = []
    family = details.get("family")
    if isinstance(family, str) and family:
        values.append(family)
    families = details.get("families")
    if isinstance(families, list):
        values.extend(value for value in families if isinstance(value, str) and value)
    return tuple(values)


def _credible_family_keys(values: tuple[str, ...]) -> set[str]:
    return {
        key
        for key in model_identity_keys(*values)
        if key.startswith(("base-family:", "family:"))
    }


def _validate_identity_evidence(
    *,
    tag_details: Mapping[str, object],
    show_details: Mapping[str, object],
    architecture: str,
) -> None:
    """Require credible, mutually compatible upstream-family evidence."""

    sources: list[tuple[str, tuple[str, ...]]] = []
    tag_values = _family_evidence(tag_details)
    if tag_values:
        sources.append(("/api/tags details", tag_values))
    show_values = _family_evidence(show_details)
    if show_values:
        sources.append(("/api/show details", show_values))
    if architecture:
        sources.append(("/api/show architecture", (architecture,)))
    if not sources:
        raise ValueError("model has no credible upstream family identity evidence")

    keyed: list[tuple[str, set[str]]] = []
    for label, values in sources:
        keys = _credible_family_keys(values)
        if not keys:
            raise ValueError(f"{label} lacks a credible model-family identity")
        keyed.append((label, keys))
    common_keys = set.intersection(*(keys for _label, keys in keyed))
    if not common_keys:
        labels = "/".join(label for label, _keys in keyed)
        raise ValueError(f"{labels} model-family identity mismatch")


def _identity_keys(*values: str) -> set[str]:
    """Compatibility wrapper over the shared base-family-safe normalizer."""

    return model_identity_keys(*values)


def vllm_identity_index(
    entries: Mapping[str, Mapping[str, object]],
) -> dict[str, tuple[str, ...]]:
    """Map normalized upstream/name/family keys to exact vLLM specs."""

    return _shared_vllm_identity_index(entries)


def ollama_overlap_specs(
    tag: str,
    details: Mapping[str, object],
    vllm_index: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """Return exact vLLM entries sharing a normalized name/model family."""

    return _shared_ollama_overlap_specs(tag, details, vllm_index)


def _tag_rows(
    document: Mapping[str, object], *, maximum: int = _MAX_MODELS
) -> tuple[list[dict[str, object]], list[str]]:
    raw_models = document.get("models")
    if not isinstance(raw_models, list) or len(raw_models) > maximum:
        if maximum == _MAX_DISCOVERY_MODELS:
            raise OllamaProtocolError(
                "Ollama installed roster exceeds the 64-model live discovery limit"
            )
        raise OllamaProtocolError("/api/tags models must be a bounded list")
    rows: list[dict[str, object]] = []
    issues: list[str] = []
    seen: set[str] = set()
    ambiguous: set[str] = set()
    for index, raw in enumerate(raw_models):
        if not isinstance(raw, dict):
            issues.append(f"tags row {index} is not an object")
            continue
        name = _bounded_text(raw.get("name"))
        model = _bounded_text(raw.get("model"))
        try:
            name = validate_ollama_tag(name)
            model = validate_ollama_tag(model)
            digest = normalize_ollama_digest(raw.get("digest"))
            details = _details(raw.get("details"))
        except ValueError as exc:
            issues.append(f"tags row {index}: {exc}")
            continue
        if name != model:
            issues.append(f"tags row {index}: name/model mismatch")
            continue
        if name in seen:
            issues.append(f"tags row {index}: duplicate model tag {name!r}")
            ambiguous.add(name)
            continue
        seen.add(name)
        rows.append(
            {
                "name": name,
                "model": model,
                "digest": digest,
                "details": details,
            }
        )
    return [row for row in rows if str(row["name"]) not in ambiguous], issues


def _loaded_rows(document: Mapping[str, object]) -> tuple[set[tuple[str, str]], list[str]]:
    raw_models = document.get("models")
    if not isinstance(raw_models, list) or len(raw_models) > _MAX_MODELS:
        raise OllamaProtocolError("/api/ps models must be a bounded list")
    loaded: set[tuple[str, str]] = set()
    issues: list[str] = []
    for index, raw in enumerate(raw_models):
        if not isinstance(raw, dict):
            issues.append(f"ps row {index} is not an object")
            continue
        name = _bounded_text(raw.get("name"))
        model = _bounded_text(raw.get("model"))
        try:
            name = validate_ollama_tag(name)
            model = validate_ollama_tag(model)
            digest = normalize_ollama_digest(raw.get("digest"))
        except ValueError as exc:
            issues.append(f"ps row {index}: {exc}")
            continue
        if name != model:
            issues.append(f"ps row {index}: name/model mismatch")
            continue
        loaded.add((name, digest))
    return loaded, issues


def _linux_listener_owner(pid: int, host: str, port: int) -> bool | None:
    """Compatibility wrapper for the shared exact-listener proof."""

    return literal_loopback_listener_owner(pid, host, port)


class OllamaService:
    """Own one optional ``ollama serve`` child and expose exact live discovery."""

    def __init__(
        self,
        state_dir: Path,
        *,
        base_url: str = DEFAULT_OLLAMA_URL,
        api: OllamaAPI | None = None,
        executable: str = "ollama",
        popen_factory: Callable[..., Any] = subprocess.Popen,
        which: Callable[[str], str | None] = shutil.which,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        start_timeout: float = 10.0,
        discovery_timeout: float = 5.0,
        platform: str | None = None,
        listener_owner: Callable[[int, str, int], bool | None] = _linux_listener_owner,
        process_identity: Callable[[int], str | None] = process_start_identity,
    ) -> None:
        self.state_dir = state_dir
        self.api = api or OllamaAPI(base_url)
        self.base_url = validate_ollama_base_url(str(self.api.base_url))
        self.executable = executable
        self._popen_factory = popen_factory
        self._which = which
        self._sleep = sleep
        self._monotonic = monotonic
        self._platform = platform or os.name
        self._listener_owner = listener_owner
        self._process_identity = process_identity
        if self._platform not in {"nt", "posix"}:
            raise ValueError("unsupported Ollama service platform")
        if not 0.1 <= float(start_timeout) <= 30.0:
            raise ValueError("Ollama start timeout must be in [0.1, 30] seconds")
        self.start_timeout = float(start_timeout)
        if not 0.5 <= float(discovery_timeout) <= 30.0:
            raise ValueError("Ollama discovery timeout must be in [0.5, 30] seconds")
        self.discovery_timeout = float(discovery_timeout)
        self._lock = threading.RLock()
        self._owned_process: Any | None = None
        self._owned_pgid: int | None = None
        self._owned_job_handle: Any | None = None
        self._owned_models_path: Path | None = None
        self._owned_process_identity: str | None = None
        self._owned_listener_verified = False
        self._owned_cleanup_error = ""
        self._last_error = ""
        self._roster_cache: dict[str, object] | None = None
        self._roster_cache_at = 0.0

    def invalidate_roster(self) -> None:
        with self._lock:
            self._roster_cache = None
            self._roster_cache_at = 0.0

    def _capture_process_identity(self, pid: int) -> str | None:
        try:
            value = self._process_identity(pid)
        except (OSError, RuntimeError, ValueError):
            return None
        return value if isinstance(value, str) and 0 < len(value) <= 256 else None

    def _owned_identity_matches(self) -> bool:
        process = self._owned_process
        expected = self._owned_process_identity
        return bool(
            process is not None
            and expected is not None
            and self._capture_process_identity(int(process.pid)) == expected
        )

    def _prepare_owned_models_path(self, daemon_directory: Path) -> Path:
        configured = str(os.environ.get("OLLAMA_MODELS", "")).strip()
        path = Path(configured) if configured else daemon_directory / "models"
        if not path.is_absolute():
            raise OllamaUnavailable(
                "OLLAMA_MODELS must be absolute for an owned daemon storage contract"
            )
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.is_symlink():
                raise OllamaUnavailable("owned Ollama model storage must not be a symlink")
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise OllamaUnavailable("owned Ollama model storage is unavailable") from exc
        if not resolved.is_dir() or resolved == Path(resolved.anchor):
            raise OllamaUnavailable("owned Ollama model storage path is unsafe")
        return resolved

    def validate_pull_storage(self) -> dict[str, object]:
        """Return the exact owned storage contract or reject external ambiguity."""

        deadline = self._monotonic() + 2.0
        try:
            with OllamaProcessLock(
                base_url=self.base_url,
                exclusive=False,
                deadline=deadline,
                monotonic=self._monotonic,
                sleep=self._sleep,
            ):
                return self._validate_pull_storage_locked(deadline=deadline)
        except OllamaUnavailable:
            raise
        except (OSError, RuntimeError, TimeoutError) as exc:
            raise OllamaUnavailable(
                "could not verify the owned Ollama storage contract"
            ) from exc

    def _validate_pull_storage_locked(self, *, deadline: float) -> dict[str, object]:
        """Validate storage while the endpoint cannot be mutated cross-process."""

        with self._lock:
            self._reap_owned(deadline=deadline)
            if (
                self._owned_process is None
                or self._owned_models_path is None
                or not self._owned_listener_verified
                or not self._owned_identity_matches()
            ):
                raise OllamaUnavailable(
                    "model pulls require a listener and storage path verified as owned "
                    "by this console process; external/ambiguous daemons are read-only"
                )
            result: dict[str, object] = dict(
                validate_ollama_pull_storage(
                    {"OLLAMA_MODELS": str(self._owned_models_path)}
                )
            )
            result["models_path"] = str(self._owned_models_path)
            result["base_url"] = self.base_url
            result["owned_pid"] = int(self._owned_process.pid)
            result["owned_process_identity"] = self._owned_process_identity
            return result

    def _close_process_handles(self) -> None:
        if self._owned_job_handle is not None:
            _win_close_handle(self._owned_job_handle)
            self._owned_job_handle = None

    def _clear_owned(self) -> None:
        self._owned_process = None
        self._owned_pgid = None
        self._owned_models_path = None
        self._owned_process_identity = None
        self._owned_listener_verified = False
        self._owned_cleanup_error = ""
        self._close_process_handles()

    def _posix_group_exists(self, pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError as exc:
            return exc.errno != errno.ESRCH

    def _posix_signal_ownership_proven(self, process: Any, pgid: int) -> bool:
        """Prove the live process-group leader is still the child we started."""

        pid = int(process.pid)
        expected = self._owned_process_identity
        return bool(
            pgid == pid
            and process.poll() is None
            and expected is not None
            and self._capture_process_identity(pid) == expected
        )

    def _raise_cleanup_error(self, reason: str) -> None:
        message = (
            "could not confirm cleanup of the console-owned Ollama process tree"
            f" ({reason}); ownership is retained so Stop can retry"
        )
        self._owned_cleanup_error = message
        raise OllamaError(message)

    def _reap_owned(self, *, deadline: float | None = None) -> None:
        process = self._owned_process
        if process is not None and process.poll() is not None:
            try:
                self._terminate_owned_locked(deadline=deadline)
            except OllamaError as exc:
                # Retain every ownership handle/path so Stop can retry. Never
                # reclassify an unconfirmed descendant residue as external.
                self._owned_cleanup_error = str(exc)

    def _api_state(
        self, *, deadline: float | None = None
    ) -> tuple[bool, tuple[str, ...], str]:
        deadline = deadline or (
            self._monotonic() + min(5.0, max(0.2, self.api.timeout * 2.0))
        )

        def remaining() -> float:
            budget = min(
                self.api.timeout,
                remaining_seconds(
                    deadline,
                    self._monotonic,
                    label="Ollama status",
                ),
            )
            # OllamaAPI deliberately rejects sub-50 ms overrides.  A slow tags
            # sample can consume all but that sliver of the shared status
            # deadline; treat it as an exhausted optional sample instead of
            # leaking the API's argument ValueError into page rendering.
            if budget < 0.05:
                raise TimeoutError("Ollama status request budget is exhausted")
            return budget

        try:
            tags, tag_issues = _tag_rows(self.api.tags(timeout=remaining()))
        except (OllamaError, TimeoutError) as exc:
            return False, (), str(exc)
        loaded: tuple[str, ...] = ()
        warnings = list(tag_issues[:4])
        try:
            loaded_pairs, ps_issues = _loaded_rows(self.api.ps(timeout=remaining()))
            loaded = tuple(sorted(name for name, _digest in loaded_pairs))
            warnings.extend(ps_issues[: max(0, 4 - len(warnings))])
        except (OllamaError, TimeoutError) as exc:
            warnings.append(str(exc))
        return True, loaded, "; ".join(warnings[:4])

    def _status_document(
        self, *, reachable: bool, loaded: tuple[str, ...], warning: str
    ) -> dict[str, object]:
        owned = self._owned_process is not None
        if owned and self._owned_cleanup_error:
            state = "error"
        elif reachable and owned and self._owned_listener_verified:
            state = "owned"
        elif reachable and owned:
            state = "ambiguous"
        elif reachable:
            state = "external"
        elif owned:
            state = "starting"
        else:
            state = "stopped"
        return {
            "api_reachable": reachable,
            "base_url": self.base_url,
            "can_pull": bool(
                reachable
                and owned
                and self._owned_listener_verified
                and self._owned_models_path is not None
                and self._owned_identity_matches()
            ),
            "can_stop": bool(owned),
            "last_error": self._owned_cleanup_error or self._last_error,
            "loaded_models": list(loaded),
            "owned_by_console": bool(owned),
            "listener_owner_verified": bool(self._owned_listener_verified),
            "pid": int(self._owned_process.pid) if owned else None,
            "state": state,
            "warning": warning,
        }

    def _status_locked(self, *, deadline: float) -> dict[str, object]:
        """Sample status while the caller holds the endpoint process lock."""

        with self._lock:
            self._reap_owned(deadline=deadline)
            reachable, loaded, warning = self._api_state(deadline=deadline)
            return self._status_document(
                reachable=reachable,
                loaded=loaded,
                warning=warning,
            )

    def status(self) -> dict[str, object]:
        """Return one hard-bounded status sample that cannot race mutation."""

        deadline = self._monotonic() + min(
            5.0, max(0.2, float(getattr(self.api, "timeout", 1.0)) * 2.0)
        )
        try:
            with OllamaProcessLock(
                base_url=self.base_url,
                exclusive=False,
                deadline=deadline,
                monotonic=self._monotonic,
                sleep=self._sleep,
            ):
                return self._status_locked(deadline=deadline)
        except (OSError, RuntimeError, TimeoutError) as exc:
            # Do not wait behind a long pull or mutation merely to render the
            # page. Preserve the in-process ownership classification and make
            # the unavailable live sample explicit.
            with self._lock:
                self._reap_owned(deadline=deadline)
                owned = self._owned_process is not None
                cleanup_error = self._owned_cleanup_error
                return {
                    "api_reachable": False,
                    "base_url": self.base_url,
                    "can_pull": False,
                    "can_stop": bool(owned),
                    "last_error": cleanup_error or self._last_error,
                    "loaded_models": [],
                    "owned_by_console": bool(owned),
                    "listener_owner_verified": bool(
                        self._owned_listener_verified
                    ),
                    "pid": int(self._owned_process.pid) if owned else None,
                    "state": "error" if cleanup_error else "busy",
                    "warning": str(exc),
                }

    def _resolve_executable(self) -> str:
        candidate = self._which(self.executable)
        if not candidate:
            raise OllamaUnavailable("ollama executable is not installed or not on PATH")
        try:
            path = Path(candidate).resolve(strict=True)
        except OSError as exc:
            raise OllamaUnavailable("ollama executable could not be resolved") from exc
        if not path.is_file() or (
            self._platform != "nt" and not os.access(path, os.X_OK)
        ):
            raise OllamaUnavailable("ollama executable is not an executable file")
        return str(path)

    def start(self) -> dict[str, object]:
        """Start ``ollama serve`` iff no daemon already owns the endpoint."""

        deadline = self._monotonic() + self.start_timeout
        try:
            with OllamaProcessLock(
                base_url=self.base_url,
                exclusive=True,
                deadline=deadline,
                monotonic=self._monotonic,
                sleep=self._sleep,
            ):
                return self._start_locked(deadline)
        except TimeoutError as exc:
            raise OllamaUnavailable(str(exc)) from exc

    def _start_locked(self, deadline: float) -> dict[str, object]:
        """Start while holding the cross-process mutation lock."""

        with self._lock:
            self._reap_owned(deadline=deadline)
            reachable, loaded, warning = self._api_state(deadline=deadline)
            if reachable:
                # Whether owned or external, never create a competing daemon.
                return self._status_document(
                    reachable=True,
                    loaded=loaded,
                    warning=warning,
                )
            if self._owned_process is not None:
                return self._status_document(
                    reachable=False,
                    loaded=(),
                    warning=warning,
                )
            executable = self._resolve_executable()
            directory = self.state_dir / "ollama"
            directory.mkdir(parents=True, exist_ok=True)
            if directory.is_symlink():
                raise OllamaUnavailable("Ollama state directory must not be a symlink")
            models_path = self._prepare_owned_models_path(directory)
            parsed = urlsplit(self.base_url)
            host = parsed.hostname or "127.0.0.1"
            rendered_host = f"[{host}]" if ":" in host else host
            environment = _ollama_child_environment(
                os.environ,
                host=f"{rendered_host}:{parsed.port or 11434}",
                models_path=models_path,
            )
            kwargs: dict[str, object] = {
                "cwd": directory,
                "env": environment,
                "stdin": subprocess.DEVNULL,
                # A long-lived daemon can be arbitrarily chatty. Never attach
                # an unbounded pipe or file to the web process.
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "shell": False,
            }
            if self._platform == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True
            try:
                process = self._popen_factory([executable, "serve"], **kwargs)
            except OSError as exc:
                raise OllamaUnavailable("could not start ollama serve") from exc
            self._owned_process = process
            self._owned_pgid = int(process.pid) if self._platform != "nt" else None
            self._owned_models_path = models_path
            self._owned_process_identity = self._capture_process_identity(
                int(process.pid)
            )
            self._owned_listener_verified = False
            self._owned_cleanup_error = ""
            if self._platform == "nt":
                handle = _win_managed_job()
                if handle is not None and _win_assign_job(handle, process):
                    self._owned_job_handle = handle
                elif handle is not None:
                    _win_close_handle(handle)
            endpoint_reachable = False
            while self._monotonic() < deadline:
                if process.poll() is not None:
                    # An external daemon can win the bind race after our first
                    # probe. Reap our failed child, then classify the live API
                    # as external instead of claiming or stopping it.
                    self._reap_owned(deadline=deadline)
                    reachable, loaded, warning = self._api_state(deadline=deadline)
                    if reachable:
                        self._last_error = "endpoint became externally owned during start"
                        return self._status_document(
                            reachable=True,
                            loaded=loaded,
                            warning=warning,
                        )
                    self._last_error = "ollama serve exited before the API became ready"
                    raise OllamaUnavailable(self._last_error)
                reachable, _loaded, _warning = self._api_state(deadline=deadline)
                if reachable:
                    endpoint_reachable = True
                    try:
                        ownership = self._listener_owner(
                            int(process.pid),
                            host,
                            parsed.port or 11434,
                        )
                    except (OSError, RuntimeError, ValueError):
                        ownership = None
                    current_identity = self._capture_process_identity(
                        int(process.pid)
                    )
                    if (
                        ownership is True
                        and self._owned_process_identity is not None
                        and current_identity == self._owned_process_identity
                    ):
                        self._owned_listener_verified = True
                        self._last_error = ""
                        self.invalidate_roster()
                        return self._status_locked(deadline=deadline)
                    self._last_error = (
                        "Ollama endpoint is reachable but listener ownership is "
                        "unverified; classified as ambiguous"
                    )
                self._sleep(0.1)
            if endpoint_reachable and process.poll() is None:
                self.invalidate_roster()
                return self._status_document(
                    reachable=True,
                    loaded=(),
                    warning=self._last_error,
                )
            self._terminate_owned_locked(deadline=deadline)
            self._last_error = "ollama serve did not become ready before the timeout"
            raise OllamaUnavailable(self._last_error)

    def _terminate_owned_locked(self, *, deadline: float | None = None) -> None:
        process = self._owned_process
        if process is None:
            return

        def wait_bound(maximum: float) -> float:
            if deadline is None:
                return maximum
            return max(0.001, min(maximum, deadline - self._monotonic()))

        descendants_confirmed = False
        if self._platform == "nt":
            if self._owned_job_handle is not None:
                descendants_confirmed = _win_terminate_job(self._owned_job_handle)
            elif process.poll() is None:
                try:
                    result = subprocess.run(  # noqa: S603 - fixed executable/argv
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        shell=False,
                    timeout=wait_bound(10.0),
                    )
                    descendants_confirmed = result.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    pass
            # A dead parent without its Job handle cannot prove that its child
            # tree is gone. Retain ownership/error state for an operator retry.
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=wait_bound(5.0))
            except (OSError, subprocess.TimeoutExpired, TimeoutError):
                pass
        else:
            pgid = self._owned_pgid or int(process.pid)
            group_exists = self._posix_group_exists(pgid)
            if not group_exists:
                descendants_confirmed = True
            elif not self._posix_signal_ownership_proven(process, pgid):
                self._raise_cleanup_error(
                    "the recorded process group exists but its live leader identity "
                    "is absent, changed, or unprovable"
                )
            else:
                try:
                    os.killpg(pgid, _SIGTERM)
                except ProcessLookupError:
                    group_exists = False
                except OSError as exc:
                    self._raise_cleanup_error(f"SIGTERM failed: {exc}")
                try:
                    process.wait(timeout=wait_bound(5.0))
                except (OSError, subprocess.TimeoutExpired, TimeoutError):
                    pass
                group_exists = self._posix_group_exists(pgid)
                if group_exists:
                    # The leader may have exited after SIGTERM while a child
                    # retained (or an unrelated process reused) its PGID. Do
                    # not escalate unless the exact live leader identity is
                    # still positively proven immediately before SIGKILL.
                    if not self._posix_signal_ownership_proven(process, pgid):
                        self._raise_cleanup_error(
                            "the process-group leader identity disappeared during "
                            "cleanup"
                        )
                    try:
                        os.killpg(pgid, _SIGKILL)
                    except ProcessLookupError:
                        group_exists = False
                    except OSError as exc:
                        self._raise_cleanup_error(f"SIGKILL failed: {exc}")
                    try:
                        process.wait(timeout=wait_bound(5.0))
                    except (OSError, subprocess.TimeoutExpired, TimeoutError):
                        pass
                    cleanup_deadline = self._monotonic() + 2.0
                    if deadline is not None:
                        cleanup_deadline = min(cleanup_deadline, deadline)
                    while (
                        self._posix_group_exists(pgid)
                        and self._monotonic() < cleanup_deadline
                    ):
                        self._sleep(0.05)
            descendants_confirmed = not self._posix_group_exists(pgid)
            # Reap the original child only after all possible group signals.
            # Reaping earlier can erase the only positive start-identity proof.
            try:
                process.wait(timeout=wait_bound(5.0))
            except (OSError, subprocess.TimeoutExpired, TimeoutError):
                pass
        if process.poll() is None or not descendants_confirmed:
            self._raise_cleanup_error("process or process-group absence is unproven")
        self._clear_owned()

    def stop(self) -> dict[str, object]:
        """Stop only this service instance's live child; refuse external daemons."""

        deadline = self._monotonic() + 20.0
        try:
            with OllamaProcessLock(
                base_url=self.base_url,
                exclusive=True,
                deadline=deadline,
                monotonic=self._monotonic,
                sleep=self._sleep,
            ):
                return self._stop_locked(deadline=deadline)
        except TimeoutError as exc:
            raise OllamaError(str(exc)) from exc

    def _stop_locked(self, *, deadline: float) -> dict[str, object]:
        """Stop while holding the cross-process mutation lock."""

        with self._lock:
            had_owned = self._owned_process is not None
            self._reap_owned(deadline=deadline)
            if self._owned_process is None:
                if had_owned:
                    self.invalidate_roster()
                    self._last_error = ""
                    return self._status_locked(deadline=deadline)
                reachable, _loaded, _warning = self._api_state(deadline=deadline)
                if reachable:
                    raise OllamaError(
                        "Ollama daemon is external; this console will not stop it"
                    )
                raise OllamaError("no console-owned Ollama daemon is running")
            self._terminate_owned_locked(deadline=deadline)
            self.invalidate_roster()
            self._last_error = ""
            return self._status_locked(deadline=deadline)

    def close(self) -> None:
        """Best-effort cleanup of this process's daemon only."""

        # An external daemon is not ours to clean up. In particular, a read-only
        # console must not wait on an experiment's inference lock at shutdown.
        with self._lock:
            if self._owned_process is None:
                return
        deadline = self._monotonic() + 20.0
        try:
            with OllamaProcessLock(
                base_url=self.base_url,
                exclusive=True,
                deadline=deadline,
                monotonic=self._monotonic,
                sleep=self._sleep,
            ):
                with self._lock:
                    self._reap_owned(deadline=deadline)
                    if self._owned_process is None:
                        return
                    try:
                        self._terminate_owned_locked(deadline=deadline)
                    except OllamaError as exc:
                        self._owned_cleanup_error = str(exc)
        except (OSError, RuntimeError, TimeoutError) as exc:
            self._owned_cleanup_error = str(exc)

    def roster(
        self,
        vllm_entries: Mapping[str, Mapping[str, object]],
        *,
        force: bool = False,
    ) -> dict[str, object]:
        """Discover exact installed tags independently of vLLM availability."""

        deadline = self._monotonic() + self.discovery_timeout
        try:
            with OllamaProcessLock(
                base_url=self.base_url,
                exclusive=False,
                deadline=deadline,
                monotonic=self._monotonic,
                sleep=self._sleep,
            ):
                return self._roster_locked(
                    vllm_entries,
                    force=force,
                    deadline=deadline,
                )
        except (OSError, RuntimeError, TimeoutError) as exc:
            return {
                "available": False,
                "error": str(exc),
                "excluded": [],
                "issues": [],
                "models": [],
            }

    def _roster_locked(
        self,
        vllm_entries: Mapping[str, Mapping[str, object]],
        *,
        force: bool,
        deadline: float,
    ) -> dict[str, object]:
        """Discover while holding the cross-process shared lock."""

        with self._lock:
            del vllm_entries
            now = self._monotonic()
            if (
                not force
                and self._roster_cache is not None
                and now - self._roster_cache_at <= 2.0
            ):
                return json.loads(json.dumps(self._roster_cache))
            try:
                def remaining() -> float:
                    value = deadline - self._monotonic()
                    if value < 0.05:
                        raise OllamaUnavailable(
                            "Ollama capability discovery exceeded its aggregate timeout"
                        )
                    return min(self.api.timeout, value)

                first_rows, issues = _tag_rows(
                    self.api.tags(timeout=remaining()),
                    maximum=_MAX_DISCOVERY_MODELS,
                )
                loaded, ps_issues = _loaded_rows(
                    self.api.ps(timeout=remaining())
                )
                issues.extend(ps_issues)
                candidates: list[dict[str, object]] = []
                excluded: list[dict[str, object]] = []
                for row in first_rows:
                    tag = str(row["name"])
                    show = self.api.show(tag, timeout=remaining())
                    capabilities = show.get("capabilities")
                    if (
                        not isinstance(capabilities, list)
                        or not capabilities
                        or len(capabilities) > 32
                        or any(
                            not _bounded_text(value, maximum=128)
                            for value in capabilities
                        )
                    ):
                        issues.append(f"{tag}: /api/show lacks explicit capabilities")
                        continue
                    normalized_capabilities = [
                        str(value).strip().lower() for value in capabilities
                    ]
                    if len(set(normalized_capabilities)) != len(normalized_capabilities):
                        issues.append(f"{tag}: /api/show capabilities are duplicated")
                        continue
                    normalized_capabilities.sort()
                    if "completion" not in normalized_capabilities:
                        issues.append(f"{tag}: model has no completion capability")
                        continue
                    try:
                        show_details = _details(show.get("details"))
                        architecture = _show_architecture(show)
                    except ValueError as exc:
                        issues.append(f"{tag}: /api/show {exc}")
                        continue
                    tag_details = dict(row["details"])
                    for identity_key in ("family", "families"):
                        if (
                            identity_key in tag_details
                            and identity_key in show_details
                            and tag_details[identity_key] != show_details[identity_key]
                        ):
                            issues.append(
                                f"{tag}: tags/show {identity_key} identity mismatch"
                            )
                            break
                    else:
                        merged_details = {**show_details, **tag_details}
                        try:
                            _validate_identity_evidence(
                                tag_details=tag_details,
                                show_details=show_details,
                                architecture=architecture,
                            )
                        except ValueError as exc:
                            issues.append(f"{tag}: {exc}")
                            continue
                        identity_details = dict(merged_details)
                        if architecture:
                            identity_details["architecture"] = architecture
                        modalities = ["text"]
                        if "vision" in normalized_capabilities:
                            modalities.append("image")
                        model = {
                            "capabilities": normalized_capabilities,
                            "details": merged_details,
                            "digest": row["digest"],
                            "loaded": (tag, str(row["digest"])) in loaded,
                            "modalities": modalities,
                            "model": row["model"],
                            "name": row["name"],
                            "overlap_with": [],
                            "spec": f"ollama:{tag}",
                            "tag": tag,
                        }
                        if architecture:
                            model["architecture"] = architecture
                        candidates.append(model)
                # Close the mutable-tag race: no capability result is used
                # unless a second /api/tags snapshot has the same exact tags
                # and digests as the first snapshot.
                second_rows, second_issues = _tag_rows(
                    self.api.tags(timeout=remaining()),
                    maximum=_MAX_DISCOVERY_MODELS,
                )
                if self._monotonic() > deadline:
                    raise OllamaUnavailable(
                        "Ollama capability discovery exceeded its aggregate timeout"
                    )
                issues.extend(second_issues)
                first_identity = {
                    (str(row["name"]), str(row["digest"])) for row in first_rows
                }
                second_identity = {
                    (str(row["name"]), str(row["digest"])) for row in second_rows
                }
                if first_identity != second_identity:
                    raise OllamaProtocolError(
                        "Ollama tags changed during capability discovery; refresh again"
                    )
                result: dict[str, object] = {
                    "available": True,
                    "base_url": self.base_url,
                    "excluded": sorted(excluded, key=lambda row: str(row["spec"])),
                    "issues": issues[:128],
                    "models": sorted(candidates, key=lambda row: str(row["spec"])),
                    "refreshed_at": time.time(),
                }
            except OllamaError as exc:
                result = {
                    "available": False,
                    "base_url": self.base_url,
                    "error": str(exc),
                    "excluded": [],
                    "issues": [],
                    "models": [],
                    "refreshed_at": time.time(),
                }
            self._roster_cache = result
            self._roster_cache_at = self._monotonic()
            return json.loads(json.dumps(result))
