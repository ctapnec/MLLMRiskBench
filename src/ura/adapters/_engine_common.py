"""Shared helpers for the external red-team engine adapters (thesis III.2.2).

In addition to lazy imports and schema-valid attempts, this module reduces
accidental environment-secret leakage to command-line engines. Child
environments are filtered, execution is time-bounded, and returned failure
diagnostics are size-bounded. This is *not* an OS/filesystem/process sandbox:
children retain the invoking account's filesystem privileges, may create
descendants, and may fill the temporary-output filesystem before timeout.
Untrusted engines therefore require the external isolation described in
``SECURITY.md``.
"""
from __future__ import annotations

import math
import os
import re
import subprocess
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ..data_models import Attempt, DataPoint, DialogTurn


DEFAULT_ENGINE_TIMEOUT_SECONDS = 300.0
DEFAULT_DIAGNOSTIC_LIMIT_BYTES = 16_384
_MAX_ENGINE_TIMEOUT_SECONDS = 86_400.0
_MAX_DIAGNOSTIC_LIMIT_BYTES = 1_048_576

# Environment names are compared case-insensitively because Windows environment
# variables are case-insensitive.  This deliberately covers provider keys as well
# as less obvious credential carriers (cookies, DSNs and credential-file paths).
_CREDENTIAL_NAME = re.compile(
    r"(?:"
    r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|COOKIES?|CREDENTIALS?|"
    r"AUTH(?:ORIZATION)?|BEARER|PRIVATE_KEY|ACCESS_KEY|SESSION(?:_KEY)?)(?:_|$)"
    r"|(?:^|_)(?:DATABASE_URL|REDIS_URL|MONGODB_URI|CONNECTION_STRING|DSN)(?:_|$)"
    r"|APIKEY"
    r")",
    re.IGNORECASE,
)

# These variables can execute code or load attacker-controlled libraries before
# the requested engine entry point.  They are removed from inherited state.  A
# trusted adapter can deliberately supply a needed value through ``env_overrides``
# (PurpleLlama does this for its checked-out repository's PYTHONPATH).
_RUNTIME_INJECTION_NAMES = {
    "BASH_ENV",
    "ENV",
    "GIT_SSH_COMMAND",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PROMPT_COMMAND",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
}

# Names that CARRY credentials in their value (authenticated proxy/index URLs)
# or point at credential-config files, even though the name is not itself a
# secret. These are dropped unless explicitly allowlisted.
_CREDENTIAL_URL_NAME = re.compile(
    r"(?:^|_)(?:(?:HTTP|HTTPS|ALL|FTP)_PROXY|PROXY|INDEX_URL|EXTRA_INDEX_URL"
    r"|REPOSITORY_URL|REGISTRY)(?:_|$)",
    re.IGNORECASE,
)
_CREDENTIAL_CONFIG_NAMES = {
    "NETRC", "PIP_CONFIG_FILE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "BOTO_CONFIG",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "AZURE_CONFIG_DIR",
    "KUBECONFIG", "DOCKER_CONFIG", "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_GLOBALCONFIG", "GH_CONFIG_DIR", "HF_TOKEN_PATH",
    "PGPASSFILE", "PGSERVICEFILE", "PGSYSCONFDIR", "GNUPGHOME",
    "SSH_AUTH_SOCK", "GIT_ASKPASS", "SSH_ASKPASS",
}


def _is_credential_or_carrier(name: str) -> bool:
    upper_name = name.upper()
    return bool(
        _CREDENTIAL_NAME.search(upper_name)
        or _CREDENTIAL_URL_NAME.search(upper_name)
        or upper_name in _CREDENTIAL_CONFIG_NAMES
    )


class ExternalEngineError(RuntimeError):
    """An external engine failed without exposing unbounded child output."""


class ExternalEngineOutputError(ValueError):
    """An engine returned successfully but emitted no usable generated output.

    Treating this condition as a baseline/replay prompt changes the attack
    estimand while making the cell look successful.  Adapters use this distinct
    error so matrix drivers preserve the failed cell instead.
    """


class ExternalEngineConformanceError(ExternalEngineError):
    """A registered bridge has no verified upstream execution contract.

    This is intentionally different from a missing dependency or malformed run
    output.  It prevents an invented/obsolete CLI or Python surface from being
    presented as a successful integration merely because a local module exists.
    """


def require_generated_texts(
    values: Iterable[object], *, feature: str, limit: int | None = None
) -> list[str]:
    """Return non-blank string outputs or fail closed.

    Leading/trailing whitespace is retained because it can be part of an attack;
    ``strip`` is used only to distinguish an actual prompt from an empty value.
    Non-string values are never coerced into prompts.
    """

    prompts = [value for value in values if isinstance(value, str) and value.strip()]
    if limit is not None:
        prompts = prompts[:limit]
    if not prompts:
        raise ExternalEngineOutputError(
            f"{feature} produced no valid generated prompts"
        )
    return prompts


def _normalise_env_names(names: Iterable[str]) -> set[str]:
    normalised: set[str] = set()
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(
                "credential environment allowlists accept explicit variable names only"
            )
        normalised.add(name.upper())
    return normalised


def _sanitised_child_env(
    *,
    allow_credentials: Iterable[str] = (),
    env_overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a compatibility-preserving environment with secrets removed.

    Ordinary locale, executable-path and accelerator settings are retained.
    Credential-like variables and runtime-injection variables are removed by
    default.  A caller must name each credential variable explicitly in
    ``allow_credentials`` to forward it.  ``env_overrides`` is for deliberate,
    non-secret adapter configuration; a secret override is rejected unless its
    name is also credential-allowlisted.
    """

    allowed = _normalise_env_names(allow_credentials)
    child: dict[str, str] = {}
    source_by_upper = {name.upper(): (name, value) for name, value in os.environ.items()}

    for upper_name, (name, value) in source_by_upper.items():
        is_sensitive = _is_credential_or_carrier(upper_name)
        is_runtime_injection = (
            upper_name in _RUNTIME_INJECTION_NAMES or upper_name.startswith("DYLD_")
        )
        if is_runtime_injection:
            continue
        if is_sensitive and upper_name not in allowed:
            continue
        child[name] = value

    # Re-add explicitly allowed credentials using their original spelling.
    for upper_name in allowed:
        source = source_by_upper.get(upper_name)
        if source is not None:
            child[source[0]] = source[1]

    for name, value in (env_overrides or {}).items():
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", name
        ):
            raise ValueError(f"invalid child environment variable name: {name!r}")
        if not isinstance(value, str):
            raise TypeError(f"child environment value for {name!r} must be a string")
        if _is_credential_or_carrier(name) and name.upper() not in allowed:
            raise ValueError(
                f"credential-like child variable {name!r} must be explicitly allowlisted"
            )
        # Remove a differently-cased inherited spelling on Windows-like systems.
        for inherited in tuple(child):
            if inherited.upper() == name.upper():
                child.pop(inherited)
        child[name] = value
    return child


def _resolve_timeout(timeout_seconds: float | None) -> float:
    raw: object = timeout_seconds
    if raw is None:
        raw = os.environ.get(
            "URA_ENGINE_TIMEOUT_SECONDS", str(DEFAULT_ENGINE_TIMEOUT_SECONDS)
        )
    try:
        timeout = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("external-engine timeout must be a number of seconds") from exc
    if not math.isfinite(timeout) or timeout <= 0 or timeout > _MAX_ENGINE_TIMEOUT_SECONDS:
        raise ValueError(
            "external-engine timeout must be finite and in the range (0, 86400] seconds"
        )
    return timeout


def _read_bounded(stream, limit: int) -> str:
    marker = b"\n...[diagnostic truncated]"
    stream.flush()
    stream.seek(0)
    data = stream.read(limit + 1)
    if len(data) > limit:
        if limit <= len(marker):
            data = marker[:limit]
        else:
            data = data[: limit - len(marker)] + marker
    return data.decode("utf-8", errors="replace")


def _redact(text: str, env: Mapping[str, str], allowed: set[str]) -> str:
    """Redact deliberately forwarded credentials from child diagnostics."""

    for name, value in env.items():
        if name.upper() in allowed and value:
            text = text.replace(value, "[REDACTED]")
    return text


def _command_label(command: Sequence[str | os.PathLike[str]]) -> str:
    label = " ".join(str(part) for part in command)
    return label if len(label) <= 512 else label[:509] + "..."


def run_engine_command(
    command: Sequence[str | os.PathLike[str]],
    *,
    feature: str,
    cwd: str | os.PathLike[str] | None = None,
    allow_credentials: Iterable[str] = (),
    env_overrides: Mapping[str, str] | None = None,
    timeout_seconds: float | None = None,
    diagnostic_limit_bytes: int = DEFAULT_DIAGNOSTIC_LIMIT_BYTES,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run one external engine command with bounded, filtered diagnostics.

    ``command`` must be an argument sequence; strings are rejected and
    ``shell=False`` is always enforced.  Output is redirected to temporary files
    so a noisy or hostile child cannot grow an in-memory pipe without bound.  At
    most ``diagnostic_limit_bytes`` per stream is returned or attached to an
    actionable :class:`ExternalEngineError`.

    This helper is not a security sandbox and does not isolate HOME, the
    workspace, the network, process descendants, or temporary-file growth while
    the child is running. A provider-backed engine that genuinely needs a credential must expose that
    choice to its caller and pass the exact variable name in ``allow_credentials``
    (for example ``("OPENAI_API_KEY",)``).  No credential is forwarded by default.
    """

    if isinstance(command, (str, bytes)) or not command:
        raise TypeError("external-engine command must be a non-empty argument sequence")
    args = [os.fspath(part) for part in command]
    if any(not isinstance(part, str) or not part for part in args):
        raise ValueError("external-engine command arguments must be non-empty strings")
    if (
        not isinstance(diagnostic_limit_bytes, int)
        or diagnostic_limit_bytes <= 0
        or diagnostic_limit_bytes > _MAX_DIAGNOSTIC_LIMIT_BYTES
    ):
        raise ValueError(
            "diagnostic_limit_bytes must be in the range [1, 1048576]"
        )

    timeout = _resolve_timeout(timeout_seconds)
    allowed = _normalise_env_names(allow_credentials)
    child_env = _sanitised_child_env(
        allow_credentials=allowed,
        env_overrides=env_overrides,
    )
    command_text = _redact(_command_label(args), child_env, allowed)

    with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
        mode="w+b"
    ) as stderr_file:
        try:
            completed = subprocess.run(
                args,
                check=False,
                cwd=Path(cwd) if cwd is not None else None,
                env=child_env,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _redact(
                _read_bounded(stdout_file, diagnostic_limit_bytes), child_env, allowed
            )
            stderr = _redact(
                _read_bounded(stderr_file, diagnostic_limit_bytes), child_env, allowed
            )
            detail = _diagnostic_detail(stdout, stderr)
            raise ExternalEngineError(
                f"{feature} timed out after {timeout:g}s while running: "
                f"{command_text}{detail}"
            ) from exc
        except OSError as exc:
            raise ExternalEngineError(
                f"{feature} could not start external command {command_text}: {exc}"
            ) from exc

        stdout = _redact(
            _read_bounded(stdout_file, diagnostic_limit_bytes), child_env, allowed
        )
        stderr = _redact(
            _read_bounded(stderr_file, diagnostic_limit_bytes), child_env, allowed
        )
        result = subprocess.CompletedProcess(
            args=args,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )
        if check and result.returncode != 0:
            raise ExternalEngineError(
                f"{feature} external command exited with status {result.returncode}: "
                f"{command_text}{_diagnostic_detail(stdout, stderr)}"
            )
        return result


def _diagnostic_detail(stdout: str, stderr: str) -> str:
    parts: list[str] = []
    if stdout:
        parts.append(f"stdout={stdout!r}")
    if stderr:
        parts.append(f"stderr={stderr!r}")
    return " (" + "; ".join(parts) + ")" if parts else ""


def _require(module: str, feature: str, pip_name: str | None = None):
    """Lazily import ``module`` or raise a uniform install hint.

    Kept in one place so every engine reports missing deps identically. The
    install hint names the distributable ``pip_name`` (defaults to the module's
    top-level package).
    """
    import importlib

    pkg = pip_name or module.split(".", 1)[0]
    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            f"{pkg} is required for {feature}; pip install {pkg}"
        ) from exc


def _seed_dialog(datapoint: DataPoint, prompt: str) -> list[DialogTurn]:
    """Render an engine-produced prompt as a dialog, preserving prior history."""
    history = list(datapoint.dialog_history)
    history.append(DialogTurn(role="user", content=prompt))
    return history


def _attempt(
    datapoint: DataPoint,
    attacker: str,
    strategy: str,
    turn_index: int,
    prompt: str,
    seed: int,
    params: dict | None = None,
) -> Attempt:
    """Build a schema-valid :class:`Attempt` for a single engine turn."""
    return Attempt(
        # seed in the id so multi-seed runs do not collide across the transfer/kappa
        # maps that key on attempt_id (id stays model-independent for transfer matching).
        id=f"{datapoint.id}:{attacker}:{turn_index}::s{seed}",
        datapoint_id=datapoint.id,
        attacker=attacker,
        strategy=strategy,
        turn_index=turn_index,
        rendered_input=_seed_dialog(datapoint, prompt),
        seed=seed,
        params=params or {},
    )
