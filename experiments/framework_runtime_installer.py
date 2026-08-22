"""Install the locked third-party framework runtimes without polluting the URA venv.

The repository lock is intentionally data-only.  This module validates it before doing
anything, creates each runtime in a private staging directory, verifies it without model or
provider access, and atomically promotes the stage.  Mutating/whole-matrix verification
commands relaunch under tmux (screen is the explicit fallback) so an SSH disconnect cannot
orphan the operation.
"""

from __future__ import annotations

import argparse
import codecs
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import tomllib
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "ura-framework-runtime-lock/1"
DEFAULT_LOCK = Path(__file__).with_name("framework_runtime_lock.json")
RECEIPT_NAME = ".ura-runtime-receipt.json"
STATE_NAME = ".ura-install-state.json"
CONTENT_SEAL_SCHEMA = "ura-framework-runtime-content-seal/2"
CAMPAIGN_SCHEMA = "ura-engineering-campaign/1"
MAX_CAMPAIGN_LOG_BYTES = 512 * 1024
MAX_COMMAND_LOG_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_SESSION_SECONDS = 168 * 60 * 60
SAFE_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PINNED_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?(?:==[^\s;]+|\s+@\s+https://[^\s]+)"
)
ALLOWED_TOP_LEVEL = {
    "schema",
    "lock_id",
    "generated_at",
    "platform",
    "policy",
    "runtimes",
    "frameworks",
    "coverage",
}
ALLOWED_FRAMEWORK = {
    "name",
    "canonical_name",
    "kind",
    "version",
    "env_slug",
    "runtime",
    "source",
    "artifacts",
    "dependencies",
    "install",
    "smoke",
    "expected_inventory",
    "audit",
}
PROVIDER_ENV_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "AWS_",
    "AZURE_",
    "MISTRAL_",
    "HF_",
    "HUGGINGFACE_",
)
EXPECTED_ATTACKERS = {
    "replay",
    "crescendo",
    "pyrit",
    "deepteam",
    "h4rm3l",
    "spikee",
    "nanogcg",
    "harmbench",
    "purplellama",
    "ideator",
    "t3mp3st",
    "garak",
    "promptfoo",
    "petri",
    "fuzzyai",
    "easyjailbreak",
    "autodan",
    "giskard",
    "asb",
    "agentdojo",
}


class InstallerError(RuntimeError):
    """A fail-closed installer or verifier error."""


def _exact_keys(
    value: Any,
    required: set[str],
    label: str,
    *,
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InstallerError(f"{label} must be an object")
    keys = set(value)
    allowed = required | (optional or set())
    missing = required - keys
    unknown = keys - allowed
    if missing or unknown:
        raise InstallerError(
            f"{label} keys are invalid (missing={sorted(missing)}, unknown={sorted(unknown)})"
        )
    return value


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _strict_json_loads(value: str | bytes) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return json.loads(
        value,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_json_constant,
    )


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _check_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise InstallerError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _path_free(value: Any, label: str = "receipt") -> None:
    """Reject host-specific absolute paths in persistent receipts and summaries."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            _path_free(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _path_free(item, f"{label}[{index}]")
    elif isinstance(value, str):
        if value.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", value):
            raise InstallerError(f"{label} contains an absolute host path")


def _logical_requirements(text: str) -> list[str]:
    logical: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        current += line
        logical.append(current.strip())
        current = ""
    if current:
        raise InstallerError("dependency lock ends in a dangling continuation")
    return logical


def _validate_hashed_requirements(text: str, expected_count: int, label: str) -> None:
    rows = _logical_requirements(text)
    if len(rows) != expected_count:
        raise InstallerError(f"{label} package count is {len(rows)}, expected {expected_count}")
    for row in rows:
        if not PINNED_REQUIREMENT.match(row):
            raise InstallerError(f"{label} contains a non-exact requirement: {row[:100]}")
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)", row)
        if not hashes:
            raise InstallerError(f"{label} requirement lacks a SHA-256 hash: {row[:100]}")


def load_lock(path: Path = DEFAULT_LOCK) -> dict[str, Any]:
    """Load and strictly validate the single repository-owned runtime lock."""

    try:
        raw = path.read_bytes()
        lock = _strict_json_loads(raw)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise InstallerError(f"cannot read runtime lock: {exc}") from exc
    if not isinstance(lock, dict):
        raise InstallerError("runtime lock must be a JSON object")
    unknown = set(lock) - ALLOWED_TOP_LEVEL
    if unknown:
        raise InstallerError(f"unknown runtime-lock keys: {sorted(unknown)}")
    if lock.get("schema") != SCHEMA:
        raise InstallerError(f"runtime lock schema must be {SCHEMA!r}")
    _check_sha(lock.get("lock_id"), "lock_id")
    generated_at = lock.get("generated_at")
    if not isinstance(generated_at, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", generated_at
    ):
        raise InstallerError("generated_at must be one canonical UTC timestamp")
    platform = lock.get("platform")
    if platform != {"os": "linux", "arch": "x86_64"}:
        raise InstallerError("this lock must target linux/x86_64 exactly")
    required_policy = {
        "one_environment_per_framework": True,
        "system_site_packages": False,
        "provider_calls": False,
        "model_calls": False,
        "offline_smoke": True,
        "atomic_promotion": True,
        "session_launcher": "tmux-or-screen",
        "content_seal": True,
        "path_free_receipts": True,
        "fully_hashed_dependencies": True,
    }
    policy = _exact_keys(lock.get("policy"), set(required_policy), "policy")
    for key, expected in required_policy.items():
        if policy.get(key) != expected:
            raise InstallerError(f"policy.{key} must be {expected!r}")
    runtimes = lock.get("runtimes")
    if not isinstance(runtimes, dict) or set(runtimes) != {"python", "node", "git_lfs"}:
        raise InstallerError("runtimes must define exactly python, node, and git_lfs")
    py_runtime = _exact_keys(
        runtimes["python"],
        {"kind", "version", "binary_sha256"},
        "runtimes.python",
    )
    if py_runtime.get("kind") != "cpython" or py_runtime.get("version") != "3.12.13":
        raise InstallerError("the Python runtime must be exact CPython 3.12.13")
    _check_sha(py_runtime.get("binary_sha256"), "runtimes.python.binary_sha256")
    node_runtime = _exact_keys(
        runtimes["node"],
        {
            "kind",
            "version",
            "url",
            "filename",
            "sha256",
            "size",
            "checksums",
            "signature",
            "signing_keyring",
            "signer_fingerprint",
        },
        "runtimes.node",
    )
    if node_runtime.get("kind") != "nodejs-official-tar":
        raise InstallerError("Node must use the official retained tar runtime")
    _validate_artifact(node_runtime, "runtimes.node", allow_extra=True)
    for key in ("checksums", "signature"):
        _validate_artifact(node_runtime.get(key), f"runtimes.node.{key}")
    _validate_source(node_runtime.get("signing_keyring"), "runtimes.node.signing_keyring", runtimes)
    fingerprint = node_runtime.get("signer_fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
        raise InstallerError("runtimes.node.signer_fingerprint must be an uppercase fingerprint")
    lfs_runtime = runtimes["git_lfs"]
    if lfs_runtime not in (None, {"required": False}):
        _exact_keys(
            lfs_runtime,
            {"required", "url", "filename", "sha256", "size", "version"},
            "runtimes.git_lfs",
        )
        if lfs_runtime.get("required") is not True:
            raise InstallerError("git_lfs must be disabled or a pinned runtime object")
        _validate_artifact(lfs_runtime, "runtimes.git_lfs", allow_extra=True)

    frameworks = lock.get("frameworks")
    if not isinstance(frameworks, list) or not frameworks:
        raise InstallerError("frameworks must be a non-empty list")
    names: set[str] = set()
    slugs: set[str] = set()
    for index, entry in enumerate(frameworks):
        label = f"frameworks[{index}]"
        if not isinstance(entry, dict):
            raise InstallerError(f"{label} must be an object")
        _exact_keys(entry, ALLOWED_FRAMEWORK, label)
        name = entry.get("name")
        slug = entry.get("env_slug")
        if not isinstance(name, str) or not SAFE_SLUG.fullmatch(name):
            raise InstallerError(f"{label}.name is invalid")
        if not isinstance(slug, str) or not SAFE_SLUG.fullmatch(slug):
            raise InstallerError(f"{label}.env_slug is invalid")
        if name in names or slug in slugs:
            raise InstallerError("framework names and environment slugs must be unique")
        canonical_name = entry.get("canonical_name")
        version = entry.get("version")
        kind = entry.get("kind")
        if not isinstance(canonical_name, str) or not canonical_name.strip() or len(canonical_name) > 200:
            raise InstallerError(f"{label}.canonical_name is invalid")
        if not isinstance(version, str) or not version.strip() or len(version) > 128:
            raise InstallerError(f"{label}.version is invalid")
        if kind not in {"pypi", "git", "pypi+git", "npm+git"}:
            raise InstallerError(f"{label}.kind is invalid")
        names.add(name)
        slugs.add(slug)
        runtime_name = entry.get("runtime")
        if runtime_name not in ("python", "node"):
            raise InstallerError(f"{label}.runtime must be python or node")
        artifacts = entry.get("artifacts")
        if not isinstance(artifacts, list):
            raise InstallerError(f"{label}.artifacts must be a list")
        artifact_names: set[str] = set()
        for artifact_index, artifact in enumerate(artifacts):
            _validate_artifact(artifact, f"{label}.artifacts[{artifact_index}]")
            filename = artifact["filename"]
            if filename in artifact_names:
                raise InstallerError(f"{label}.artifacts filenames must be unique")
            artifact_names.add(filename)
        source = entry.get("source")
        if source is not None:
            _validate_source(source, f"{label}.source", runtimes)
        if kind == "pypi" and (source is not None or not artifacts):
            raise InstallerError(f"{label} pypi provenance is inconsistent")
        if kind == "git" and (source is None or artifacts):
            raise InstallerError(f"{label} git provenance is inconsistent")
        if kind in {"pypi+git", "npm+git"} and (source is None or not artifacts):
            raise InstallerError(f"{label} combined provenance is inconsistent")
        if runtime_name == "python":
            deps = _exact_keys(
                entry.get("dependencies"),
                {"fully_hashed", "requirements", "sha256", "package_count"},
                f"{label}.dependencies",
            )
            if deps.get("fully_hashed") is not True:
                raise InstallerError(f"{label}.dependencies must be fully hash locked")
            text = deps.get("requirements")
            if not isinstance(text, str) or not text.endswith("\n"):
                raise InstallerError(f"{label}.dependencies.requirements must end in newline")
            _check_sha(deps.get("sha256"), f"{label}.dependencies.sha256")
            if _sha256_bytes(text.encode()) != deps["sha256"]:
                raise InstallerError(f"{label}.dependencies SHA-256 mismatch")
            count = deps.get("package_count")
            if not isinstance(count, int) or count < 0:
                raise InstallerError(f"{label}.dependencies.package_count is invalid")
            _validate_hashed_requirements(text, count, label)
        else:
            deps = _exact_keys(
                entry.get("dependencies"),
                {"fully_hashed", "npm_lock", "sha256", "package_count"},
                f"{label}.dependencies",
            )
            if deps.get("fully_hashed") is not True:
                raise InstallerError(f"{label}.dependencies must be fully hash locked")
            npm_lock = deps.get("npm_lock")
            if not isinstance(npm_lock, dict) or npm_lock.get("lockfileVersion") != 3:
                raise InstallerError(f"{label} must embed npm lockfileVersion 3")
            digest = deps.get("sha256")
            _check_sha(digest, f"{label}.dependencies.sha256")
            if _sha256_bytes(_canonical_json(npm_lock)) != digest:
                raise InstallerError(f"{label} npm lock SHA-256 mismatch")
            packages = npm_lock.get("packages", {})
            if deps.get("package_count") != len(packages) - 1:
                raise InstallerError(f"{label} npm package count is invalid")
            for package_path, package in packages.items():
                if package.get("resolved") and not package.get("integrity"):
                    raise InstallerError(f"{label} npm package lacks integrity: {package_path}")
        install_required = (
            {"source_mode", "timeout_seconds", "commands", "constraints", "repair"}
            if runtime_name == "python"
            else {
                "source_mode",
                "timeout_seconds",
                "commands",
                "constraints",
                "repair",
                "node_runtime_dir",
                "node_version",
            }
        )
        install = _exact_keys(entry.get("install"), install_required, f"{label}.install")
        source_mode = install.get("source_mode")
        if source_mode not in {"none", "wheel", "source-only", "provenance-only"}:
            raise InstallerError(f"{label}.install.source_mode is invalid")
        if (source_mode == "none") != (source is None):
            raise InstallerError(f"{label}.install.source_mode disagrees with source provenance")
        if runtime_name == "node" and source_mode != "provenance-only":
            raise InstallerError(f"{label}.install Node source mode is invalid")
        if not isinstance(install.get("timeout_seconds"), int) or install["timeout_seconds"] <= 0:
            raise InstallerError(f"{label}.install.timeout_seconds is invalid")
        if not isinstance(install.get("commands"), list) or not all(
            isinstance(command, str) and command for command in install["commands"]
        ):
            raise InstallerError(f"{label}.install.commands is invalid")
        if not isinstance(install.get("constraints"), list) or not all(
            isinstance(item, str) and item for item in install["constraints"]
        ):
            raise InstallerError(f"{label}.install.constraints is invalid")
        if not isinstance(install.get("repair"), str) or not install["repair"]:
            raise InstallerError(f"{label}.install.repair is invalid")
        if runtime_name == "node" and (
            install.get("node_version") != node_runtime["version"]
            or not isinstance(install.get("node_runtime_dir"), str)
            or not SAFE_SLUG.fullmatch(install["node_runtime_dir"])
        ):
            raise InstallerError(f"{label}.install Node runtime identity is invalid")
        smoke_required = (
            {"mode", "network", "module", "environment", "timeout_seconds"}
            if runtime_name == "python"
            else {
                "mode",
                "network",
                "relative_cli",
                "args",
                "expected_version",
                "timeout_seconds",
            }
        )
        smoke = _exact_keys(entry.get("smoke"), smoke_required, f"{label}.smoke")
        if smoke.get("network") != "denied":
            raise InstallerError(f"{label}.smoke must deny network")
        timeout = smoke.get("timeout_seconds")
        if not isinstance(timeout, int) or timeout <= 0:
            raise InstallerError(f"{label}.smoke.timeout_seconds is invalid")
        if runtime_name == "python":
            module = smoke.get("module")
            environment = smoke.get("environment")
            if smoke.get("mode") != "import":
                raise InstallerError(f"{label}.smoke mode must be import")
            if not isinstance(module, str) or not re.fullmatch(
                r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module
            ):
                raise InstallerError(f"{label}.smoke.module is invalid")
            if not isinstance(environment, Mapping) or not all(
                isinstance(key, str) and key and isinstance(value, str)
                for key, value in environment.items()
            ):
                raise InstallerError(f"{label}.smoke.environment is invalid")
            for key in environment:
                if any(marker in key.upper() for marker in PROVIDER_ENV_MARKERS):
                    raise InstallerError(f"{label}.smoke.environment contains a credential key")
        else:
            relative_cli = smoke.get("relative_cli")
            args = smoke.get("args")
            expected_version = smoke.get("expected_version")
            if smoke.get("mode") != "cli-version":
                raise InstallerError(f"{label}.smoke mode must be cli-version")
            if (
                not isinstance(relative_cli, str)
                or not relative_cli
                or Path(relative_cli).is_absolute()
                or ".." in Path(relative_cli).parts
            ):
                raise InstallerError(f"{label}.smoke.relative_cli is invalid")
            if not isinstance(args, list) or not all(
                isinstance(argument, str) and argument for argument in args
            ):
                raise InstallerError(f"{label}.smoke.args is invalid")
            if not isinstance(expected_version, str) or expected_version != version:
                raise InstallerError(f"{label}.smoke.expected_version is invalid")
        inventory_keys = (
            {"distributions", "sha256"}
            if runtime_name == "python"
            else {"packages", "package_count", "sha256"}
        )
        inventory = _exact_keys(
            entry.get("expected_inventory"), inventory_keys, f"{label}.expected_inventory"
        )
        rows = inventory.get("distributions")
        if runtime_name == "python":
            parsed_rows = (
                [tuple(row.split("==", 1)) for row in rows]
                if isinstance(rows, list)
                and all(
                    isinstance(row, str)
                    and re.fullmatch(r"[a-z0-9][a-z0-9._-]*==\S+", row)
                    for row in rows
                )
                else []
            )
            if (
                not isinstance(rows, list)
                or len(parsed_rows) != len(rows)
                or parsed_rows != sorted(set(parsed_rows))
            ):
                raise InstallerError(f"{label} inventory distributions are invalid")
            blob = "".join(f"{row}\n" for row in rows).encode()
            _check_sha(inventory.get("sha256"), f"{label}.expected_inventory.sha256")
            if _sha256_bytes(blob) != inventory["sha256"]:
                raise InstallerError(f"{label} expected inventory SHA-256 mismatch")
        else:
            packages = inventory.get("packages")
            count = inventory.get("package_count")
            if (
                not isinstance(packages, list)
                or not all(isinstance(row, str) for row in packages)
                or packages != sorted(packages)
                or not isinstance(count, int)
                or count != len(packages)
            ):
                raise InstallerError(f"{label} installed npm inventory is invalid")
            blob = "".join(f"{row}\n" for row in packages).encode()
            _check_sha(inventory.get("sha256"), f"{label}.expected_inventory.sha256")
            if _sha256_bytes(blob) != inventory["sha256"]:
                raise InstallerError(f"{label} expected npm inventory SHA-256 mismatch")
        audit = _exact_keys(
            entry.get("audit"),
            {
                "packaging_status",
                "check_status",
                "smoke_status",
                "inventory_sha256",
                "distribution_count",
                "disk_usage_bytes",
                "receipt_sha256",
                "git_lfs_required",
                "notes",
            },
            f"{label}.audit",
        )
        _check_sha(audit.get("inventory_sha256"), f"{label}.audit.inventory_sha256")
        if audit["inventory_sha256"] != inventory["sha256"]:
            raise InstallerError(f"{label} audit inventory differs from expected inventory")
        if audit.get("packaging_status") != "passed" or audit.get("check_status") != "passed" or audit.get("smoke_status") != "passed":
            raise InstallerError(f"{label} audit is not terminal-passed")
        expected_count = len(rows) if runtime_name == "python" else inventory["package_count"]
        if audit.get("distribution_count") != expected_count:
            raise InstallerError(f"{label} audit package count is invalid")
        if not isinstance(audit.get("disk_usage_bytes"), int) or audit["disk_usage_bytes"] <= 0:
            raise InstallerError(f"{label} audit disk usage is invalid")
        receipt_sha = audit.get("receipt_sha256")
        if receipt_sha is not None:
            _check_sha(receipt_sha, f"{label}.audit.receipt_sha256")
        if audit.get("git_lfs_required") is not False:
            raise InstallerError(f"{label} audit Git LFS fact is invalid")
        if not isinstance(audit.get("notes"), list) or not all(
            isinstance(note, str) and note for note in audit["notes"]
        ):
            raise InstallerError(f"{label} audit notes are invalid")
        _path_free({"entry": {k: v for k, v in entry.items() if k != "source"}}, label)
    coverage = lock.get("coverage")
    if not isinstance(coverage, list) or len(coverage) != 20:
        raise InstallerError("coverage must contain exactly the 20 registered attackers")
    coverage_names: set[str] = set()
    framework_names = {entry["name"] for entry in frameworks}
    for index, item in enumerate(coverage):
        label = f"coverage[{index}]"
        row = _exact_keys(item, {"attacker", "status", "runtime", "reason"}, label)
        attacker = row.get("attacker")
        if not isinstance(attacker, str) or not SAFE_SLUG.fullmatch(attacker):
            raise InstallerError(f"{label}.attacker is invalid")
        if attacker in coverage_names:
            raise InstallerError("coverage attacker names must be unique")
        coverage_names.add(attacker)
        status = row.get("status")
        if status not in {"installer-managed", "built-in", "precomputed-only", "blocked-unpinned"}:
            raise InstallerError(f"{label}.status is invalid")
        runtime_name = row.get("runtime")
        if status == "installer-managed" and runtime_name not in framework_names:
            raise InstallerError(f"{label} references an unknown managed runtime")
        if status != "installer-managed" and runtime_name is not None:
            raise InstallerError(f"{label} non-managed attacker must have null runtime")
        if not isinstance(row.get("reason"), str) or not row["reason"]:
            raise InstallerError(f"{label}.reason is invalid")
    if coverage_names != EXPECTED_ATTACKERS:
        raise InstallerError("coverage does not match the 20 registered attackers")
    managed_runtime_names = {
        item["runtime"] for item in coverage if item["status"] == "installer-managed"
    }
    if managed_runtime_names != framework_names:
        raise InstallerError("managed attacker coverage differs from framework runtimes")
    _path_free(coverage, "coverage")
    expected_lock_id = _lock_content_id(lock)
    if lock["lock_id"] != expected_lock_id:
        raise InstallerError("lock_id does not match canonical lock content")
    return lock


def _lock_content_id(lock: Mapping[str, Any]) -> str:
    content = dict(lock)
    content["lock_id"] = "0" * 64
    return _sha256_bytes(_canonical_json(content))


def _validate_artifact(
    artifact: Mapping[str, Any], label: str, *, allow_extra: bool = False
) -> None:
    if not isinstance(artifact, Mapping):
        raise InstallerError(f"{label} must be an object")
    if not allow_extra:
        _exact_keys(artifact, {"url", "filename", "sha256", "size"}, label)
    url = artifact.get("url")
    if not isinstance(url, str) or urllib.parse.urlparse(url).scheme != "https":
        raise InstallerError(f"{label}.url must use https")
    filename = artifact.get("filename")
    if not isinstance(filename, str) or Path(filename).name != filename:
        raise InstallerError(f"{label}.filename must be a basename")
    _check_sha(artifact.get("sha256"), f"{label}.sha256")
    if "size" not in artifact or not isinstance(artifact["size"], int) or artifact["size"] <= 0:
        raise InstallerError(f"{label}.size must be positive")


def _validate_source(source: Mapping[str, Any], label: str, runtimes: Mapping[str, Any]) -> None:
    _exact_keys(
        source,
        {"kind", "url", "commit", "tree", "archive_sha256", "git_lfs_required"},
        label,
    )
    if source.get("kind") != "git":
        raise InstallerError(f"{label}.kind must be git")
    url = source.get("url")
    if not isinstance(url, str) or urllib.parse.urlparse(url).scheme != "https":
        raise InstallerError(f"{label}.url must use https")
    commit = source.get("commit")
    tree = source.get("tree")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise InstallerError(f"{label}.commit must be a full SHA-1")
    if not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise InstallerError(f"{label}.tree must be a full SHA-1")
    _check_sha(source.get("archive_sha256"), f"{label}.archive_sha256")
    lfs_required = source.get("git_lfs_required")
    if not isinstance(lfs_required, bool):
        raise InstallerError(f"{label}.git_lfs_required must be boolean")
    if lfs_required and runtimes.get("git_lfs") in (None, {"required": False}):
        raise InstallerError(f"{label} needs Git LFS but no pinned runtime is locked")


def select_frameworks(lock: Mapping[str, Any], only: Sequence[str] | None) -> list[dict[str, Any]]:
    entries = list(lock["frameworks"])
    if not only:
        return entries
    requested = {_canonical_name(name) for name in only}
    by_name = {_canonical_name(entry["name"]): entry for entry in entries}
    missing = sorted(requested - set(by_name))
    if missing:
        raise InstallerError(f"unknown --only framework(s): {', '.join(missing)}")
    return [entry for entry in entries if _canonical_name(entry["name"]) in requested]


@dataclass(frozen=True)
class Layout:
    env_root: Path
    state_root: Path

    @property
    def store_root(self) -> Path:
        """Stable construction paths; built environments are never renamed."""

        return self.env_root / ".store"

    @property
    def lock_file(self) -> Path:
        return self.state_root / "framework-runtime-installer.lock"

    @property
    def cache_root(self) -> Path:
        """Shared package cache outside every sealed runtime store.

        Installer subprocesses receive a clean, per-runtime ``HOME``.  Without
        an explicit cache root that also discards the operator's pip/npm cache,
        making an interrupted repair or a new lock download every unchanged
        artifact again.  The cache is only a transport optimization: hashes,
        inventories, smokes, and content seals still decide admission.
        """

        return _lexically_contained(self.env_root, self.env_root / ".cache")

    @property
    def pip_cache(self) -> Path:
        return _lexically_contained(self.cache_root, self.cache_root / "pip")

    @property
    def npm_cache(self) -> Path:
        return _lexically_contained(self.cache_root, self.cache_root / "npm")

    def final(self, slug: str) -> Path:
        return _lexically_contained(self.env_root, self.env_root / slug)

    def store(self, slug: str, lock_id: str) -> Path:
        if not SHA256.fullmatch(lock_id):
            raise InstallerError("invalid lock id for environment store")
        name = f"{slug}-{lock_id[:16]}"
        return _lexically_contained(self.store_root, self.store_root / name)


def _lexically_contained(root: Path, candidate: Path) -> Path:
    """Return an absolute lexical child without following the final alias symlink."""

    root_absolute = Path(os.path.abspath(root))
    candidate_absolute = Path(os.path.abspath(candidate))
    if candidate_absolute == root_absolute or root_absolute not in candidate_absolute.parents:
        raise InstallerError("unsafe target outside runtime root")
    return candidate_absolute


def _path_exists(path: Path) -> bool:
    """Like lexists: a broken publication symlink still occupies its name."""

    return path.exists() or path.is_symlink()


def _unsafe_link(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        attributes = 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return (
        path.is_symlink()
        or bool(hasattr(path, "is_junction") and path.is_junction())
        or bool(reparse_flag and attributes & reparse_flag)
    )


def _safe_regular_identity(path: Path) -> tuple[int, int, int]:
    info = path.lstat()
    if _unsafe_link(path) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InstallerError(f"unsafe managed file: {path.name}")
    return info.st_dev, info.st_ino, info.st_mode


def _safe_managed_parent(path: Path) -> Path:
    parent = path.parent.resolve(strict=True)
    if Path(os.path.abspath(path.parent)) != parent or _unsafe_link(path.parent):
        raise InstallerError(f"unsafe managed parent for {path.name}")
    return parent


def _fsync_parent(parent: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """Create a no-follow temp and replace one safe managed regular file."""

    parent = _safe_managed_parent(path)
    if _path_exists(path):
        _safe_regular_identity(path)
    temporary = parent / f".{path.name}.tmp-{os.getpid()}-{time.time_ns()}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        opened = os.fstat(descriptor)
        visible = temporary.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or visible.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_mode)
            != (visible.st_dev, visible.st_ino, visible.st_mode)
        ):
            raise InstallerError(f"unsafe managed temporary for {path.name}")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _safe_regular_identity(path)
        _fsync_parent(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def _append_bounded_bytes(path: Path, payload: bytes, *, limit: int) -> bool:
    """Append through a no-follow single-link descriptor; return false if truncated."""

    _safe_managed_parent(path)
    before = _safe_regular_identity(path) if _path_exists(path) else None
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        opened = os.fstat(descriptor)
        visible = path.lstat()
        identity = (opened.st_dev, opened.st_ino, opened.st_mode)
        if (
            _unsafe_link(path)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or visible.st_nlink != 1
            or identity != (visible.st_dev, visible.st_ino, visible.st_mode)
            or (before is not None and before != identity)
        ):
            raise InstallerError(f"unsafe managed append file: {path.name}")
        remaining = max(0, limit - opened.st_size)
        chunk = payload[:remaining]
        if chunk:
            written = os.write(descriptor, chunk)
            if written != len(chunk):
                raise InstallerError(f"incomplete managed append: {path.name}")
            os.fsync(descriptor)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            after.st_nlink != 1
            or named.st_nlink != 1
            or (after.st_dev, after.st_ino, after.st_mode)
            != (named.st_dev, named.st_ino, named.st_mode)
        ):
            raise InstallerError(f"managed append target changed: {path.name}")
        return len(chunk) == len(payload)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _unlink_owned_regular(path: Path) -> None:
    parent = _safe_managed_parent(path)
    if not _path_exists(path):
        return
    identity = _safe_regular_identity(path)
    current = path.lstat()
    if identity != (current.st_dev, current.st_ino, current.st_mode):
        raise InstallerError(f"managed file changed before unlink: {path.name}")
    path.unlink()
    _fsync_parent(parent)


def _alias_points_to(alias: Path, store: Path) -> bool:
    if not alias.is_symlink():
        return False
    try:
        return alias.resolve(strict=True) == store.resolve(strict=True)
    except OSError:
        return False


def _managed_alias_target(layout: Layout, slug: str) -> Path | None:
    alias = layout.final(slug)
    if not alias.is_symlink():
        return None
    try:
        raw_target = os.readlink(alias)
        if Path(raw_target).is_absolute():
            return None
        target = alias.parent.joinpath(raw_target).resolve(strict=True)
        store_root = layout.store_root.resolve(strict=True)
        if (
            target.parent != store_root
            or _unsafe_link(target)
            or not target.is_dir()
            or not re.fullmatch(rf"{re.escape(slug)}-[0-9a-f]{{16}}", target.name)
        ):
            return None
        return target
    except OSError:
        return None


def _publish_alias(layout: Layout, slug: str, store: Path) -> None:
    """Atomically publish a relative symlink while preserving venv shebang paths."""

    final = layout.final(slug)
    if _path_exists(final):
        if _alias_points_to(final, store):
            return
        if _managed_alias_target(layout, slug) is None:
            raise InstallerError(f"refusing to replace existing runtime alias: {slug}")
    relative_target = os.path.relpath(store, layout.env_root)
    temp = _lexically_contained(
        layout.env_root,
        layout.env_root / f".publish-{slug}-{os.getpid()}-{time.time_ns()}",
    )
    try:
        os.symlink(relative_target, temp, target_is_directory=True)
        os.replace(temp, final)
        _fsync_parent(layout.env_root.resolve(strict=True))
    finally:
        if temp.is_symlink():
            temp.unlink()
    if not _alias_points_to(final, store):
        raise InstallerError(f"runtime alias publication failed: {slug}")


def canonical_python_interpreter(
    entry: Mapping[str, Any], lock: Mapping[str, Any], layout: Layout
) -> Path:
    """Return the stable venv-root path while preserving its final python link."""

    if entry.get("runtime") != "python":
        raise InstallerError("canonical Python handoff requires a Python runtime")
    store = layout.store(str(entry["env_slug"]), str(lock["lock_id"]))
    alias = layout.final(str(entry["env_slug"]))
    if not _alias_points_to(alias, store):
        raise InstallerError(f"published runtime alias is invalid: {entry['env_slug']}")
    interpreter = store / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    try:
        info = interpreter.lstat()
    except OSError as exc:
        raise InstallerError(f"runtime interpreter is missing: {entry['env_slug']}") from exc
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        raise InstallerError(f"runtime interpreter is invalid: {entry['env_slug']}")
    return interpreter


class CrossProcessLock:
    """A non-blocking repository-runtime lock on Unix and Windows."""

    def __init__(self, path: Path):
        self.path = path
        self.handle: Any = None

    def __enter__(self) -> "CrossProcessLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor: int | None = None
        try:
            parent = self.path.parent.resolve(strict=True)
            if (
                Path(os.path.abspath(self.path.parent)) != parent
                or _unsafe_link(self.path.parent)
            ):
                raise InstallerError("installer lock parent is unsafe")
            try:
                before = self.path.lstat()
            except FileNotFoundError:
                before = None
            if before is not None and (
                _unsafe_link(self.path)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
            ):
                raise InstallerError("installer lock path is unsafe")
            descriptor = os.open(
                self.path,
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            opened = os.fstat(descriptor)
            after = self.path.lstat()
            opened_identity = (opened.st_dev, opened.st_ino, opened.st_mode)
            after_identity = (after.st_dev, after.st_ino, after.st_mode)
            if (
                _unsafe_link(self.path)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or after.st_nlink != 1
                or opened_identity != after_identity
                or (
                    before is not None
                    and (before.st_dev, before.st_ino, before.st_mode) != opened_identity
                )
                or self.path.resolve(strict=True) != Path(os.path.abspath(self.path))
                or self.path.parent.resolve(strict=True) != parent
            ):
                raise InstallerError("installer lock changed while opening")
            self.handle = os.fdopen(descriptor, "r+b", closefd=True)
            descriptor = None
            self.handle.seek(0)
            if self.handle.read(1) != b"L":
                self.handle.seek(0)
                self.handle.write(b"L")
                self.handle.flush()
                os.fsync(self.handle.fileno())
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError, InstallerError) as exc:
            if descriptor is not None:
                os.close(descriptor)
            if self.handle is not None:
                self.handle.close()
                self.handle = None
            raise InstallerError("another framework runtime installer holds the lock") from exc
        return self

    def __exit__(self, *_: Any) -> None:
        if self.handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()


def _safe_env(home: Path, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "NPM_CONFIG_USERCONFIG": os.devnull,
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    }
    if extra:
        for key, value in extra.items():
            upper = key.upper()
            if any(marker in upper for marker in PROVIDER_ENV_MARKERS):
                raise InstallerError(f"provider/credential environment key is forbidden: {key}")
            env[key] = value
    return env


class _PathRedactor:
    def __init__(self, paths: Sequence[Path | str]):
        tokens: set[str] = set()
        for raw in paths:
            if raw is None:
                continue
            token = str(raw)
            if not token:
                continue
            tokens.add(token)
            tokens.add(token.replace("\\", "/"))
            tokens.add(token.replace("/", "\\"))
            with contextlib.suppress(OSError):
                resolved = str(Path(token).resolve())
                tokens.add(resolved)
                tokens.add(resolved.replace("\\", "/"))
                tokens.add(resolved.replace("/", "\\"))
        self._tokens = tuple(sorted((item for item in tokens if item), key=len, reverse=True))
        self.max_token_length = max((len(item) for item in self._tokens), default=1)

    def __call__(self, text: str) -> str:
        result = text
        for token in self._tokens:
            result = re.sub(re.escape(token), "<runtime-root>", result, flags=re.IGNORECASE)
        return result

    def fixed_width(self, text: str) -> str:
        """Redact with same-width markers so streaming boundaries stay stable."""

        result = text
        for token in self._tokens:
            marker = "<" + ("x" * max(0, len(token) - 2)) + ">"
            marker = marker[: len(token)].ljust(len(token), "x")
            result = re.sub(re.escape(token), marker, result, flags=re.IGNORECASE)
        return result


class CommandRunner:
    def __init__(
        self,
        log_path: Path,
        home: Path,
        *,
        redact_paths: Sequence[Path | str] = (),
        base_env: Mapping[str, str] | None = None,
    ):
        self.log_path = log_path
        self.home = home
        self.base_env = dict(base_env or {})
        self.redact = _PathRedactor((home, *redact_paths))
        self._log_truncated = False
        log_path.parent.mkdir(parents=True, exist_ok=True)

    def _log(self, text: str) -> None:
        if not text or self._log_truncated:
            return
        complete = _append_bounded_bytes(
            self.log_path,
            text.encode("utf-8", errors="replace"),
            limit=MAX_COMMAND_LOG_BYTES,
        )
        if not complete:
            self._log_truncated = True

    @staticmethod
    def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None and os.name == "nt":
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                env={"PATH": os.environ.get("PATH", "")},
            )
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        cwd: Path | None = None,
        extra_env: Mapping[str, str] | None = None,
        timeout: int = 7200,
        capture: bool = False,
        allowed_returncodes: Sequence[int] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in argv]
        executable = Path(command[0]).name if command else "unknown"
        cwd_label = cwd.name if cwd is not None else "default"
        self._log(f"[command] executable={executable} argc={len(command)} cwd={cwd_label}\n")
        child_env = dict(self.base_env)
        if extra_env:
            for key, value in extra_env.items():
                if key in child_env and child_env[key] != value:
                    raise InstallerError(f"command attempted to replace fixed environment key: {key}")
                child_env[key] = value
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=_safe_env(self.home, child_env),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            start_new_session=os.name != "nt",
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt"
                else 0
            ),
        )
        captured: list[str] = []
        captured_bytes = 0
        capture_overflow = False
        reader_errors: list[BaseException] = []

        def drain() -> None:
            nonlocal captured_bytes, capture_overflow
            assert process.stdout is not None
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            pending = ""

            def consume(text: str) -> None:
                nonlocal pending, captured_bytes, capture_overflow
                if capture:
                    encoded_size = len(text.encode("utf-8", errors="replace"))
                    if captured_bytes + encoded_size <= MAX_CAPTURE_BYTES:
                        captured.append(text)
                        captured_bytes += encoded_size
                    else:
                        capture_overflow = True
                pending += text
                cutoff = len(pending) - self.redact.max_token_length
                if cutoff > 0:
                    redacted = self.redact.fixed_width(pending)
                    self._log(redacted[:cutoff])
                    pending = pending[cutoff:]

            try:
                while True:
                    chunk = process.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    consume(decoder.decode(chunk))
                consume(decoder.decode(b"", final=True))
                if pending:
                    self._log(self.redact.fixed_width(pending))
            except BaseException as exc:  # surfaced in the controlling thread
                reader_errors.append(exc)

        reader = threading.Thread(target=drain, name="ura-runtime-log-drain", daemon=True)
        reader.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self._terminate_tree(process)
            reader.join(timeout=10)
            raise InstallerError(f"{executable} command timed out") from exc
        reader.join(timeout=10)
        if reader.is_alive():
            self._terminate_tree(process)
            process.stdout.close() if process.stdout is not None else None
            reader.join(timeout=2)
            raise InstallerError(f"{executable} output stream did not close")
        if reader_errors:
            error = reader_errors[0]
            if isinstance(error, InstallerError):
                raise error
            raise InstallerError(f"{executable} output logging failed") from error
        self._log(f"[exit {returncode}]\n")
        if capture_overflow:
            raise InstallerError(f"{executable} captured output exceeded its bound")
        stdout = "".join(captured) if capture else ""
        completed = subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")
        if returncode not in allowed_returncodes:
            raise InstallerError(f"{executable} command failed with exit code {returncode}")
        return completed


def _download(artifact: Mapping[str, Any], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    _safe_managed_parent(destination)
    if _path_exists(destination):
        _safe_regular_identity(destination)
    if _path_exists(partial):
        _unlink_owned_regular(partial)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(artifact["url"], headers={"User-Agent": "ura-runtime-installer/1"})
    digest = hashlib.sha256()
    size = 0
    expected_size = artifact["size"]
    descriptor: int | None = None
    try:
        descriptor = os.open(
            partial,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        opened = os.fstat(descriptor)
        visible = partial.lstat()
        if (
            _unsafe_link(partial)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or visible.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_mode)
            != (visible.st_dev, visible.st_ino, visible.st_mode)
        ):
            raise InstallerError(f"unsafe artifact partial: {artifact['filename']}")
        with opener.open(request, timeout=60) as response, os.fdopen(
            descriptor, "wb", closefd=True
        ) as output:
            descriptor = None
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise InstallerError(
                        f"invalid Content-Length for {artifact['filename']}"
                    ) from exc
                if declared_length != expected_size:
                    raise InstallerError(f"artifact size mismatch: {artifact['filename']}")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                if size + len(chunk) > expected_size:
                    raise InstallerError(f"artifact exceeds locked size: {artifact['filename']}")
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if _path_exists(partial):
            with contextlib.suppress(InstallerError, OSError):
                _unlink_owned_regular(partial)
        raise
    if digest.hexdigest() != artifact["sha256"]:
        _unlink_owned_regular(partial)
        raise InstallerError(f"artifact hash mismatch: {artifact['filename']}")
    if size != expected_size:
        _unlink_owned_regular(partial)
        raise InstallerError(f"artifact size mismatch: {artifact['filename']}")
    _safe_regular_identity(partial)
    os.replace(partial, destination)
    _safe_regular_identity(destination)
    _fsync_parent(destination.parent)


def _artifact_matches(artifact: Mapping[str, Any], path: Path) -> bool:
    if not _path_exists(path):
        return False
    _safe_regular_identity(path)
    return path.stat().st_size == artifact["size"] and _sha256_file(path) == artifact["sha256"]


def _verify_python_identity(executable: Path, runtime: Mapping[str, Any]) -> None:
    if not executable.is_file():
        raise InstallerError(f"Python executable does not exist: {executable}")
    if _sha256_file(executable) != runtime["binary_sha256"]:
        raise InstallerError("Python executable SHA-256 does not match the lock")
    result = subprocess.run(
        [str(executable), "-c", "import platform; print(platform.python_version())"],
        env=_safe_env(Path(tempfile.gettempdir())),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode or result.stdout.strip() != runtime["version"]:
        raise InstallerError("Python executable version does not match the lock")


def _state_path(stage: Path) -> Path:
    return stage / STATE_NAME


def _read_state(stage: Path) -> dict[str, Any]:
    path = _state_path(stage)
    if not path.exists():
        return {"completed": []}
    try:
        value = _strict_json_loads(path.read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise InstallerError(f"invalid staging state for {stage.name}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("completed"), list):
        raise InstallerError(f"invalid staging state for {stage.name}")
    if any(not isinstance(item, str) for item in value["completed"]):
        raise InstallerError(f"invalid staging phases for {stage.name}")
    if set(value) - {"completed", "lock_id", "framework", "env_slug"}:
        raise InstallerError(f"unknown staging state field for {stage.name}")
    _path_free(value, "install state")
    return value


def _write_state(stage: Path, state: Mapping[str, Any]) -> None:
    _path_free(state, "install state")
    target = _state_path(stage)
    _atomic_write_bytes(target, _canonical_json(state))


def _phase_done(state: dict[str, Any], phase: str) -> bool:
    return phase in state.setdefault("completed", [])


def _complete_phase(stage: Path, state: dict[str, Any], phase: str) -> None:
    if phase not in state.setdefault("completed", []):
        state["completed"].append(phase)
        _write_state(stage, state)


def _remove_owned_path(root: Path, target: Path) -> None:
    expected = _lexically_contained(root, target)
    if expected != Path(os.path.abspath(target)):
        raise InstallerError("refusing to clean outside the owned runtime store")
    if target.is_symlink() or target.is_file():
        target.unlink(missing_ok=True)
    elif target.is_dir():
        shutil.rmtree(target)


def _clear_owned_store(root: Path, *, preserve: set[str]) -> None:
    if _unsafe_link(root) or not root.is_dir():
        raise InstallerError("owned runtime store is unsafe")
    for child in root.iterdir():
        if child.name not in preserve:
            _remove_owned_path(root, child)


def _git_archive_sha(runner: CommandRunner, source_dir: Path) -> str:
    with tempfile.NamedTemporaryFile(dir=source_dir.parent, delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        with archive_path.open("wb") as output:
            completed = subprocess.run(
                ["git", "archive", "--format=tar", "HEAD"],
                cwd=source_dir,
                env=_safe_env(runner.home),
                stdout=output,
                stderr=subprocess.PIPE,
                timeout=300,
                check=False,
            )
        if completed.returncode:
            raise InstallerError("git archive failed")
        return _sha256_file(archive_path)
    finally:
        archive_path.unlink(missing_ok=True)


def _checkout_git_source(
    source: Mapping[str, Any],
    target: Path,
    artifact_root: Path,
    runner: CommandRunner,
    runtimes: Mapping[str, Any],
    label: str,
) -> Path:
    owned_target = _lexically_contained(artifact_root, target)
    if owned_target != Path(os.path.abspath(target)):
        raise InstallerError(f"source checkout is outside the owned store for {label}")
    target.parent.mkdir(parents=True, exist_ok=True)
    _safe_managed_parent(target)
    if _path_exists(target):
        if _unsafe_link(target) or not target.is_dir():
            raise InstallerError(f"source checkout target is unsafe for {label}")
        git_metadata = target / ".git"
        if _path_exists(git_metadata) and (
            _unsafe_link(git_metadata) or not git_metadata.is_dir()
        ):
            raise InstallerError(f"source checkout metadata is unsafe for {label}")
    if not (target / ".git").is_dir():
        runner.run(["git", "init", str(target)])
    remote = runner.run(
        ["git", "remote", "get-url", "origin"],
        cwd=target,
        capture=True,
        allowed_returncodes=(0, 2),
    )
    if remote.returncode == 0:
        if remote.stdout.strip() != source["url"]:
            runner.run(["git", "remote", "set-url", "origin", source["url"]], cwd=target)
    else:
        runner.run(["git", "remote", "add", "origin", source["url"]], cwd=target)
    # Always refetch and force the exact detached checkout.  This repairs an
    # interrupted or locally modified owned checkout instead of making resume
    # fail forever on its stale .git directory.
    runner.run(["git", "fetch", "--force", "--depth=1", "origin", source["commit"]], cwd=target)
    runner.run(["git", "checkout", "--detach", "--force", source["commit"]], cwd=target)
    runner.run(["git", "clean", "-ffdx"], cwd=target)
    head = runner.run(["git", "rev-parse", "HEAD"], cwd=target, capture=True).stdout.strip()
    tree = runner.run(["git", "rev-parse", "HEAD^{tree}"], cwd=target, capture=True).stdout.strip()
    if head != source["commit"] or tree != source["tree"]:
        raise InstallerError(f"source identity mismatch for {label}")
    pointer_result = runner.run(
        ["git", "grep", "-Il", "^version https://git-lfs.github.com/spec/v1$", "HEAD"],
        cwd=target,
        capture=True,
        allowed_returncodes=(0, 1),
    )
    pointers = [line for line in pointer_result.stdout.splitlines() if line.strip()]
    if bool(pointers) != source["git_lfs_required"]:
        raise InstallerError(f"Git LFS pointer audit disagrees with lock for {label}")
    if pointers:
        _run_git_lfs(runtimes["git_lfs"], target, artifact_root, runner)
    if _git_archive_sha(runner, target) != source["archive_sha256"]:
        raise InstallerError(f"git archive SHA-256 mismatch for {label}")
    return target


def _acquire_source(
    entry: Mapping[str, Any], stage: Path, runner: CommandRunner, runtimes: Mapping[str, Any]
) -> Path | None:
    source = entry.get("source")
    if not source:
        return None
    return _checkout_git_source(
        source,
        stage / "source" / entry["name"],
        stage,
        runner,
        runtimes,
        entry["name"],
    )


def _run_git_lfs(
    spec: Mapping[str, Any], source: Path, artifact_root: Path, runner: CommandRunner
) -> None:
    artifact = artifact_root / ".ura" / "artifacts" / spec["filename"]
    if not _artifact_matches(spec, artifact):
        _download(spec, artifact)
    binary = artifact_root / ".ura" / "git-lfs"
    if _path_exists(binary):
        _remove_owned_path(artifact_root, binary)
    shutil.copy2(artifact, binary)
    binary.chmod(0o755)
    runner.run([str(binary), "install", "--local"], cwd=source)
    runner.run([str(binary), "fetch", "origin", "HEAD"], cwd=source)
    runner.run([str(binary), "checkout"], cwd=source)


def _python_inventory(python: Path, runner: CommandRunner) -> tuple[list[str], str]:
    code = (
        "import importlib.metadata as m,json,re;"
        "r=sorted((re.sub(r'[-_.]+','-',d.metadata['Name']).lower(),d.version) "
        "for d in m.distributions() if d.metadata.get('Name'));"
        "print(json.dumps([f'{n}=={v}' for n,v in r],separators=(',',':')))"
    )
    result = runner.run([str(python), "-c", code], capture=True, timeout=120)
    rows = _strict_json_loads(result.stdout)
    digest = _sha256_bytes("".join(f"{row}\n" for row in rows).encode())
    return rows, digest


def _seal_excluded(relative: Path) -> bool:
    # Receipt/state are installer metadata written outside the immutable
    # runtime payload.  Bytecode is payload: nested legacy sourceless modules
    # are executable and therefore must be bound by the published seal.
    return relative.name in {RECEIPT_NAME, STATE_NAME}


def _content_seal(root: Path) -> dict[str, Any]:
    """Bind every regular/symlinked runtime payload file to a receipt."""

    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    if not root.is_dir():
        raise InstallerError("runtime content root is missing")
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if _seal_excluded(relative):
            continue
        try:
            if path.is_symlink():
                target = os.readlink(path)
                digest.update(b"L\0")
                digest.update(relative.as_posix().encode("utf-8"))
                digest.update(b"\0")
                digest.update(target.encode("utf-8"))
                digest.update(b"\0")
                file_count += 1
            elif path.is_file():
                stat_result = path.stat()
                digest.update(b"F\0")
                digest.update(relative.as_posix().encode("utf-8"))
                digest.update(b"\0")
                digest.update(b"x" if stat_result.st_mode & 0o111 else b"-")
                digest.update(b"\0")
                digest.update(str(stat_result.st_size).encode("ascii"))
                digest.update(b"\0")
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                digest.update(b"\0")
                file_count += 1
                byte_count += stat_result.st_size
            elif not path.is_dir():
                raise InstallerError(f"unsupported special file in runtime: {relative.as_posix()}")
        except OSError as exc:
            raise InstallerError(
                f"could not seal runtime file: {relative.as_posix()} ({exc.__class__.__name__})"
            ) from exc
    result = {
        "schema": CONTENT_SEAL_SCHEMA,
        "sha256": digest.hexdigest(),
        "file_count": file_count,
        "byte_count": byte_count,
    }
    _path_free(result, "content seal")
    return result


def _verify_content_seal(env_dir: Path, receipt: Mapping[str, Any], label: str) -> dict[str, Any]:
    expected = receipt.get("content_seal")
    if not isinstance(expected, Mapping) or expected.get("schema") != CONTENT_SEAL_SCHEMA:
        raise InstallerError(f"content seal missing from receipt for {label}")
    _check_sha(expected.get("sha256"), f"receipt content seal for {label}")
    actual = _content_seal(env_dir)
    if actual != expected:
        raise InstallerError(f"installed content seal mismatch for {label}")
    return actual


def _network_guard_code(module: str) -> str:
    return (
        "import importlib,socket\n"
        "class GuardedSocket(socket.socket):\n"
        " def connect(self,*a,**k): raise OSError('network disabled')\n"
        " def connect_ex(self,*a,**k): raise OSError('network disabled')\n"
        "socket.socket=GuardedSocket\n"
        "def denied(*a,**k): raise OSError('network disabled')\n"
        "socket.create_connection=denied\n"
        "socket.getaddrinfo=denied\n"
        f"importlib.import_module({module!r})\n"
    )


def _verify_python(
    entry: Mapping[str, Any], env_dir: Path, runner: CommandRunner
) -> dict[str, Any]:
    python = env_dir / "bin" / "python"
    config = (env_dir / "pyvenv.cfg").read_text(encoding="utf-8").lower()
    if "include-system-site-packages = false" not in config:
        raise InstallerError(f"{entry['name']} venv enables system site packages")
    runner.run([str(python), "-m", "pip", "check"], timeout=300)
    rows, digest = _python_inventory(python, runner)
    expected = entry["expected_inventory"]
    if rows != expected["distributions"] or digest != expected["sha256"]:
        raise InstallerError(f"installed inventory differs from lock for {entry['name']}")
    smoke = entry["smoke"]
    extra: dict[str, str] = dict(smoke.get("environment", {}))
    source_dir = env_dir / "source" / entry["name"]
    source_import = source_dir.is_dir() and entry["install"]["source_mode"] == "source-only"
    if source_import:
        extra["PYTHONPATH"] = str(source_dir)
    runner.run(
        [str(python), "-c", _network_guard_code(smoke["module"])],
        cwd=source_dir if source_import else env_dir,
        extra_env=extra,
        timeout=smoke.get("timeout_seconds", 180),
    )
    return {"inventory_sha256": digest, "distribution_count": len(rows)}


def _canonical_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _vcs_pretend_version(
    source_dir: Path, entry: Mapping[str, Any], framework: str
) -> dict[str, str]:
    """Declare a VCS-derived version that the pinned checkout cannot compute.

    A framework versioned by setuptools-scm or hatch-vcs reads its version from
    the tags reachable from HEAD. The source is acquired as a depth-1 fetch of
    one pinned commit, so no tag and no history are present, and the backend
    silently falls back to a placeholder such as ``0.1.dev1`` instead of
    failing; the installed distribution then disagrees with the lock. Deepening
    the fetch would not fix this so much as move the problem: the version would
    become a function of upstream tags, which are mutable and are not part of
    the lock, so a retag upstream would change a supposedly pinned build.

    The version the lock already records for the framework's own distribution
    is therefore declared to the build. This does not weaken the seal on what
    is installed: the code identity is fixed independently by the pinned
    commit, the pinned tree and the git archive digest, all three of which are
    compared before the build runs. What it removes is only the independent
    rederivation of a metadata string that the acquisition method cannot
    produce at all.
    """

    pyproject = source_dir / "pyproject.toml"
    if not pyproject.is_file():
        return {}
    try:
        config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise InstallerError(f"unreadable pyproject.toml for {framework}") from exc
    project = config.get("project")
    if not isinstance(project, Mapping):
        return {}
    dynamic = project.get("dynamic")
    if not isinstance(dynamic, list) or "version" not in dynamic:
        return {}
    build_system = config.get("build-system")
    requires = build_system.get("requires", []) if isinstance(build_system, Mapping) else []
    backends = {
        _canonical_distribution(re.split(r"[<>=!~\[; ]", str(item))[0])
        for item in requires
        if isinstance(item, str) and item.strip()
    }
    if not backends & {"hatch-vcs", "setuptools-scm"}:
        return {}
    name = project.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InstallerError(f"source project declares no name for {framework}")
    canonical = _canonical_distribution(name)
    expected = entry.get("expected_inventory", {}).get("distributions", [])
    versions = {
        row.split("==", 1)[0]: row.split("==", 1)[1]
        for row in expected
        if isinstance(row, str) and "==" in row
    }
    version = versions.get(canonical)
    if not version:
        raise InstallerError(
            f"lock records no version for the VCS-versioned distribution "
            f"{canonical} of {framework}"
        )
    # Both spellings carry the same value: the targeted variable wins wherever
    # the backend resolves a distribution name, and the plain one covers the
    # backends that do not. The build produces exactly one wheel, which is
    # asserted below, so neither can reach an unrelated project.
    variable = re.sub(r"[-_.]+", "_", canonical).upper()
    return {
        "SETUPTOOLS_SCM_PRETEND_VERSION": version,
        f"SETUPTOOLS_SCM_PRETEND_VERSION_FOR_{variable}": version,
    }


def _build_source_wheel(
    python: Path,
    source_dir: Path,
    wheel_dir: Path,
    runner: CommandRunner,
    framework: str,
    entry: Mapping[str, Any],
) -> Path:
    wheel_dir.mkdir(parents=True, exist_ok=True)
    for old_wheel in wheel_dir.glob("*.whl"):
        old_wheel.unlink()
    runner.run(
        [
            str(python),
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(source_dir),
        ],
        extra_env=_vcs_pretend_version(source_dir, entry, framework) or None,
    )
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise InstallerError(f"expected one source wheel for {framework}")
    return wheels[0]


def _install_python(
    entry: Mapping[str, Any],
    lock: Mapping[str, Any],
    stage: Path,
    runner: CommandRunner,
    *,
    resume: bool,
) -> dict[str, Any]:
    state = _read_state(stage)
    if resume and not _phase_done(state, "dependencies"):
        _clear_owned_store(stage, preserve={STATE_NAME})
        state["completed"] = []
        _write_state(stage, state)
    python = stage / "bin" / "python"
    if not _phase_done(state, "venv"):
        base = Path(runner_python(lock))
        runner.run([str(base), "-m", "venv", "--copies", str(stage)])
        _complete_phase(stage, state, "venv")
    if not _phase_done(state, "dependencies"):
        metadata = stage / ".ura"
        metadata.mkdir(parents=True, exist_ok=True)
        requirements = metadata / "dependencies.lock"
        _atomic_write_bytes(
            requirements,
            entry["dependencies"]["requirements"].encode("utf-8"),
        )
        if _sha256_file(requirements) != entry["dependencies"]["sha256"]:
            raise InstallerError("materialized dependency lock digest mismatch")
        if entry["dependencies"]["package_count"]:
            runner.run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--require-hashes",
                    "--index-url",
                    "https://pypi.org/simple",
                    "-r",
                    str(requirements),
                ],
                timeout=entry["install"].get("timeout_seconds", 14400),
            )
        _complete_phase(stage, state, "dependencies")
    if not _phase_done(state, "artifacts"):
        artifact_dir = stage / ".ura" / "artifacts"
        for artifact in entry.get("artifacts", []):
            target = artifact_dir / artifact["filename"]
            if not _artifact_matches(artifact, target):
                _download(artifact, target)
            runner.run([str(python), "-m", "pip", "install", "--no-deps", str(target)])
        _complete_phase(stage, state, "artifacts")
    source_dir: Path | None = None
    if not _phase_done(state, "source"):
        source_dir = _acquire_source(entry, stage, runner, lock["runtimes"])
        mode = entry["install"]["source_mode"]
        if source_dir is not None and mode == "wheel":
            wheel_dir = stage / ".ura" / "built"
            wheel = _build_source_wheel(
                python, source_dir, wheel_dir, runner, entry["name"], entry
            )
            runner.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)])
        _complete_phase(stage, state, "source")
    return _verify_python(entry, stage, runner)


_ACTIVE_PYTHON: Path | None = None


def runner_python(lock: Mapping[str, Any]) -> str:
    if _ACTIVE_PYTHON is None:
        raise InstallerError("internal Python executable was not configured")
    _verify_python_identity(_ACTIVE_PYTHON, lock["runtimes"]["python"])
    return str(_ACTIVE_PYTHON)


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise InstallerError("Node archive contains an unsafe path")
            if member.issym() or member.islnk():
                import posixpath

                target = member.linkname
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), target))
                if target.startswith("/") or resolved == ".." or resolved.startswith("../"):
                    raise InstallerError("Node archive contains an unsafe link")
        tar.extractall(destination, filter="data")


def _node_lock_inventory(npm_lock: Mapping[str, Any]) -> tuple[int, str]:
    rows = []
    for package_path, package in sorted(npm_lock.get("packages", {}).items()):
        if not package_path:
            continue
        rows.append(
            {
                "package": package_path,
                "version": package.get("version"),
                "integrity": package.get("integrity"),
            }
        )
    return len(rows), _sha256_bytes(_canonical_json(rows))


def _node_package_json_path(relative: Path) -> bool:
    if relative.name != "package.json" or "node_modules" not in relative.parts:
        return False
    index = len(relative.parts) - 1 - tuple(reversed(relative.parts)).index("node_modules")
    tail = relative.parts[index + 1 : -1]
    return len(tail) == 1 or (len(tail) == 2 and tail[0].startswith("@"))


def _node_installed_inventory(env_dir: Path) -> tuple[list[str], str]:
    rows: list[str] = []
    modules = env_dir / "node_modules"
    if not modules.is_dir():
        raise InstallerError("installed node_modules directory is missing")
    for package_json in modules.rglob("package.json"):
        relative = package_json.relative_to(env_dir)
        if not _node_package_json_path(relative):
            continue
        try:
            package = _strict_json_loads(package_json.read_bytes())
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise InstallerError(
                f"invalid installed npm package metadata: {relative.parent.as_posix()}"
            ) from exc
        name = package.get("name") if isinstance(package, Mapping) else None
        version = package.get("version") if isinstance(package, Mapping) else None
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise InstallerError(
                f"incomplete installed npm package metadata: {relative.parent.as_posix()}"
            )
        rows.append(f"{relative.parent.as_posix()}|{name}=={version}")
    rows.sort()
    return rows, _sha256_bytes("".join(f"{row}\n" for row in rows).encode())


#: ``npm ls`` states an invalid resolution as ``"<range>" from <requirer path>``.
_NPM_INVALID_SOURCE = re.compile(r'^"(?P<range>[^"]*)" from (?P<path>.+)$')


def _npm_invalid_nodes(tree: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Every resolved node npm marked invalid, as (name, range, requirer path)."""

    found: list[tuple[str, str, str]] = []

    def walk(node: Mapping[str, Any]) -> None:
        dependencies = node.get("dependencies")
        if not isinstance(dependencies, Mapping):
            return
        for name, meta in dependencies.items():
            if not isinstance(meta, Mapping):
                continue
            invalid = meta.get("invalid")
            if isinstance(invalid, str) and invalid:
                match = _NPM_INVALID_SOURCE.match(invalid)
                if match is None:
                    found.append((str(name), invalid, ""))
                else:
                    found.append(
                        (str(name), match.group("range"), match.group("path"))
                    )
            walk(meta)

    walk(tree)
    return found


def _npm_optional_peer(env_dir: Path, requirer: str, name: str) -> bool:
    """True when ``requirer`` declares ``name`` as an OPTIONAL peer dependency.

    An optional peer is allowed to be absent or unsatisfied - that is exactly
    what ``peerDependenciesMeta.<name>.optional`` means - so npm marking the
    hoisted copy invalid for such a requirer is an upstream graph fact, not a
    defect in this installation. Every other invalid resolution stays fatal.
    """

    if not requirer:
        return False
    manifest = env_dir / requirer / "package.json"
    try:
        package = _strict_json_loads(manifest.read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError):
        return False
    if not isinstance(package, Mapping):
        return False
    peers = package.get("peerDependencies")
    meta = package.get("peerDependenciesMeta")
    if not isinstance(peers, Mapping) or name not in peers:
        return False
    if not isinstance(meta, Mapping):
        return False
    entry = meta.get(name)
    return isinstance(entry, Mapping) and entry.get("optional") is True


def _npm_json_document(output: str, entry: Mapping[str, Any]) -> str:
    """Isolate the one JSON document npm printed among its diagnostics.

    The command runner merges stderr into stdout deliberately, so that every
    byte a child writes goes through one redacted logging path. npm writes its
    ELSPROBLEMS diagnostics to stderr and the ``--json`` tree to stdout, so the
    captured stream interleaves them and the tree has to be isolated before it
    can be parsed. Anchoring on a brace at the start of a line matches npm's
    pretty-printed output and cannot be confused by a brace inside a diagnostic
    line; the decoder then reports where the document ends, so trailing
    diagnostics are dropped without guessing.
    """

    match = re.search(r"^\{", output, re.MULTILINE)
    if match is None:
        raise InstallerError(f"npm ls printed no JSON tree for {entry['name']}")
    start = match.start()
    try:
        _, length = json.JSONDecoder().raw_decode(output[start:])
    except ValueError as exc:
        raise InstallerError(
            f"npm ls returned invalid JSON for {entry['name']}"
        ) from exc
    return output[start : start + length]


def _validate_npm_ls_output(
    output: str, entry: Mapping[str, Any], env_dir: Path, *, returncode: int = 0
) -> list[str]:
    """Validate the installed npm tree, returning tolerated optional-peer notes.

    ``npm ls`` exits non-zero whenever it reports any problem at all, so the
    exit code alone cannot distinguish a broken tree from an unsatisfied
    optional peer. The reported tree is therefore the authority and the exit
    code is cross-checked against it: the two signals must agree, or the
    verification fails closed.
    """

    try:
        tree = _strict_json_loads(_npm_json_document(output, entry))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise InstallerError(f"npm ls returned invalid JSON for {entry['name']}") from exc
    if not isinstance(tree, Mapping):
        raise InstallerError(f"npm ls returned a non-object for {entry['name']}")
    problems = tree.get("problems", [])
    tolerated: list[str] = []
    if problems not in (None, []):
        # Only an invalid resolution can be excused, and only when every
        # requirer that rejects it declared it as an optional peer. A missing,
        # extraneous or otherwise reported problem stays fatal. Counts are not
        # compared: ``npm ls --all`` repeats a deduplicated node at each path it
        # is reachable from, so one problem can surface as several tree nodes.
        if not all(
            isinstance(problem, str) and problem.startswith("invalid:")
            for problem in problems
        ):
            raise InstallerError(
                f"npm ls reported dependency problems for {entry['name']}"
            )
        invalid = set(_npm_invalid_nodes(tree))
        if not invalid:
            raise InstallerError(
                f"npm ls reported dependency problems for {entry['name']}"
            )
        for name, wanted, requirer in sorted(invalid):
            if not _npm_optional_peer(env_dir, requirer, name):
                raise InstallerError(
                    f"npm ls reported dependency problems for {entry['name']}"
                )
            tolerated.append(f"{name} {wanted} optional peer of {requirer}")
    dependencies = tree.get("dependencies")
    if not isinstance(dependencies, Mapping) or "promptfoo" not in dependencies:
        raise InstallerError(f"npm ls did not report promptfoo for {entry['name']}")
    if returncode and not tolerated:
        raise InstallerError(
            f"npm ls exited {returncode} for {entry['name']} with no tolerable cause"
        )
    if tolerated and not returncode:
        raise InstallerError(
            f"npm ls reported problems for {entry['name']} but exited zero"
        )
    return sorted(tolerated)


def _node_network_guard(path: Path) -> None:
    _atomic_write_bytes(
        path,
        "const net=require('node:net');const dns=require('node:dns');"
        "function denied(){throw new Error('network disabled for packaging smoke');}"
        "net.Socket.prototype.connect=denied;dns.lookup=denied;dns.resolve=denied;\n".encode(
            "utf-8"
        ),
    )


def _verify_node_release(
    runtime: Mapping[str, Any], stage: Path, runner: CommandRunner, runtimes: Mapping[str, Any]
) -> Path:
    artifacts = stage / "artifacts"
    archive = artifacts / runtime["filename"]
    checksums = artifacts / runtime["checksums"]["filename"]
    signature = artifacts / runtime["signature"]["filename"]
    for spec, target in ((runtime, archive), (runtime["checksums"], checksums), (runtime["signature"], signature)):
        if not _artifact_matches(spec, target):
            _download(spec, target)
    expected_line = f"{runtime['sha256']}  {runtime['filename']}"
    if expected_line not in checksums.read_text(encoding="utf-8").splitlines():
        raise InstallerError("Node SHASUMS256.txt does not contain the locked runtime digest")
    keys = _checkout_git_source(
        runtime["signing_keyring"],
        stage / ".ura" / "nodejs-release-keys",
        stage,
        runner,
        runtimes,
        "nodejs-release-keys",
    )
    gnupg = stage / ".ura" / "node-gnupg"
    if _path_exists(gnupg):
        _remove_owned_path(stage, gnupg)
    shutil.copytree(keys / "gpg", gnupg)
    gnupg.chmod(0o700)
    result = runner.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(gnupg),
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(checksums),
        ],
        capture=True,
        timeout=300,
    )
    marker = f"[GNUPG:] VALIDSIG {runtime['signer_fingerprint']} "
    if marker not in result.stdout:
        raise InstallerError("Node release signature fingerprint does not match the lock")
    return archive


def _verify_node(entry: Mapping[str, Any], env_dir: Path, runner: CommandRunner) -> dict[str, Any]:
    runtime = entry["install"]["node_runtime_dir"]
    node = env_dir / "runtime" / runtime / "bin" / "node"
    npm = env_dir / "runtime" / runtime / "bin" / "npm"
    version = runner.run([str(node), "--version"], capture=True).stdout.strip().removeprefix("v")
    if version != entry["install"]["node_version"]:
        raise InstallerError(f"Node version mismatch for {entry['name']}")
    npm_tree = runner.run(
        [str(npm), "ls", "--all", "--json"],
        cwd=env_dir,
        extra_env={"PATH": f"{node.parent}:/usr/bin:/bin"},
        capture=True,
        timeout=300,
        # npm exits 1 for ELSPROBLEMS whatever the problem is, including an
        # unsatisfied optional peer, which is allowed to be unsatisfied. The
        # printed tree is classified instead, and it fails closed on anything
        # else; an exit that the tree does not explain is itself an error.
        allowed_returncodes=(0, 1),
    )
    tolerated_peers = _validate_npm_ls_output(
        npm_tree.stdout, entry, env_dir, returncode=npm_tree.returncode
    )
    guard = env_dir / ".ura" / "node-network-guard.cjs"
    guard.parent.mkdir(parents=True, exist_ok=True)
    _node_network_guard(guard)
    smoke = entry["smoke"]
    cli = env_dir / smoke["relative_cli"]
    result = runner.run(
        [str(node), str(cli), *smoke["args"]],
        extra_env={
            "NODE_OPTIONS": f"--require={guard}",
            "NO_UPDATE_NOTIFIER": "1",
            "PROMPTFOO_DISABLE_TELEMETRY": "1",
        },
        capture=True,
        timeout=smoke.get("timeout_seconds", 180),
    )
    if smoke["expected_version"] not in (result.stdout + result.stderr):
        raise InstallerError(f"CLI version smoke mismatch for {entry['name']}")
    rows, digest = _node_installed_inventory(env_dir)
    count = len(rows)
    expected = entry["expected_inventory"]
    if (
        rows != expected["packages"]
        or count != expected["package_count"]
        or digest != expected["sha256"]
    ):
        raise InstallerError(f"installed Node inventory differs from lock for {entry['name']}")
    return {
        "inventory_sha256": digest,
        "distribution_count": count,
        # Recorded rather than hidden: an unsatisfied OPTIONAL peer is a
        # fact about the upstream dependency graph, so the receipt names
        # each one instead of the verification silently passing.
        "tolerated_optional_peers": tolerated_peers,
    }


def _install_node(
    entry: Mapping[str, Any],
    lock: Mapping[str, Any],
    stage: Path,
    runner: CommandRunner,
    *,
    resume: bool,
) -> dict[str, Any]:
    state = _read_state(stage)
    runtime = lock["runtimes"]["node"]
    artifacts = stage / "artifacts"
    if not _phase_done(state, "node-runtime"):
        _remove_owned_path(stage, stage / "runtime")
        archive = _verify_node_release(runtime, stage, runner, lock["runtimes"])
        _safe_extract_tar(archive, stage / "runtime")
        _complete_phase(stage, state, "node-runtime")
    if not _phase_done(state, "npm"):
        if resume:
            for relative in ("node_modules", "package.json", "package-lock.json"):
                _remove_owned_path(stage, stage / relative)
        package_artifact = entry["artifacts"][0]
        package_tar = artifacts / package_artifact["filename"]
        if not _artifact_matches(package_artifact, package_tar):
            _download(package_artifact, package_tar)
        package_json = {
            "name": "ura-locked-promptfoo-runtime",
            "private": True,
            "dependencies": {"promptfoo": f"file:artifacts/{package_artifact['filename']}"},
        }
        npm_lock = _strict_json_loads(_canonical_json(entry["dependencies"]["npm_lock"]))
        relative_tar = f"file:artifacts/{package_artifact['filename']}"
        npm_lock["packages"][""]["dependencies"]["promptfoo"] = relative_tar
        npm_lock["packages"]["node_modules/promptfoo"]["resolved"] = relative_tar
        _atomic_write_bytes(stage / "package.json", _canonical_json(package_json))
        _atomic_write_bytes(stage / "package-lock.json", _canonical_json(npm_lock))
        node_dir = stage / "runtime" / entry["install"]["node_runtime_dir"] / "bin"
        runner.run(
            [str(node_dir / "npm"), "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=stage,
            extra_env={"PATH": f"{node_dir}:/usr/bin:/bin"},
            timeout=entry["install"].get("timeout_seconds", 14400),
        )
        _complete_phase(stage, state, "npm")
    _acquire_source(entry, stage, runner, lock["runtimes"])
    return _verify_node(entry, stage, runner)


def _receipt(
    entry: Mapping[str, Any],
    lock: Mapping[str, Any],
    verification: Mapping[str, Any],
    content_seal: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = {
        "schema": "ura-framework-runtime-receipt/1",
        "lock_id": lock["lock_id"],
        "framework": entry["name"],
        "version": entry["version"],
        "env_slug": entry["env_slug"],
        "runtime": entry["runtime"],
        "inventory_sha256": verification["inventory_sha256"],
        "distribution_count": verification["distribution_count"],
        "content_seal": dict(content_seal),
        "pip_check": "passed" if entry["runtime"] == "python" else "not-applicable",
        "smoke": "passed",
        "provider_calls": 0,
        "model_calls": 0,
        "network_smoke": "denied",
        "status": "passed",
    }
    _path_free(receipt)
    return receipt


def _read_receipt(env_dir: Path) -> dict[str, Any] | None:
    path = env_dir / RECEIPT_NAME
    if not path.is_file():
        return None
    try:
        value = _strict_json_loads(path.read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    expected_keys = {
        "schema",
        "lock_id",
        "framework",
        "version",
        "env_slug",
        "runtime",
        "inventory_sha256",
        "distribution_count",
        "content_seal",
        "pip_check",
        "smoke",
        "provider_calls",
        "model_calls",
        "network_smoke",
        "status",
    }
    if set(value) != expected_keys:
        return None
    try:
        _path_free(value, "runtime receipt")
    except InstallerError:
        return None
    return value


def _receipt_matches(receipt: Mapping[str, Any] | None, entry: Mapping[str, Any], lock_id: str) -> bool:
    content_seal = receipt.get("content_seal") if receipt else None
    return bool(
        receipt
        and receipt.get("schema") == "ura-framework-runtime-receipt/1"
        and isinstance(content_seal, Mapping)
        and content_seal.get("schema") == CONTENT_SEAL_SCHEMA
        and receipt.get("lock_id") == lock_id
        and receipt.get("framework") == entry["name"]
        and receipt.get("env_slug") == entry["env_slug"]
        and receipt.get("status") == "passed"
    )


def plan(lock: Mapping[str, Any], layout: Layout, entries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    actions = []
    for entry in entries:
        final = layout.final(entry["env_slug"])
        store = layout.store(entry["env_slug"], lock["lock_id"])
        receipt = _read_receipt(final) if _alias_points_to(final, store) else None
        if _receipt_matches(receipt, entry, lock["lock_id"]):
            action = "verify"
        elif _path_exists(final) and _managed_alias_target(layout, entry["env_slug"]) is None:
            action = "blocked-existing-unverified"
        elif store.exists():
            action = "resume"
        else:
            action = "install"
        actions.append({"framework": entry["name"], "env_slug": entry["env_slug"], "action": action})
    summary = {"schema": "ura-framework-runtime-plan/1", "lock_id": lock["lock_id"], "actions": actions}
    _path_free(summary)
    return summary


def _runner(
    layout: Layout,
    entry: Mapping[str, Any],
    env_dir: Path,
    prefix: str = "",
    *,
    home: Path | None = None,
) -> CommandRunner:
    """A runner for one framework. ``home`` defaults to the environment itself.

    During installation the environment is the natural HOME for tool state.
    Package-manager caches are explicitly bound to ``env_root/.cache`` instead:
    they persist across clean per-runtime homes and remain outside every sealed
    store. Verification uses a separate writable HOME because the artifact is
    already sealed and any tool state written into it would change its bytes.
    """

    filename = f"{prefix}{entry['name']}.log"
    process_home = home or env_dir
    cache = layout.pip_cache if entry["runtime"] == "python" else layout.npm_cache
    cache.mkdir(parents=True, exist_ok=True)
    cache_env = (
        {"PIP_CACHE_DIR": str(cache)}
        if entry["runtime"] == "python"
        else {"NPM_CONFIG_CACHE": str(cache)}
    )
    redact_paths: list[Path | str] = [
        layout.env_root,
        layout.state_root,
        env_dir,
        cache,
    ]
    if home is not None:
        redact_paths.append(home)
    if _ACTIVE_PYTHON is not None:
        redact_paths.append(_ACTIVE_PYTHON)
        redact_paths.append(_ACTIVE_PYTHON.parent)
    return CommandRunner(
        layout.state_root / "logs" / filename,
        process_home,
        redact_paths=redact_paths,
        base_env=cache_env,
    )


def _verify_runtime(
    entry: Mapping[str, Any], env_dir: Path, runner: CommandRunner
) -> dict[str, Any]:
    return (
        _verify_python(entry, env_dir, runner)
        if entry["runtime"] == "python"
        else _verify_node(entry, env_dir, runner)
    )


def _verify_published(
    entry: Mapping[str, Any],
    lock: Mapping[str, Any],
    layout: Layout,
    final: Path,
    receipt: Mapping[str, Any],
    *,
    log_prefix: str,
) -> dict[str, Any]:
    # Verify the managed directory, not the alias that names it. The store is
    # content-addressed behind stable aliases, so `final` is a symlink by
    # design, and a verification that writes inside the environment refuses a
    # symlinked parent: the Node network guard did exactly that, so a published
    # Node runtime could never be re-verified through its own alias, however
    # correctly it had been installed. The alias has already been proved to
    # point at this store entry by the caller, so resolving it changes which
    # path is used and not which bytes are checked.
    managed = final.resolve(strict=True) if final.is_symlink() else final
    # Verification must not modify what it is verifying. The environment is its
    # own home during installation, so a tool that writes a log, a cache or a
    # database into its home writes inside the sealed tree: npm leaves a
    # timestamped debug log per invocation and the Promptfoo CLI creates its
    # application directory, so every verification changed the content the seal
    # covers and the next one failed against its own receipt. A scratch home
    # outside the environment keeps the check read-only.
    with tempfile.TemporaryDirectory(prefix="ura-runtime-verify-") as scratch:
        runner = _runner(layout, entry, managed, log_prefix, home=Path(scratch))
        verification = _verify_runtime(entry, managed, runner)
    if receipt.get("inventory_sha256") != verification["inventory_sha256"]:
        raise InstallerError(f"receipt inventory mismatch for {entry['name']}")
    _verify_content_seal(managed, receipt, entry["name"])
    return verification


def install_one(
    entry: Mapping[str, Any], lock: Mapping[str, Any], layout: Layout, *, resume: bool
) -> dict[str, Any]:
    final = layout.final(entry["env_slug"])
    store = layout.store(entry["env_slug"], lock["lock_id"])
    existing = _read_receipt(final) if _alias_points_to(final, store) else None
    if _receipt_matches(existing, entry, lock["lock_id"]):
        _verify_published(entry, lock, layout, final, existing, log_prefix="install-verify-")
        return {
            "framework": entry["name"],
            "env_slug": entry["env_slug"],
            "status": "already-installed-verified",
        }
    if _path_exists(final) and _managed_alias_target(layout, entry["env_slug"]) is None:
        raise InstallerError(f"refusing to replace unverified existing environment: {entry['env_slug']}")
    if store.exists() and not resume:
        raise InstallerError(f"staging exists for {entry['name']}; use resume")
    store.mkdir(parents=True, exist_ok=True)
    state = _read_state(store)
    if state.get("lock_id") not in (None, lock["lock_id"]):
        raise InstallerError(f"staging lock mismatch for {entry['name']}")
    state.update({"lock_id": lock["lock_id"], "framework": entry["name"], "env_slug": entry["env_slug"]})
    _write_state(store, state)
    runner = _runner(layout, entry, store)
    verification = (
        _install_python(entry, lock, store, runner, resume=resume)
        if entry["runtime"] == "python"
        else _install_node(entry, lock, store, runner, resume=resume)
    )
    seal = _content_seal(store)
    receipt = _receipt(entry, lock, verification, seal)
    _atomic_write_bytes(store / RECEIPT_NAME, _canonical_json(receipt))
    _publish_alias(layout, entry["env_slug"], store)
    # Verify through the published alias, including one generated console
    # script. This catches stale shebangs and incomplete publication.
    if entry["runtime"] == "python":
        runner.run([str(final / "bin" / "pip"), "--version"], timeout=60)
    _verify_published(entry, lock, layout, final, receipt, log_prefix="publish-verify-")
    return {"framework": entry["name"], "env_slug": entry["env_slug"], "status": "installed"}


def verify_one(
    entry: Mapping[str, Any], lock: Mapping[str, Any], layout: Layout
) -> dict[str, Any]:
    final = layout.final(entry["env_slug"])
    store = layout.store(entry["env_slug"], lock["lock_id"])
    if not _alias_points_to(final, store):
        raise InstallerError(f"valid runtime alias not found for {entry['name']}")
    receipt = _read_receipt(final)
    if not _receipt_matches(receipt, entry, lock["lock_id"]):
        raise InstallerError(f"valid receipt not found for {entry['name']}")
    _verify_published(entry, lock, layout, final, receipt, log_prefix="verify-")
    return {"framework": entry["name"], "env_slug": entry["env_slug"], "status": "verified"}


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _campaign_task(entry: Mapping[str, Any]) -> str:
    return f"framework-runtime-{entry['name']}"


def _ensure_campaign(state_root: Path, lock: Mapping[str, Any]) -> None:
    """Create/extend a current UI-readable, explicitly non-empirical campaign."""

    state_root.mkdir(parents=True, exist_ok=True)
    marker_path = state_root / "ENGINEERING_ONLY.json"
    planned = [_campaign_task(entry) for entry in lock["frameworks"]]
    if marker_path.exists():
        if marker_path.is_symlink():
            raise InstallerError("engineering campaign marker must not be a symlink")
        try:
            marker = _strict_json_loads(marker_path.read_bytes())
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise InstallerError("engineering campaign marker is invalid") from exc
        if not isinstance(marker, dict):
            raise InstallerError("engineering campaign marker must be an object")
        if (
            marker.get("schema") != CAMPAIGN_SCHEMA
            or marker.get("thesis_empirical_evidence") is not False
            or marker.get("hosted_calls_allowed") is not False
        ):
            raise InstallerError("state root is not a compatible engineering-only campaign")
        model_tasks = marker.get("model_tasks", [])
        if model_tasks != []:
            raise InstallerError("framework installer campaign must declare no model tasks")
        existing = marker.get("planned_tasks", [])
        if not isinstance(existing, list) or not all(isinstance(item, str) for item in existing):
            raise InstallerError("engineering campaign has an invalid planned task list")
        marker["planned_tasks"] = list(dict.fromkeys([*existing, *planned]))
        marker["model_tasks"] = []
        marker["started_at"] = _utc_now()
        marker["runtime_lock_id"] = lock["lock_id"]
    else:
        campaign_id = state_root.name
        if not SAFE_SLUG.fullmatch(campaign_id):
            campaign_id = f"framework-runtime-{lock['lock_id'][:12]}"
        marker = {
            "schema": CAMPAIGN_SCHEMA,
            "campaign_id": campaign_id,
            "evidence_class": "framework_runtime_setup",
            "thesis_empirical_evidence": False,
            "hosted_calls_allowed": False,
            "target_call_cap": 0,
            "hard_stop_hours": 168,
            "started_at": _utc_now(),
            "runtime_lock_id": lock["lock_id"],
            "planned_tasks": planned,
            "model_tasks": [],
        }
    _path_free(marker, "engineering campaign marker")
    _atomic_write_bytes(marker_path, _canonical_json(marker))


def _append_campaign_event(state_root: Path, event: Mapping[str, Any]) -> None:
    row = {"at": _utc_now(), **event}
    _path_free(row, "engineering campaign event")
    encoded = _canonical_json(row)
    path = state_root / "task-log.jsonl"
    _safe_managed_parent(path)
    if _path_exists(path):
        before = _safe_regular_identity(path)
    else:
        before = None
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        opened = os.fstat(descriptor)
        visible = path.lstat()
        identity = (opened.st_dev, opened.st_ino, opened.st_mode)
        if (
            _unsafe_link(path)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or visible.st_nlink != 1
            or identity != (visible.st_dev, visible.st_ino, visible.st_mode)
            or (before is not None and before != identity)
        ):
            raise InstallerError("engineering campaign task log is unsafe")
        if opened.st_size + len(encoded) > MAX_CAMPAIGN_LOG_BYTES:
            raise InstallerError("engineering campaign task log reached its bounded size")
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise InstallerError("engineering campaign task event write was incomplete")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            after.st_nlink != 1
            or named.st_nlink != 1
            or (after.st_dev, after.st_ino, after.st_mode)
            != (named.st_dev, named.st_ino, named.st_mode)
        ):
            raise InstallerError("engineering campaign task log changed while writing")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _session_inner_argv(policy: str, session_name: str) -> list[str]:
    args = list(sys.argv[1:])
    if "--session-policy" in args:
        index = args.index("--session-policy")
        del args[index : index + 2]
    if "--session-name-proof" in args:
        index = args.index("--session-name-proof")
        del args[index : index + 2]
    args.extend(
        ["--session-policy", policy, "--session-name-proof", session_name]
    )
    return [sys.executable, str(Path(__file__).resolve()), *args]


def _session_wrapper_main(argv: Sequence[str]) -> int:
    """Run one owned session child with bounded output and a safe exit marker."""

    try:
        delimiter = list(argv).index("--")
    except ValueError:
        return 125
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--redact", type=Path, action="append", default=[])
    try:
        args = parser.parse_args(list(argv)[:delimiter])
    except SystemExit:
        return 125
    command = list(argv)[delimiter + 1 :]
    if (
        not command
        or not SAFE_SLUG.fullmatch(args.session)
        or args.log.name != f"{args.session}.log"
        or args.marker.name != f"{args.session}.exit"
        or args.home.name != f"{args.session}.home"
        or args.log.parent != args.marker.parent
        or args.log.parent != args.home.parent
    ):
        return 125
    runner = CommandRunner(
        args.log,
        args.home,
        redact_paths=[args.log.parent, *args.redact],
    )
    returncode = 125
    try:
        completed = runner.run(
            command,
            extra_env={"URA_FRAMEWORK_NAMED_SESSION": args.session},
            timeout=MAX_SESSION_SECONDS,
            allowed_returncodes=tuple(range(256)),
        )
        returncode = completed.returncode
    except InstallerError as exc:
        if "timed out" in str(exc):
            returncode = 124
        with contextlib.suppress(InstallerError, OSError):
            runner._log(f"[session-wrapper-error] {exc.__class__.__name__}\n")
    try:
        _atomic_write_bytes(args.marker, f"{returncode}\n".encode("ascii"))
    except (InstallerError, OSError):
        return 126
    return returncode


def _session_name(
    command: str,
    lock_id: str,
    only: Sequence[str] | None,
    layout: Layout,
    python: Path | None,
) -> str:
    suffix = _sha256_bytes(",".join(sorted(only or [])).encode())[:8] if only else "all"
    invocation = {
        "env_root": str(layout.env_root.resolve()),
        "state_root": str(layout.state_root.resolve()),
        "python": str(python.resolve()) if python is not None else "none",
    }
    invocation_id = _sha256_bytes(_canonical_json(invocation))[:10]
    return f"ura-framework-{command}-{lock_id[:8]}-{suffix}-{invocation_id}"


def _tmux_socket_name(session: str) -> str:
    """Bind one private tmux server to the sanitized installer invocation."""

    return f"ura-fw-{_sha256_bytes(session.encode('ascii'))[:16]}"


def _launch_session(
    command: str,
    lock: Mapping[str, Any],
    layout: Layout,
    only: Sequence[str] | None,
    python: Path | None,
) -> dict[str, Any]:
    layout.state_root.mkdir(parents=True, exist_ok=True)
    session = _session_name(command, lock["lock_id"], only, layout, python)
    sessions = layout.state_root / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    log = sessions / f"{session}.log"
    marker = sessions / f"{session}.exit"
    session_home = sessions / f"{session}.home"
    session_home.mkdir(mode=0o700, exist_ok=True)
    inner = _session_inner_argv("required", session)
    wrapper = [
        sys.executable,
        str(Path(__file__).resolve()),
        "__session_wrapper",
        "--log",
        str(log),
        "--marker",
        str(marker),
        "--home",
        str(session_home),
        "--session",
        session,
        "--redact",
        str(layout.env_root),
        "--redact",
        str(layout.state_root),
    ]
    if python is not None:
        wrapper.extend(["--redact", str(python)])
    wrapper.extend(["--", *inner])
    clean_wrapper = [
        "env",
        "-i",
        f"HOME={session_home}",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PATH=/usr/bin:/bin",
        f"URA_FRAMEWORK_NAMED_SESSION={session}",
        *wrapper,
    ]
    launcher_env = {
        "HOME": str(session_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    tmux = shutil.which("tmux")
    screen = shutil.which("screen")
    if tmux:
        tmux_socket = _tmux_socket_name(session)
        exists = (
            subprocess.run(
                [tmux, "-L", tmux_socket, "has-session", "-t", session],
                capture_output=True,
                env=launcher_env,
                check=False,
            ).returncode
            == 0
        )
        if not exists:
            _unlink_owned_regular(marker)
            _atomic_write_bytes(log, b"")
            subprocess.run(
                [
                    tmux,
                    "-L",
                    tmux_socket,
                    "new-session",
                    "-d",
                    "-s",
                    session,
                    *clean_wrapper,
                ],
                env=launcher_env,
                check=True,
            )
        launcher = "tmux"
        attach = f"tmux -L {tmux_socket} attach -t {session}"
    elif screen:
        listing = subprocess.run(
            [screen, "-ls"],
            capture_output=True,
            text=True,
            env=launcher_env,
            check=False,
        )
        screen_exists = bool(
            re.search(
                rf"(?m)^\s*\d+\.{re.escape(session)}\s+"
                r"\((?:Attached|Detached|Multi(?:,\s*attached)?)\)\s*$",
                listing.stdout,
            )
        )
        if not screen_exists:
            _unlink_owned_regular(marker)
            _atomic_write_bytes(log, b"")
            subprocess.run(
                [
                    screen,
                    "-DmS",
                    session,
                    *clean_wrapper,
                ],
                env=launcher_env,
                check=True,
            )
        launcher = "screen"
        attach = f"screen -r {session}"
    else:
        raise InstallerError("tmux is required (screen is the only allowed fallback)")
    result = {
        "schema": "ura-framework-runtime-session/1",
        "launcher": launcher,
        "session_name": session,
        "attach_command": attach,
        "log": f"sessions/{log.name}",
        "exit_marker": f"sessions/{marker.name}",
        "status": "running",
    }
    _path_free(result)
    return result


def _inside_session(
    args: argparse.Namespace,
    lock: Mapping[str, Any],
    layout: Layout,
    only: Sequence[str] | None,
) -> bool:
    expected = _session_name(args.command, lock["lock_id"], only, layout, args.python)
    return bool(
        args.session_name_proof == expected
        and os.environ.get("URA_FRAMEWORK_NAMED_SESSION") == expected
    )


def _maybe_session(
    args: argparse.Namespace,
    lock: Mapping[str, Any],
    layout: Layout,
    only: Sequence[str] | None,
) -> dict[str, Any] | None:
    if args.command == "plan" or _inside_session(args, lock, layout, only):
        return None
    if args.session_policy == "off":
        if os.environ.get("URA_FRAMEWORK_INSTALLER_TESTING") != "1":
            raise InstallerError("--session-policy off is restricted to installer tests")
        return None
    if args.session_policy == "required":
        raise InstallerError("install/resume/verify must run inside tmux or screen")
    return _launch_session(args.command, lock, layout, only, args.python)


def _parse_only(values: Sequence[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        result.extend(item.strip() for item in value.split(",") if item.strip())
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "install", "resume", "verify"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
        sub.add_argument("--env-root", type=Path, required=True)
        sub.add_argument("--state-root", type=Path, required=True)
        sub.add_argument("--python", type=Path)
        sub.add_argument("--only", action="append", default=[])
        sub.add_argument("--session-policy", choices=("auto", "required", "off"), default="auto")
        sub.add_argument("--session-name-proof", help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    global _ACTIVE_PYTHON
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        lock = load_lock(args.lock)
        only = _parse_only(args.only)
        entries = select_frameworks(lock, only)
        layout = Layout(args.env_root, args.state_root)
        if args.command == "plan":
            print(json.dumps(plan(lock, layout, entries), sort_keys=True))
            return 0
        session = _maybe_session(args, lock, layout, only)
        if session is not None:
            print(json.dumps(session, sort_keys=True))
            return 0
        needs_python = any(entry["runtime"] == "python" for entry in entries)
        if args.python is not None:
            _ACTIVE_PYTHON = args.python.resolve()
        results = []
        with CrossProcessLock(layout.lock_file):
            layout.env_root.mkdir(parents=True, exist_ok=True)
            layout.store_root.mkdir(parents=True, exist_ok=True)
            layout.pip_cache.mkdir(parents=True, exist_ok=True)
            layout.npm_cache.mkdir(parents=True, exist_ok=True)
            _ensure_campaign(layout.state_root, lock)
            _append_campaign_event(
                layout.state_root,
                {
                    "event": "campaign_start",
                    "task": "bootstrap",
                    "status": "running",
                    "detail": f"framework-runtime-{args.command}",
                },
            )
            campaign_failed = False
            try:
                if needs_python:
                    if _ACTIVE_PYTHON is None:
                        raise InstallerError("--python is required for Python runtimes")
                    _verify_python_identity(_ACTIVE_PYTHON, lock["runtimes"]["python"])
                for entry in entries:
                    task = _campaign_task(entry)
                    _append_campaign_event(
                        layout.state_root,
                        {
                            "event": "task_start",
                            "task": task,
                            "status": "running",
                            "detail": args.command,
                        },
                    )
                    try:
                        result = (
                            install_one(
                                entry,
                                lock,
                                layout,
                                resume=args.command == "resume",
                            )
                            if args.command in ("install", "resume")
                            else verify_one(entry, lock, layout)
                        )
                    except Exception as exc:
                        campaign_failed = True
                        _append_campaign_event(
                            layout.state_root,
                            {
                                "event": "task_end",
                                "task": task,
                                "status": "failed",
                                "detail": exc.__class__.__name__,
                            },
                        )
                        raise
                    results.append(result)
                    _append_campaign_event(
                        layout.state_root,
                        {
                            "event": "task_end",
                            "task": task,
                            "status": "passed",
                            "detail": result["status"],
                        },
                    )
            except Exception:
                campaign_failed = True
                raise
            finally:
                _append_campaign_event(
                    layout.state_root,
                    {
                        "event": "campaign_end",
                        "task": "bootstrap",
                        "status": "failed" if campaign_failed else "passed",
                        "detail": "framework-runtime-installer",
                    },
                )
        summary = {
            "schema": "ura-framework-runtime-summary/1",
            "lock_id": lock["lock_id"],
            "command": args.command,
            "results": results,
            "provider_calls": 0,
            "model_calls": 0,
            "status": "passed",
        }
        _path_free(summary)
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (InstallerError, OSError, subprocess.SubprocessError) as exc:
        paths = [
            value
            for value in (
                getattr(args, "env_root", None),
                getattr(args, "state_root", None),
                getattr(args, "lock", None),
            )
            if value is not None
        ]
        if getattr(args, "python", None) is not None:
            paths.append(args.python)
        error = _PathRedactor(paths)(str(exc))
        failure = {"status": "failed", "error": error}
        _path_free(failure, "failure summary")
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "__session_wrapper":
        raise SystemExit(_session_wrapper_main(sys.argv[2:]))
    raise SystemExit(main())
