"""Fail-closed identity for the exact clean URA project checkout.

The Git commit and the executed source digests answer different questions.  A
commit names a reconstructible revision; the source digests bind the Python
bytes that this process actually imported.  A project-revision receipt retains
both and deliberately makes no empirical or remote-authenticity claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Mapping

from . import runner as runner_module
from .eligibility import canonical_json_sha256
from .runner import _harness_source_identity


PROJECT_REVISION_SCHEMA = "ura-project-revision/1"
ROOT_RELATIONSHIP = "experiments_driver_and_src_ura_share_one_git_toplevel"
_REVISION_ID = re.compile(r"project-revision-[0-9a-f]{24}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_RECEIPT_BYTES = 1024 * 1024
_EXECUTABLE_SOURCE_SUFFIXES = frozenset({
    ".py", ".pyi", ".pyx", ".pyc", ".pyd", ".so", ".dll",
})
_TOP_FIELDS = frozenset({
    "schema", "status", "purpose", "revision_id", "repository", "source",
    "limitations",
})
_REPOSITORY_FIELDS = frozenset({
    "expected_commit", "observed_commit", "head_tree", "clean",
    "root_relationship",
})
_SOURCE_FIELDS = frozenset({"harness_source", "driver_source"})
_HARNESS_FIELDS = frozenset({"algorithm", "sha256", "file_count", "bytes"})
_DRIVER_FIELDS = frozenset({"module", "sha256", "file_count"})
_BINDING_FIELDS = frozenset({
    "mode", "revision_id", "file", "sha256", "bytes", "expected_commit",
    "observed_commit", "head_tree", "harness_source_sha256",
    "driver_source_sha256",
})
_LIMITATIONS = {
    "empirical_evidence_established": False,
    "remote_repository_authenticity_established": False,
    "dependency_environment_bound": False,
    "upstream_project_revisions_bound": False,
    "source_archive_included": False,
    "interpretation": (
        "local clean-checkout and executed-source identity only; dependency, "
        "upstream-runtime, remote-authenticity, and empirical claims require "
        "separate evidence"
    ),
}


def _strict_object(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} has an invalid field inventory")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r} is forbidden in {label}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON key {key!r} is forbidden in {label}")
            output[key] = value
        return output

    value = json.loads(
        raw.decode("utf-8"),
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicates,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _run_git(root_or_member: Path, *arguments: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise ValueError("Git is required to establish project revision identity")
    base = root_or_member if root_or_member.is_dir() else root_or_member.parent
    try:
        completed = subprocess.run(
            [git, "-C", str(base), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("project revision Git inspection failed") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise ValueError(f"project revision Git inspection failed: {detail}")
    return completed.stdout


def _git_text(root_or_member: Path, *arguments: str) -> str:
    try:
        value = _run_git(root_or_member, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("project revision Git output is not UTF-8") from exc
    if not value or "\n" in value or "\r" in value:
        raise ValueError("project revision Git output is not one nonblank line")
    return value


def _module_paths(
    driver_path: Path,
    harness_module_path: Path | None,
) -> tuple[Path, Path, Path]:
    driver = Path(driver_path).absolute()
    harness = Path(
        harness_module_path if harness_module_path is not None else runner_module.__file__
    ).absolute()
    if (
        not driver.is_file()
        or not harness.is_file()
        or driver.is_symlink()
        or harness.is_symlink()
    ):
        raise ValueError("project driver and harness must be regular non-symlink files")
    driver_root = Path(_git_text(driver, "rev-parse", "--show-toplevel")).resolve()
    harness_root = Path(_git_text(harness, "rev-parse", "--show-toplevel")).resolve()
    if driver_root != harness_root:
        raise ValueError("experiment driver and imported harness come from different Git roots")
    try:
        driver_relative = driver.resolve().relative_to(driver_root).as_posix()
        harness_relative = harness.resolve().relative_to(driver_root).as_posix()
    except ValueError as exc:
        raise ValueError("project source path escapes its reported Git root") from exc
    if driver_relative != "experiments/run_matrix.py":
        raise ValueError("project driver is not experiments/run_matrix.py in the detected root")
    if harness_relative != "src/ura/runner.py":
        raise ValueError("imported harness is not src/ura/runner.py in the detected root")
    return driver_root, driver.resolve(), harness.resolve()


def _source_identities(root: Path, driver: Path, harness: Path) -> dict[str, Any]:
    package_root = harness.parent
    files = sorted(package_root.rglob("*.py"))
    if not files:
        raise ValueError("imported harness package contains no Python source")
    digest = hashlib.sha256()
    total_bytes = 0
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"harness source member must be a regular non-symlink: {path}")
        raw = path.read_bytes()
        relative = path.relative_to(package_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw).hexdigest().encode("ascii"))
        digest.update(b"\n")
        total_bytes += len(raw)
    harness_identity = {
        "algorithm": "sha256_relative_path_size_file_digest_v1",
        "sha256": digest.hexdigest(),
        "file_count": len(files),
        "bytes": total_bytes,
    }
    # The default path must agree with the identity function used by Runner.
    if harness.resolve() == Path(runner_module.__file__).resolve():
        canonical = _harness_source_identity()
        if canonical != harness_identity:
            raise ValueError("project receipt and Runner harness source identities disagree")
    return {
        "harness_source": harness_identity,
        "driver_source": {
            "module": "run_matrix.py",
            "sha256": _sha256_file(driver),
            "file_count": 1,
        },
    }


def _untracked_or_ignored_executable_sources(root: Path) -> list[str]:
    untracked = _run_git(
        root,
        "ls-files", "--others", "--exclude-standard", "-z", "--",
        "src/ura", "experiments",
    )
    ignored = _run_git(
        root,
        "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--",
        "src/ura", "experiments",
    )
    try:
        candidates = {
            item
            for payload in (untracked, ignored)
            for item in payload.decode("utf-8").split("\0")
            if item
        }
    except UnicodeDecodeError as exc:
        raise ValueError("untracked project-source inventory is not UTF-8") from exc
    rejected: list[str] = []
    for item in sorted(candidates):
        path = Path(item)
        if any(part in {"__pycache__", ".pytest_cache", ".ruff_cache"} for part in path.parts):
            continue
        if path.suffix.lower() in _EXECUTABLE_SOURCE_SUFFIXES:
            rejected.append(path.as_posix())
    return sorted(rejected)


def current_project_revision(
    driver_path: Path,
    *,
    expected_revision: str | None = None,
    harness_module_path: Path | None = None,
) -> dict[str, Any]:
    """Inspect the current checkout and return portable revision/source identity.

    This is intentionally a live check: callers may invoke it again at a cell or
    publication boundary to detect source drift without making a provider call.
    """

    root, driver, harness = _module_paths(driver_path, harness_module_path)
    observed = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}").lower()
    tree = _git_text(root, "rev-parse", "--verify", "HEAD^{tree}").lower()
    if _HEX40.fullmatch(observed) is None or _HEX40.fullmatch(tree) is None:
        raise ValueError("project Git commit/tree must be full lowercase 40-hex identities")
    if expected_revision is not None:
        if expected_revision != expected_revision.strip():
            raise ValueError("expected project revision must not be padded")
        expected = expected_revision
        if _HEX40.fullmatch(expected) is None:
            raise ValueError("expected project revision must be a full 40-hex commit")
        if observed != expected:
            raise ValueError(
                f"project checkout revision mismatch: expected {expected}, observed {observed}"
            )
    status = _run_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no")
    if status:
        raise ValueError("project checkout has staged or unstaged tracked changes")
    executable_dirt = _untracked_or_ignored_executable_sources(root)
    if executable_dirt:
        raise ValueError(
            "project checkout contains untracked or ignored executable source members: "
            + ", ".join(executable_dirt[:20])
        )
    source = _source_identities(root, driver, harness)
    return {
        "repository": {
            "expected_commit": observed if expected_revision is None else expected_revision.lower(),
            "observed_commit": observed,
            "head_tree": tree,
            "clean": True,
            "root_relationship": ROOT_RELATIONSHIP,
        },
        "source": source,
    }


def create_project_revision(
    expected_revision: str,
    driver_path: Path,
    *,
    harness_module_path: Path | None = None,
) -> dict[str, Any]:
    """Create one deterministic receipt for an exact clean local checkout."""

    current = current_project_revision(
        driver_path,
        expected_revision=expected_revision,
        harness_module_path=harness_module_path,
    )
    body: dict[str, Any] = {
        "schema": PROJECT_REVISION_SCHEMA,
        "status": "complete",
        "purpose": "immutable_clean_project_source_receipt",
        **current,
        "limitations": dict(_LIMITATIONS),
    }
    body["revision_id"] = "project-revision-" + canonical_json_sha256(body)[:24]
    return validate_project_revision(body)


def validate_project_revision(value: object) -> dict[str, Any]:
    """Validate exact receipt fields, semantics, and content identity."""

    receipt = _strict_object(value, _TOP_FIELDS, "project revision receipt")
    if receipt.get("schema") != PROJECT_REVISION_SCHEMA:
        raise ValueError("unsupported project-revision schema")
    if receipt.get("status") != "complete" or receipt.get("purpose") != (
        "immutable_clean_project_source_receipt"
    ):
        raise ValueError("project-revision status/purpose is invalid")
    if receipt.get("limitations") != _LIMITATIONS:
        raise ValueError("project-revision claim limitations are incomplete")
    repository = _strict_object(
        receipt.get("repository"), _REPOSITORY_FIELDS, "project repository"
    )
    expected = repository.get("expected_commit")
    observed = repository.get("observed_commit")
    tree = repository.get("head_tree")
    if any(not isinstance(item, str) or _HEX40.fullmatch(item) is None for item in (
        expected, observed, tree,
    )):
        raise ValueError("project repository commit/tree identities must be lowercase 40-hex")
    if expected != observed:
        raise ValueError("project expected and observed commits differ")
    if repository.get("clean") is not True:
        raise ValueError("project revision receipt must describe a clean checkout")
    if repository.get("root_relationship") != ROOT_RELATIONSHIP:
        raise ValueError("project source-root relationship is invalid")
    source = _strict_object(receipt.get("source"), _SOURCE_FIELDS, "project source")
    harness = _strict_object(
        source.get("harness_source"), _HARNESS_FIELDS, "harness source identity"
    )
    if (
        harness.get("algorithm") != "sha256_relative_path_size_file_digest_v1"
        or not isinstance(harness.get("sha256"), str)
        or _HEX64.fullmatch(harness["sha256"]) is None
    ):
        raise ValueError("harness source identity is invalid")
    _positive_integer(harness.get("file_count"), "harness file_count")
    _positive_integer(harness.get("bytes"), "harness bytes")
    driver = _strict_object(
        source.get("driver_source"), _DRIVER_FIELDS, "driver source identity"
    )
    if (
        driver.get("module") != "run_matrix.py"
        or not isinstance(driver.get("sha256"), str)
        or _HEX64.fullmatch(driver["sha256"]) is None
        or driver.get("file_count") != 1
    ):
        raise ValueError("experiment-driver source identity is invalid")
    body = {key: item for key, item in receipt.items() if key != "revision_id"}
    expected_id = "project-revision-" + canonical_json_sha256(body)[:24]
    if receipt.get("revision_id") != expected_id or _REVISION_ID.fullmatch(expected_id) is None:
        raise ValueError("project-revision ID/content mismatch")
    return receipt


def recheck_project_revision(
    receipt: Mapping[str, Any],
    driver_path: Path,
    *,
    harness_module_path: Path | None = None,
) -> dict[str, Any]:
    """Require the current checkout to still match a validated receipt."""

    validated = validate_project_revision(dict(receipt))
    current = current_project_revision(
        driver_path,
        expected_revision=validated["repository"]["expected_commit"],
        harness_module_path=harness_module_path,
    )
    if current["repository"] != validated["repository"]:
        raise ValueError("current project repository identity differs from its receipt")
    if current["source"] != validated["source"]:
        raise ValueError("current project source bytes differ from their receipt")
    return validated


def project_revision_bytes(value: Mapping[str, Any]) -> bytes:
    receipt = validate_project_revision(dict(value))
    return (json.dumps(
        receipt, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False,
    ) + "\n").encode("utf-8")


def write_project_revision(directory: Path, value: Mapping[str, Any]) -> Path:
    """Persist an immutable content-addressed receipt without overwrite."""

    payload = project_revision_bytes(value)
    receipt = validate_project_revision(dict(value))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{receipt['revision_id']}.project-revision.json"
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError(f"project-revision artifact collision: {path}")
        return path
    temporary = path.with_name(f".{path.name}.pending-{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            raise FileExistsError(f"project-revision artifact appeared concurrently: {path}")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def load_project_revision_file(
    path: Path,
    expected_sha256: str,
    driver_path: Path,
    *,
    recheck_checkout: bool = True,
    harness_module_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load a digest-approved receipt and optionally recheck the live checkout."""

    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("project-revision input must be a regular non-symlink file")
    size = candidate.stat().st_size
    if size < 1 or size > _MAX_RECEIPT_BYTES:
        raise ValueError("project-revision input has an invalid byte size")
    digest = _sha256_file(candidate)
    if expected_sha256 != expected_sha256.strip():
        raise ValueError("project-revision SHA-256 must not be padded")
    expected_digest = expected_sha256
    if _HEX64.fullmatch(expected_digest) is None:
        raise ValueError("project-revision SHA-256 must be exactly 64 lowercase hex characters")
    if digest != expected_digest:
        raise ValueError(
            f"project-revision sha256 mismatch: expected {expected_digest}, got {digest}"
        )
    receipt = validate_project_revision(
        _strict_json_object(candidate.read_bytes(), label="project-revision input")
    )
    if recheck_checkout:
        recheck_project_revision(
            receipt, driver_path, harness_module_path=harness_module_path
        )
    return receipt, {
        "file": candidate.name,
        "sha256": digest,
        "bytes": size,
        "revision_id": receipt["revision_id"],
    }


def project_revision_binding(
    receipt: Mapping[str, Any], descriptor: Mapping[str, Any]
) -> dict[str, Any]:
    """Return the compact exact binding persisted by experiment artifacts."""

    validated = validate_project_revision(dict(receipt))
    repository = validated["repository"]
    source = validated["source"]
    required_descriptor = {"file", "sha256", "bytes", "revision_id"}
    if set(descriptor) != required_descriptor:
        raise ValueError("project-revision descriptor has an invalid field inventory")
    if descriptor.get("revision_id") != validated["revision_id"]:
        raise ValueError("project-revision descriptor identity mismatch")
    if (
        not isinstance(descriptor.get("file"), str)
        or Path(descriptor["file"]).name != descriptor["file"]
        or not isinstance(descriptor.get("sha256"), str)
        or _HEX64.fullmatch(descriptor["sha256"]) is None
        or isinstance(descriptor.get("bytes"), bool)
        or not isinstance(descriptor.get("bytes"), int)
        or descriptor["bytes"] < 1
    ):
        raise ValueError("project-revision descriptor is invalid")
    return validate_project_revision_binding({
        "mode": "verified",
        **dict(descriptor),
        "expected_commit": repository["expected_commit"],
        "observed_commit": repository["observed_commit"],
        "head_tree": repository["head_tree"],
        "harness_source_sha256": source["harness_source"]["sha256"],
        "driver_source_sha256": source["driver_source"]["sha256"],
    })


def diagnostic_project_revision_binding(
    harness_source_sha256: str, driver_source_sha256: str,
) -> dict[str, Any]:
    """Represent intentionally unverified Git identity for an offline diagnostic."""

    return validate_project_revision_binding({
        "mode": "not_required_diagnostic_dry_run",
        "revision_id": None,
        "file": None,
        "sha256": None,
        "bytes": None,
        "expected_commit": None,
        "observed_commit": None,
        "head_tree": None,
        "harness_source_sha256": harness_source_sha256,
        "driver_source_sha256": driver_source_sha256,
    })


def validate_project_revision_binding(
    value: object, *, allow_not_required: bool = True,
) -> dict[str, Any]:
    """Validate the exact compact receipt binding shared by all consumers."""

    binding = _strict_object(value, _BINDING_FIELDS, "project-revision binding")
    for field in ("harness_source_sha256", "driver_source_sha256"):
        item = binding.get(field)
        if not isinstance(item, str) or _HEX64.fullmatch(item) is None:
            raise ValueError(f"project-revision binding {field} is invalid")
    mode = binding.get("mode")
    identity_fields = (
        "revision_id", "file", "sha256", "bytes", "expected_commit",
        "observed_commit", "head_tree",
    )
    if mode == "not_required_diagnostic_dry_run":
        if not allow_not_required:
            raise ValueError("verified project revision is required")
        if any(binding.get(field) is not None for field in identity_fields):
            raise ValueError("diagnostic project-revision identity fields must be null")
        return binding
    if mode != "verified":
        raise ValueError("project-revision binding mode is invalid")
    revision_id = binding.get("revision_id")
    filename = binding.get("file")
    digest = binding.get("sha256")
    byte_count = binding.get("bytes")
    if not isinstance(revision_id, str) or _REVISION_ID.fullmatch(revision_id) is None:
        raise ValueError("project-revision binding revision_id is invalid")
    if (
        not isinstance(filename, str)
        or Path(filename).name != filename
        or filename != f"{revision_id}.project-revision.json"
    ):
        raise ValueError("project-revision binding filename is invalid")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError("project-revision binding sha256 is invalid")
    _positive_integer(byte_count, "project-revision binding bytes")
    expected = binding.get("expected_commit")
    observed = binding.get("observed_commit")
    tree = binding.get("head_tree")
    if any(not isinstance(item, str) or _HEX40.fullmatch(item) is None for item in (
        expected, observed, tree,
    )):
        raise ValueError("project-revision binding commit/tree identity is invalid")
    if expected != observed:
        raise ValueError("project-revision binding expected/observed commits differ")
    return binding


__all__ = [
    "PROJECT_REVISION_SCHEMA", "ROOT_RELATIONSHIP", "create_project_revision",
    "current_project_revision", "diagnostic_project_revision_binding",
    "load_project_revision_file",
    "project_revision_binding", "project_revision_bytes", "recheck_project_revision",
    "validate_project_revision", "validate_project_revision_binding",
    "write_project_revision",
]
