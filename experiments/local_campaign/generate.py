"""Render commit-bound campaign controllers from versioned source templates.

The source templates are the reviewable implementation.  A workspace render is
only a disposable binding of those sources to one deployed revision, receipt
set, evidence inventory, and tmux schedule.  This keeps controller fixes in Git
without pretending that a controller can contain the hash of the commit that
will eventually contain it.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
from typing import Mapping, Sequence


BINDINGS_SCHEMA = "ura-local-campaign-controller-bindings/1"
GENERATION_SCHEMA = "ura-local-campaign-controller-generation/1"
TOKEN = re.compile(
    r"@@([A-Z][A-Z0-9_]*|(?:SHA|BYTES):[a-z0-9_.-]+|"
    r"(?:PAYLOAD_SHA|PAYLOAD_BYTES):[a-z0-9_.-]+:[A-Z][A-Z0-9_]*)@@"
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TAG = re.compile(r"20[0-9]{6}T[0-9]{6}Z")
SAFE_BINDING_VALUE = re.compile(r"[A-Za-z0-9_./-]+")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")
SAFE_REASON = re.compile(r"[a-z][a-z0-9_]{0,127}")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")
CANONICAL_NONNEGATIVE_INTEGER = re.compile(r"0|[1-9][0-9]*")
MAX_PHASE3_DOWNLOAD_BYTES = 8 * 1024 * 1024 * 1024

DERIVED_BINDINGS = frozenset(
    {"COMMIT_SHORT", "PROJECT_RECEIPT_NAME", "SOURCE_RECEIPT_NAME"}
)
SUPPORT_BINDINGS = frozenset(
    {
        "ARCHIVE_BYTES",
        "ARCHIVE_SHA256",
        "INVENTORY_BYTES",
        "INVENTORY_NAME",
        "INVENTORY_SHA256",
        "VERIFIER_SHA256",
    }
)
INTERNAL_BINDINGS = DERIVED_BINDINGS | SUPPORT_BINDINGS

# This is deliberately explicit rather than inferred as the accepted input
# schema. A reviewed template change and a reviewed binding-schema change must
# happen together, so an added placeholder cannot silently become an operator
# controlled shell/Python source fragment.
EXTERNAL_BINDINGS = frozenset(
    {
        "CONTROLLER_INSTALL_ROOT",
        "EXPECTED_COMMIT",
        "FAILED_CANARY_ONE_TAG",
        "FAILED_CANARY_THREE_TAG",
        "FAILED_CANARY_TWO_TAG",
        "FRAMEWORK_LOCK_SHA256",
        "GATE5_SEQUENCE_TAG",
        "HISTORICAL_PROMPT_PROJECT_NAME",
        "HISTORICAL_PROMPT_PROJECT_SHA256",
        "PHASE3_ACQUISITION_BYTES",
        "PHASE3_ACQUISITION_RECEIPT_BYTES",
        "PHASE3_ACQUISITION_RECEIPT_NAME",
        "PHASE3_ACQUISITION_RECEIPT_SHA256",
        "PHASE3_ACQUISITION_SHA256",
        "PHASE3_CANONICAL_ARGV_SHA256",
        "PHASE3_DOWNLOADED_BYTES",
        "PHASE3_ELIGIBILITY_BYTES",
        "PHASE3_ELIGIBILITY_NAME",
        "PHASE3_ELIGIBILITY_SHA256",
        "PHASE3_ENVELOPE_BYTES",
        "PHASE3_ENVELOPE_NAME",
        "PHASE3_ENVELOPE_SHA256",
        "PHASE3_FIT_LOG_BYTES",
        "PHASE3_FIT_LOG_SHA256",
        "PHASE3_FIT_RESULT_BYTES",
        "PHASE3_FIT_RESULT_SHA256",
        "PHASE3_GPU_AFTER_BYTES",
        "PHASE3_GPU_AFTER_SHA256",
        "PHASE3_GPU_BEFORE_BYTES",
        "PHASE3_GPU_BEFORE_SHA256",
        "PHASE3_GUARD_TAG",
        "PHASE3_PLAN_BYTES",
        "PHASE3_PLAN_NAME",
        "PHASE3_PLAN_SHA256",
        "PHASE3_PROJECTION_BYTES",
        "PHASE3_PROJECTION_NAME",
        "PHASE3_PROJECTION_SHA256",
        "PHASE3_REQUEST_BYTES",
        "PHASE3_REQUEST_SHA256",
        "PHASE5_SEQUENCE_TAG",
        "PHASE6_SEQUENCE_TAG",
        "PHASE7_WATCHER_TAG",
        "PROJECT_RECEIPT_BYTES",
        "PROJECT_RECEIPT_PATH",
        "PROJECT_RECEIPT_SHA256",
        "PROJECT_ROOT",
        "PROMPT_OBSERVATION_TAG",
        "PROMPT_SUMMARY_SHA256",
        "PHASE6_RECOVERY_INPUTS_BYTES",
        "PHASE6_RECOVERY_INPUTS_PATH",
        "PHASE6_RECOVERY_INPUTS_SHA256",
        "PHASE6_RECOVERY_TAG",
        "QWEN_CONFIG_SHA256",
        "RR_IMAGE_EVIDENCE_ROOT",
        "RR_TEXT_EVIDENCE_ROOT",
        "RR_TRANSFORMERS_EVIDENCE_ROOT",
        "RR_VLLM_TAIL_EVIDENCE_ROOT",
        "SOURCE_CONFIG_SHA256",
        "SOURCE_RECEIPT_PATH",
        "SOURCE_RECEIPT_RETAINED_NAME",
        "SOURCE_RECEIPT_SHA256",
        "SEVEN_POLICY_INPUTS_BYTES",
        "SEVEN_POLICY_INPUTS_PATH",
        "SEVEN_POLICY_INPUTS_SHA256",
        "SEVEN_POLICY_TAG",
        "WORK_ROOT",
    }
)

PHASE3_BINDINGS_ADDED_AFTER_A05 = frozenset(
    {
        "PHASE3_ACQUISITION_BYTES",
        "PHASE3_ACQUISITION_RECEIPT_BYTES",
        "PHASE3_DOWNLOADED_BYTES",
        "PHASE3_ELIGIBILITY_BYTES",
        "PHASE3_ENVELOPE_BYTES",
        "PHASE3_FIT_LOG_BYTES",
        "PHASE3_FIT_RESULT_BYTES",
        "PHASE3_GPU_AFTER_BYTES",
        "PHASE3_GPU_AFTER_SHA256",
        "PHASE3_GPU_BEFORE_BYTES",
        "PHASE3_GPU_BEFORE_SHA256",
        "PHASE3_PLAN_BYTES",
        "PHASE3_PROJECTION_BYTES",
        "PHASE3_REQUEST_BYTES",
        "PROJECT_RECEIPT_BYTES",
    }
)

# Commit 5719a4f and its retained controller binding predate the four exact
# GraySwan RR termination-evidence roots.  Keep that historical inventory
# explicit so rebind can migrate it without accepting an arbitrary partial
# current document.
RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719 = frozenset(
    {
        "RR_IMAGE_EVIDENCE_ROOT",
        "RR_TEXT_EVIDENCE_ROOT",
        "RR_TRANSFORMERS_EVIDENCE_ROOT",
        "RR_VLLM_TAIL_EVIDENCE_ROOT",
    }
)
RECOVERY_BINDINGS_ADDED_AFTER_73C5331 = frozenset(
    {
        "PHASE6_RECOVERY_INPUTS_BYTES",
        "PHASE6_RECOVERY_INPUTS_PATH",
        "PHASE6_RECOVERY_INPUTS_SHA256",
        "PHASE6_RECOVERY_TAG",
        "SEVEN_POLICY_INPUTS_BYTES",
        "SEVEN_POLICY_INPUTS_PATH",
        "SEVEN_POLICY_INPUTS_SHA256",
        "SEVEN_POLICY_TAG",
    }
)
PRE_RECOVERY_EXTERNAL_BINDINGS = frozenset(
    EXTERNAL_BINDINGS - RECOVERY_BINDINGS_ADDED_AFTER_73C5331
)
PRE_RR_EXTERNAL_BINDINGS = frozenset(
    PRE_RECOVERY_EXTERNAL_BINDINGS - RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719
)
LEGACY_A05_EXTERNAL_BINDINGS = frozenset(
    (PRE_RR_EXTERNAL_BINDINGS - PHASE3_BINDINGS_ADDED_AFTER_A05)
    | {"PHASE3_GPU_INVENTORY_SHA256"}
)


@dataclass(frozen=True)
class Controller:
    template: str
    output: str
    self_test: str = "none"


# Keep this list explicit.  It is both the packaging allow-list and the test
# oracle that prevents an operator-only controller from silently becoming the
# sole implementation of a campaign phase.
CONTROLLERS: tuple[Controller, ...] = (
    Controller("phase3_guard1b_acquire_fit.sh.in", "phase3_guard1b_acquire_fit.sh", "phase3-guard-fit"),
    Controller("phase5_core_projections.sh.in", "phase5_core_projections.sh"),
    Controller("phase5_core_attest_canary.sh.in", "phase5_core_attest_canary.sh"),
    Controller("phase5_bridge_projections.sh.in", "phase5_bridge_projections.sh"),
    Controller("phase5_bridge_attest_canary.sh.in", "phase5_bridge_attest_canary.sh"),
    Controller("phase5_ollama_workflow.sh.in", "phase5_ollama_workflow.sh"),
    Controller("phase5_sequence_after_core.sh.in", "phase5_sequence_after_core.sh"),
    Controller("phase5_finalize_gate5.sh.in", "phase5_finalize_gate5.sh", "gate5-inventory"),
    Controller("phase5_promote_gate5.sh.in", "phase5_promote_gate5.sh", "gate5-promotion"),
    Controller("phase5_followon_prepared.sh.in", "phase5_followon_prepared.sh"),
    Controller("gate5_after_phase5_sequence.sh.in", "gate5_after_phase5_sequence.sh"),
    Controller("launch_phase5_sequence.sh.in", "launch_phase5_sequence.sh"),
    Controller("launch_gate5_sequence.sh.in", "launch_gate5_sequence.sh"),
    Controller("phase6_core_measured.sh.in", "phase6_core_measured.sh"),
    Controller("phase6_extended_measured.sh.in", "phase6_extended_measured.sh"),
    Controller("phase6_current_ollama.sh.in", "phase6_current_ollama.sh"),
    Controller("phase6_followon_prepared.sh.in", "phase6_followon_prepared.sh"),
    Controller(
        "followon_prepared_controller.py.in",
        "followon_prepared_controller.py",
        "followon-contract",
    ),
    Controller("phase6_native_diagnostics.sh.in", "phase6_native_diagnostics.sh"),
    Controller("phase6_sequence.sh.in", "phase6_sequence.sh"),
    Controller("launch_phase6_sequence.sh.in", "launch_phase6_sequence.sh"),
    Controller("phase6_core_length_recovery.py.in", "phase6_core_length_recovery.py"),
    Controller("phase6_seven_output_policy.py.in", "phase6_seven_output_policy.py"),
    Controller(
        "launch_phase6_recovery_and_seven.sh.in",
        "launch_phase6_recovery_and_seven.sh",
        "recovery-sequence",
    ),
    Controller("phase7_analysis.py.in", "phase7_analysis.py", "phase7-contract"),
    Controller("phase7_analysis.sh.in", "phase7_analysis.sh"),
    Controller("phase7_after_phase6_sequence.sh.in", "phase7_after_phase6_sequence.sh"),
    Controller("launch_phase7_watcher.sh.in", "launch_phase7_watcher.sh"),
    Controller("phase8_human_audit.py.in", "phase8_human_audit.py", "phase8-self-test"),
    Controller("phase8_human_audit.sh.in", "phase8_human_audit.sh"),
    Controller("phase8_human_audit.README.md.in", "phase8_human_audit.README.md"),
    Controller("launch_chain.sh.in", "launch_chain_{commit_short}.sh"),
)
SUPPORT_TEMPLATES = {"verify_controller_set.sh.in", "install_controller_set.sh.in"}


class ControllerGenerationError(ValueError):
    """A binding or generated controller violates the source contract."""


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _simple_template_tokens() -> frozenset[str]:
    tokens: set[str] = set()
    for path in _template_dir().glob("*.in"):
        text = path.read_text(encoding="utf-8")
        tokens.update(token for token in TOKEN.findall(text) if ":" not in token)
    return frozenset(tokens)


def external_binding_keys_from_templates() -> frozenset[str]:
    """Return the reviewed external placeholder inventory or fail closed."""

    observed = _simple_template_tokens()
    expected = EXTERNAL_BINDINGS | INTERNAL_BINDINGS
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise ControllerGenerationError(
            "template binding inventory differs: "
            f"missing={missing}, extra={extra}"
        )
    return observed - INTERNAL_BINDINGS


def _validate_posix_path(key: str, value: str) -> None:
    parts = value.split("/")
    if (
        value == "/"
        or not value.startswith("/")
        or value.startswith("//")
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in parts[1:])
        or any(len(part) > 255 for part in parts[1:])
        or PurePosixPath(value).as_posix() != value
    ):
        raise ControllerGenerationError(
            f"{key} must be one canonical absolute POSIX path"
        )


def _validate_binding_value(
    key: str,
    value: str,
    *,
    allow_legacy_controller_root: bool = False,
) -> None:
    if len(value) > 4096 or SAFE_BINDING_VALUE.fullmatch(value) is None:
        raise ControllerGenerationError(
            f"{key} contains unsafe or non-ASCII binding characters"
        )
    if key == "EXPECTED_COMMIT":
        if HEX40.fullmatch(value) is None:
            raise ControllerGenerationError(
                "EXPECTED_COMMIT must be lowercase 40-hex"
            )
        return
    if key == "PHASE3_DOWNLOADED_BYTES":
        if CANONICAL_NONNEGATIVE_INTEGER.fullmatch(value) is None:
            raise ControllerGenerationError(
                "PHASE3_DOWNLOADED_BYTES must be one canonical nonnegative integer"
            )
        if int(value) > MAX_PHASE3_DOWNLOAD_BYTES:
            raise ControllerGenerationError(
                "PHASE3_DOWNLOADED_BYTES exceeds the 8 GiB acquisition cap"
            )
        return
    if key.endswith("_BYTES"):
        if POSITIVE_INTEGER.fullmatch(value) is None:
            raise ControllerGenerationError(
                f"{key} must be one canonical positive integer"
            )
        return
    if key.endswith("SHA256"):
        if HEX64.fullmatch(value) is None:
            raise ControllerGenerationError(f"{key} must be lowercase 64-hex")
        return
    if key.endswith("_TAG"):
        if TAG.fullmatch(value) is None:
            raise ControllerGenerationError(f"{key} must be a UTC campaign tag")
        try:
            parsed = datetime.strptime(value, "%Y%m%dT%H%M%SZ")
        except ValueError as exc:
            raise ControllerGenerationError(
                f"{key} must be a real UTC datetime"
            ) from exc
        if parsed.strftime("%Y%m%dT%H%M%SZ") != value:
            raise ControllerGenerationError(f"{key} must be a real UTC datetime")
        return
    if key.endswith(("_PATH", "_ROOT")):
        _validate_posix_path(key, value)
        if (
            key == "CONTROLLER_INSTALL_ROOT"
            and PurePosixPath(value).name != ".ura-controller-active"
            and not (allow_legacy_controller_root and value == "/home/ura")
        ):
            raise ControllerGenerationError(
                "CONTROLLER_INSTALL_ROOT must name .ura-controller-active"
            )
        return
    if key.endswith("_NAME"):
        if SAFE_NAME.fullmatch(value) is None or value in {".", ".."}:
            raise ControllerGenerationError(f"{key} must be one safe basename")
        return
    if key.endswith("_REASON"):
        if SAFE_REASON.fullmatch(value) is None:
            raise ControllerGenerationError(
                f"{key} must be one lowercase safe reason identifier"
            )
        return
    raise ControllerGenerationError(f"{key} has no semantic binding validator")


def validate_binding_document(
    raw: object,
    *,
    expected_keys: frozenset[str] = EXTERNAL_BINDINGS,
) -> dict[str, str]:
    external_binding_keys_from_templates()
    if expected_keys not in {
        EXTERNAL_BINDINGS,
        PRE_RECOVERY_EXTERNAL_BINDINGS,
        PRE_RR_EXTERNAL_BINDINGS,
        LEGACY_A05_EXTERNAL_BINDINGS,
    }:
        raise ControllerGenerationError("unsupported binding-key inventory")
    if not isinstance(raw, dict) or set(raw) != {"schema", "values"}:
        raise ControllerGenerationError("bindings must contain exactly schema and values")
    if raw["schema"] != BINDINGS_SCHEMA or not isinstance(raw["values"], dict):
        raise ControllerGenerationError("unsupported controller binding schema")
    values = raw["values"]
    if any(
        not isinstance(key, str) or not isinstance(value, str) or not value
        for key, value in values.items()
    ):
        raise ControllerGenerationError("binding names and values must be non-empty strings")
    actual_keys = set(values)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise ControllerGenerationError(
            f"external binding inventory differs: missing={missing}, extra={extra}"
        )
    for key, value in values.items():
        _validate_binding_value(
            key,
            value,
            allow_legacy_controller_root=(
                expected_keys == LEGACY_A05_EXTERNAL_BINDINGS
            ),
        )
    return dict(values)


def _load_bindings(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControllerGenerationError(f"cannot load controller bindings: {exc}") from exc
    return validate_binding_document(raw)


def _template_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def _output_name(spec: Controller, values: Mapping[str, str]) -> str:
    return spec.output.format(commit_short=values["EXPECTED_COMMIT"][:7])


def _embedded_payload(data: bytes, *, marker: str, dependency: str) -> bytes:
    opening = f"<<'{marker}'\n".encode("ascii")
    closing = f"\n{marker}\n".encode("ascii")
    if data.count(opening) != 1:
        raise ControllerGenerationError(
            f"cannot locate one {marker} payload opener in {dependency}"
        )
    body = data.split(opening, 1)[1]
    if body.count(closing) != 1:
        raise ControllerGenerationError(
            f"cannot locate one {marker} payload closer in {dependency}"
        )
    return body.split(closing, 1)[0] + b"\n"


def _dependency_replacement(token: str, rendered: Mapping[str, bytes]) -> str:
    parts = token.split(":")
    kind, dependency = parts[:2]
    try:
        data = rendered[dependency]
    except KeyError as exc:
        raise ControllerGenerationError(
            f"missing rendered dependency {dependency}"
        ) from exc
    if kind == "SHA":
        return _sha(data)
    if kind == "BYTES":
        return str(len(data))
    if len(parts) != 3:
        raise ControllerGenerationError(f"invalid embedded-payload token: {token}")
    payload = _embedded_payload(data, marker=parts[2], dependency=dependency)
    return _sha(payload) if kind == "PAYLOAD_SHA" else str(len(payload))


def _render_all(values: Mapping[str, str]) -> tuple[dict[str, bytes], dict[str, str]]:
    templates = _template_dir()
    expanded_values = dict(values)
    expanded_values.update(
        {
            "COMMIT_SHORT": values["EXPECTED_COMMIT"][:7],
            "PROJECT_RECEIPT_NAME": Path(values["PROJECT_RECEIPT_PATH"]).name,
            "SOURCE_RECEIPT_NAME": Path(values["SOURCE_RECEIPT_PATH"]).name,
        }
    )
    expected_templates = {spec.template for spec in CONTROLLERS}
    actual_templates = {path.name for path in templates.glob("*.in")}
    expected_all_templates = expected_templates | SUPPORT_TEMPLATES
    if actual_templates != expected_all_templates:
        missing = sorted(expected_all_templates - actual_templates)
        extra = sorted(actual_templates - expected_all_templates)
        raise ControllerGenerationError(f"controller template inventory differs: missing={missing}, extra={extra}")

    pending = {spec.template: spec for spec in CONTROLLERS}
    rendered: dict[str, bytes] = {}
    source_sha: dict[str, str] = {}
    while pending:
        progressed = False
        for template_name, spec in tuple(pending.items()):
            source_path = templates / template_name
            source = source_path.read_bytes()
            source_sha[template_name] = _sha(source)
            try:
                text = source.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ControllerGenerationError(f"template is not UTF-8: {template_name}") from exc

            unresolved_dependency = False
            replacements: dict[str, str] = {}
            for token in set(TOKEN.findall(text)):
                if token.startswith(("SHA:", "BYTES:", "PAYLOAD_SHA:", "PAYLOAD_BYTES:")):
                    dependency = token.split(":", 2)[1]
                    if dependency not in rendered:
                        unresolved_dependency = True
                        break
                    replacements[token] = _dependency_replacement(token, rendered)
                else:
                    try:
                        replacements[token] = expanded_values[token]
                    except KeyError as exc:
                        raise ControllerGenerationError(f"missing binding {token} required by {template_name}") from exc
            if unresolved_dependency:
                continue
            for token, replacement in replacements.items():
                text = text.replace(f"@@{token}@@", replacement)
            leftover = TOKEN.findall(text)
            if leftover or "@@" in text:
                raise ControllerGenerationError(
                    f"unresolved template marker in {template_name}: "
                    f"tokens={sorted(set(leftover))}"
                )
            output = _output_name(spec, values)
            rendered[output] = text.encode("utf-8")
            del pending[template_name]
            progressed = True
        if not progressed:
            waiting = sorted(pending)
            raise ControllerGenerationError(f"controller hash dependency cycle or missing output: {waiting}")
    return rendered, source_sha


def _render_support(
    template_name: str,
    values: Mapping[str, str],
    rendered: Mapping[str, bytes],
    extra: Mapping[str, str],
) -> bytes:
    expanded = dict(values)
    expanded.update(
        {
            "COMMIT_SHORT": values["EXPECTED_COMMIT"][:7],
            "PROJECT_RECEIPT_NAME": Path(values["PROJECT_RECEIPT_PATH"]).name,
            "SOURCE_RECEIPT_NAME": Path(values["SOURCE_RECEIPT_PATH"]).name,
        }
    )
    expanded.update(extra)
    text = (_template_dir() / template_name).read_text(encoding="utf-8")
    for token in set(TOKEN.findall(text)):
        if token.startswith(("SHA:", "BYTES:", "PAYLOAD_SHA:", "PAYLOAD_BYTES:")):
            replacement = _dependency_replacement(token, rendered)
        else:
            try:
                replacement = expanded[token]
            except KeyError as exc:
                raise ControllerGenerationError(
                    f"missing support-template binding {token}"
                ) from exc
        text = text.replace(f"@@{token}@@", replacement)
    leftover = TOKEN.findall(text)
    if leftover or "@@" in text:
        raise ControllerGenerationError(
            "unresolved support-template marker: "
            f"tokens={sorted(set(leftover))}"
        )
    return text.encode("utf-8")


def _inventory_bytes(rendered: Mapping[str, bytes], values: Mapping[str, str]) -> bytes:
    self_tests = {_output_name(spec, values): spec.self_test for spec in CONTROLLERS}
    ordered_names = [_output_name(spec, values) for spec in CONTROLLERS]
    if set(rendered) != set(ordered_names) or len(rendered) != len(ordered_names):
        raise ControllerGenerationError("rendered controller inventory is not exact")
    rows = [
        (
            f"{name}\t{len(rendered[name])}\t{_sha(rendered[name])}\t"
            f"{self_tests[name]}\n"
        )
        for name in ordered_names
    ]
    return "".join(rows).encode("utf-8")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def render_controller_set(bindings_path: Path, output_dir: Path) -> dict[str, object]:
    values = _load_bindings(bindings_path.resolve(strict=True))
    rendered, source_sha = _render_all(values)
    short = values["EXPECTED_COMMIT"][:7]
    inventory_name = f"controller_inventory_{short}.tsv"
    inventory = _inventory_bytes(rendered, values)
    for name, data in rendered.items():
        _atomic_write(output_dir / name, data, 0o700 if name.endswith(".sh") else 0o600)
    _atomic_write(output_dir / inventory_name, inventory)
    record: dict[str, object] = {
        "schema": GENERATION_SCHEMA,
        "bindings": {"path": str(bindings_path.resolve()), "sha256": _sha(bindings_path.read_bytes())},
        "expected_commit": values["EXPECTED_COMMIT"],
        "inventory": {"name": inventory_name, "sha256": _sha(inventory), "size": len(inventory)},
        "outputs": {name: {"sha256": _sha(data), "size": len(data)} for name, data in rendered.items()},
        "sources": source_sha,
    }
    _atomic_write(output_dir / f"controller_generation_{short}.json", _canonical_json(record))
    return record


def verify_controller_set(bindings_path: Path, output_dir: Path) -> dict[str, object]:
    values = _load_bindings(bindings_path.resolve(strict=True))
    rendered, source_sha = _render_all(values)
    short = values["EXPECTED_COMMIT"][:7]
    inventory_name = f"controller_inventory_{short}.tsv"
    expected = dict(rendered)
    expected[inventory_name] = _inventory_bytes(rendered, values)
    differences: list[str] = []
    for name, data in expected.items():
        path = output_dir / name
        if not path.is_file() or path.is_symlink() or path.read_bytes() != data:
            differences.append(name)
    if differences:
        raise ControllerGenerationError(f"generated controller set diverges: {sorted(differences)}")
    return {
        "schema": GENERATION_SCHEMA,
        "expected_commit": values["EXPECTED_COMMIT"],
        "inventory": inventory_name,
        "outputs": sorted(rendered),
        "sources": source_sha,
    }


def _archive_bytes(files: Mapping[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o700 if name.endswith(".sh") else 0o600
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def package_controller_set(bindings_path: Path, output_dir: Path) -> dict[str, object]:
    values = _load_bindings(bindings_path.resolve(strict=True))
    rendered, _ = _render_all(values)
    short = values["EXPECTED_COMMIT"][:7]
    inventory_name = f"controller_inventory_{short}.tsv"
    inventory = _inventory_bytes(rendered, values)
    verifier_name = f"verify_controllers_{short}.sh"
    verifier = _render_support(
        "verify_controller_set.sh.in",
        values,
        rendered,
        {
            "INVENTORY_NAME": inventory_name,
            "INVENTORY_SHA256": _sha(inventory),
            "INVENTORY_BYTES": str(len(inventory)),
        },
    )
    archive_name = f"controller-set-{short}.tar"
    archive = _archive_bytes({**rendered, inventory_name: inventory, verifier_name: verifier})
    installer_name = f"install_controller_set_{short}.sh"
    installer = _render_support(
        "install_controller_set.sh.in",
        values,
        rendered,
        {
            "ARCHIVE_SHA256": _sha(archive),
            "ARCHIVE_BYTES": str(len(archive)),
            "INVENTORY_NAME": inventory_name,
            "INVENTORY_SHA256": _sha(inventory),
            "INVENTORY_BYTES": str(len(inventory)),
            "VERIFIER_SHA256": _sha(verifier),
        },
    )
    # Refuse rather than overwrite a workspace-only controller edit. Rendering
    # and review are separate operator steps before packaging.
    verify_controller_set(bindings_path, output_dir)
    _atomic_write(output_dir / verifier_name, verifier, 0o700)
    _atomic_write(output_dir / archive_name, archive)
    _atomic_write(output_dir / installer_name, installer, 0o700)
    record: dict[str, object] = {
        "schema": "ura-local-campaign-controller-package/1",
        "expected_commit": values["EXPECTED_COMMIT"],
        "archive": {"name": archive_name, "sha256": _sha(archive), "size": len(archive)},
        "installer": {"name": installer_name, "sha256": _sha(installer), "size": len(installer)},
        "verifier": {"name": verifier_name, "sha256": _sha(verifier), "size": len(verifier)},
        "inventory": {"name": inventory_name, "sha256": _sha(inventory), "size": len(inventory)},
    }
    _atomic_write(output_dir / f"controller_package_{short}.json", _canonical_json(record))
    return record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--check", action="store_true", help="fail unless every generated byte matches")
    parser.add_argument("--package", action="store_true", help="also build the verifier, archive, and installer")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check and args.package:
            raise ControllerGenerationError("--check and --package are mutually exclusive")
        if args.package:
            result = package_controller_set(args.bindings, args.output_dir)
        elif args.check:
            result = verify_controller_set(args.bindings, args.output_dir)
        else:
            result = render_controller_set(args.bindings, args.output_dir)
    except ControllerGenerationError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
