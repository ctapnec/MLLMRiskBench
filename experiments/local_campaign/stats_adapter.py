"""Local-campaign adapter for sealed read-only analysis reports."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from ura.strict_json import strict_json_loads

from experiments.rig_web_app.external_analysis import (
    ExternalAnalysisReportSpec,
    publish_external_analysis_registration,
)
from experiments.rig_web_app.reports import _validate_report_document


class EngineeringCampaignRecord(Protocol):
    """Structural campaign record consumed by this plan-owned adapter."""

    route_id: str
    directory: Path
    evidence_class: str
    status_tag: str
    release_commit: str


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CONTROL_BYTES = 16 * 1024 * 1024
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_ARTIFACTS = 5_000

_WATCHER_LAUNCH_FIELDS = {
    "schema",
    "status",
    "started_at_utc",
    "expected_commit",
    "framework_lock_id",
    "control_root",
    "authorized_watcher_sha256",
    "watcher",
    "phase7_wrapper",
    "phase7_payload",
    "phase6_wait",
    "target_calls_permitted",
    "judge_calls_permitted",
    "provider_http_attempts_permitted",
}
_PREPARE_RESULT_FIELDS = {
    "status",
    "schema",
    "output",
    "sha256",
    "bytes",
    "bound_artifacts",
    "runner_lanes",
    "metric_runner_lanes",
    "native_outcomes",
    "campaign_terminal_rows",
    "campaign_terminal_status",
    "authorization_required_before_launch",
}
_PHASE7_LAUNCH_FIELDS = {
    "SESSION",
    "SOCKET",
    "ATTACH",
    "CONTROL_ROOT",
    "ANALYSIS_ROOT",
    "LOG",
    "EXIT_MARKER",
    "COMPLETION",
}
_ANALYSIS_LAUNCH_FIELDS = {
    "schema",
    "authorized_input_manifest_sha256",
    "input_manifest",
    "payload",
    "control_root",
    "analysis_root",
}
_PHASE6_COMPLETION_FIELDS = {
    "schema",
    "status",
    "completed_at_utc",
    "expected_commit",
    "framework_lock_id",
    "control_root",
    "controller_order",
    "all_controllers_attempted",
    "terminal_states",
    "terminal_inventories",
    "successful_controller_evidence",
    "failed_controller_terminals",
    "failed_controller_receipts_are_evidence",
    "conditional_na_lanes",
    "children",
    "sequence_launch",
    "sequence_script",
    "phase7_validator",
    "phase7_contract_self_test",
    "controller_wrappers",
    "steps",
    "gate5",
    "native_plan",
    "native_plan_result",
    "hosted_target_calls",
    "hosted_judge_calls",
    "provider_http_attempts",
    "downloads_observed_bytes",
}
_PHASE6_LAUNCH_FIELDS = {
    "schema",
    "status",
    "started_at_utc",
    "expected_commit",
    "framework_lock_id",
    "control_root",
    "authorized_sequence_sha256",
    "sequence_script",
    "phase7_validator",
    "phase7_contract_self_test",
    "controller_wrappers",
    "gate5_wait",
    "controller_order",
    "long_running_children_use_tmux",
    "local_only",
}
_PHASE6_GATE5_FIELDS = {
    "sequence_completion",
    "sequence_exit",
    "initial_validation",
    "final_validation",
    "covered_manifest",
    "canonical_runnote",
    "promotion_receipt",
    "runnable_lanes",
    "typed_terminal_lanes",
    "target_runtime_terminal",
    "conditional_na_lanes",
}
_STRATUM_ID = re.compile(r"[0-9a-f]{12}-[0-9a-f]{12}\Z")

_WATCHER_FIELDS = {
    "schema",
    "status",
    "completed_at_utc",
    "expected_commit",
    "framework_lock_id",
    "watcher_launch",
    "watcher",
    "phase7_wrapper",
    "phase7_payload",
    "phase6_sequence_completion",
    "phase6_sequence_exit",
    "prepare_result",
    "authorized_input_manifest",
    "authorized_input_manifest_sha256",
    "phase7_launch_output",
    "phase7_control_root",
    "analysis_root",
    "phase7_completion",
    "phase7_exit",
    "artifact_inventory",
    "campaign_terminal_inventory",
    "runner_input_view",
    "human_audit_runner_input_view",
    "human_audit_sampling_index",
    "analysis_statuses",
    "explicit_limitations",
    "target_calls",
    "judge_calls",
    "provider_http_attempts",
    "downloads_observed_bytes",
    "human_labels_consumed",
}
_CONTROLLER_FIELDS = {
    "schema",
    "status",
    "started_at_utc",
    "completed_at_utc",
    "inventory_complete",
    "input_manifest",
    "authorized_input_manifest_sha256",
    "payload",
    "analysis_root",
    "artifact_inventory",
    "campaign_terminal_inventory",
    "runner_input_view",
    "human_audit_runner_input_view",
    "human_audit_sampling_index",
    "analysis_statuses",
    "explicit_limitations",
    "phase6_terminal_states",
    "followon_terminal_states",
    "followon_metric_revision_strata",
    "seven_output_policy_terminal_states",
    "seven_output_policy_metric_revision_strata",
    "current_ollama_terminal_states",
    "current_ollama_metric_revision_strata",
    "current_ollama_target_execution",
    "current_ollama_stability_terminal_states",
    "current_ollama_stability_metric_revision_strata",
    "current_ollama_stability_target_execution",
    "vllm_stability_terminal_states",
    "vllm_stability_metric_revision_strata",
    "vllm_stability_target_execution",
    "target_calls",
    "judge_calls",
    "provider_http_attempts",
    "downloads_observed_bytes",
    "human_labels_consumed",
    "human_validity_claimed",
    "universal_safety_score_defined",
    "native_scales_pooled",
    "evaluator_modes_pooled",
}
_INVENTORY_FIELDS = {
    "schema",
    "status",
    "analysis_root",
    "artifacts",
    "artifact_count",
    "status_inventory",
    "input_manifest_sha256",
    "payload_sha256",
    "runner_input_view",
    "campaign_terminal_inventory",
    "human_audit_runner_input_view",
    "human_audit_sampling_index",
    "target_calls",
    "judge_calls",
    "provider_http_attempts",
    "human_labels_consumed",
}

_LOCAL_TERMINAL_INVENTORY_SCHEMA = "ura-phase6-campaign-terminal-inventory/3"
_LOCAL_TERMINAL_INVENTORY_COHORTS = (
    "canonical",
    "output_policy_amendment",
    "followon_prepared",
    "current_ollama",
    "current_ollama_stability",
    "vllm_stability",
    "native",
)
_LOCAL_TERMINAL_INVENTORY_COHORT_COUNTS = {
    "canonical": 46,
    "output_policy_amendment": 4,
    "followon_prepared": 3,
    "current_ollama": 14,
    "current_ollama_stability": 14,
    "vllm_stability": 7,
    "native": 9,
}
_LOCAL_TERMINAL_INVENTORY_STATES = {
    "canonical": {
        "measured_complete",
        "partial",
        "failed",
        "unavailable",
        "structural_na",
        "conditional_na",
        "target_runtime_terminal",
    },
    "output_policy_amendment": {
        "measured_complete",
        "gate5_failed",
        "measured_failed",
    },
    "followon_prepared": {"measured_complete", "partial", "failed"},
    "current_ollama": {"measured_complete", "failed", "unavailable"},
    "current_ollama_stability": {"measured_complete"},
    "vllm_stability": {"measured_complete"},
    "native": {"run", "failed", "unavailable", "not-selected"},
}
_LOCAL_TERMINAL_INVENTORY_ACCOUNTING_FIELDS = {
    "hosted_target_calls",
    "hosted_judge_calls",
    "provider_http_attempts",
    "paid_provider_calls",
    "model_downloads",
}


def _validate_local_campaign_terminal_inventory(
    document: Mapping[str, Any],
) -> None:
    """Retain the exact plan-owned terminal union before Stats registration."""

    _validate_report_document("terminal_inventory", document)
    rows = document["rows"]
    accounting = document["accounting"]
    if (
        document.get("schema") != _LOCAL_TERMINAL_INVENTORY_SCHEMA
        or document.get("cohort_order")
        != list(_LOCAL_TERMINAL_INVENTORY_COHORTS)
        or document.get("cohort_counts")
        != _LOCAL_TERMINAL_INVENTORY_COHORT_COUNTS
        or len(rows) != 97
        or len(document["row_order"]) != 97
        or document.get("cross_revision_pooling_permitted") is not False
        or document.get("cross_source_pooling_permitted") is not False
    ):
        raise ValueError("local campaign terminal inventory size or policy differs")
    if (
        set(accounting) != _LOCAL_TERMINAL_INVENTORY_ACCOUNTING_FIELDS
        or any(
            type(accounting.get(field)) is not int or accounting[field] != 0
            for field in _LOCAL_TERMINAL_INVENTORY_ACCOUNTING_FIELDS
        )
    ):
        raise ValueError("local campaign terminal inventory is not local-only")

    failures: list[str] = []
    cohort_rows = {
        cohort: [] for cohort in _LOCAL_TERMINAL_INVENTORY_COHORTS
    }
    for row in rows:
        cohort = row["cohort"]
        state = row["terminal_state"]
        source = row["source_conformance_stratum"]
        expected_failure = (
            state in {"partial", "failed"}
            or cohort == "output_policy_amendment"
            and state != "measured_complete"
            or cohort == "followon_prepared"
            and state != "measured_complete"
        )
        if (
            cohort not in _LOCAL_TERMINAL_INVENTORY_STATES
            or state not in _LOCAL_TERMINAL_INVENTORY_STATES[cohort]
            or row["failure"] is not expected_failure
            or _HEX64.fullmatch(row["project_revision_stratum"]) is None
            or (
                source != "not_applicable"
                and _HEX64.fullmatch(source) is None
            )
            or (cohort == "native") != (source == "not_applicable")
        ):
            raise ValueError(
                "local campaign terminal row state or stratum differs"
            )
        cohort_rows[cohort].append(row["key"])
        if expected_failure:
            failures.append(row["key"])
    if (
        any(
            len(cohort_rows[cohort])
            != _LOCAL_TERMINAL_INVENTORY_COHORT_COUNTS[cohort]
            for cohort in _LOCAL_TERMINAL_INVENTORY_COHORTS
        )
        or document["failure_rows"] != failures
        or document["status"]
        != ("complete_with_failures" if failures else "complete")
    ):
        raise ValueError("local campaign terminal inventory partition differs")


@dataclass(frozen=True)
class LocalCampaignReport:
    path: Path
    artifact_relative: str
    display_name: str
    kind: str


@dataclass(frozen=True)
class LocalCampaignStatsBundle:
    route_id: str
    analysis_root: Path
    artifact_relative: str
    expected_commit: str
    framework_lock_id: str
    gate5_sha256: str
    completion_status: str
    explicit_limitations: tuple[tuple[str, str], ...]
    reports: tuple[LocalCampaignReport, ...]


@dataclass(frozen=True)
class _PublishCampaignRecord:
    route_id: str
    directory: Path
    evidence_class: str
    status_tag: str
    release_commit: str


def _beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return path != root
    except ValueError:
        return False


def _regular_bytes(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink():
        raise ValueError("symlinked Phase 7 artifact")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise ValueError("invalid Phase 7 regular file")
        payload = b""
        while len(payload) <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - len(payload)))
            if not block:
                break
            payload += block
        after = os.fstat(fd)
    finally:
        os.close(fd)
    named = path.lstat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
        or named.st_nlink != 1
    ):
        raise ValueError("Phase 7 file changed during read")
    return payload


def _object(payload: bytes) -> dict[str, Any]:
    value = strict_json_loads(payload)
    if not isinstance(value, dict):
        raise ValueError("Phase 7 document is not an object")
    return value


def _descriptor_file(
    raw: object,
    *,
    allowed_root: Path,
    maximum: int,
) -> tuple[Path, bytes]:
    if not isinstance(raw, Mapping) or set(raw) != {"path", "sha256", "bytes"}:
        raise ValueError("invalid Phase 7 descriptor")
    path_value = raw.get("path")
    digest = raw.get("sha256")
    size = raw.get("bytes")
    if (
        not isinstance(path_value, str)
        or not isinstance(digest, str)
        or _HEX64.fullmatch(digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > maximum
    ):
        raise ValueError("invalid Phase 7 descriptor identity")
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError("Phase 7 descriptor path is not absolute")
    resolved = path.resolve(strict=True)
    if not _beneath(resolved, allowed_root):
        raise ValueError("Phase 7 descriptor escapes its owned root")
    payload = _regular_bytes(resolved, maximum=maximum)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("Phase 7 descriptor bytes differ")
    return resolved, payload


def _zeros(value: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(type(value.get(field)) is int and value[field] == 0 for field in fields)


def _exact_descriptor(
    raw: object,
    *,
    expected: Path,
    allowed_root: Path,
    maximum: int,
) -> tuple[Path, bytes]:
    path, payload = _descriptor_file(
        raw,
        allowed_root=allowed_root,
        maximum=maximum,
    )
    if path != expected:
        raise ValueError("Phase 7 descriptor path differs from the sealed chain")
    return path, payload


def _phase7_launch_rows(payload: bytes) -> dict[str, str]:
    if b"\r" in payload or not payload.endswith(b"\n"):
        raise ValueError("Phase 7 launch output is not canonical LF text")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Phase 7 launch output is not ASCII") from exc
    rows: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not value or key in rows:
            raise ValueError("invalid Phase 7 launch output row")
        rows[key] = value
    if set(rows) != _PHASE7_LAUNCH_FIELDS:
        raise ValueError("Phase 7 launch output field inventory changed")
    return rows


def _campaign_report_strata(
    campaign_inventory: Mapping[str, Any],
) -> tuple[dict[str, tuple[str, str]], set[str]]:
    """Return exact non-native strata and the metric-eligible stratum IDs."""

    rows = campaign_inventory.get("rows")
    if not isinstance(rows, list):
        raise ValueError("campaign terminal rows are absent")
    strata: dict[str, tuple[str, str]] = {}
    measured: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("campaign terminal row is malformed")
        revision = row.get("project_revision_stratum")
        source = row.get("source_conformance_stratum")
        if source == "not_applicable":
            continue
        if (
            not isinstance(revision, str)
            or _HEX64.fullmatch(revision) is None
            or not isinstance(source, str)
            or _HEX64.fullmatch(source) is None
        ):
            raise ValueError("campaign report stratum identity is malformed")
        stratum_id = f"{revision[:12]}-{source[:12]}"
        pair = (revision, source)
        if stratum_id in strata and strata[stratum_id] != pair:
            raise ValueError("campaign report stratum prefix is ambiguous")
        strata[stratum_id] = pair
        if row.get("terminal_state") == "measured_complete":
            measured.add(stratum_id)
    if not strata or not measured:
        raise ValueError("campaign report strata are empty")
    return strata, measured


def _report_scope_matches(
    kind: str,
    document: Mapping[str, Any],
    *,
    revision: str,
    source: str,
) -> bool:
    """Bind producer report content to its exact path-level stratum."""

    if kind == "level1":
        requests = document.get("requests")
        envelopes = document.get("request_envelopes")
        if not isinstance(requests, list) or not isinstance(envelopes, list):
            return False
        if not requests:
            # A lifecycle stratum can contain only a pre-materialization request
            # envelope. Its Level-1 format intentionally retains no project/source
            # fields in the envelope projection, so the exact validated path is
            # the only available scope carrier.
            return bool(envelopes)
        for request in requests:
            bindings = request.get("bindings") if isinstance(request, Mapping) else None
            project = (
                bindings.get("project_revision")
                if isinstance(bindings, Mapping)
                else None
            )
            selected = (
                bindings.get("selected_config_identities")
                if isinstance(bindings, Mapping)
                else None
            )
            source_identity = (
                selected.get("source_conformance")
                if isinstance(selected, Mapping)
                else None
            )
            if (
                not isinstance(project, Mapping)
                or project.get("sha256") != revision
                or not isinstance(source_identity, Mapping)
                or source_identity.get("sha256") != source
            ):
                return False
        return True

    if kind == "level2":
        inputs = document.get("inputs")
        cells = inputs.get("cells") if isinstance(inputs, Mapping) else None
        if (
            not isinstance(cells, list)
            or not cells
            or inputs.get("n_completed_cells") != len(cells)
        ):
            return False
        return all(
            isinstance(cell, Mapping)
            and isinstance(cell.get("project_revision"), Mapping)
            and cell["project_revision"].get("sha256") == revision
            for cell in cells
        )
    return False


def load_local_campaign_stats_bundle(
    results_root: Path,
    campaign: EngineeringCampaignRecord,
) -> LocalCampaignStatsBundle | None:
    """Return report bindings only for an intact terminal Phase 7 watcher chain."""

    try:
        results = results_root.resolve(strict=True)
        watcher_root = campaign.directory.resolve(strict=True)
        engineering = (results / "engineering").resolve(strict=True)
        if (
            campaign.evidence_class != "local_campaign_control"
            or campaign.status_tag not in {"passed", "partial"}
            or not campaign.route_id.startswith("phase7-after-phase6-")
            or watcher_root.parent != engineering
        ):
            return None
        watcher = _object(
            _regular_bytes(watcher_root / "completion.json", maximum=_MAX_CONTROL_BYTES)
        )
        if (
            set(watcher) != _WATCHER_FIELDS
            or watcher.get("schema") != "ura-phase7-after-phase6-completion/1"
            or watcher.get("status") not in {"complete", "complete_with_explicit_limitations"}
            or watcher.get("expected_commit") != campaign.release_commit
            or _HEX40.fullmatch(str(watcher.get("expected_commit"))) is None
            or _HEX64.fullmatch(str(watcher.get("framework_lock_id"))) is None
            or not _zeros(
                watcher,
                (
                    "target_calls",
                    "judge_calls",
                    "provider_http_attempts",
                    "downloads_observed_bytes",
                ),
            )
            or watcher.get("human_labels_consumed") is not False
        ):
            return None
        expected_commit = str(watcher["expected_commit"])
        framework_lock = str(watcher["framework_lock_id"])
        control_value = watcher.get("phase7_control_root")
        analysis_value = watcher.get("analysis_root")
        if not isinstance(control_value, str) or not isinstance(analysis_value, str):
            return None
        control = Path(control_value).resolve(strict=True)
        analysis = Path(analysis_value).resolve(strict=True)
        analysis_parent = (results / "thesis" / "analysis").resolve(strict=True)
        if (
            control.parent != engineering
            or not control.name.startswith("phase7-analysis-")
            or analysis.parent != analysis_parent
            or not analysis.name.startswith("phase7-")
        ):
            return None

        sealed = (watcher_root / "sealed").resolve(strict=True)
        if sealed.parent != watcher_root:
            return None
        _watcher_script_path, watcher_script_bytes = _exact_descriptor(
            watcher.get("watcher"),
            expected=sealed / "phase7_after_phase6_sequence.sh",
            allowed_root=watcher_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        _wrapper_path, _wrapper_bytes = _exact_descriptor(
            watcher.get("phase7_wrapper"),
            expected=sealed / "phase7_analysis.sh",
            allowed_root=watcher_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        _sealed_payload_path, sealed_payload_bytes = _exact_descriptor(
            watcher.get("phase7_payload"),
            expected=sealed / "phase7_analysis.py",
            allowed_root=watcher_root,
            maximum=_MAX_CONTROL_BYTES,
        )

        _watcher_launch_path, watcher_launch_bytes = _exact_descriptor(
            watcher.get("watcher_launch"),
            expected=watcher_root / "watcher-launch.json",
            allowed_root=watcher_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_launch = _object(watcher_launch_bytes)
        phase6_wait = watcher_launch.get("phase6_wait")
        if (
            set(watcher_launch) != _WATCHER_LAUNCH_FIELDS
            or watcher_launch.get("schema") != "ura-phase7-after-phase6-launch/1"
            or watcher_launch.get("status") != "waiting_for_phase6"
            or watcher_launch.get("expected_commit") != expected_commit
            or watcher_launch.get("framework_lock_id") != framework_lock
            or watcher_launch.get("control_root") != str(watcher_root)
            or watcher_launch.get("authorized_watcher_sha256")
            != hashlib.sha256(watcher_script_bytes).hexdigest()
            or watcher_launch.get("watcher") != watcher.get("watcher")
            or watcher_launch.get("phase7_wrapper") != watcher.get("phase7_wrapper")
            or watcher_launch.get("phase7_payload") != watcher.get("phase7_payload")
            or not isinstance(phase6_wait, Mapping)
            or set(phase6_wait) != {"control_root", "session", "socket"}
            or phase6_wait.get("session")
            != f"ura-phase6-sequence-{expected_commit[:7]}"
            or phase6_wait.get("socket") != phase6_wait.get("session")
            or not _zeros(
                watcher_launch,
                (
                    "target_calls_permitted",
                    "judge_calls_permitted",
                    "provider_http_attempts_permitted",
                ),
            )
        ):
            return None

        phase6_path, phase6_bytes = _descriptor_file(
            watcher.get("phase6_sequence_completion"),
            allowed_root=engineering,
            maximum=_MAX_CONTROL_BYTES,
        )
        phase6_root = phase6_path.parent
        if (
            phase6_path.name != "completion.json"
            or phase6_root.parent != engineering
            or not phase6_root.name.startswith("phase6-sequence-")
            or phase6_wait.get("control_root") != str(phase6_root)
        ):
            return None
        _phase6_exit_path, phase6_exit_bytes = _exact_descriptor(
            watcher.get("phase6_sequence_exit"),
            expected=phase6_root / ".exit",
            allowed_root=phase6_root,
            maximum=16,
        )
        phase6 = _object(phase6_bytes)
        phase6_status = phase6.get("status")
        expected_phase6_exit = b"0\n" if phase6_status == "complete" else b"1\n"
        phase6_states = phase6.get("terminal_states")
        _phase6_validator_path, phase6_validator_bytes = _exact_descriptor(
            phase6.get("phase7_validator"),
            expected=phase6_root / "sealed" / "phase7_analysis.py",
            allowed_root=phase6_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        _phase6_launch_path, phase6_launch_bytes = _exact_descriptor(
            phase6.get("sequence_launch"),
            expected=phase6_root / "sequence-launch.json",
            allowed_root=phase6_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        phase6_launch = _object(phase6_launch_bytes)
        launch_validator_path, launch_validator_bytes = _descriptor_file(
            phase6_launch.get("phase7_validator"),
            allowed_root=phase6_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        phase6_gate5 = phase6.get("gate5")
        phase6_commit = str(phase6.get("expected_commit"))
        if (
            set(phase6) != _PHASE6_COMPLETION_FIELDS
            or phase6.get("schema") != "ura-phase6-sequence-completion/2"
            or phase6_status not in {"complete", "complete_with_failures"}
            or _HEX40.fullmatch(phase6_commit) is None
            or phase6.get("framework_lock_id") != framework_lock
            or phase6.get("control_root") != str(phase6_root)
            or phase6.get("controller_order") != ["core", "extended", "native"]
            or phase6.get("all_controllers_attempted") is not True
            or not isinstance(phase6_states, Mapping)
            or set(phase6_states) != {"core", "extended", "native"}
            or set(phase6_states.values()) - {"complete", "complete_with_failures"}
            or phase6.get("failed_controller_receipts_are_evidence") is not False
            or not isinstance(phase6.get("conditional_na_lanes"), list)
            or phase6_exit_bytes != expected_phase6_exit
            or set(phase6_launch) != _PHASE6_LAUNCH_FIELDS
            or phase6_launch.get("schema") != "ura-phase6-sequence-launch/1"
            or phase6_launch.get("status") != "running"
            or phase6_launch.get("expected_commit") != phase6_commit
            or phase6_launch.get("framework_lock_id") != framework_lock
            or phase6_launch.get("control_root") != str(phase6_root)
            or phase6_launch.get("controller_order") != ["core", "extended", "native"]
            or phase6_launch.get("long_running_children_use_tmux") is not True
            or phase6_launch.get("local_only") is not True
            or phase6_launch.get("phase7_validator")
            != phase6.get("phase7_validator")
            or launch_validator_path != _phase6_validator_path
            or launch_validator_bytes != phase6_validator_bytes
            or not isinstance(phase6_gate5, Mapping)
            or set(phase6_gate5) != _PHASE6_GATE5_FIELDS
            or not _zeros(
                phase6,
                (
                    "hosted_target_calls",
                    "hosted_judge_calls",
                    "provider_http_attempts",
                    "downloads_observed_bytes",
                ),
            )
        ):
            return None
        if any(
            (phase6_root / name).exists() or (phase6_root / name).is_symlink()
            for name in ("failure.json", "controller-failure.json")
        ):
            return None

        input_sha = watcher.get("authorized_input_manifest_sha256")
        _prepare_path, prepare_bytes = _exact_descriptor(
            watcher.get("prepare_result"),
            expected=watcher_root / "prepare-result.json",
            allowed_root=watcher_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        prepare = _object(prepare_bytes)
        if (
            set(prepare) != _PREPARE_RESULT_FIELDS
            or prepare.get("status") != "prepared"
            or prepare.get("schema") != "ura-phase7-analysis-inputs/3"
            or prepare.get("output") != str(watcher_root / "phase7-inputs.json")
            or prepare.get("sha256") != input_sha
            or type(prepare.get("bytes")) is not int
            or prepare["bytes"] < 1
            or type(prepare.get("bound_artifacts")) is not int
            or prepare["bound_artifacts"] < 1
            or type(prepare.get("runner_lanes")) is not int
            or prepare["runner_lanes"] < 1
            or type(prepare.get("metric_runner_lanes")) is not int
            or not 0 <= prepare["metric_runner_lanes"] <= prepare["runner_lanes"]
            or not isinstance(prepare.get("native_outcomes"), Mapping)
            or prepare.get("campaign_terminal_rows") != 97
            or prepare.get("campaign_terminal_status")
            not in {"complete", "complete_with_failures"}
            or prepare.get("authorization_required_before_launch") is not True
        ):
            return None

        _phase7_launch_path, phase7_launch_bytes = _exact_descriptor(
            watcher.get("phase7_launch_output"),
            expected=watcher_root / "phase7-launch.txt",
            allowed_root=watcher_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        launch_rows = _phase7_launch_rows(phase7_launch_bytes)
        suffix = control.name.removeprefix("phase7-analysis-")
        phase7_session = f"ura-phase7-{suffix}"
        if (
            launch_rows["SESSION"] != phase7_session
            or launch_rows["SOCKET"] != phase7_session
            or launch_rows["ATTACH"] != f"tmux -L {phase7_session} attach -t {phase7_session}"
            or launch_rows["CONTROL_ROOT"] != str(control)
            or launch_rows["ANALYSIS_ROOT"] != str(analysis)
            or launch_rows["LOG"] != str(control / "controller.log")
            or launch_rows["EXIT_MARKER"] != str(control / ".exit")
            or launch_rows["COMPLETION"] != str(control / "completion.json")
        ):
            return None

        analysis_launch = _object(
            _regular_bytes(control / "launch.json", maximum=_MAX_CONTROL_BYTES)
        )
        if (
            set(analysis_launch) != _ANALYSIS_LAUNCH_FIELDS
            or analysis_launch.get("schema") != "ura-phase7-analysis-launch/1"
            or analysis_launch.get("authorized_input_manifest_sha256") != input_sha
            or analysis_launch.get("control_root") != str(control)
            or analysis_launch.get("analysis_root") != str(analysis)
        ):
            return None

        controller_path, controller_payload = _descriptor_file(
            watcher.get("phase7_completion"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        if controller_path != control / "completion.json":
            return None
        exit_path, exit_payload = _descriptor_file(
            watcher.get("phase7_exit"),
            allowed_root=control,
            maximum=16,
        )
        if exit_path != control / ".exit" or exit_payload != b"0\n":
            return None
        controller = _object(controller_payload)
        statuses = controller.get("analysis_statuses")
        limitations = controller.get("explicit_limitations")
        expected_limitations = (
            {name: status for name, status in statuses.items() if status != "complete"}
            if isinstance(statuses, dict)
            else None
        )
        expected_status = (
            "complete" if expected_limitations == {} else "complete_with_explicit_limitations"
        )
        if (
            set(controller) != _CONTROLLER_FIELDS
            or controller.get("schema") != "ura-phase7-analysis-completion/3"
            or controller.get("status") != watcher.get("status")
            or not isinstance(statuses, dict)
            or not statuses
            or limitations != expected_limitations
            or controller.get("status") != expected_status
            or controller.get("inventory_complete") is not True
            or controller.get("authorized_input_manifest_sha256") != input_sha
            or controller.get("analysis_root") != str(analysis)
            or controller.get("analysis_statuses") != watcher.get("analysis_statuses")
            or controller.get("explicit_limitations") != watcher.get("explicit_limitations")
            or not _zeros(
                controller,
                (
                    "target_calls",
                    "judge_calls",
                    "provider_http_attempts",
                    "downloads_observed_bytes",
                ),
            )
            or any(
                controller.get(field) is not False
                for field in (
                    "human_labels_consumed",
                    "human_validity_claimed",
                    "universal_safety_score_defined",
                    "native_scales_pooled",
                    "evaluator_modes_pooled",
                )
            )
        ):
            return None

        _controller_payload_path, payload_bytes = _exact_descriptor(
            controller.get("payload"),
            expected=control / "payload.py",
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        if payload_bytes != sealed_payload_bytes or analysis_launch.get(
            "payload"
        ) != controller.get("payload"):
            return None
        runner_view_path, runner_view_bytes = _descriptor_file(
            controller.get("runner_input_view"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_runner_path, watcher_runner_bytes = _descriptor_file(
            watcher.get("runner_input_view"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        if (
            runner_view_path != control / "read-only-runner-view.json"
            or watcher_runner_path != runner_view_path
            or watcher_runner_bytes != runner_view_bytes
        ):
            return None
        human_view_path, human_view_payload = _descriptor_file(
            controller.get("human_audit_runner_input_view"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_human_view_path, watcher_human_view_payload = _descriptor_file(
            watcher.get("human_audit_runner_input_view"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        human_index_path, human_index_payload = _descriptor_file(
            controller.get("human_audit_sampling_index"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_human_index_path, watcher_human_index_payload = _descriptor_file(
            watcher.get("human_audit_sampling_index"),
            allowed_root=control,
            maximum=_MAX_CONTROL_BYTES,
        )
        if (
            human_view_path != control / "read-only-human-audit-runner-view.json"
            or human_index_path
            != control / "read-only-human-audit-runner-view.index.json"
            or watcher_human_view_path != human_view_path
            or watcher_human_view_payload != human_view_payload
            or watcher_human_index_path != human_index_path
            or watcher_human_index_payload != human_index_payload
        ):
            return None
        campaign_path, campaign_payload = _descriptor_file(
            controller.get("campaign_terminal_inventory"),
            allowed_root=analysis,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_campaign_path, watcher_campaign_payload = _descriptor_file(
            watcher.get("campaign_terminal_inventory"),
            allowed_root=analysis,
            maximum=_MAX_CONTROL_BYTES,
        )
        if (
            campaign_path != analysis / "campaign-terminal-inventory.json"
            or watcher_campaign_path != campaign_path
            or watcher_campaign_payload != campaign_payload
        ):
            return None
        campaign_inventory = _object(campaign_payload)
        _validate_local_campaign_terminal_inventory(campaign_inventory)

        _input_path, input_payload = _exact_descriptor(
            controller.get("input_manifest"),
            expected=control / "phase7-inputs.json",
            allowed_root=control,
            maximum=_MAX_INPUT_BYTES,
        )
        _watcher_input_path, watcher_input_payload = _exact_descriptor(
            watcher.get("authorized_input_manifest"),
            expected=watcher_root / "phase7-inputs.json",
            allowed_root=watcher_root,
            maximum=_MAX_INPUT_BYTES,
        )
        if (
            input_payload != watcher_input_payload
            or hashlib.sha256(input_payload).hexdigest() != input_sha
            or prepare.get("bytes") != len(input_payload)
            or analysis_launch.get("input_manifest") != controller.get("input_manifest")
        ):
            return None
        inputs = _object(input_payload)
        code_identity = inputs.get("code_identity")
        gate5 = inputs.get("gate5")
        gate5_identity = gate5.get("code_identity") if isinstance(gate5, Mapping) else None
        project_and_source = inputs.get("project_and_source")
        project_revision = (
            project_and_source.get("project_revision")
            if isinstance(project_and_source, Mapping)
            else None
        )
        project_artifact = (
            project_revision.get("artifact")
            if isinstance(project_revision, Mapping)
            else None
        )
        project_binding = (
            project_revision.get("experiment_binding")
            if isinstance(project_revision, Mapping)
            else None
        )
        phase6_inputs = inputs.get("phase6")
        native_outcomes = inputs.get("native_outcomes")
        runner_inputs = inputs.get("runner")
        followon_inputs = inputs.get("followon")
        seven_inputs = inputs.get("seven_output_policy_amendment")
        current_ollama_inputs = inputs.get("current_ollama")
        current_ollama_stability_inputs = inputs.get("current_ollama_stability")
        vllm_stability_inputs = inputs.get("vllm_stability")
        followon_states = (
            followon_inputs.get("terminal_states")
            if isinstance(followon_inputs, Mapping)
            else None
        )
        followon_strata = (
            followon_inputs.get("revision_strata")
            if isinstance(followon_inputs, Mapping)
            else None
        )
        expected_phase6_states = (
            {
                "core": phase6_inputs.get("core", {}).get("lane_terminal_states"),
                "extended": phase6_inputs.get("extended", {}).get("lane_terminal_states"),
                "native": native_outcomes.get("states"),
            }
            if isinstance(phase6_inputs, Mapping) and isinstance(native_outcomes, Mapping)
            else None
        )
        if (
            inputs.get("schema") != "ura-phase7-analysis-inputs/3"
            or inputs.get("inventory_complete") is not True
            or inputs.get("scope") != "all_local_phase7_read_only_analysis_over_phase6_lifecycle"
            or code_identity
            != {"expected_commit": expected_commit, "framework_lock_id": framework_lock}
            or not isinstance(gate5, Mapping)
            or gate5_identity
            != {"expected_commit": phase6_commit, "framework_lock_id": framework_lock}
            or phase6_gate5.get("covered_manifest") != gate5.get("manifest")
            or not isinstance(project_and_source, Mapping)
            or not isinstance(project_revision, Mapping)
            or not isinstance(project_artifact, Mapping)
            or _HEX64.fullmatch(str(project_artifact.get("sha256"))) is None
            or not isinstance(project_binding, Mapping)
            or project_binding.get("sha256") != project_artifact.get("sha256")
            or project_binding.get("expected_commit") != phase6_commit
            or project_binding.get("observed_commit") != phase6_commit
            or project_artifact.get("sha256")
            not in campaign_inventory.get("project_revision_strata", {})
            or inputs.get("campaign_terminal_inventory") != campaign_inventory
            or not isinstance(runner_inputs, Mapping)
            or not isinstance(runner_inputs.get("lifecycle_lane_order"), list)
            or not isinstance(runner_inputs.get("metric_lane_order"), list)
            or len(runner_inputs["lifecycle_lane_order"]) != prepare.get("runner_lanes")
            or len(runner_inputs["metric_lane_order"]) != prepare.get("metric_runner_lanes")
            or not isinstance(native_outcomes, Mapping)
            or native_outcomes.get("states") != prepare.get("native_outcomes")
            or controller.get("phase6_terminal_states") != expected_phase6_states
            or not isinstance(followon_inputs, Mapping)
            or not isinstance(followon_states, Mapping)
            or not isinstance(followon_strata, Mapping)
            or controller.get("followon_terminal_states") != followon_states
            or controller.get("followon_metric_revision_strata") != followon_strata
            or not isinstance(seven_inputs, Mapping)
            or controller.get("seven_output_policy_terminal_states")
            != seven_inputs.get("terminal_states")
            or controller.get("seven_output_policy_metric_revision_strata")
            != seven_inputs.get("revision_strata")
            or not isinstance(current_ollama_inputs, Mapping)
            or controller.get("current_ollama_terminal_states")
            != current_ollama_inputs.get("terminal_states")
            or controller.get("current_ollama_metric_revision_strata")
            != current_ollama_inputs.get("revision_strata")
            or controller.get("current_ollama_target_execution")
            != current_ollama_inputs.get("target_execution")
            or not isinstance(current_ollama_stability_inputs, Mapping)
            or controller.get("current_ollama_stability_terminal_states")
            != current_ollama_stability_inputs.get("terminal_states")
            or controller.get("current_ollama_stability_metric_revision_strata")
            != current_ollama_stability_inputs.get("revision_strata")
            or controller.get("current_ollama_stability_target_execution")
            != current_ollama_stability_inputs.get("target_execution")
            or not isinstance(vllm_stability_inputs, Mapping)
            or controller.get("vllm_stability_terminal_states")
            != vllm_stability_inputs.get("terminal_states")
            or controller.get("vllm_stability_metric_revision_strata")
            != vllm_stability_inputs.get("revision_strata")
            or controller.get("vllm_stability_target_execution")
            != vllm_stability_inputs.get("target_execution")
        ):
            return None
        gate5_path, gate5_payload = _descriptor_file(
            gate5.get("manifest"),
            allowed_root=results / "thesis",
            maximum=_MAX_INPUT_BYTES,
        )
        gate5_document = _object(gate5_payload)
        if (
            gate5_document.get("schema") != "ura-gate5-covered-manifest/1"
            or gate5_document.get("inventory_complete") is not True
            or gate5_document.get("code_identity") != gate5.get("code_identity")
        ):
            return None

        inventory_path, inventory_payload = _descriptor_file(
            controller.get("artifact_inventory"),
            allowed_root=analysis,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_inventory_path, watcher_inventory_payload = _descriptor_file(
            watcher.get("artifact_inventory"),
            allowed_root=analysis,
            maximum=_MAX_CONTROL_BYTES,
        )
        if (
            inventory_path != analysis / "artifact-inventory.json"
            or watcher_inventory_path != inventory_path
            or watcher_inventory_payload != inventory_payload
        ):
            return None
        inventory = _object(inventory_payload)
        artifacts = inventory.get("artifacts")
        if (
            set(inventory) != _INVENTORY_FIELDS
            or inventory.get("schema") != "ura-phase7-analysis-artifact-inventory/1"
            or inventory.get("status") != "complete"
            or inventory.get("analysis_root") != str(analysis)
            or not isinstance(artifacts, list)
            or len(artifacts) > _MAX_ARTIFACTS
            or inventory.get("artifact_count") != len(artifacts)
            or inventory.get("input_manifest_sha256") != input_sha
            or inventory.get("payload_sha256") != hashlib.sha256(payload_bytes).hexdigest()
            or inventory.get("runner_input_view") != controller.get("runner_input_view")
            or inventory.get("campaign_terminal_inventory")
            != controller.get("campaign_terminal_inventory")
            or inventory.get("human_audit_runner_input_view")
            != controller.get("human_audit_runner_input_view")
            or inventory.get("human_audit_sampling_index")
            != controller.get("human_audit_sampling_index")
            or inventory.get("status_inventory") != controller.get("analysis_statuses")
            or not _zeros(
                inventory,
                ("target_calls", "judge_calls", "provider_http_attempts"),
            )
            or inventory.get("human_labels_consumed") is not False
        ):
            return None

        descriptors: dict[Path, object] = {}
        for raw in artifacts:
            if not isinstance(raw, Mapping) or set(raw) != {"path", "sha256", "bytes"}:
                return None
            raw_path = raw.get("path")
            if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
                return None
            resolved = Path(raw_path).resolve(strict=True)
            if not _beneath(resolved, analysis) or resolved in descriptors:
                return None
            descriptors[resolved] = raw
        lifecycle_strata_root = (analysis / "lifecycle-strata").resolve()
        metric_strata_root = (analysis / "metric-strata").resolve()
        lifecycle_reports = sorted(
            path
            for path in descriptors
            if path.name == "level1-evidence.json"
            and path.parent.parent == lifecycle_strata_root
        )
        stratum_reports = sorted(
            path
            for path in descriptors
            if path.name == "level2-report.json"
            and path.parent.parent == metric_strata_root
        )
        strata, expected_metric_strata = _campaign_report_strata(campaign_inventory)
        lifecycle_ids = [path.parent.name for path in lifecycle_reports]
        metric_ids = [path.parent.name for path in stratum_reports]
        if (
            not lifecycle_reports
            or not stratum_reports
            or len(set(lifecycle_ids)) != len(lifecycle_ids)
            or len(set(metric_ids)) != len(metric_ids)
            or any(_STRATUM_ID.fullmatch(item) is None for item in lifecycle_ids)
            or any(_STRATUM_ID.fullmatch(item) is None for item in metric_ids)
            or any(item not in strata for item in lifecycle_ids)
            or set(metric_ids) != expected_metric_strata
            or not set(metric_ids) <= set(lifecycle_ids)
        ):
            return None
        selected = [
            (campaign_path, "terminal_inventory"),
        ] + [
            (path, "level1") for path in lifecycle_reports
        ] + [
            (path, "level2") for path in stratum_reports
        ]
        reports = []
        for path, kind in selected:
            verified, report_payload = _descriptor_file(
                descriptors[path],
                allowed_root=analysis,
                maximum=_MAX_REPORT_BYTES,
            )
            report_document = _object(report_payload)
            if kind == "terminal_inventory":
                _validate_local_campaign_terminal_inventory(report_document)
            else:
                _validate_report_document(kind, report_document)
                revision, source = strata[path.parent.name]
                if not _report_scope_matches(
                    kind,
                    report_document,
                    revision=revision,
                    source=source,
                ):
                    return None
            reports.append(
                LocalCampaignReport(
                    path=verified,
                    artifact_relative=verified.relative_to(results).as_posix(),
                    display_name=verified.relative_to(analysis).as_posix(),
                    kind=kind,
                )
            )
        return LocalCampaignStatsBundle(
            route_id=campaign.route_id,
            analysis_root=analysis,
            artifact_relative=analysis.relative_to(results).as_posix(),
            expected_commit=expected_commit,
            framework_lock_id=framework_lock,
            gate5_sha256=hashlib.sha256(gate5_payload).hexdigest(),
            completion_status=str(controller["status"]),
            explicit_limitations=tuple(
                sorted((str(name), str(status)) for name, status in limitations.items())
            ),
            reports=tuple(reports),
        )
    except (OSError, TypeError, ValueError, RecursionError):
        return None


def publish_local_campaign_stats_registration(
    results_root: Path,
    campaign: EngineeringCampaignRecord,
) -> Path:
    """Validate the plan-owned chain, then publish its generic UI registration."""

    bundle = load_local_campaign_stats_bundle(results_root, campaign)
    if bundle is None:
        raise ValueError("local campaign analysis chain is not publishable")
    return publish_external_analysis_registration(
        results_root,
        job_id=bundle.route_id,
        analysis_root=bundle.analysis_root,
        work_label="local campaign read-only analysis",
        completion_status=bundle.completion_status,
        explicit_limitations=dict(bundle.explicit_limitations),
        reports=tuple(
            ExternalAnalysisReportSpec(
                path=report.path,
                kind=report.kind,
                display_name=report.display_name,
            )
            for report in bundle.reports
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish a validated local-campaign analysis to generic Rig Web Stats"
    )
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--status-tag", choices=("passed", "partial"), default="passed")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    campaign_root = args.campaign_root.resolve(strict=True)
    if _HEX40.fullmatch(args.release_commit) is None:
        raise SystemExit("release commit must be lowercase 40-hex")
    record = _PublishCampaignRecord(
        route_id=campaign_root.name,
        directory=campaign_root,
        evidence_class="local_campaign_control",
        status_tag=args.status_tag,
        release_commit=args.release_commit,
    )
    path = publish_local_campaign_stats_registration(args.results_root, record)
    print(path)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
