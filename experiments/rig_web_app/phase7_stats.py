"""Strict read-only binding of sealed Phase 7 reports to their watcher campaign."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ura.strict_json import strict_json_loads

from .campaigns import EngineeringCampaign


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
    "runner_input_view",
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
    "runner_input_view",
    "analysis_statuses",
    "explicit_limitations",
    "phase6_terminal_states",
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
    "target_calls",
    "judge_calls",
    "provider_http_attempts",
    "human_labels_consumed",
}


@dataclass(frozen=True)
class Phase7Report:
    path: Path
    artifact_relative: str
    display_name: str
    kind: str


@dataclass(frozen=True)
class Phase7StatsBundle:
    route_id: str
    analysis_root: Path
    artifact_relative: str
    expected_commit: str
    framework_lock_id: str
    gate5_sha256: str
    reports: tuple[Phase7Report, ...]


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
        or identity
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity
        != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
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


def load_phase7_stats_bundle(
    results_root: Path,
    campaign: EngineeringCampaign,
) -> Phase7StatsBundle | None:
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
            or watcher.get("status")
            not in {"complete", "complete_with_explicit_limitations"}
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
        expected_phase6_exit = (
            b"0\n" if phase6_status == "complete" else b"1\n"
        )
        phase6_states = phase6.get("terminal_states")
        _phase6_validator_path, phase6_validator_bytes = _exact_descriptor(
            phase6.get("phase7_validator"),
            expected=phase6_root / "sealed" / "phase7_analysis.py",
            allowed_root=phase6_root,
            maximum=_MAX_CONTROL_BYTES,
        )
        if (
            set(phase6) != _PHASE6_COMPLETION_FIELDS
            or phase6.get("schema") != "ura-phase6-sequence-completion/2"
            or phase6_status not in {"complete", "complete_with_failures"}
            or phase6.get("expected_commit") != expected_commit
            or phase6.get("framework_lock_id") != framework_lock
            or phase6.get("control_root") != str(phase6_root)
            or phase6.get("controller_order") != ["core", "extended", "native"]
            or phase6.get("all_controllers_attempted") is not True
            or not isinstance(phase6_states, Mapping)
            or set(phase6_states) != {"core", "extended", "native"}
            or set(phase6_states.values())
            - {"complete", "complete_with_failures"}
            or phase6.get("failed_controller_receipts_are_evidence") is not False
            or not isinstance(phase6.get("conditional_na_lanes"), list)
            or phase6_exit_bytes != expected_phase6_exit
            or not _zeros(
                phase6,
                (
                    "hosted_target_calls",
                    "hosted_judge_calls",
                    "provider_http_attempts",
                    "downloads_observed_bytes",
                ),
            )
            or phase6_validator_bytes != sealed_payload_bytes
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
            or prepare.get("schema") != "ura-phase7-analysis-inputs/1"
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
            or launch_rows["ATTACH"]
            != f"tmux -L {phase7_session} attach -t {phase7_session}"
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
            or controller.get("schema") != "ura-phase7-analysis-completion/1"
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
        if (
            payload_bytes != sealed_payload_bytes
            or analysis_launch.get("payload") != controller.get("payload")
        ):
            return None
        runner_view_path, runner_view_bytes = _descriptor_file(
            controller.get("runner_input_view"),
            allowed_root=analysis,
            maximum=_MAX_CONTROL_BYTES,
        )
        watcher_runner_path, watcher_runner_bytes = _descriptor_file(
            watcher.get("runner_input_view"),
            allowed_root=analysis,
            maximum=_MAX_CONTROL_BYTES,
        )
        if (
            watcher_runner_path != runner_view_path
            or watcher_runner_bytes != runner_view_bytes
        ):
            return None

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
        phase6_inputs = inputs.get("phase6")
        native_outcomes = inputs.get("native_outcomes")
        runner_inputs = inputs.get("runner")
        expected_phase6_states = (
            {
                "core": phase6_inputs.get("core", {}).get("lane_terminal_states"),
                "extended": phase6_inputs.get("extended", {}).get(
                    "lane_terminal_states"
                ),
                "native": native_outcomes.get("states"),
            }
            if isinstance(phase6_inputs, Mapping)
            and isinstance(native_outcomes, Mapping)
            else None
        )
        if (
            inputs.get("schema") != "ura-phase7-analysis-inputs/1"
            or inputs.get("inventory_complete") is not True
            or inputs.get("scope")
            != "all_local_phase7_read_only_analysis_over_phase6_lifecycle"
            or code_identity
            != {"expected_commit": expected_commit, "framework_lock_id": framework_lock}
            or not isinstance(gate5, Mapping)
            or not isinstance(runner_inputs, Mapping)
            or not isinstance(runner_inputs.get("lifecycle_lane_order"), list)
            or not isinstance(runner_inputs.get("metric_lane_order"), list)
            or len(runner_inputs["lifecycle_lane_order"])
            != prepare.get("runner_lanes")
            or len(runner_inputs["metric_lane_order"])
            != prepare.get("metric_runner_lanes")
            or not isinstance(native_outcomes, Mapping)
            or native_outcomes.get("states") != prepare.get("native_outcomes")
            or controller.get("phase6_terminal_states") != expected_phase6_states
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
            or gate5_document.get("code_identity") != code_identity
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
            or inventory.get("payload_sha256")
            != hashlib.sha256(payload_bytes).hexdigest()
            or inventory.get("runner_input_view") != controller.get("runner_input_view")
            or inventory.get("status_inventory") != controller.get("analysis_statuses")
            or not _zeros(
                inventory,
                ("target_calls", "judge_calls", "provider_http_attempts"),
            )
            or inventory.get("human_labels_consumed") is not False
        ):
            return None

        selected = {
            (analysis / "level1" / "level1-evidence.json").resolve(): "level1",
            (analysis / "level2" / "level2-report.json").resolve(): "level2",
        }
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
        if not set(selected).issubset(descriptors):
            return None
        reports = []
        for path, kind in selected.items():
            verified, _payload = _descriptor_file(
                descriptors[path],
                allowed_root=analysis,
                maximum=_MAX_REPORT_BYTES,
            )
            reports.append(
                Phase7Report(
                    path=verified,
                    artifact_relative=verified.relative_to(results).as_posix(),
                    display_name=verified.relative_to(analysis).as_posix(),
                    kind=kind,
                )
            )
        return Phase7StatsBundle(
            route_id=campaign.route_id,
            analysis_root=analysis,
            artifact_relative=analysis.relative_to(results).as_posix(),
            expected_commit=expected_commit,
            framework_lock_id=framework_lock,
            gate5_sha256=hashlib.sha256(gate5_payload).hexdigest(),
            reports=tuple(reports),
        )
    except (OSError, TypeError, ValueError, RecursionError):
        return None
