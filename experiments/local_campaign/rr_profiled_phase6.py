"""Execute the four still-unmeasured GraySwan defense-comparison lanes.

Reuse the retained selections and admitted execution profile. The shared local
unit executor performs sealed acquisition, attestation, canary, projection and
measured execution, and publishes each measured unit to Jobs.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Sequence

from experiments.local_campaign.console_events import (
    finish_child_controller, publish_target_execution, start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import _descriptor
from experiments.local_campaign.failed_output_recovery_phase6 import _durable_outcomes
from experiments.local_campaign.local_bounded_output_continuation_phase6 import (
    profiled_bounded_local_config,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit, _create_json, _framework_lock_id, _load_json, _option, _project_python,
    _replace_option, _run_unit, _utc_now, _validate_descriptor,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-profiled-rr-phase6/1"
STATE_SCHEMA = "ura-profiled-rr-phase6-unit-state/1"
RR_SPEC = "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR"
RR_REVISION = "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e"
LAYOUT = (
    ("local-llava-rr-text-primary-100", 3854),
    ("local-llava-rr-image-primary-100", 1632),
    ("rjudge-llava-rr", 100),
    ("gptgeochat-llava-rr", 2020),
)


def execution_counts(results, *, work_root: Path, control_root: Path):
    attempted = successful = 0
    for lane, _count in LAYOUT:
        if lane in results:
            attempted += results[lane]["target_attempts"]
            successful += results[lane]["successful_target_generations"]
        else:
            root = work_root / "runs/thesis/runner" / lane / control_root.name
            if root.exists():
                attempts, outcomes, _attempt_files, _response_files = _durable_outcomes(root)
                attempted += len(attempts)
                successful += sum(status in {"usable_first_response", "recovered_after_retry"}
                                  for status in outcomes.values())
    return {"target_attempts": attempted, "successful_target_generations": successful,
            "missing_responses": attempted - successful}


def configure_units(source_root: Path, control_root: Path, profile_registry: Path):
    """Keep every original input-selection argument and replace only serving config."""
    units = []
    evidence = {}
    for index, (lane, count) in enumerate(LAYOUT, 1):
        path = source_root / f"{index:02d}-{lane}.json"
        spec = _load_json(path, label=f"{lane} retained specification")
        argv = spec.get("base_argv")
        if (
            spec.get("lane_id") != lane
            or not isinstance(argv, list)
            or any(not isinstance(item, str) for item in argv)
            or _option(argv, "--local") != RR_SPEC
            or _option(argv, "--limit") != "100"
            or _option(argv, "--sample-seed") != "0"
            or _option(argv, "--seeds") != "0"
            or _option(argv, "--attackers") != "replay"
            or spec.get("approved_caps", {}).get("target_calls") != count
            or spec.get("target", {}).get("revision") != RR_REVISION
        ):
            raise ValueError(f"{lane} retained selection changed")
        config_path = _validate_descriptor(spec.get("local_config"), label="RR config")
        config = _load_json(config_path, label="RR config")
        if config.get(RR_SPEC, {}).get("revision") != RR_REVISION:
            raise ValueError("RR checkpoint identity changed")
        config, profile = profiled_bounded_local_config(
            config, spec=RR_SPEC, profile_registry=profile_registry,
        )
        configured = control_root / "configs" / f"{lane}.json"
        _create_json(configured, config)
        configured_desc = _descriptor(configured, label="profiled RR config")
        argv = _replace_option(argv, "--local-config", str(configured))
        argv = _replace_option(argv, "--local-config-sha256", configured_desc["sha256"])
        updated = {**spec, "base_argv": argv, "local_config": configured_desc}
        units.append(Unit(lane, lane, None, updated, count))
        evidence[lane] = {
            "source_specification": _descriptor(path, label="retained RR specification"),
            "local_config": configured_desc, "execution_profile": profile,
            "selected_records": count,
        }
    return units, evidence


def run(args: argparse.Namespace) -> int:
    project = args.project_root.resolve(strict=True)
    python = _project_python(project, args.python or project / ".venv/bin/python")
    work = args.work_root.resolve(strict=True)
    root = args.control_root
    if (not root.is_absolute() or root.exists() or root.is_symlink()
            or root.parent != (work / "runs/engineering").resolve(strict=True)):
        raise ValueError("RR campaign requires a fresh canonical engineering root")
    revision = _descriptor(args.project_revision.resolve(strict=True), label="project revision")
    revision_value = _load_json(Path(revision["path"]), label="project revision")
    if (
        revision["sha256"] != args.project_revision_sha256
        or revision_value.get("repository", {}).get("expected_commit") != args.expected_commit
        or revision_value.get("repository", {}).get("observed_commit") != args.expected_commit
    ):
        raise ValueError("RR deployment receipt changed")
    # No completed RR unit may be silently scheduled again.
    for lane, _count in LAYOUT:
        old_root = work / "runs/thesis/runner" / lane
        if any(old_root.rglob("*.grid.json")) or any(old_root.rglob("*.responses*.jsonl")):
            raise ValueError(f"{lane} already has measured artifacts; use checkpoint recovery")
    root.mkdir(mode=0o700)
    (root / "configs").mkdir(mode=0o700)
    units, evidence = configure_units(args.source_spec_root.resolve(strict=True), root,
                                      args.profile_registry.resolve(strict=True))
    launch = {
        "schema": SCHEMA, "status": "running", "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit, "runner_code_version": CODE_VERSION,
        "project_revision": revision, "unit_order": [unit.unit_id for unit in units],
        "units": evidence, "planned_unique_rows": sum(unit.selected_records for unit in units),
        "target_answer_retries": 1, "max_total_target_calls": 15212,
        "per_unit_wall_time_seconds": 86400, "paid_provider_calls": 0,
        "successful_rows_repeated": 0, "cross_condition_pooling_permitted": False,
    }
    _create_json(root / "launch.json", launch)
    admission = _descriptor(root / "launch.json", label="RR launch")
    start_child_controller(
        work_root=work, control_root=root, campaign_id=root.name,
        release_commit=args.expected_commit, evidence_class="measured_profiled_rr",
        hard_stop_hours=96, tmux_socket=args.tmux_socket, tmux_session=args.tmux_session,
        target_execution=True,
    )
    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for unit in units:
        try:
            results[unit.unit_id] = _run_unit(
                unit, python=python, work_root=work, control_root=root,
                project_revision=Path(revision["path"]), project_revision_sha256=revision["sha256"],
                scope=args.execution_scope_id, recovery_path=None, recovery_sha256=None,
                expected_commit=args.expected_commit, framework_lock_id=_framework_lock_id(),
                admission_sha256=admission["sha256"], tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session, state_schema=STATE_SCHEMA,
            )
        except Exception as exc:
            failures[unit.unit_id] = {"status": "failed", "error_type": type(exc).__name__,
                                      "error": str(exc)}
        _create_json(root / f"{unit.unit_id}.terminal.json", {
            "result": results.get(unit.unit_id), "failure": failures.get(unit.unit_id),
            "completed_at_utc": _utc_now(),
        })
    counts = execution_counts(results, work_root=work, control_root=root)
    _create_json(root / "completion.json", {
        **launch, "launch": admission, "completed_at_utc": _utc_now(),
        "status": "complete_with_failures" if failures else "complete",
        "controller_exit_code": int(bool(failures)), "unit_results": results,
        "unit_failures": failures, "target_execution": counts,
    })
    publish_target_execution(
        work_root=work, control_root=root,
        target_attempts=counts["target_attempts"],
        successful_target_generations=counts["successful_target_generations"],
    )
    finish_child_controller(work_root=work, control_root=root, exit_code=int(bool(failures)))
    return int(bool(failures))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project-root", "work-root", "control-root", "source-spec-root",
                 "profile-registry", "project-revision"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--python", type=Path)
    for name in ("project-revision-sha256", "expected-commit", "execution-scope-id",
                 "tmux-socket", "tmux-session"):
        parser.add_argument(f"--{name}", required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
