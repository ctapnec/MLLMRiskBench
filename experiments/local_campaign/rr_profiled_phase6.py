"""Execute the four still-unmeasured GraySwan defense-comparison lanes.

Reuse the retained selections and admitted execution profile. The shared local
unit executor performs sealed acquisition, attestation, canary, projection and
measured execution, and publishes each measured unit to Jobs.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
from typing import Any, Sequence

from experiments.local_campaign.console_events import (
    finish_child_controller, publish_target_execution, start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import _descriptor
from experiments.local_campaign.failed_output_recovery_phase6 import _durable_outcomes, _selected_rows
from experiments.local_campaign.local_bounded_output_continuation_phase6 import (
    profiled_bounded_local_config,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit, _base_argv, _create_json, _framework_lock_id, _load_json, _option, _project_python,
    _replace_option, _run_unit, _sha256_json, _utc_now, _validate_descriptor,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-profiled-rr-phase6/1"
STATE_SCHEMA = "ura-profiled-rr-phase6-unit-state/1"
CONTINUATION_SCHEMA = "ura-profiled-rr-phase6-continuation/1"
RR_SPEC = "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR"
RR_REVISION = "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e"
LAYOUT = (
    ("local-llava-rr-text-primary-100", 3854),
    ("local-llava-rr-image-primary-100", 1632),
    ("rjudge-llava-rr", 100),
    ("gptgeochat-llava-rr", 2020),
)


def checkpoint_selection(selected_ids, completed_ids):
    """Exclude every durable response, not only successful or non-truncated ones."""
    all_ids = [item for rows in selected_ids.values() for item in rows]
    completed = set(completed_ids)
    if (len(all_ids) != len(set(all_ids)) or len(completed) != len(completed_ids)
            or not completed.issubset(all_ids)):
        raise ValueError("RR durable IDs do not form an exact selected subset")
    corpora = {}
    remaining_count = 0
    for corpus, ids in selected_ids.items():
        retained = sorted(item for item in ids if item in completed)
        remaining = [item for item in ids if item not in completed]
        if not remaining:
            continue
        corpora[corpus] = {
            "completed_record_count": len(retained),
            "selected_datapoint_ids_sha256": _sha256_json(ids),
            "completed_datapoint_ids": retained,
            "completed_datapoint_ids_sha256": _sha256_json(retained),
            "remaining_datapoint_ids_sha256": _sha256_json(remaining),
        }
        remaining_count += len(remaining)
    return {"schema": "ura-recovery-completed-selection/1", "corpora": corpora}, remaining_count


def continuation_partition(selected_ids, completed_ids):
    """Use the existing positive-count selector; schedule untouched arms separately."""
    selector, _remaining = checkpoint_selection(selected_ids, completed_ids)
    entries = selector["corpora"]
    partial = {name: item for name, item in entries.items() if item["completed_record_count"]}
    chosen = partial or entries
    count = sum(len(selected_ids[name]) - item["completed_record_count"]
                for name, item in chosen.items())
    return ({"schema": selector["schema"], "corpora": partial} if partial else None), list(chosen), count


def terminal_chain(completion_path: Path, *, runner_root: Path):
    """Read a terminal RR chain without promoting its interrupted grids.

    A Runner deadline is durable from the first invocation. Continuing after it
    requires a new request, selection and result root, never resetting that file.
    """
    chain = []
    seen = set()
    path = completion_path.resolve(strict=True)
    while True:
        if path in seen:
            raise ValueError("RR continuation chain contains a cycle")
        seen.add(path)
        root = path.parent
        value = _load_json(path, label="terminal RR completion")
        launch_path = _validate_descriptor(value.get("launch"), label="RR launch")
        launch = _load_json(launch_path, label="RR launch")
        order = value.get("unit_order")
        results, failures = value.get("unit_results"), value.get("unit_failures")
        if (root.parent != runner_root.parent.parent / "engineering"
                or path.name != "completion.json" or launch_path != root / "launch.json"
                or value.get("schema") not in {SCHEMA, CONTINUATION_SCHEMA}
                or value.get("status") not in {"complete", "complete_with_failures"}
                or not isinstance(results, dict) or not isinstance(failures, dict)
                or not isinstance(order, list) or len(order) != len(set(order))
                or set(order) != set(results) | set(failures) or set(results) & set(failures)
                or not set(order).issubset(dict(LAYOUT))
                or value.get("controller_exit_code") != int(bool(failures))
                or value.get("status") != ("complete_with_failures" if failures else "complete")
                or value.get("target_answer_retries") != 1
                or value.get("successful_rows_repeated") != 0
                or value.get("paid_provider_calls") != 0
                or value.get("cross_condition_pooling_permitted") is not False
                or any(value.get(key) != item for key, item in launch.items() if key != "status")
                or set(launch.get("units", {})) != set(dict(LAYOUT))):
            raise ValueError("RR terminal chain contract changed")
        chain.append({"path": path, "root": root, "value": value, "launch": launch})
        revision_path = _validate_descriptor(value.get("project_revision"), label="RR project revision")
        revision = _load_json(revision_path, label="RR project revision")
        if (revision.get("repository", {}).get("expected_commit") != value.get("expected_commit")
                or revision.get("repository", {}).get("observed_commit") != value.get("expected_commit")):
            raise ValueError("RR retained deployment identity changed")
        if value["schema"] == SCHEMA:
            if order != list(dict(LAYOUT)) or value.get("planned_unique_rows") != 7606:
                raise ValueError("RR original population changed")
            break
        path = _validate_descriptor(value.get("prior_completion"), label="prior RR completion")
    chain.reverse()
    evidence = chain[0]["launch"]["units"]
    selected = {}
    for lane, count in LAYOUT:
        item = evidence[lane]
        spec_path = _validate_descriptor(item["source_specification"], label="RR source specification")
        spec = _load_json(spec_path, label="RR source specification")
        config_path = _validate_descriptor(item["local_config"], label="RR profiled config")
        config = _load_json(config_path, label="RR profiled config")
        argv = spec.get("base_argv", [])
        if (spec.get("lane_id") != lane or _option(argv, "--local") != RR_SPEC
                or _option(argv, "--limit") != "100" or _option(argv, "--seeds") != "0"
                or _option(argv, "--sample-seed") != "0" or _option(argv, "--attackers") != "replay"
                or spec.get("target", {}).get("revision") != RR_REVISION
                or config.get(RR_SPEC, {}).get("revision") != RR_REVISION):
            raise ValueError("RR retained population or model identity changed")
        rows, _audits = _selected_rows(argv)
        selected[lane] = {corpus: [row.id for row in items] for corpus, items in rows.items()}
        if sum(map(len, selected[lane].values())) != count:
            raise ValueError("RR source population cardinality changed")
    outcomes = {lane: {} for lane, _count in LAYOUT}
    snapshots = []
    metric_segments = []
    for generation in chain:
        value, root = generation["value"], generation["root"]
        if generation["launch"]["units"] != evidence:
            raise ValueError("RR continuation changed its retained serving profile or source")
        if value["schema"] == CONTINUATION_SCHEMA:
            if value.get("retained_inputs") != snapshots:
                raise ValueError("RR continuation source checkpoints changed")
        generation_snapshot = {"completion": _descriptor(generation["path"], label="RR completion"),
                               "lanes": {}}
        generation_count = generation_success = 0
        for lane in value["unit_order"]:
            unit_root = root / "units" / lane
            state_path = unit_root / "state.json"
            result = value["unit_results"].get(lane)
            if not state_path.exists():
                if (result is not None or any(
                        (runner_root / lane / root.name).glob("*.responses*.jsonl"))):
                    raise ValueError("RR retained responses have no measured state")
                continue
            state = _load_json(state_path, label="RR measured state")
            argv = state.get("runner_argv", [])
            source_config = evidence[lane]["local_config"]
            result_root = runner_root / lane / root.name
            selector, corpora, remaining = continuation_partition(selected[lane], list(outcomes[lane]))
            spec = _load_json(Path(evidence[lane]["source_specification"]["path"]), label="RR source specification")
            base = _replace_option(spec["base_argv"], "--local-config", source_config["path"])
            base = _replace_option(base, "--local-config-sha256", source_config["sha256"])
            base = _replace_option(base, "--corpora", ",".join(corpora))
            base = _base_argv(Unit(lane, lane, None, {**spec, "base_argv": base}, remaining),
                              project_revision=Path(value["project_revision"]["path"]),
                              project_revision_sha256=value["project_revision"]["sha256"])
            if selector is not None:
                descriptor = value["selectors"][lane]
                base.extend(("--recovery-completed-prefix", descriptor["path"],
                             "--recovery-completed-prefix-sha256", descriptor["sha256"]))
            if argv[:len(base)] != base:
                raise ValueError("RR source request arguments changed beyond the bound continuation")
            if (state.get("schema") != STATE_SCHEMA or state.get("unit_id") != lane
                    or state.get("source_lane") != lane or state.get("corpus") is not None
                    or state.get("result_root") != str(result_root)
                    or state.get("selected_records") != remaining
                    or state.get("target_answer_retries") != 1
                    or _option(argv, "--local-config") != source_config["path"]
                    or _option(argv, "--local-config-sha256") != source_config["sha256"]
                    or _option(argv, "--local") != RR_SPEC
                    or _option(argv, "--limit") != "100" or _option(argv, "--sample-seed") != "0"
                    or _option(argv, "--seeds") != "0" or _option(argv, "--attackers") != "replay"
                    or _option(argv, "--corpora") != ",".join(corpora)
                    or _option(argv, "--deadline-seconds") != "86400"
                    or _option(argv, "--max-total-target-calls") != str(remaining * 2)
                    or _option(argv, "--max-total-judge-calls") != "0"
                    or _option(argv, "--max-total-http-attempts") != "0"
                    or _option(argv, "--project-revision") != value["project_revision"]["path"]
                    or _option(argv, "--project-revision-sha256") != value["project_revision"]["sha256"]
                    or _option(argv, "--target-answer-retries") != "1"):
                raise ValueError("RR measured state changed its exact continuation selection")
            if value["schema"] == CONTINUATION_SCHEMA and selector is not None:
                selector_path = _validate_descriptor(value["selectors"][lane], label="RR selector")
                if (_load_json(selector_path, label="RR selector") != selector
                        or _option(argv, "--recovery-completed-prefix") != str(selector_path)
                        or _option(argv, "--recovery-completed-prefix-sha256")
                        != value["selectors"][lane]["sha256"]):
                    raise ValueError("RR continuation did not exclude every retained response")
            elif "--recovery-completed-prefix" in argv:
                raise ValueError("RR unfiltered unit unexpectedly changed its population")
            if result_root.is_symlink() or result_root.resolve(strict=True) != result_root:
                raise ValueError("RR measured root is not canonical")
            files = list(result_root.glob("*.responses*.jsonl"))
            if files:
                _attempts, current, attempt_files, response_files = _durable_outcomes(result_root)
            else:
                current, attempt_files, response_files = {}, [], []
            allowed = {"usable_first_response", "recovered_after_retry", "failed_output", "input_incompatible"}
            if (set(current) & set(outcomes[lane]) or any(status not in allowed for status in current.values())):
                raise ValueError("RR continuation repeated a durable response or changed its status")
            chosen_ids = {item for corpus in corpora for item in selected[lane][corpus]}
            if not set(current).issubset(chosen_ids):
                raise ValueError("RR response lies outside its scheduled corpus partition")
            checkpoint_selection(selected[lane], [*outcomes[lane], *current])
            outcomes[lane].update(current)
            successful = sum(status in {"usable_first_response", "recovered_after_retry"}
                             for status in current.values())
            generation_count += len(current)
            generation_success += successful
            generation_snapshot["lanes"][lane] = {
                "state": _descriptor(state_path, label="RR state"),
                "attempt_files": [_descriptor(p, label="RR attempts") for p in attempt_files],
                "response_files": [_descriptor(p, label="RR responses") for p in response_files],
                "durable_responses": len(current), "successful_generations": successful,
                "result_root": str(result_root),
            }
            if result is not None:
                if (len(current) != remaining or result.get("target_attempts") != remaining
                        or result.get("successful_target_generations") != successful):
                    raise ValueError("RR complete segment cardinality changed")
                metric_segments.append({"generation": generation, "lane": lane,
                                        "result": result, "selected_records": remaining})
        if value["target_execution"] != {"target_attempts": generation_count,
                                          "successful_target_generations": generation_success,
                                          "missing_responses": generation_count - generation_success}:
            raise ValueError("RR generation accounting changed")
        snapshots.append(generation_snapshot)
    return chain, selected, outcomes, snapshots, metric_segments


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


def configure_continuation(completion_path: Path, expected_sha256: str, *,
                           control_root: Path, runner_root: Path):
    source = _descriptor(completion_path.resolve(strict=True), label="prior RR completion")
    if source["sha256"] != expected_sha256:
        raise ValueError("prior RR completion digest changed")
    chain, selected, outcomes, snapshots, _segments = terminal_chain(
        completion_path, runner_root=runner_root,
    )
    ancestor_names = {generation["root"].name for generation in chain}
    for lane, _count in LAYOUT:
        lane_root = runner_root / lane
        for response in lane_root.glob("*/*.responses*.jsonl"):
            if response.parent.name not in ancestor_names:
                raise ValueError("RR continuation source omits a later measured result root")
    evidence = chain[0]["launch"]["units"]
    units, selectors, canaries = [], {}, {}
    for lane, _count in LAYOUT:
        selector, corpora, remaining = continuation_partition(selected[lane], list(outcomes[lane]))
        if not remaining:
            continue
        spec = _load_json(Path(evidence[lane]["source_specification"]["path"]), label="RR specification")
        config = evidence[lane]["local_config"]
        argv = _replace_option(spec["base_argv"], "--local-config", config["path"])
        argv = _replace_option(argv, "--local-config-sha256", config["sha256"])
        argv = _replace_option(argv, "--corpora", ",".join(corpora))
        unit = Unit(lane, lane, None, {**spec, "base_argv": argv, "local_config": config}, remaining)
        if selector is not None:
            path = control_root / "inputs" / f"{lane}.json"
            _create_json(path, selector)
            selectors[lane] = _descriptor(path, label="RR continuation selector")
            unit = replace(unit, recovery=selector)
        units.append(unit)
        for generation in chain:
            canary = generation["root"] / "units" / lane / "canary"
            if canary.is_dir() and list(canary.glob("eligibility-*.eligibility.json")):
                canaries[lane] = canary
                break
    if not units:
        raise ValueError("RR population is already fully retained; no target calls are needed")
    return units, evidence, {
        "prior_completion": source, "retained_inputs": snapshots, "selectors": selectors,
        "retained_response_count": sum(map(len, outcomes.values())),
        "continuation_policy": "never_attempted_only_including_retention_of_failed_and_truncated_outputs",
        "reused_canary_roots": {lane: str(path) for lane, path in canaries.items()},
    }, canaries


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
    prior = getattr(args, "continue_from", None)
    prior_sha = getattr(args, "continue_from_sha256", None)
    if bool(prior) != bool(prior_sha):
        raise ValueError("RR continuation requires its completion and exact SHA-256 together")
    if prior is None:
        # No completed RR unit may be silently scheduled again.
        for lane, _count in LAYOUT:
            old_root = work / "runs/thesis/runner" / lane
            if any(old_root.rglob("*.grid.json")) or any(old_root.rglob("*.responses*.jsonl")):
                raise ValueError(f"{lane} already has measured artifacts; use checkpoint recovery")
        if args.source_spec_root is None or args.profile_registry is None:
            raise ValueError("initial RR execution requires specifications and the admitted profile registry")
    root.mkdir(mode=0o700)
    (root / "configs").mkdir(mode=0o700)
    (root / "inputs").mkdir(mode=0o700)
    continuation, canaries = {}, {}
    if prior is None:
        units, evidence = configure_units(args.source_spec_root.resolve(strict=True), root,
                                          args.profile_registry.resolve(strict=True))
    else:
        units, evidence, continuation, canaries = configure_continuation(
            prior, prior_sha, control_root=root, runner_root=work / "runs/thesis/runner",
        )
    launch = {
        "schema": CONTINUATION_SCHEMA if prior else SCHEMA,
        "status": "running", "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit, "runner_code_version": CODE_VERSION,
        "project_revision": revision, "unit_order": [unit.unit_id for unit in units],
        "units": evidence, "planned_unique_rows": sum(unit.selected_records for unit in units),
        "target_answer_retries": 1, "max_total_target_calls": sum(unit.selected_records for unit in units) * 2,
        "per_unit_wall_time_seconds": 86400, "paid_provider_calls": 0,
        "successful_rows_repeated": 0, "cross_condition_pooling_permitted": False,
        **continuation,
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
            recovery = continuation.get("selectors", {}).get(unit.unit_id)
            results[unit.unit_id] = _run_unit(
                unit, python=python, work_root=work, control_root=root,
                project_revision=Path(revision["path"]), project_revision_sha256=revision["sha256"],
                scope=args.execution_scope_id,
                recovery_path=Path(recovery["path"]) if recovery else None,
                recovery_sha256=recovery["sha256"] if recovery else None,
                expected_commit=args.expected_commit, framework_lock_id=_framework_lock_id(),
                admission_sha256=admission["sha256"], tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session, state_schema=STATE_SCHEMA,
                validated_canary_root=canaries.get(unit.unit_id),
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
    for name in ("project-root", "work-root", "control-root", "project-revision"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("source-spec-root", "profile-registry", "continue-from"):
        parser.add_argument(f"--{name}", type=Path)
    parser.add_argument("--continue-from-sha256")
    parser.add_argument("--python", type=Path)
    for name in ("project-revision-sha256", "expected-commit", "execution-scope-id",
                 "tmux-socket", "tmux-session"):
        parser.add_argument(f"--{name}", required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
