"""One operator action over existing preparation jobs, never automatic generation."""

from __future__ import annotations

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import hashlib
import html
import importlib
import json
import re
import threading
import time
from pathlib import Path
from uuid import uuid4

from .ui import _page


# These functions already own command construction and artifact semantics.
_STEPS = {
    "campaign": (),
    "attack-capture": (
        (_ui_text("operations.preparing_attack_material"), "operations", "prepare_transport_check"),
    ),
    "transport-check": (
        (
            _ui_text("operations.waiting_for_your_diagnostic_probe"),
            "operations",
            "prepare_transport_check",
        ),
        (
            _ui_text("operations.saving_the_connection_check"),
            "operations",
            "prepare_transport_check",
        ),
    ),
    "matched": (
        (
            _ui_text("operations.selecting_saved_inputs"),
            "builder_sources",
            "prepare_selected_inputs",
        ),
        (_ui_text("operations.calculating_workload_and_costs"), "builder_budget", "prepare_budget"),
        (_ui_text("operations.preparing_selected_inputs"), "builder_replays", "prepare_replays"),
        (
            _ui_text("operations.counting_and_preparing_execution"),
            "builder_programs",
            "prepare_programs",
        ),
    ),
    "local-judging": (
        (
            _ui_text("operations.preparing_saved_answers"),
            "builder_native_judging",
            "prepare_native_judging",
        ),
    ),
    "haiku-judging": (
        (
            _ui_text("operations.preparing_saved_answers"),
            "builder_native_judging",
            "prepare_native_judging",
        ),
        (
            _ui_text("operations.matching_selected_outputs"),
            "builder_judging_inventory",
            "prepare_judging_inventory",
        ),
        (
            _ui_text("operations.calculating_judging_costs"),
            "builder_judging_inventory",
            "prepare_inventory_judging",
        ),
        (
            _ui_text("operations.preparing_judging_execution"),
            "builder_inventory_execution",
            "prepare",
        ),
    ),
    "paired-haiku": (
        (
            _ui_text("operations.preparing_saved_answers"),
            "builder_native_judging",
            "prepare_native_judging",
        ),
        (
            _ui_text("operations.matching_answers_and_calculating_judging_costs"),
            "builder_haiku_judging",
            "prepare_haiku_judging",
        ),
    ),
}
_DIRECT = (
    _ui_text("operations.planning_installed_models"),
    _ui_text("operations.preparing_installed_models"),
    _ui_text("operations.checking_the_workload"),
    _ui_text("operations.preparing_execution"),
    _ui_text("operations.finishing_model_preparation"),
)
_TITLES = {
    "direct": _ui_text("operations.prepare_run"),
    "matched": _ui_text("operations.prepare_hosted_comparison"),
    "attack-capture": _ui_text("operations.prepare_attack_material"),
    "campaign": _ui_text("operations.campaign"),
    "local-judging": _ui_text("operations.prepare_local_judging"),
    "haiku-judging": _ui_text("operations.prepare_haiku_judging"),
    "paired-haiku": _ui_text("operations.prepare_sampled_haiku_comparison"),
    "transport-check": _ui_text("operations.finish_diagnostic_probe"),
}


def prepare_transport_check(app, params):
    owner, values, previous = app._transport_check_from_job(
        params["probe_job"], params.get("campaign_id", "")
    )
    if previous:
        return app.jobs[previous]
    return app.start_job("live_attestation", values, campaign_id=owner)


def operator_operations(operations, owner):
    """Show owned workflows, not their internal preparation/check handoffs."""
    children = {row.get("preparation") for row in operations.values()}
    for row in operations.values():
        for connection in row.get("connection_operations", []):
            children.update((connection.get("preparation"), connection.get("check")))
    return [
        row
        for row in operations.values()
        if row["params"].get("campaign_id", "") == owner
        and row["id"] not in children
        and not row.get("campaign_parent")
    ]


def operation_contains_job(operations, operation_id, job_id, seen=None):
    """Follow saved ownership so guidance stays on the parent progress page."""
    seen = set() if seen is None else seen
    if operation_id in seen or operation_id not in operations:
        return False
    seen.add(operation_id)
    row = operations[operation_id]
    jobs = list(row.get("jobs", [])) + [
        row.get(key)
        for key in (
            "current_job",
            "execution_job",
            "collection_job",
            "local_preparation",
            "local_execution",
            "haiku_preparation",
            "haiku_execution",
        )
    ]
    if job_id in jobs:
        return True
    children = [row.get("preparation")]
    for connection in row.get("connection_operations", []):
        children.extend((connection.get("preparation"), connection.get("check")))
    return any(operation_contains_job(operations, child, job_id, seen) for child in children)


def campaign_selection(values, *, completed=False):
    """Operator choices, excluding automatic preparation locators."""
    if values.get("setup_mode") != "automatic":
        return values
    return {
        key: value
        for key, value in values.items()
        if key != "out"
        and not key.startswith(("att_path", "att_sha"))
        and not (
            completed
            and values.get("campaign_inputs") == "saved"
            and key == "retained_pricing_date"
        )
    }


def completed_equivalent(operations, operation):
    """Resolve an obsolete unstarted review using saved configuration identity.

    No model files, live registries or providers are consulted. Missing frozen
    configuration is not proof of equivalence; changed work stays separate.
    """
    if (
        operation["kind"] != "campaign"
        or operation["status"] != "ready"
        or operation.get("execution_authorized")
    ):
        return None

    def frozen(row):
        child = operations.get(row.get("preparation"), {})
        if child.get("kind") != "direct":
            return {}
        return {
            k: v
            for k, v in child.get("snapshot_manifest", {}).items()
            if not k.startswith("live_attestation_")
        }

    snapshot = frozen(operation)
    if not snapshot:
        return None
    wanted = campaign_selection(
        operation.get("original_params", operation["params"]), completed=True
    )
    for row in sorted(operations.values(), key=lambda r: r.get("created_at", 0)):
        if (
            row["kind"] == "campaign"
            and row["status"] == "complete"
            and campaign_selection(row.get("original_params", row["params"]), completed=True)
            == wanted
            and frozen(row) == snapshot
        ):
            return row
    return None


class _Context:
    """Existing preparers update this operation, not a concurrently edited draft."""

    def __init__(self, app, operation):
        self.app, self.operation = app, operation

    def __getattr__(self, key):
        return getattr(self.app, key)

    def _save_build_campaign(self, params):
        self.operation["params"] = dict(params)
        self.app._save_operation(self.operation)
        return dict(params)

    def start_job(self, command, values, **kwargs):
        job_id = kwargs.get("reserved_job_id") or self.app._job_id_factory()
        kwargs["reserved_job_id"] = job_id
        self.operation["current_job"] = job_id
        self.operation["launch_pending"] = True
        self.app._save_operation(self.operation)
        return self.app.start_job(command, values, **kwargs)


class OperationsMixin:
    def _restore_operations(self):
        self._operations = {}
        self._operation_workers = {}
        self._operation_shutdown = threading.Event()
        base = self.state_dir.resolve() / ".private-operations"
        if base.is_dir():
            for path in base.glob("*/operation.json"):
                try:
                    raw = self._bounded_private_bytes(path, max_bytes=512 * 1024, label="operation")
                    value = json.loads(raw)
                    if (
                        value["kind"] not in _TITLES
                        or value["id"] != path.parent.name
                        or not re.fullmatch("[a-f0-9]{32}", value["id"])
                        or value["status"]
                        not in {"preparing", "ready", "failed", "stopped", "complete"}
                        or not isinstance(value["params"], dict)
                        or not isinstance(value["jobs"], list)
                        or not isinstance(value["current_job"], str)
                        or not isinstance(value["signature"], str)
                        or type(value["step"]) is not int
                        or not 0 <= value["step"] <= len(self._operation_labels(value))
                    ):
                        continue
                    self._operations[value["id"]] = value
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        for value in self._operations.values():
            if value["status"] == "preparing":
                self._ensure_operation_worker(value["id"])

    def _operation_root(self, operation):
        return self.state_dir.resolve() / ".private-operations" / operation["id"]

    def _save_operation(self, operation):
        root = self._operation_root(operation)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._write_private_workflow_file(
            root / "operation.json",
            (json.dumps(operation, sort_keys=True, ensure_ascii=False) + "\n").encode(),
        )

    def _operation_snapshot(self, operation):
        if not operation.get("snapshot_manifest"):
            return {}
        return self._workflow_execution_snapshot(
            dict(operation, root=self._operation_root(operation))
        )

    def _start_operation(self, kind, params, *, snapshot=None):
        if kind not in _TITLES:
            raise ValueError(_ui_text("operations.choose_a_supported_operation"))
        params = dict(params)
        if kind not in {"direct", "transport-check", "attack-capture"} and not params.get(
            "campaign_id"
        ):
            raise ValueError(
                _ui_text("operations.save_the_campaign_before_preparing_this_operation")
            )
        # Exact frozen selection: a second click/review reopens existing work.
        identity = {
            key: value
            for key, value in params.items()
            if not (kind == "matched" and key.startswith("retained_") and key.endswith("_job"))
        }
        signature = hashlib.sha256(
            json.dumps({"kind": kind, "params": identity}, sort_keys=True).encode()
        ).hexdigest()

        # Automatic output attempts and discovered connection receipts are
        # preparation results, not new operator selections. Compare original
        # choices as well as the exact frozen signature when reopening a
        # campaign. Manual paths/receipts remain significant; execution still
        # uses the original, unchanged snapshot, never these refreshed values.
        def selection(values, *, completed=False):
            return campaign_selection(values, completed=completed) if kind == "campaign" else values

        with self._app_lock:
            candidates = self._operations.values()
            if kind == "campaign":
                # Historical duplicate preparations can precede completed work
                # in filesystem restore order. Never offer another Start just
                # because that unexecuted preparation was restored first.
                candidates = sorted(
                    candidates, key=lambda row: (row["status"] != "complete", row["created_at"])
                )
            for operation in candidates:
                reusable = operation["status"] == "preparing" or (
                    operation["status"] in {"ready", "complete"}
                    and kind in {"direct", "matched", "transport-check", "campaign"}
                )
                same_campaign = (
                    kind == "campaign"
                    and operation["kind"] == kind
                    and selection(
                        operation.get("original_params", operation["params"]),
                        completed=operation["status"] == "complete",
                    )
                    == selection(params, completed=operation["status"] == "complete")
                )
                if (
                    reusable
                    and (operation["signature"] == signature or same_campaign)
                    and (
                        kind != "campaign"
                        or self._campaign_configuration_matches(operation, params)
                    )
                ):
                    return operation["id"]
            operation = dict(
                id=uuid4().hex,
                kind=kind,
                params=params,
                signature=signature,
                status="preparing",
                step=0,
                current_job="",
                jobs=[],
                launch_pending=False,
                error="",
                created_at=time.time(),
                failed_jobs=[],
                snapshot_manifest={},
            )
            operation["original_params"] = dict(params)
            if kind == "transport-check":
                operation["current_job"] = params["probe_job"]
            if kind == "attack-capture":
                operation["current_job"] = params["capture_job"]
                operation["original_params"] = {
                    k: v for k, v in params.items() if k != "capture_job"
                }
            if kind == "direct":
                operation["acquisition"] = self._builder_model_acquisition_required(params)
                self._reuse_direct_preparation(operation)
            root = self._operation_root(operation)
            root.mkdir(parents=True, mode=0o700)
            for name, payload in (snapshot or {}).items():
                name = self._workflow_component_name(name)
                self._write_private_workflow_file(root / ("snapshot-" + name + ".bin"), payload)
                operation["snapshot_manifest"][name] = dict(
                    bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()
                )
            self._operations[operation["id"]] = operation
            self._save_operation(operation)
            self._ensure_operation_worker(operation["id"])
            return operation["id"]

    def _campaign_configuration_matches(self, operation, params):
        """Do not mistake changed configured generation settings for a reopen.

        Compare the small retained configuration files, not model/corpus files.
        Reopening results requires no live model discovery or inference.
        """
        child = self._operations.get(operation.get("preparation"))
        if child is None:
            return True  # Preparation has not frozen configuration yet.
        try:
            if child["kind"] == "matched":
                if not child["params"].get("retained_budget_job"):
                    return True
                from .builder_replays import prepared_sources

                current = dict(child["params"], **params)
                if operation["status"] == "complete":
                    # A new calendar day does not repeat a completed campaign.
                    # Unstarted work still requires the current forecast date.
                    current["retained_pricing_date"] = child["params"].get(
                        "retained_pricing_date", ""
                    )
                prepared_sources(self, current)
                return True
            manifest = child.get("snapshot_manifest", {})
            current = {}
            if "api_config" in manifest:
                current["api_config"] = self._canonical_json_bytes(
                    self._selected_api_config_snapshot(params)[3]
                )
            if "source_config" in manifest:
                current["source_config"] = self._canonical_json_bytes(
                    self._selected_source_config_snapshot(params)[2]
                )
            if "local_config" in manifest:
                specs = self._split_list(params.get("local", ""))
                judge = params.get("judge_model", "")
                if judge.startswith(("vllm:", "ollama:")) and judge not in specs:
                    specs.append(judge)
                current["local_config"] = self._selected_local_config_payload(
                    specs,
                    default_quantization=params.get("quantization", ""),
                    quantization_overrides={
                        k.removeprefix("quantization::"): v
                        for k, v in params.items()
                        if k.startswith("quantization::")
                    },
                )
            return all(
                payload
                == self._bounded_private_bytes(
                    self._operation_root(child) / ("snapshot-" + name + ".bin"),
                    max_bytes=1024 * 1024,
                    label=_ui_text("operations.retained_campaign_configuration"),
                )
                for name, payload in current.items()
            )
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def _reuse_direct_preparation(self, operation):
        params = operation["params"]
        projection, _ = self._read_lane_projection(params)
        if projection is None:
            return
        # A valid exact projection need not be recomputed. Empty positions
        # represent skipped technical stages, not invented jobs.
        operation.update(
            step=3 if operation["acquisition"] else 1,
            jobs=["", "", ""] if operation["acquisition"] else [],
        )
        if not operation["acquisition"]:
            return
        wanted = {k: v for k, v in self._durable_builder_params(params).items() if v}
        for workflow in self._model_acquisition_workflows.values():
            retained = {
                k: v for k, v in self._durable_builder_params(workflow["params"]).items() if v
            }
            if workflow["next_stage"] != "run" or workflow.get("consumed") or retained != wanted:
                continue
            job = self.jobs.get(workflow.get("acquisition_job_id"))
            if job is not None and job.state() == "complete" and job.exit_code() == 0:
                operation.update(step=5, jobs=["", "", "", workflow["plan_job_id"], job.job_id])
                return

    def _ensure_operation_worker(self, operation_id):
        existing = self._operation_workers.get(operation_id)
        if existing is not None and existing.is_alive():
            return

        def work():
            while not self._operation_shutdown.is_set():
                with self._app_lock:
                    if self._operation_shutdown.is_set():
                        return
                    operation = self._operations[operation_id]
                    if operation["status"] != "preparing":
                        return
                    try:
                        self._reconcile_locked()
                        self._advance_operation(operation)
                    except Exception as exc:
                        operation.update(
                            status="failed",
                            error=_ui_text("operations.preparation_could_not_continue")
                            + str(exc)[:1200],
                        )
                        self._save_operation(operation)
                if self._operation_shutdown.wait(3):
                    return

        worker = threading.Thread(target=work, name="prepare-" + operation_id[:8], daemon=True)
        self._operation_workers[operation_id] = worker
        worker.start()

    @staticmethod
    def _operation_labels(operation):
        if operation["kind"] == "campaign":
            return (
                _ui_text("operations.preparing_campaign"),
                _ui_text("operations.collecting_answers"),
                _ui_text("operations.local_assessment"),
                _ui_text("operations.haiku_assessment"),
                _ui_text("operations.results_ready"),
            )
        if operation["kind"] == "direct":
            return (
                _DIRECT
                if operation.get("acquisition")
                else (_ui_text("operations.checking_the_workload"),)
            )
        return tuple(item[0] for item in _STEPS[operation["kind"]])

    def _advance_operation(self, operation):
        if operation["status"] != "preparing":
            return
        try:
            if operation["kind"] == "campaign":
                from .campaign_flow import advance

                advance(self, operation)
                return
            if operation["current_job"]:
                job = self.jobs.get(operation["current_job"])
                if job is None:
                    raise ValueError(
                        _ui_text(
                            "operations.preparation_was_interrupted_before_its_job_was_registered_no_next"
                        )
                    )
                state = job.state()
                if state in {"running", "queued", "starting", "retry_wait", "retry_waiting"}:
                    return
                partial_native = (
                    job.command == "retained_native_judge_prepare"
                    and state == "failed"
                    and job.exit_code() == 1
                )
                if not partial_native and (state != "complete" or job.exit_code() != 0):
                    if (
                        job.command == "hosted_campaign_prepare"
                        and "whole source cluster for measurement" in (job.failure or "")
                    ):
                        raise ValueError(
                            _ui_text(
                                "operations.choose_saved_source_runs_and_a_request_cap_covering_at_least_two"
                            )
                        )
                    raise ValueError(
                        job.failure
                        or _ui_text("operations.the_preparation_job")
                        + job.job_id
                        + _ui_text("operations.ended_as")
                        + state
                        + "."
                    )
                operation["jobs"].append(job.job_id)
                operation["current_job"] = ""
                operation["launch_pending"] = False
                operation["step"] += 1
                self._save_operation(operation)
            length = len(self._operation_labels(operation))
            if operation["kind"] == "direct" and operation["step"] == (
                3 if operation["acquisition"] else 1
            ):
                self._resolve_operation_caps(operation)
                from .connection_workflow import advance

                if advance(self, operation):
                    return
                # A fresh transport binding may require an exact no-call
                # projection before the execution plan can use that binding.
                if operation.get("refresh_after_connections"):
                    operation.pop("refresh_after_connections")
                    operation.update(step=0, jobs=[])
                    self._save_operation(operation)
                    return
            if operation["step"] == length:
                if operation["kind"] == "direct" and operation.get("execution_authorized"):
                    from .connection_workflow import launch

                    launch(self, operation)
                operation["status"] = "ready"
                self._publish_operation_selection(operation)
                self._save_operation(operation)
                return
            if operation["kind"] == "direct":
                job = self._launch_direct_preparation_step(operation)
            else:
                _, module, function = _STEPS[operation["kind"]][operation["step"]]
                preparer = getattr(importlib.import_module("." + module, __package__), function)
                job = preparer(_Context(self, operation), dict(operation["params"]))
            operation["current_job"] = job.job_id
            operation["launch_pending"] = False
            self._save_operation(operation)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            operation["status"] = "failed"
            operation["error"] = str(exc)[:1500]
            self._save_operation(operation)

    def _publish_operation_selection(self, operation):
        """Update preparation pointers only if the operator has not edited the draft."""
        if operation["kind"] == "attack-capture":
            from .prepared_inputs import capture_result

            operation["params"] = {k: v for k, v in operation["original_params"].items()}
            operation["params"].update(capture_result(self, self.jobs[operation["jobs"][0]]))
        owner = operation["params"].get("campaign_id")
        if owner and operation["kind"] != "direct":
            saved = self.db.workspace_definition(owner)
            if saved == operation["original_params"]:
                self.db.save_workspace_definition(owner, operation["params"])

    def _resolve_operation_caps(self, operation):
        params = operation["params"]
        if params.get("automatic_caps") != "on" or params.get("_caps_resolved") == "yes":
            return
        projection, why = self._read_lane_projection(params)
        if projection is None:
            raise ValueError(_ui_text("operations.could_not_calculate_execution_limits") + why)
        for field, key in (
            ("cap_target", "target_calls"),
            ("cap_judge", "judge_calls"),
            ("cap_http", "http_attempts"),
        ):
            params[field] = str(max(1, int(projection["call_projection"][key])))
        params["_caps_resolved"] = "yes"
        self._save_operation(operation)

    def _launch_direct_preparation_step(self, operation):
        step = operation["step"]
        if not operation["acquisition"]:
            snapshot = self._operation_snapshot(operation)
            command, values, params = self._compose_from_builder(
                operation["params"], execution_snapshot=snapshot
            )
            try:
                attacker = self._materialize_prepared_attacker_config(
                    params,
                    snapshot_payload=snapshot.get("attacker_config"),
                    artifact_snapshots=snapshot,
                )
                if attacker is not None:
                    values.update(
                        {
                            "--attacker-config": str(attacker),
                            "--attacker-config-sha256": hashlib.sha256(
                                attacker.read_bytes()
                            ).hexdigest(),
                        }
                    )
                preflight = self._builder_preflight_values(
                    values, output=self._preflight_output_dir(params)
                )
                return _Context(self, operation).start_job(
                    command, preflight, builder_params=params, execution_snapshot=snapshot
                )
            except BaseException:
                self._discard_unlaunched_local_config(values)
                raise
        if step in {0, 3}:
            next_stage = "preflight" if step == 0 else "run"
            params = dict(operation["params"], _model_acquisition_next=next_stage)
            reserved = self._job_id_factory()
            operation["current_job"] = reserved
            operation["launch_pending"] = True
            self._save_operation(operation)
            job = self._start_model_acquisition_plan(
                params,
                execution_snapshot=self._operation_snapshot(operation),
                reserved_job_id=reserved,
            )
            return job
        if step in {1, 4}:
            plan_id = operation["jobs"][0 if step == 1 else 3]
            workflow = self._model_acquisition_workflows[plan_id]
            existing = workflow.get("acquisition_job_id")
            if existing and self.jobs[existing].state() not in {"failed", "stopped", "interrupted"}:
                return self.jobs[existing]
            reserved = self._job_id_factory()
            operation.update(current_job=reserved, launch_pending=True)
            self._save_operation(operation)
            return self._start_model_acquisition_download(plan_id, reserved_job_id=reserved)
        # The only automatic run is the no-call preflight. Generation is never
        # a background transition, including probe/canary execution.
        acquisition = operation["jobs"][1]
        if self._model_acquisition_workflows[acquisition]["next_stage"] != "preflight":
            raise ValueError(
                _ui_text("operations.automatic_preparation_may_only_execute_a_no_call_preflight")
            )
        reserved = self._job_id_factory()
        operation["current_job"] = reserved
        operation["launch_pending"] = True
        self._save_operation(operation)
        return self._start_model_acquisition_run(acquisition, reserved_job_id=reserved)

    def _stop_operation(self, operation_id):
        with self._app_lock:
            operation = self._operations.get(operation_id)
            if operation is None or operation["status"] != "preparing":
                raise ValueError(_ui_text("operations.only_an_active_preparation_can_be_stopped"))
            if operation["kind"] == "campaign":
                from .campaign_flow import stop

                stop(self, operation)
                return
            operation["status"] = "stopped"
            self._save_operation(operation)  # Prevent the next handoff first.
            pending = {operation["current_job"], operation.get("execution_job")}
            for item in operation.get("connection_operations", []):
                for key in ("preparation", "check"):
                    child = self._operations.get(item.get(key))
                    if child and child["status"] == "preparing":
                        self._stop_operation(child["id"])
                    if child:
                        # Launch identity is durable before the parent records
                        # its probe/check handoff. A ready preparation may
                        # therefore own an active diagnostic execution.
                        pending.add(child.get("execution_job"))
                pending.add(item.get("probe"))
            for job_id in sorted(key for key in pending if key):
                job = self.jobs.get(job_id)
                if job is not None and job.state() in {
                    "running",
                    "queued",
                    "starting",
                    "retry_wait",
                    "retry_waiting",
                }:
                    self.stop_job(job.job_id)

    def _retry_operation(self, operation_id):
        with self._app_lock:
            operation = self._operations.get(operation_id)
            if operation is None or operation["status"] not in {"failed", "stopped"}:
                raise ValueError(
                    _ui_text("operations.only_interrupted_preparation_can_be_continued")
                )
            if operation["kind"] == "campaign":
                from .campaign_flow import retry

                retry(self, operation)
                return
            if operation["kind"] == "direct":
                from .connection_workflow import check_recovery

                check_recovery(self, operation)
            job = self.jobs.get(operation["current_job"])
            if job is not None and job.state() in {
                "running",
                "queued",
                "starting",
                "retry_wait",
                "retry_waiting",
            }:
                raise ValueError(
                    _ui_text(
                        "operations.the_previous_preparation_is_still_stopping_wait_for_it_to_finish"
                    )
                )
            if job is None and operation["current_job"]:
                # start_job records identity before spawning. A failure before
                # creating its directory is therefore safe to retry; retained
                # launch files require reconciliation, not a duplicate launch.
                if (self.state_dir / operation["current_job"]).exists():
                    raise ValueError(
                        _ui_text(
                            "operations.the_interrupted_job_has_saved_launch_files_reopen_the_console_to"
                        )
                    )
                operation.update(current_job="", launch_pending=False)
            if job is not None and job.state() != "complete":
                if (
                    operation["kind"] in {"transport-check", "attack-capture"}
                    and operation["step"] == 0
                ):
                    raise ValueError(
                        _ui_text(
                            "operations.the_diagnostic_probe_did_not_complete_open_its_saved_job_and_reco"
                        )
                    )
                # This can only re-enable a failed no-call preflight, never a
                # consumed target-generation workflow.
                if (
                    operation["kind"] == "direct"
                    and operation.get("acquisition")
                    and operation["step"] == 2
                ):
                    workflow = self._model_acquisition_workflows[operation["jobs"][1]]
                    if workflow["next_stage"] != "preflight":
                        raise ValueError(
                            _ui_text(
                                "operations.only_a_no_call_preflight_can_be_resumed_automatically"
                            )
                        )
                    workflow["consumed"] = False
                    self._persist_model_acquisition_workflow(workflow)
                operation["failed_jobs"].append(job.job_id)
                operation["current_job"] = ""
            if operation["kind"] == "direct":
                from .connection_workflow import resume_probes

                resume_probes(self, operation)
            for item in operation.get("connection_operations", []):
                for key in ("preparation", "check"):
                    child = self._operations.get(item.get(key))
                    if child and child["status"] in {"failed", "stopped"}:
                        self._retry_operation(child["id"])
            operation.update(status="preparing", error="")
            self._save_operation(operation)
            # A failed worker may still be returning from its last cycle.
            # It exits only on the status check above; if live, it will resume.
            self._ensure_operation_worker(operation_id)

    def _operation_review(self, operation):
        params = dict(operation["params"])
        if operation.get("campaign_parent"):
            return _page(
                _ui_text("operations.campaign_preparation_ready"),
                _ui_template(
                    '<h1>[[text:operations.preparation_ready]]</h1><p>[[text:operations.collection_and_judging_are_controlled_by_your_campaign]]</p><a href="/operations/'
                )
                + operation["campaign_parent"]
                + _ui_template('">[[text:operations.return_to_campaign_progress]]</a>'),
                active=_ui_text("operations.campaigns"),
            )
        if operation.get("execution_job"):
            return _page(
                _ui_text("operations.experiment_started"),
                _ui_template("<h1>[[text:operations.experiment_started]]</h1>")
                + self._campaign_banner(params.get("campaign_id", ""))
                + _ui_template(
                    '<p>[[text:operations.connection_checks_are_saved_separately_your_measured_job_is_avail]]</p><p><a href="/jobs/'
                )
                + html.escape(operation["execution_job"])
                + _ui_template('">[[text:operations.open_measured_job_and_results]]</a></p>'),
                active=_ui_text("operations.build"),
            )
        if operation.get("awaiting_connections"):
            from .connection_workflow import review

            return review(self, operation)
        if operation["kind"] == "attack-capture":
            owner = params.get("campaign_id", "")
            return _page(
                _ui_text("operations.attack_material_ready"),
                _ui_template("<h1>[[text:operations.attack_material_ready]]</h1>")
                + self._campaign_banner(owner)
                + _ui_template(
                    "<p>[[text:operations.your_capture_is_saved_an_unchanged_campaign_draft_is_updated_auto]]</p>"
                )
                + '<p><a href="/build?campaign_id='
                + html.escape(owner)
                + _ui_template(
                    '#prepared-workflows">[[text:operations.return_to_experiment]]</a></p>'
                ),
                active=_ui_text("operations.build"),
            )
        if operation["kind"] == "transport-check":
            return _page(
                _ui_text("operations.probe_finished"),
                _ui_template("<h1>[[text:operations.probe_and_connection_check_complete]]</h1>")
                + self._campaign_banner(params.get("campaign_id", ""))
                + _ui_template(
                    '<p>[[text:operations.the_saved_connection_check_will_be_selected_automatically_for_mat]]</p><p><a href="/jobs/'
                )
                + operation["jobs"][0]
                + _ui_template('">[[text:operations.view_the_probe_result]]</a></p>'),
                active=_ui_text("operations.build"),
            )
        if operation["kind"] == "direct":
            if not operation["acquisition"]:
                command, values, params = self._compose_from_builder(
                    params, execution_snapshot=self._operation_snapshot(operation)
                )
                try:
                    return self._preview_page(
                        command,
                        values,
                        params,
                        prepared=True,
                        held_snapshot=self._operation_snapshot(operation),
                    )
                finally:
                    self._discard_unlaunched_local_config(values)
            acquisition = operation["jobs"][-1]
            workflow = self._model_acquisition_workflows[acquisition]
            ceilings, eligible = self._ceilings_card(workflow["params"])
            mode = params.get("mode", "measured")
            label = {
                "attestation_probe": _ui_text("operations.start_probe"),
                "diagnostic_canary": _ui_text("operations.start_canary"),
            }.get(mode, _ui_text("operations.start_run"))
            if workflow.get("consumed"):
                action = _ui_template(
                    "<p>[[text:operations.this_prepared_run_has_already_been_started_its_results_remain_in]]</p>"
                )
            elif eligible:
                ticket = self._new_launch_ticket(
                    {"acquisition_job_id": acquisition}, purpose="acquisition_run"
                )
                action = (
                    '<form class="action-row" method="post" action="/build/model-acquisition/run">'
                    '<input type="hidden" name="launch_ticket" value="' + html.escape(ticket) + '">'
                    "<button>" + label + "</button></form>"
                )
            else:
                action = _ui_template(
                    '<p class="notice amber">[[text:operations.the_workload_exceeds_the_configured_limits_adjust_the_limits_or_s]]</p>'
                )
            experiment = _ui_template(
                '<section class="card"><h2>[[text:operations.your_prepared_run]]</h2><dl>'
            )
            for name, key in [
                (_ui_text("operations.models"), "local"),
                (_ui_text("operations.hosted_models"), "api"),
                (_ui_text("operations.inputs"), "corpora"),
                (_ui_text("operations.per_arm_sample"), "limit"),
                (_ui_text("operations.evaluation"), "judges"),
            ]:
                if params.get(key):
                    experiment += "<dt>" + name + "</dt><dd>" + html.escape(params[key]) + "</dd>"
            experiment += _ui_template(
                "</dl><p>[[text:operations.preparation_is_complete_starting_makes_real_model_calls_hosted_ca]]</p></section>"
            )
            return _page(
                _ui_text("operations.review_prepared_run"),
                _ui_template("<h1>[[text:operations.review_prepared_run]]</h1>")
                + self._campaign_banner(params.get("campaign_id", ""))
                + experiment
                + ceilings
                + action,
                active=_ui_text("operations.build"),
            )
        module, function = {
            "matched": ("builder_collection", "collection_review"),
            "local-judging": ("builder_native_judging", "native_judging_review"),
            "haiku-judging": ("builder_inventory_execution", "review"),
            "paired-haiku": ("builder_haiku_judging", "haiku_judging_review"),
        }[operation["kind"]]
        return getattr(importlib.import_module("." + module, __package__), function)(self, params)

    def _operation_page(self, operation_id):
        operation = self._operations.get(operation_id)
        if operation is None:
            raise ValueError(_ui_text("operations.this_operation_is_unavailable"))
        if operation["kind"] == "campaign":
            from .campaign_flow import progress

            return progress(self, operation)
        if operation["status"] == "ready":
            return self._operation_review(operation)
        escape = html.escape
        labels = self._operation_labels(operation)
        label = labels[min(operation["step"], len(labels) - 1)]
        body = (
            "<h1>"
            + escape(_TITLES[operation["kind"]])
            + "</h1>"
            + self._campaign_banner(operation["params"].get("campaign_id", ""))
        )
        body += _ui_template(
            '<section class="card"><h2>[[text:operations.preparing_your_selected_work]]</h2><p>'
        )
        body += (
            _ui_text("operations.your_explicitly_started_probe_may_make_real_calls_its_connection")
            if operation["kind"] == "transport-check"
            else _ui_text(
                "operations.your_explicitly_started_attack_capture_may_invoke_its_source_mode"
            )
            if operation["kind"] == "attack-capture"
            else _ui_text(
                "operations.the_reviewed_connection_checks_and_measured_experiment_run_automa"
            )
            if operation.get("execution_authorized")
            else _ui_text(
                "operations.preparation_runs_automatically_no_target_answers_or_judge_decisio"
            )
        )
        body += _ui_template(" [[text:operations.you_can_leave_this_page_and_return]]</p>")
        if operation["status"] == "preparing":
            body += (
                _ui_template(
                    '<p role="status">[[text:operations.preparing_your_selected_work_2]]</p><form class="action-row" method="post" action="/operations/'
                )
                + operation_id
                + _ui_template(
                    '/stop"><button class="danger">[[text:operations.stop_preparation]]</button></form>'
                )
            )
            body += "<script>setTimeout(()=>window.uraBusy.reload(),3000);</script>"
        else:
            body += (
                '<p class="notice amber">'
                + escape(operation["error"] or _ui_text("operations.preparation_stopped"))
                + "</p>"
            )
            body += (
                '<form class="action-row" method="post" action="/operations/'
                + operation_id
                + _ui_template(
                    '/retry"><button>[[text:operations.continue_preparation]]</button></form>'
                )
            )
            body += _ui_template(
                "<p>[[text:operations.completed_stages_and_existing_installed_models_are_retained_if_se]]</p>"
            )
        body += (
            _ui_template(
                '</section><details class="card"><summary>[[text:operations.technical_job_details]]</summary><p>'
            )
            + escape(label)
            + "</p><ul>"
        )
        for job_id in filter(
            None,
            operation.get("failed_jobs", [])
            + operation["jobs"]
            + ([operation["current_job"]] if operation["current_job"] else []),
        ):
            body += '<li><a href="/jobs/' + escape(job_id) + '">' + escape(job_id) + "</a></li>"
        return _page(
            _ui_text("operations.preparing_work"),
            body + "</ul></details>",
            active=_ui_text("operations.build"),
        )

    def _operation_links(self, owner):
        selected = sorted(
            operator_operations(self._operations, owner), key=lambda row: row.get("created_at", 0)
        )
        if not selected:
            return ""
        body = _ui_template(
            '<section class="card"><h2>[[text:operations.prepared_and_active_work]]</h2><ul>'
        )
        for row in selected[-8:][::-1]:
            action = (
                _ui_text("operations.review_and_start")
                if row["status"] == "ready"
                else _ui_text("operations.view_progress")
                if row["status"] in {"preparing", "complete"}
                else _ui_text("operations.inspect_problem")
            )
            body += (
                "<li>"
                + html.escape(_TITLES[row["kind"]])
                + " - "
                + html.escape(_ui_label(row["status"]))
                + ' - <a href="/operations/'
                + row["id"]
                + '">'
                + action
                + "</a></li>"
            )
        return body + "</ul></section>"

    def _finish_probe_automatically(self, job):
        if (
            getattr(job, "command", "") == "run_matrix"
            and "--attestation-probe" in job.argv
            and "--preflight-only" not in job.argv
        ):
            params = job.builder_params or {}
            return self._start_operation(
                "transport-check",
                dict(probe_job=job.job_id, campaign_id=params.get("campaign_id", "")),
            )
        return None
