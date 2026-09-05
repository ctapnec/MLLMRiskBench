"""Operational publication of separately retained historical analysis steps.

This campaign-only adapter never invents an original controller completion.
It copies exact validated producer reports, retaining their original bindings.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from experiments.local_campaign.stats_adapter import (
    _campaign_report_strata,
    _descriptor_file,
    _object,
    _report_scope_matches,
    _validate_local_campaign_terminal_inventory,
    _zeros,
)
from experiments.rig_web_app.external_analysis import (
    ExternalAnalysisReportSpec,
    publish_external_analysis_registration,
)
from experiments.rig_web_app.external_measured import _write_create_only
from experiments.rig_web_app.reports import _validate_report_document

_MAXIMUM = 64 * 1024 * 1024
_STEPS = (
    "run_suite_summary", "run_level2", "run_judge_sensitivity", "run_kappa",
    "run_transfer", "run_llava_pairs", "run_adaptivity_pairs", "build_boundaries",
)
_REQUIRED = {
    "campaign-terminal-inventory", "level1-evidence", "execution-accounting",
    "suite-summary", "level2-report", "judge-sensitivity", "kappa",
    "transfer-matrix", "analysis-boundaries",
}


def _identity(path: Path, payload: bytes) -> dict[str, Any]:
    return {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload)}


def retained_continuation_reports(
    results_root: Path, result_descriptor: Mapping[str, Any],
) -> list[tuple[str, str, Mapping[str, Any]]]:
    """Validate the exact handoff and return source reports without writing."""
    root = results_root.resolve(strict=True)

    def read(raw: object) -> tuple[Path, bytes]:
        return _descriptor_file(raw, allowed_root=root, maximum=_MAXIMUM)

    result_path, payload = read(result_descriptor)
    result = _object(payload)
    if (
        result.get("status") != "complete"
        or result.get("scope") != "historical_phase7_remaining_report_steps"
        or result.get("report_promotion") is not False
        or result.get("original_status_inventory_checks_passed") is not True
        or not _zeros(result, ("target_calls", "judge_calls", "level1_reports_regenerated"))
        or (result_path.parent / "failure.json").exists()
    ):
        raise ValueError("historical continuation has unfinished or unbound steps")
    _binding_path, binding_payload = read(result.get("generated_from"))
    binding = _object(binding_payload)
    reused_methods = binding.get("reused_completed_methods", [])
    if reused_methods not in ([], list(_STEPS[:2])):
        raise ValueError("historical continuation reused method prefix differs")
    remaining = list(_STEPS[len(reused_methods):])
    if (binding.get("scope") != result["scope"]
        or binding.get("report_promotion") is not False
        or binding.get("remaining_methods") != remaining
        or result.get("completed_methods") != remaining
        or not _zeros(binding, ("target_calls", "judge_calls", "level1_reports_regenerated"))):
        raise ValueError("historical continuation input binding differs")
    for key in (
        "original_failure", "prior_payload", "prior_launch", "prior_input_manifest",
        "accounting_result", "continuation_driver", "human_view_receipt",
        "last_metric_failure", "last_metric_inputs", "exact_metric_view",
        "metric_view_source_template", "old_metric_view_retained",
    ):
        read(binding.get(key))
    _path, launch_payload = read(binding["prior_launch"])
    launch = _object(launch_payload)
    if (launch.get("input_manifest") != binding["prior_input_manifest"]
        or launch.get("payload") != binding["prior_payload"]):
        raise ValueError("continuation does not share the original authorization")

    reused = binding.get("reused_outputs")
    current = result.get("new_outputs")
    states = result.get("analysis_statuses")
    if (not isinstance(reused, list) or not isinstance(current, dict)
        or not isinstance(states, dict) or not _REQUIRED <= set(states)):
        raise ValueError("historical continuation report inventory is incomplete")
    descriptors: dict[Path, Mapping[str, Any]] = {}
    documents: dict[Path, dict[str, Any]] = {}
    for raw in [*reused, *(item for rows in current.values() for item in rows)]:
        path, data = read(raw)
        if path in descriptors and descriptors[path] != raw:
            raise ValueError("continuation report descriptor collision")
        descriptors[path] = raw
        if path.suffix == ".json":
            documents[path] = _object(data)
    statuses: dict[str, dict[str, Any]] = {}
    for path, document in documents.items():
        if document.get("schema") != "ura-phase7-analysis-status/1":
            continue
        name = document.get("analysis")
        if (name in statuses or name not in states
            or document.get("status") != states[name]
            or not _zeros(document, ("target_calls", "judge_calls", "provider_http_attempts"))
            or document.get("human_labels_consumed") is not False):
            raise ValueError("historical continuation status identity differs")
        for raw in document.get("outputs", []):
            output, _data = read(raw)
            if descriptors.get(output) != raw:
                raise ValueError("status references an unbound producer output")
        statuses[str(name)] = document
    if set(statuses) != set(states):
        raise ValueError("historical continuation status coverage differs")
    if reused_methods:
        # A failed successor can retain successful suite/Level2 producers. Reuse
        # only this exact prefix, bound to its unchanged failed handoff and inputs.
        # It is not reported as work performed by the final continuation.
        _path, previous_failure_bytes = read(binding.get("prior_remaining_failure"))
        previous_failure = _object(previous_failure_bytes)
        _path, previous_inputs_bytes = read(binding.get("prior_remaining_inputs"))
        previous_inputs = _object(previous_inputs_bytes)
        if (previous_failure.get("generated_from") != binding["prior_remaining_inputs"]
            or previous_failure.get("completed_methods") != reused_methods
            or previous_inputs.get("remaining_methods") != list(_STEPS)
            or any(previous_inputs.get(key) != binding[key] for key in (
                "prior_payload", "prior_launch", "prior_input_manifest", "exact_metric_view",
            ))):
            raise ValueError("reused analysis prefix has different retained authorization")
        reusable_outputs = binding.get("reused_method_outputs")
        if not isinstance(reusable_outputs, dict) or set(reusable_outputs) != set(reused_methods):
            raise ValueError("reused analysis method outputs are incomplete")
        for method, name in zip(_STEPS[:2], ("suite-summary", "level2-report"), strict=True):
            rows = reusable_outputs[method]
            if (not isinstance(rows, list) or not rows
                or any(raw not in reused for raw in rows)
                or name in current
                or name not in previous_failure.get("completed_statuses", [])
                or statuses[name].get("status") not in ("complete", "complete_with_limitations")):
                raise ValueError("reused analysis status was not retained as successful")
            status_paths = [path for path, document in documents.items() if document is statuses[name]]
            expected = [descriptors[status_paths[0]], *statuses[name]["outputs"]]
            if rows != expected:
                raise ValueError("reused analysis producer descriptors differ")

    def one(name: str) -> tuple[Mapping[str, Any], dict[str, Any]]:
        outputs = statuses[name]["outputs"]
        if not outputs:
            raise ValueError("required historical report is absent")
        path, _data = read(outputs[0])
        return outputs[0], documents[path]

    terminal, inventory = one("campaign-terminal-inventory")
    _validate_local_campaign_terminal_inventory(inventory)
    strata, metric_strata = _campaign_report_strata(inventory)
    metric_names = {"metric-stratum-" + key for key in metric_strata}
    if ({name for name in statuses if name.startswith("metric-stratum-")} != metric_names
        or binding.get("reused_metric_reports") != len(metric_names)):
        raise ValueError("historical metric stratum coverage differs")
    selected = [("terminal_inventory", "Historical terminal inventory (144 units)", terminal)]
    accounting, accounting_document = one("execution-accounting")
    _validate_report_document("execution_accounting", accounting_document)
    generated = accounting_document.get("generated_from", {})
    _terminal_path, terminal_bytes = read(terminal)
    _accounting_terminal, accounting_terminal_bytes = read(generated.get("campaign_terminal_inventory"))
    if (generated.get("human_audit_runner_input_view") != binding["human_view_receipt"]
        or accounting_terminal_bytes != terminal_bytes):
        raise ValueError("execution accounting references different retained inputs")
    read(generated.get("human_audit_sampling_index"))
    selected.append(("execution_accounting", "Historical calls, outputs and judges", accounting))
    seen_level1: set[str] = set()
    for raw in statuses["level1-evidence"]["outputs"]:
        path, _data = read(raw)
        if path.suffix != ".json":
            continue
        key = path.parent.name
        if key not in strata or key in seen_level1:
            raise ValueError("historical Level1 stratum identity differs")
        seen_level1.add(key)
        document = documents[path]
        _validate_report_document("level1", document)
        if not _report_scope_matches("level1", document, revision=strata[key][0], source=strata[key][1]):
            raise ValueError("historical Level1 source scope differs")
        selected.append(("level1", f"Lifecycle stratum {key}", raw))
    if not metric_strata <= seen_level1:
        raise ValueError("metric strata lack retained lifecycle reports")
    for key in sorted(metric_strata):
        raw, document = one("metric-stratum-" + key)
        _validate_report_document("level2", document)
        if not _report_scope_matches("level2", document, revision=strata[key][0], source=strata[key][1]):
            raise ValueError("historical metric source scope differs")
        selected.append(("level2", f"Metric stratum {key}", raw))
    return selected


def publish_historical_continuation(
    results_root: Path, *, result_descriptor: Mapping[str, Any],
    publication_root: Path, job_id: str,
) -> Path:
    """Publish exact copies only after every retained analysis step passes."""
    results = results_root.resolve(strict=True)
    selected = retained_continuation_reports(results, result_descriptor)
    publication = publication_root.resolve()
    if publication == results or not publication.is_relative_to(results):
        raise ValueError("publication root escapes the results store")
    publication.mkdir(mode=0o700, parents=False, exist_ok=False)
    reports, copies = [], []
    for index, (kind, label, raw) in enumerate(selected):
        _source, payload = _descriptor_file(raw, allowed_root=results, maximum=_MAXIMUM)
        target = publication / f"{index:02d}-{kind}.json"
        with target.open("xb") as handle:
            handle.write(payload)
        target.chmod(0o400)
        # Recheck source and copy independently before registration.
        copied = _identity(target, payload)
        _descriptor_file(copied, allowed_root=publication, maximum=_MAXIMUM)
        _descriptor_file(raw, allowed_root=results, maximum=_MAXIMUM)
        copies.append({"source": dict(raw), "copy": copied})
        reports.append(ExternalAnalysisReportSpec(target, kind, label))
    _write_create_only(publication / "retained-producers.json", {
        "scope": "historical_144_unit_analysis_continuation",
        "whole_local_campaign_complete": False,
        "original_controller_failure_preserved": True,
        "continuation_result": dict(result_descriptor), "exact_report_copies": copies,
    })
    retained_continuation_reports(results, result_descriptor)
    for row in copies:
        _descriptor_file(row["copy"], allowed_root=publication, maximum=_MAXIMUM)
    return publish_external_analysis_registration(
        results, job_id=job_id, analysis_root=publication,
        work_label="Historical local campaign analysis (144 retained units)",
        completion_status="complete_with_explicit_limitations",
        explicit_limitations={
            "scope": "Historical 144-unit cohort only; the additional RR campaign remains separate.",
            "conditions": "Historical failures and corrected execution strata are retained separately, not pooled.",
            "authority": "Operational diagrams only; no whole-campaign completion or human validity is claimed.",
        }, reports=reports,
    )
