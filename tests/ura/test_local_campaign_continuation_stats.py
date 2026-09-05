from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.local_campaign import continuation_stats as module
from experiments.local_campaign.execution_accounting import build_execution_accounting
from experiments.local_campaign.stats_adapter import _campaign_report_strata
from experiments.rig_web_app.external_analysis import load_external_analysis_registration
from test_local_campaign_stats_adapter import (
    _descriptor, _level1, _level2, _terminal_inventory, _write,
)


def _continuation(root: Path) -> tuple[Path, dict[str, object]]:
    prior = root / "prior"
    current = root / "continued"
    retained, fresh, states = [], {}, {}

    def status(name: str, outputs: list[Path], *, reused: bool = False) -> None:
        directory = prior if reused else current
        path = _write(directory / "status" / f"{name}.json", {
            "schema": "ura-phase7-analysis-status/1", "analysis": name,
            "status": "complete", "outputs": [_descriptor(p) for p in outputs],
            "target_calls": 0, "judge_calls": 0, "provider_http_attempts": 0,
            "human_labels_consumed": False,
        })
        rows = [_descriptor(p) for p in [path, *outputs]]
        if reused:
            retained.extend(rows)
        else:
            fresh[name] = rows
        states[name] = "complete"

    inventory = _terminal_inventory()
    terminal = _write(prior / "terminal.json", inventory)
    status("campaign-terminal-inventory", [terminal], reused=True)
    human = _write(prior / "human-view.json", {"scope": "retained-successful-view"})
    human_index = _write(prior / "human-index.json", {"index": "retained"})
    accounting_terminal = _write(root / "accounting" / "terminal-copy.json", inventory)
    accounting = build_execution_accounting([{
        "model": "vllm:fixture", "manifest": {"config": {
            "run": {"corpus": "fixture", "attacker": "replay",
                    "project_revision": {"sha256": "a" * 64}},
            "components": {"target": {"name": "vllm:fixture", "max_tokens": 4096}},
        }}, "attempts": {"a": {"datapoint_id": "x", "seed": 0, "turn_index": 0}},
        "responses": {"a": {"raw": {}}}, "judgments": [{
            "attempt_id": "a", "judge": "rules", "label": "safe", "raw": {
                "source": "fixture", "effective_modality": "text",
                "risk_category": "safety", "expected_behavior": "refuse",
            },
        }],
    }], generated_from={
        "human_audit_runner_input_view": _descriptor(human),
        "human_audit_sampling_index": _descriptor(human_index),
        "campaign_terminal_inventory": _descriptor(accounting_terminal),
    })
    accounting_path = _write(prior / "accounting.json", accounting)
    status("execution-accounting", [accounting_path], reused=True)
    strata, measured = _campaign_report_strata(inventory)
    lifecycle = []
    for key, (revision, source) in strata.items():
        path = prior / "lifecycle" / key / "level1-evidence.json"
        _level1(path, revision=revision, source=source)
        lifecycle.append(path)
    status("level1-evidence", lifecycle, reused=True)
    for key in sorted(measured):
        path = prior / "metric" / key / "level2-report.json"
        _level2(path, revision=strata[key][0])
        status("metric-stratum-" + key, [path], reused=True)
    for name in sorted(module._REQUIRED - set(states)):
        status(name, [_write(current / f"{name}.json", {"status": "complete"})])
    original_input = _write(prior / "inputs.json", {"scope": "historical"})
    original_payload = _write(prior / "payload.py", {"payload": "retained"})
    launch = _write(prior / "launch.json", {
        "input_manifest": _descriptor(original_input), "payload": _descriptor(original_payload),
    })
    binding = {
        "scope": "historical_phase7_remaining_report_steps", "report_promotion": False,
        "remaining_methods": list(module._STEPS), "reused_metric_reports": len(measured),
        "target_calls": 0, "judge_calls": 0, "level1_reports_regenerated": 0,
        "reused_outputs": retained, "prior_input_manifest": _descriptor(original_input),
        "prior_payload": _descriptor(original_payload), "prior_launch": _descriptor(launch),
        "human_view_receipt": _descriptor(human),
    }
    for key in ("original_failure", "accounting_result", "continuation_driver",
                "last_metric_failure", "last_metric_inputs", "exact_metric_view",
                "metric_view_source_template", "old_metric_view_retained"):
        binding[key] = _descriptor(_write(prior / f"{key}.json", {"retained": key}))
    binding_path = _write(current / "inputs.json", binding)
    result = _write(current / "result.json", {
        "scope": binding["scope"], "status": "complete", "report_promotion": False,
        "original_status_inventory_checks_passed": True,
        "completed_methods": list(module._STEPS), "generated_from": _descriptor(binding_path),
        "target_calls": 0, "judge_calls": 0, "level1_reports_regenerated": 0,
        "analysis_statuses": states, "new_outputs": fresh,
    })
    return result, binding


def test_historical_continuation_copies_exact_reports_and_keeps_scope(tmp_path: Path) -> None:
    result, _binding = _continuation(tmp_path)
    selected = module.retained_continuation_reports(tmp_path, _descriptor(result))
    publication = tmp_path / "published"
    registration = module.publish_historical_continuation(
        tmp_path, result_descriptor=_descriptor(result), publication_root=publication,
        job_id="historical-fixture",
    )
    loaded = load_external_analysis_registration(tmp_path, "historical-fixture")
    assert loaded is not None and len(loaded.reports) == len(selected)
    provenance = json.loads((publication / "retained-producers.json").read_text())
    assert provenance["whole_local_campaign_complete"] is False
    assert provenance["original_controller_failure_preserved"] is True
    for row in provenance["exact_report_copies"]:
        assert Path(row["source"]["path"]).read_bytes() == Path(row["copy"]["path"]).read_bytes()
    assert json.loads(registration.read_text())["thesis_empirical_evidence"] is False


@pytest.mark.parametrize("mutation", ("unfinished", "paid", "wrong-input", "missing-stratum", "producer-bytes"))
def test_historical_continuation_rejects_changed_handoff(tmp_path: Path, mutation: str) -> None:
    result, binding = _continuation(tmp_path)
    value = json.loads(result.read_text())
    if mutation == "unfinished":
        value["completed_methods"].pop()
    elif mutation == "paid":
        value["judge_calls"] = 1
    elif mutation == "missing-stratum":
        name = next(name for name in value["analysis_statuses"] if name.startswith("metric-stratum-"))
        del value["analysis_statuses"][name]
    elif mutation == "wrong-input":
        binding["prior_input_manifest"] = binding["prior_payload"]
        path = _write(result.parent / "inputs.json", binding)
        value["generated_from"] = _descriptor(path)
    else:
        path = Path(binding["reused_outputs"][-1]["path"])
        path.write_bytes(path.read_bytes() + b" ")
    _write(result, value)
    with pytest.raises(ValueError):
        module.retained_continuation_reports(tmp_path, _descriptor(result))


def test_historical_publication_rechecks_exact_copy_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result, _binding = _continuation(tmp_path)
    original = module._write_create_only

    def mutate_copy(path: Path, value: object) -> Path:
        written = original(path, value)
        if path.name == "retained-producers.json":
            target = path.parent / "00-terminal_inventory.json"
            target.chmod(0o600)
            target.write_bytes(target.read_bytes() + b" ")
        return written

    monkeypatch.setattr(module, "_write_create_only", mutate_copy)
    with pytest.raises(ValueError, match="descriptor bytes differ"):
        module.publish_historical_continuation(
            tmp_path, result_descriptor=_descriptor(result),
            publication_root=tmp_path / "published", job_id="must-not-publish",
        )
    assert not (tmp_path / "external-analysis-jobs").exists()


@pytest.mark.parametrize("mutation", (None, "wrong-prefix", "wrong-input", "unbound-output", "rerun-status"))
def test_continuation_reuses_only_bound_successful_suite_and_level2(
    tmp_path: Path, mutation: str | None,
) -> None:
    result, binding = _continuation(tmp_path)
    value = json.loads(result.read_text())
    previous_input = _write(tmp_path / "previous-input.json", binding)
    prefix = list(module._STEPS[:2])
    previous_failure = _write(tmp_path / "previous-failure.json", {
        "generated_from": _descriptor(previous_input), "completed_methods": prefix,
        "completed_statuses": ["suite-summary", "level2-report"],
    })
    binding.update({
        "remaining_methods": list(module._STEPS[2:]),
        "reused_completed_methods": prefix,
        "prior_remaining_failure": _descriptor(previous_failure),
        "prior_remaining_inputs": _descriptor(previous_input),
        "reused_method_outputs": {},
    })
    for method, name in zip(prefix, ("suite-summary", "level2-report"), strict=True):
        rows = value["new_outputs"].pop(name)
        binding["reused_method_outputs"][method] = rows
        binding["reused_outputs"].extend(rows)
    value["completed_methods"] = list(module._STEPS[2:])
    if mutation == "wrong-prefix":
        binding["reused_completed_methods"].pop()
    elif mutation == "wrong-input":
        previous = json.loads(previous_input.read_text())
        previous["prior_input_manifest"] = previous["prior_payload"]
        _write(previous_input, previous)
        binding["prior_remaining_inputs"] = _descriptor(previous_input)
    elif mutation == "unbound-output":
        binding["reused_outputs"].pop()
    elif mutation == "rerun-status":
        value["new_outputs"]["suite-summary"] = binding["reused_method_outputs"][prefix[0]]
    path = _write(result.parent / "inputs.json", binding)
    value["generated_from"] = _descriptor(path)
    _write(result, value)
    if mutation is None:
        assert module.retained_continuation_reports(tmp_path, _descriptor(result))
    else:
        with pytest.raises(ValueError):
            module.retained_continuation_reports(tmp_path, _descriptor(result))
