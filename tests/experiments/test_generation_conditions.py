from __future__ import annotations

import copy

import pytest

from experiments.generation_conditions import build_generation_conditions, validate_generation_conditions
from experiments.rig_web_app.dashboard import DashboardMixin


def _cell():
    return {
        "run_id": "run-one", "manifest": {"config": {
            "run": {"model_spec": "ollama:fixture", "corpus": "arm-one", "attacker": "replay"},
            "components": {"target": {"num_ctx": "fit", "num_predict": 8192}},
        }},
        "responses": {
            "normal": {"raw": {"backend": "ollama", "done_reason": "stop", "generation": {
                "num_ctx": 65536, "num_ctx_policy": "fit", "num_predict": 8192}},
                "tokens": {"prompt": 40, "completion": 8192}},
            "truncated": {"raw": {"backend": "ollama", "done_reason": "length", "generation": {
                "num_ctx": 65536, "num_ctx_policy": "fit", "num_predict": 8192}},
                "tokens": {"prompt": 50, "completion": 500}},
            "missing": {"raw": {"target_input_status": "incompatible",
                "target_input_category": "context_limit_exceeded",
                "target_input_error_type": "TargetInputError"}, "tokens": None},
        },
        "judgments": [{"attempt_id": identity, "raw": {"effective_modality": "image"}}
                      for identity in ("normal", "truncated", "missing")],
    }


def test_actual_context_allowance_usage_and_truncation_are_separate():
    report = build_generation_conditions([_cell()])
    rows = report["conditions"]
    assert len(rows) == 2
    observed = next(row for row in rows if row["context_tokens"] == 65536)
    assert observed["output_allowance"] == 8192
    assert observed["context_source"] == "response_runtime"
    assert observed["rows"] == 2
    # Equal-to-cap tokens are not proof of truncation; the explicit reason is.
    assert observed["normal_stop"] == observed["truncated"] == 1
    assert observed["missing_output"] == 0
    assert observed["input_tokens"] == {"reported_rows": 2, "sum": 90, "minimum": 40, "maximum": 50}
    assert observed["output_tokens"]["sum"] == 8692
    missing = next(row for row in rows if row["context_tokens"] is None)
    assert missing["context_source"] == "not_recorded"
    assert missing["output_source"] == "manifest_config"
    assert missing["unknown_stop"] == missing["missing_output"] == missing["input_context_error"] == 1
    assert missing["output_tokens"]["reported_rows"] == 0


def test_different_windows_and_hosted_conditions_are_never_pooled():
    cell = _cell()
    second = copy.deepcopy(cell)
    second["run_id"] = "run-two"
    second["manifest"]["config"]["run"]["model_spec"] = "openai:fixture"
    second["manifest"]["config"]["components"]["target"] = {"max_tokens": 4096}
    second["responses"] = {"partial": {"raw": {"provider": "openai", "status": "incomplete",
        "incomplete_reason": "max_output_tokens", "generation": {"max_output_tokens": 4096}},
        "tokens": {"input": 50, "output": 4000}}}
    second["judgments"] = [{"attempt_id": "partial", "raw": {"effective_modality": "text"}}]
    result = build_generation_conditions([cell, second])
    hosted = next(row for row in result["conditions"] if row["run_id"] == "run-two")
    assert hosted["context_tokens"] is None
    assert hosted["output_allowance"] == 4096
    assert hosted["truncated"] == 1
    assert hosted["output_tokens"]["sum"] == 4000
    assert result["cross_condition_pooling_permitted"] is False


def test_vllm_native_output_and_effective_context_are_not_missing():
    cell = _cell()
    cell["responses"] = {"normal": {"raw": {"backend": "vllm", "finish_reason": "stop",
        "max_model_len": 152384, "max_model_len_policy": "hardware_fit",
        "generation": {"max_tokens": None}}, "tokens": {"input": 50, "prompt": 50}}}
    row = build_generation_conditions([cell])["conditions"][0]
    assert row["output_allowance"] == -1
    assert row["context_tokens"] == 152384
    assert row["input_tokens"]["sum"] == 50
    cell["responses"]["normal"]["tokens"]["input"] = 51
    with pytest.raises(ValueError, match="aliases disagree"):
        build_generation_conditions([cell])


def test_missing_answer_is_not_an_input_context_error():
    cell = _cell()
    cell["responses"] = {"missing": {"raw": {
        "model_stability_status": "failed_output",
        "model_stability_category": "empty_final_output",
    }, "tokens": None}}
    row = build_generation_conditions([cell])["conditions"][0]
    assert row["missing_output"] == 1
    assert row["input_context_error"] == 0
    assert row["truncated"] == 0


@pytest.mark.parametrize("field,value", [
    ("truncated", 9), ("missing_output", 9), ("context_tokens", -1),
    ("context_source", "not_recorded"), ("run_id", "unbound"),
])
def test_condition_report_rejects_inconsistent_counts_or_identity(field, value):
    report = build_generation_conditions([_cell()])
    row = next(row for row in report["conditions"] if row["context_tokens"] is not None)
    row[field] = value
    with pytest.raises(ValueError):
        validate_generation_conditions(report, {"run-one"})


def test_stats_renders_condition_counts_and_usage_without_inventing_old_metadata():
    renderer = DashboardMixin()
    report = {"generation_conditions": build_generation_conditions([_cell()])}
    rendered = renderer._render_generation_conditions(report)
    for label in ("Token windows and completion", "65536", "8192", "8,692 total",
                  "Missing output", "Input context errors", "Truncated", "generation-completion",
                  "reported 2/2", "not recorded (0/1 rows)"):
        assert label in rendered
    assert "not recorded in this older report" in renderer._render_generation_conditions({})
