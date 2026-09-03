from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.local_campaign.local_truncation_recovery_phase6 import (
    _source_modality,
    _without_runtime_bindings,
    build_truncation_selection,
    hardware_fit_local_config,
    length_ended_datapoint_ids,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    configure_units,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    extend_completed_selector,
)
from experiments.local_campaign.vllm_stability_phase6 import _sha256_json
from ura.data_models import DataPoint, Response, RiskCategory


def _response(attempt_id: str, *, backend: str, reason: str) -> Response:
    raw = {"backend": backend}
    raw["finish_reason" if backend == "vllm" else "done_reason"] = reason
    return Response(
        attempt_id=attempt_id,
        target=f"{backend}:fixture",
        output_turns=[],
        raw=raw,
    )


def test_hardware_fit_config_changes_only_provider_context_and_output_policy() -> None:
    vllm = {
        "vllm:Qwen/Qwen3-VL-8B-Instruct": {
            "revision": "a" * 40,
            "modalities": ["text", "image"],
            "max_model_len": 12288,
            "max_tokens": 4096,
        }
    }
    assert hardware_fit_local_config(
        vllm, expected_spec="vllm:Qwen/Qwen3-VL-8B-Instruct"
    ) == {
        "vllm:Qwen/Qwen3-VL-8B-Instruct": {
            "revision": "a" * 40,
            "modalities": ["text", "image"],
            "max_model_len": -1,
        }
    }
    ollama = {
        "ollama:gemma4:12b-it-q4_K_M": {
            "digest": "b" * 64,
            "modalities": ["text", "image"],
            "num_ctx": 8192,
            "num_predict": 512,
            "think": False,
        }
    }
    assert hardware_fit_local_config(
        ollama, expected_spec="ollama:gemma4:12b-it-q4_K_M"
    )["ollama:gemma4:12b-it-q4_K_M"] == {
        "digest": "b" * 64,
        "modalities": ["text", "image"],
        "num_ctx": "fit",
        "num_predict": -1,
        "think": False,
    }


def test_truncation_selection_reruns_only_unfinished_failed_and_length_rows() -> None:
    attempts = {f"attempt-{name}": name for name in "abcd"}
    responses = [
        _response("attempt-a", backend="vllm", reason="stop"),
        _response("attempt-b", backend="vllm", reason="length"),
        _response("attempt-c", backend="vllm", reason="stop"),
        _response("attempt-d", backend="vllm", reason="stop"),
    ]
    length_ids = length_ended_datapoint_ids(
        attempts=attempts, responses=responses
    )
    selector, summary = build_truncation_selection(
        selected_ids={"alpha": list("abcde")},
        eligible_ids={"alpha": list("abcde")},
        outcomes={
            "a": "usable_first_response",
            "b": "usable_first_response",
            "c": "failed_output",
            "d": "recovered_after_retry",
        },
        length_ended_ids=length_ids,
    )

    assert length_ids == {"b"}
    assert selector["corpora"]["alpha"]["completed_datapoint_ids"] == ["a", "d"]
    assert summary["recovery_records"] == 3
    assert summary["length_ended_records"] == 1
    assert summary["failed_output_records"] == 1
    assert summary["never_attempted_records"] == 1


def test_length_inventory_accepts_runner_synthesized_failed_output() -> None:
    response = Response(
        attempt_id="attempt-failed",
        target="ollama:fixture",
        output_turns=[],
        raw={"output_status": "failed_output"},
    )

    assert not length_ended_datapoint_ids(
        attempts={"attempt-failed": "row-failed"}, responses=[response]
    )


def test_runtime_binding_strip_preserves_selection_and_retry_policy() -> None:
    argv = [
        "--local",
        "ollama:gemma4:12b-it-q4_K_M",
        "--corpora",
        "alpha",
        "--target-answer-retries",
        "1",
        "--execution-scope-id",
        "scope",
        "--live-attestation",
        "/tmp/a",
        "--out",
        "/tmp/result",
        "--preflight-only",
    ]
    assert _without_runtime_bindings(argv) == [
        "--local",
        "ollama:gemma4:12b-it-q4_K_M",
        "--corpora",
        "alpha",
        "--target-answer-retries",
        "1",
    ]


def test_source_modality_comes_from_selected_rows() -> None:
    text = DataPoint(
        id="text",
        source="fixture",
        modalities=["text"],
        payload_text="hello",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    image = DataPoint(
        id="image",
        source="fixture",
        modalities=["text", "image"],
        payload_text="describe",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )
    assert _source_modality({"text": [text]}) == "text"
    assert _source_modality({"image": [image]}) == "image"


def test_execution_configures_exact_hardware_fit_unit(tmp_path) -> None:
    spec = "ollama:deepseek-r1:32b-qwen-distill-q4_K_M"
    inventory = {
        "units": [
            {
                "source_unit_id": "deepseek-text-extension",
                "source_result_root": "/evidence/deepseek",
                "source_lane": "ollama-deepseek-text-primary-100-extension",
                "source_corpus": None,
                "modality": "text",
                "local_spec": spec,
                "base_argv": [
                    "--local",
                    spec,
                    "--local-config",
                    "/old/config.json",
                    "--local-config-sha256",
                    "a" * 64,
                    "--corpora",
                    "alpha,beta",
                    "--target-answer-retries",
                    "1",
                ],
                "recovery_selection": {
                    "schema": "ura-recovery-completed-selection/1",
                    "corpora": {"alpha": {"completed_datapoint_ids": ["done"]}},
                },
                "hardware_fit_local_config": {
                    spec: {
                        "digest": "b" * 64,
                        "modalities": ["text"],
                        "num_ctx": "fit",
                        "num_predict": -1,
                        "think": False,
                    }
                },
                "summary": {"recovery_records": 7},
            }
        ]
    }
    control = tmp_path / "control"
    (control / "inputs").mkdir(parents=True)
    (control / "configs").mkdir()

    configured = configure_units(inventory, control_root=control)

    assert len(configured) == 1
    unit, selector_path, selector_sha = configured[0]
    assert unit.selected_records == 7
    assert unit.source_lane == "ollama-deepseek-text-primary-100-extension"
    assert unit.spec["modality"] == "text"
    assert unit.recovery == inventory["units"][0]["recovery_selection"]
    assert selector_path.is_file()
    assert len(selector_sha) == 64
    argv = unit.spec["base_argv"]
    config_path = argv[argv.index("--local-config") + 1]
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    assert config[spec]["num_ctx"] == "fit"
    assert config[spec]["num_predict"] == -1
    assert argv[argv.index("--target-answer-retries") + 1] == "1"


def test_interrupted_selector_excludes_every_durable_row_without_repeating() -> None:
    selected = {"alpha": ["a", "b", "c"], "beta": ["d", "e", "f"]}
    selector = {
        "schema": "ura-recovery-completed-selection/1",
        "corpora": {
            corpus: {
                "completed_record_count": 1,
                "selected_datapoint_ids_sha256": _sha256_json(rows),
                "completed_datapoint_ids": [rows[0]],
                "completed_datapoint_ids_sha256": _sha256_json([rows[0]]),
                "remaining_datapoint_ids_sha256": _sha256_json(rows[1:]),
            }
            for corpus, rows in selected.items()
        },
    }

    continued, remaining = extend_completed_selector(
        selector=selector,
        selected_ids=selected,
        newly_completed_ids=["b", "e"],
    )

    assert remaining == 2
    assert continued["corpora"]["alpha"]["completed_datapoint_ids"] == [
        "a",
        "b",
    ]
    assert continued["corpora"]["beta"]["completed_datapoint_ids"] == [
        "d",
        "e",
    ]
    assert continued["corpora"]["alpha"]["remaining_datapoint_ids_sha256"] == (_sha256_json(["c"]))


def test_interrupted_selector_rejects_unknown_or_duplicate_durable_identity() -> None:
    selected = {"alpha": ["a", "b", "c"]}
    selector = {
        "schema": "ura-recovery-completed-selection/1",
        "corpora": {
            "alpha": {
                "completed_record_count": 1,
                "selected_datapoint_ids_sha256": _sha256_json(selected["alpha"]),
                "completed_datapoint_ids": ["a"],
                "completed_datapoint_ids_sha256": _sha256_json(["a"]),
                "remaining_datapoint_ids_sha256": _sha256_json(["b", "c"]),
            }
        },
    }

    with pytest.raises(ValueError, match="absent from the selection"):
        extend_completed_selector(
            selector=selector,
            selected_ids=selected,
            newly_completed_ids=["unknown"],
        )
    with pytest.raises(ValueError, match="selector identity changed"):
        extend_completed_selector(
            selector=selector,
            selected_ids=selected,
            newly_completed_ids=["b", "b"],
        )
