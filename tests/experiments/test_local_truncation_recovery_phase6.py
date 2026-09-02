from __future__ import annotations

import json
from pathlib import Path

from experiments.local_campaign.local_truncation_recovery_phase6 import (
    _source_modality,
    _without_runtime_bindings,
    build_truncation_selection,
    length_ended_datapoint_ids,
    native_max_local_config,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    configure_units,
)
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


def test_native_max_config_changes_only_provider_context_and_output_policy() -> None:
    vllm = {
        "vllm:Qwen/Qwen3-VL-8B-Instruct": {
            "revision": "a" * 40,
            "modalities": ["text", "image"],
            "max_model_len": 12288,
            "max_tokens": 4096,
        }
    }
    assert native_max_local_config(
        vllm, expected_spec="vllm:Qwen/Qwen3-VL-8B-Instruct"
    ) == {
        "vllm:Qwen/Qwen3-VL-8B-Instruct": {
            "revision": "a" * 40,
            "modalities": ["text", "image"],
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
    assert native_max_local_config(
        ollama, expected_spec="ollama:gemma4:12b-it-q4_K_M"
    )["ollama:gemma4:12b-it-q4_K_M"] == {
        "digest": "b" * 64,
        "modalities": ["text", "image"],
        "num_ctx": "max",
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


def test_execution_configures_exact_native_maximum_unit(tmp_path) -> None:
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
                "native_max_local_config": {
                    spec: {
                        "digest": "b" * 64,
                        "modalities": ["text"],
                        "num_ctx": "max",
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
    assert config[spec]["num_ctx"] == "max"
    assert config[spec]["num_predict"] == -1
    assert argv[argv.index("--target-answer-retries") + 1] == "1"
