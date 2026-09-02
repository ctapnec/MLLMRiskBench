from __future__ import annotations

from ura.data_models import Response

from experiments.local_campaign.local_truncation_recovery_phase6 import (
    _without_runtime_bindings,
    build_truncation_selection,
    length_ended_datapoint_ids,
    native_max_local_config,
)


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
