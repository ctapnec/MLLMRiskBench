from __future__ import annotations

import json
import hashlib

import pytest

from experiments.local_campaign import vllm_context_recovery_phase6 as recovery


def _population() -> tuple[list[str], dict[str, str]]:
    selected = [f"gptgeochat:{index:04d}" for index in range(2020)]
    outcomes = {
        identifier: ("input_incompatible" if index >= 1790 else "usable_first_response")
        for index, identifier in enumerate(selected[375:], 375)
    }
    return selected, outcomes


def test_context_selector_leaves_only_the_exact_230_typed_rows() -> None:
    selected, outcomes = _population()

    selector, summary = recovery.build_context_selection(
        selected_ids={recovery.CORPUS: selected},
        eligible_ids={recovery.CORPUS: selected[375:]},
        outcomes=outcomes,
    )

    corpus = selector["corpora"][recovery.CORPUS]
    assert summary == {
        "selected_records": 2020,
        "prior_eligible_records": 1645,
        "completed_records_excluded": 1790,
        "context_recovery_records": 230,
    }
    assert corpus["completed_record_count"] == 1790
    assert len(corpus["completed_datapoint_ids"]) == 1790
    assert corpus["remaining_datapoint_ids_sha256"] == recovery._sha256_json(selected[1790:])


def test_context_selector_rejects_one_mutated_outcome() -> None:
    selected, outcomes = _population()
    outcomes[selected[-1]] = "usable_first_response"

    with pytest.raises(ValueError, match="exact typed population"):
        recovery.build_context_selection(
            selected_ids={recovery.CORPUS: selected},
            eligible_ids={recovery.CORPUS: selected[375:]},
            outcomes=outcomes,
        )


def test_larger_context_changes_only_engine_context() -> None:
    original = {
        "vllm:Qwen/Qwen3-VL-8B-Instruct": {
            "revision": "a" * 40,
            "modalities": ["text", "image"],
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.9,
            "max_model_len": 12288,
            "max_tokens": 4096,
        }
    }

    updated = recovery.with_larger_context(original)

    assert original["vllm:Qwen/Qwen3-VL-8B-Instruct"]["max_model_len"] == 12288
    assert updated["vllm:Qwen/Qwen3-VL-8B-Instruct"] == {
        **original["vllm:Qwen/Qwen3-VL-8B-Instruct"],
        "max_model_len": 24576,
    }
    mutated = json.loads(json.dumps(original))
    mutated["vllm:Qwen/Qwen3-VL-8B-Instruct"]["max_tokens"] = 2048
    with pytest.raises(ValueError, match="completion allowance"):
        recovery.with_larger_context(mutated)


def test_context_recovery_cli_requires_the_retained_input_completion() -> None:
    parsed = recovery.build_parser().parse_args(
        [
            "--expected-commit",
            "a" * 40,
            "--project-root",
            "/project",
            "--python",
            "/project/.venv/bin/python",
            "--work-root",
            "/work",
            "--control-root",
            "/work/runs/engineering/context-recovery",
            "--project-revision",
            "/work/project-revision.json",
            "--project-revision-sha256",
            hashlib.sha256(b"revision").hexdigest(),
            "--input-recovery-completion",
            "/work/input-recovery/completion.json",
            "--input-recovery-completion-sha256",
            hashlib.sha256(b"input-recovery").hexdigest(),
            "--execution-scope-id",
            "scope",
            "--tmux-socket",
            "default",
            "--tmux-session",
            "context-recovery",
        ]
    )

    assert parsed.input_recovery_completion.name == "completion.json"
    assert recovery.STATE_SCHEMA == "ura-vllm-context-recovery-phase6-unit-state/1"
