from __future__ import annotations

import re
from pathlib import Path

import pytest

from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_IMAGE_MODELS,
    CURRENT_OLLAMA_MODELS,
    CURRENT_OLLAMA_NATIVE_ROLES,
    CURRENT_OLLAMA_RUNNABLE_LANES,
    CURRENT_OLLAMA_TEXT_ONLY_MODELS,
    CURRENT_OLLAMA_TYPED_TERMINAL_LANES,
    image_lane,
)


def test_current_ollama_roster_is_exact_recent_thesis_cohort() -> None:
    assert [model.tag for model in CURRENT_OLLAMA_MODELS] == [
        "gemma4:12b-it-q4_K_M",
        "ministral-3:14b-instruct-2512-q4_K_M",
        "deepseek-r1:32b-qwen-distill-q4_K_M",
        "gpt-oss:20b",
    ]
    assert len({model.label for model in CURRENT_OLLAMA_MODELS}) == 4
    assert len({model.tag for model in CURRENT_OLLAMA_MODELS}) == 4
    assert [model.digest for model in CURRENT_OLLAMA_MODELS] == [
        "4eb23ef187e2c5462566d6a1d3bbbc2f1346d0b4327cbb66d58fffbcc9b2b05c",
        "4760c35aeb9d9e9c6174c2492562c0b999e80a222804fd96b1915ab72bbcdcf7",
        "edba8017331d15236e57480eb45406c0d721db77a4cdcf234df500fc2ad3960c",
        "17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7",
    ]
    assert [model.quantization for model in CURRENT_OLLAMA_MODELS] == [
        "Q4_K_M",
        "Q4_K_M",
        "Q4_K_M",
        "MXFP4",
    ]
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", model.digest)
        for model in CURRENT_OLLAMA_MODELS
    )
    assert all(
        "rwkv" not in model.tag.lower() and "mollysama" not in model.tag.lower()
        for model in CURRENT_OLLAMA_MODELS
    )


def test_current_ollama_modalities_roles_and_lanes_are_not_conflated() -> None:
    assert [model.label for model in CURRENT_OLLAMA_IMAGE_MODELS] == [
        "gemma4-12b",
        "ministral3-14b",
    ]
    assert [model.label for model in CURRENT_OLLAMA_TEXT_ONLY_MODELS] == [
        "deepseek-r1-distill-32b",
        "gpt-oss-20b",
    ]
    native_roles = {
        role: model.label for role, model in CURRENT_OLLAMA_NATIVE_ROLES.items()
    }
    assert native_roles == {
        "primary": "gemma4-12b",
        "secondary": "ministral3-14b",
        "auditor": "deepseek-r1-distill-32b",
        "judge": "gpt-oss-20b",
    }
    assert len(CURRENT_OLLAMA_RUNNABLE_LANES) == 12
    assert set(CURRENT_OLLAMA_TYPED_TERMINAL_LANES) == {
        "gptgeochat-ollama-deepseek-r1-distill-32b",
        "gptgeochat-ollama-gpt-oss-20b",
    }
    assert not set(CURRENT_OLLAMA_RUNNABLE_LANES) & set(
        CURRENT_OLLAMA_TYPED_TERMINAL_LANES
    )


def test_image_lane_rejects_text_only_model() -> None:
    with pytest.raises(ValueError, match="not image-capable"):
        image_lane(CURRENT_OLLAMA_TEXT_ONLY_MODELS[0])


def test_prospective_controllers_use_only_the_current_ollama_roster() -> None:
    templates = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    for name in (
        "phase5_ollama_workflow.sh.in",
        "phase6_native_diagnostics.sh.in",
        "phase7_analysis.py.in",
        "phase8_human_audit.py.in",
    ):
        source = (templates / name).read_text(encoding="utf-8")
        assert "mollysama/" not in source
        assert "CURRENT_OLLAMA_NATIVE_ROLES" in source or name.startswith("phase5_")
    native = (templates / "phase6_native_diagnostics.sh.in").read_text(
        encoding="utf-8"
    )
    assert "the exact local Ollama roster has no tool-call capability" not in native
    assert 'set(expected_models) != set(EXPECTED_MODELS)' in native
    assert 'get("quantization_level")' in native
