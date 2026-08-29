from __future__ import annotations

from dataclasses import replace
import re
from pathlib import Path
from typing import Sequence

import pytest

from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_IMAGE_MODELS,
    CURRENT_OLLAMA_MODELS,
    CURRENT_OLLAMA_NATIVE_ROLES,
    CURRENT_OLLAMA_RUNNABLE_LANES,
    CURRENT_OLLAMA_TEXT_ONLY_MODELS,
    CURRENT_OLLAMA_TYPED_TERMINAL_LANES,
    CurrentOllamaModel,
    image_lane,
)


def _assert_exact_current_roster(models: Sequence[CurrentOllamaModel]) -> None:
    assert [model.tag for model in models] == [
        "gemma4:12b-it-q4_K_M",
        "ministral-3:14b-instruct-2512-q4_K_M",
        "deepseek-r1:32b-qwen-distill-q4_K_M",
        "gpt-oss:20b",
    ]
    assert len({model.label for model in models}) == 4
    assert len({model.tag for model in models}) == 4
    assert [model.digest for model in models] == [
        "4eb23ef187e2c5462566d6a1d3bbbc2f1346d0b4327cbb66d58fffbcc9b2b05c",
        "4760c35aeb9d9e9c6174c2492562c0b999e80a222804fd96b1915ab72bbcdcf7",
        "edba8017331d15236e57480eb45406c0d721db77a4cdcf234df500fc2ad3960c",
        "17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7",
    ]
    assert [model.quantization for model in models] == [
        "Q4_K_M",
        "Q4_K_M",
        "Q4_K_M",
        "MXFP4",
    ]
    assert all(re.fullmatch(r"[0-9a-f]{64}", model.digest) for model in models)
    assert all(
        "rwkv" not in model.tag.lower() and "mollysama" not in model.tag.lower() for model in models
    )


def test_current_ollama_roster_is_exact_recent_thesis_cohort() -> None:
    _assert_exact_current_roster(CURRENT_OLLAMA_MODELS)


@pytest.mark.parametrize(
    ("index", "changes"),
    (
        (0, {"tag": "mollysama/rwkv-7-g1f:2.9b"}),
        (2, {"quantization": "F16"}),
        (3, {"digest": "0" * 64}),
    ),
)
def test_current_ollama_roster_regression_detects_identity_mutations(
    index: int, changes: dict[str, str]
) -> None:
    mutant = list(CURRENT_OLLAMA_MODELS)
    mutant[index] = replace(mutant[index], **changes)
    with pytest.raises(AssertionError):
        _assert_exact_current_roster(mutant)


def test_current_ollama_modalities_roles_and_lanes_are_not_conflated() -> None:
    assert [model.label for model in CURRENT_OLLAMA_IMAGE_MODELS] == [
        "gemma4-12b",
        "ministral3-14b",
    ]
    assert [model.label for model in CURRENT_OLLAMA_TEXT_ONLY_MODELS] == [
        "deepseek-r1-distill-32b",
        "gpt-oss-20b",
    ]
    native_roles = {role: model.label for role, model in CURRENT_OLLAMA_NATIVE_ROLES.items()}
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
    assert not set(CURRENT_OLLAMA_RUNNABLE_LANES) & set(CURRENT_OLLAMA_TYPED_TERMINAL_LANES)


def test_image_lane_rejects_text_only_model() -> None:
    with pytest.raises(ValueError, match="not image-capable"):
        image_lane(CURRENT_OLLAMA_TEXT_ONLY_MODELS[0])


def test_prospective_controllers_use_only_the_current_ollama_roster() -> None:
    templates = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    for name in (
        "phase5_ollama_workflow.sh.in",
        "phase6_native_diagnostics.sh.in",
        "phase7_analysis.py.in",
        "phase8_human_audit.py.in",
    ):
        source = (templates / name).read_text(encoding="utf-8")
        assert "mollysama/" not in source
        assert "CURRENT_OLLAMA_NATIVE_ROLES" in source or name.startswith("phase5_")
    native = (templates / "phase6_native_diagnostics.sh.in").read_text(encoding="utf-8")
    assert "the exact local Ollama roster has no tool-call capability" not in native
    assert "set(expected_models) != set(EXPECTED_MODELS)" in native
    assert 'get("quantization_level")' in native

    rr_amendment = (templates / "phase6_seven_output_policy.py.in").read_text(
        encoding="utf-8"
    )
    prospective_specs = rr_amendment.split("SPEC_SOURCES = (", 1)[1].split(
        "\n)\nLANE_ORDER", 1
    )[0]
    assert "rwkv" not in prospective_specs.lower()
    assert "mollysama" not in prospective_specs.lower()


def test_current_rr_amendment_excludes_retired_rwkv_rows_from_analysis() -> None:
    templates = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    expected = [
        "local-llava-rr-text-primary-100",
        "local-llava-rr-image-primary-100",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    ]
    for name in ("phase7_analysis.py.in", "phase8_human_audit.py.in"):
        source = (templates / name).read_text(encoding="utf-8")
        amendment = source.split("SEVEN_AMENDMENT_LANES = (", 1)[1].split(
            "\n)\nSEVEN_TERMINAL_STATES", 1
        )[0]
        assert re.findall(r'"([a-z0-9-]+)"', amendment) == expected
        assert "rwkv" not in amendment.lower()
    phase7 = (templates / "phase7_analysis.py.in").read_text(encoding="utf-8")
    assert '"output_policy_amendment": 4' in phase7
