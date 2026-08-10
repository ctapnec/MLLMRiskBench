"""Fail-closed schema validators (data_models.py).

Each test pins one boundary the persisted schema must reject, plus the one state
it must keep accepting: an empty Response.output_turns for a typed provider
refusal (validated centrally by the Runner via raw.provider_refusal).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from ura.data_models import (
    Attempt,
    DataPoint,
    DialogTurn,
    EvalResult,
    Response,
    RiskCategory,
    RunManifest,
)

_HASH = "a" * 64


def _dp(**over):
    base = dict(
        id="d1", source="synth", modalities=["text"],
        risk_category=RiskCategory.JAILBREAK, expected_behavior="refuse",
    )
    base.update(over)
    return DataPoint(**base)


def test_blank_identifiers_rejected():
    with pytest.raises(ValidationError):
        _dp(id=" ")
    with pytest.raises(ValidationError):
        _dp(source="")
    with pytest.raises(ValidationError):
        Attempt(id="a1", datapoint_id="", attacker="replay", rendered_input=[])
    with pytest.raises(ValidationError):
        Response(attempt_id="a1", target="  ", output_turns=[])
    with pytest.raises(ValidationError):
        RunManifest(run_id="", code_version="ura-runner/2.0")


def test_duplicate_modalities_rejected():
    with pytest.raises(ValidationError):
        _dp(modalities=["text", "text"])


def test_nonpositive_turns_and_negative_turn_index_rejected():
    with pytest.raises(ValidationError):
        _dp(turns=0)
    with pytest.raises(ValidationError):
        Attempt(id="a1", datapoint_id="d1", attacker="replay", turn_index=-1, rendered_input=[])


def test_nonfinite_and_negative_n_rejected():
    with pytest.raises(ValidationError):
        EvalResult(id="r1", metric="ASR", value=float("nan"))
    with pytest.raises(ValidationError):
        EvalResult(id="r1", metric="ASR", value=float("inf"))
    with pytest.raises(ValidationError):
        EvalResult(id="r1", metric="ASR", value=0.1, n=-1)


def test_incoherent_ci_rejected():
    with pytest.raises(ValidationError):
        EvalResult(id="r1", metric="ASR", value=0.4, ci_low=0.6, ci_high=0.5)
    with pytest.raises(ValidationError):  # point outside CI
        EvalResult(id="r1", metric="ASR", value=0.9, ci_low=0.1, ci_high=0.5)
    # coherent CI is accepted
    EvalResult(id="r1", metric="ASR", value=0.4, ci_low=0.3, ci_high=0.5, n=100)


def test_manifest_duplicate_lists_and_bad_hashes_rejected():
    ok = dict(run_id="run-1", code_version="ura-runner/2.0", dataset_hashes={"corpus": _HASH})
    RunManifest(**ok)  # baseline accepted
    with pytest.raises(ValidationError):
        RunManifest(**{**ok, "models": ["m", "m"]})
    with pytest.raises(ValidationError):
        RunManifest(**{**ok, "seeds": [0, 0]})
    with pytest.raises(ValidationError):
        RunManifest(run_id="run-1", code_version="ura-runner/2.0",
                    dataset_hashes={"corpus": "not-a-hash"})


def test_empty_response_output_turns_still_valid():
    # A typed provider refusal carries no assistant turn; the schema must allow it.
    r = Response(attempt_id="a1", target="anthropic-fable:claude-fable-5",
                 output_turns=[], raw={"provider_refusal": True})
    assert r.output_turns == []
    # a normal non-empty response also validates
    Response(attempt_id="a1", target="t", output_turns=[DialogTurn(role="assistant", content="ok")])
