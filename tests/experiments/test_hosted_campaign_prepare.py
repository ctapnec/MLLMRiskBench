from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments import hosted_campaign_prepare as subject
from test_hosted_retained_execute import _program
from test_retained_input_replay import _fixture
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker


def _save(path: Path, value: object) -> dict:
    path.write_text(json.dumps(value), encoding="utf-8")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }


def _request(tmp_path: Path, monkeypatch, **program_options) -> tuple[dict, Path]:
    program, _budget = _program(tmp_path, monkeypatch, **program_options)
    config_path = Path(
        program["jobs"][0]["argv"][
            program["jobs"][0]["argv"].index("--attacker-config") + 1
        ]
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    replay_path = Path(config["replay"]["replay_artifact"])
    replay = {
        "path": str(replay_path),
        "sha256": hashlib.sha256(replay_path.read_bytes()).hexdigest(),
        "bytes": replay_path.stat().st_size,
    }
    historical = _save(tmp_path / "historical-result.json", {"fixture": True})
    execution_root = tmp_path / "execution"
    execution_root.mkdir()
    request = {
        "schema": subject.REQUEST_SCHEMA,
        "results_root": str(tmp_path),
        "runner_view": str(tmp_path),
        "rr_analysis_root": str(tmp_path),
        "pricing_as_of": program["pricing_as_of"],
        "sources": {**program["sources"], "historical_result": historical},
        "routes": [{"target": program["target"], "replay_artifacts": [replay]}],
        "runner_common_argv": [],
        "execution_root": str(execution_root),
    }
    return request, execution_root


def test_preparation_creates_funded_disjoint_pilot_and_measured_program_without_generation(
    tmp_path, monkeypatch
):
    request, _execution_root = _request(tmp_path, monkeypatch)
    calls = []
    actual_count = subject.count_request

    def count(target, body, *, allow_network=False):
        calls.append((target.name, allow_network))
        return actual_count(target, body, allow_network=allow_network)

    monkeypatch.setattr(subject, "count_request", count)
    receipt = subject.prepare_campaign(
        request=request,
        request_descriptor={"path": str(tmp_path / "request.json"), "sha256": "a" * 64, "bytes": 1},
        out_root=tmp_path / "prepared",
        allow_network_counts=False,
    )
    assert receipt["status"] == "prepared_no_generation_calls"
    assert receipt["target_calls"] == receipt["judge_calls"] == 0
    assert receipt["generation_http_attempts"] == 0
    assert len(calls) == receipt["programs"][0]["selected_target_calls"] == 2
    assert calls == [(request["routes"][0]["target"], False)] * 2
    saved = json.loads(Path(receipt["programs"][0]["path"]).read_text(encoding="utf-8"))
    assert [job["purpose"] for job in saved["jobs"]] == ["diagnostic_canary", "measured_run"]
    ids = [identity for job in saved["jobs"] for identity in job["input_ids"]]
    assert len(ids) == len(set(ids)) == len(saved["requests"]) == 2
    budget = json.loads((tmp_path / "prepared" / "budget" / "plan.json").read_text())
    assert len(budget["planned_calls"]) == 6


@pytest.mark.parametrize("target_spec", [
    "anthropic-fable:claude-fable-5-1;effort=high;max_tokens=8192",
    "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns;max_output_tokens=8192",
])
def test_preparation_accepts_inherent_target_without_generic_config(
    tmp_path, monkeypatch, target_spec
):
    from experiments import run_matrix
    from ura.targets.api import AnthropicTarget, OpenAITarget

    request, _execution_root = _request(tmp_path, monkeypatch, target_spec=target_spec)
    api = request["sources"]["api_config"]
    normalized, _artifact = run_matrix._load_api_config(
        api["path"], [target_spec], api["sha256"]
    )
    assert target_spec not in normalized  # The actual loader's fixed-condition contract.
    for cls in (AnthropicTarget, OpenAITarget):
        monkeypatch.setattr(cls, "_get_client", lambda self: pytest.fail("SDK client reached"))
    receipt = subject.prepare_campaign(
        request=request,
        request_descriptor={},
        out_root=tmp_path / "prepared",
        allow_network_counts=False,
    )
    assert receipt["status"] == "prepared_no_generation_calls"
    assert receipt["target_calls"] == receipt["judge_calls"] == 0
    assert receipt["generation_http_attempts"] == 0
    program = json.loads(Path(receipt["programs"][0]["path"]).read_text())
    assert program["target"] == target_spec
    assert program["max_output_tokens"] == 8192
    assert len(program["requests"]) == 2


def test_preparation_rejects_controlled_runner_argument_before_creating_artifacts(
    tmp_path, monkeypatch
):
    request, _execution_root = _request(tmp_path, monkeypatch)
    request["runner_common_argv"] = ["--api", "openai:wrong"]
    out = tmp_path / "prepared"
    with pytest.raises(ValueError, match="cannot override --api"):
        subject.prepare_campaign(
            request=request,
            request_descriptor={},
            out_root=out,
            allow_network_counts=False,
        )
    assert not out.exists()


def test_preparation_blocks_over_ceiling_exact_input_count_before_budget_or_program(
    tmp_path, monkeypatch
):
    request, _execution_root = _request(tmp_path, monkeypatch)
    monkeypatch.setattr(
        subject,
        "count_request",
        lambda target, body, **kwargs: {
            "request_sha256": subject.projection._sha(body),
            "count_request_sha256": "b" * 64,
            "provider": target.provider,
            "requested_spec": target.requested_spec,
            "requested_model": target.model,
            "input_tokens": 4001,
            "method": "provider_exact",
            "method_id": "fixture",
            "count_http_attempts": 1,
            "count_fee_status": "fixture",
        },
    )
    out = tmp_path / "prepared"
    with pytest.raises(ValueError, match="input-token ceiling"):
        subject.prepare_campaign(
            request=request,
            request_descriptor={},
            out_root=out,
            allow_network_counts=True,
        )
    assert not out.exists()


def test_prepared_replay_budget_covers_multiple_retained_turns_per_datapoint(tmp_path):
    from experiments import run_matrix

    points, _cell, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=True)
    argv = subject._job_argv(
        common=[], target="openai:gpt-5.5",
        api_config={"path": "api.json", "sha256": "a" * 64},
        corpus="retained-corpus",
        attacker_config={"path": "attacker.json", "sha256": "b" * 64},
        output=tmp_path / "out", count=len(value["entries"]), pilot=False,
    )
    args = run_matrix.build_parser().parse_args(argv)
    attacker = ReplayAttacker(**config)
    observed = list(attacker.generate(points[0], AttackBudget(
        max_queries=args.max_queries, max_turns=args.max_turns, seed=0,
    )))
    assert len(observed) == args.max_total_target_calls == 2


def test_invalid_local_membership_stops_before_network_count(tmp_path, monkeypatch):
    request, _execution_root = _request(tmp_path, monkeypatch)
    def invalid(*args, **kwargs):
        raise ValueError("changed retained source membership")
    monkeypatch.setattr(subject.inputs, "resolve_inputs", invalid)
    monkeypatch.setattr(subject, "count_request", lambda *args, **kwargs: pytest.fail("network count reached"))
    out = tmp_path / "prepared"
    with pytest.raises(ValueError, match="changed retained source membership"):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=out,
                                 allow_network_counts=True)
    assert not out.exists()
