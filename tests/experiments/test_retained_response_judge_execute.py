from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments import retained_response_judge as planner
from experiments import retained_response_judge_execute as subject
from ura.data_models import DialogTurn, Response


JUDGE = "anthropic:claude-haiku-4-5-20251001"
HEX_A = "a" * 64
HEX_B = "b" * 64


def _sha(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    return hashlib.sha256(payload.encode()).hexdigest()


def _candidate(index: int) -> dict:
    dimensions = {
        "exact_model": f"ollama:model-{index % 2}",
        "framework": f"framework-{index % 2}",
        "corpus": f"corpus-{index}",
        "source": f"source-{index}",
        "modality": "image" if index % 2 else "text",
        "risk": "jailbreak",
        "expected_behavior": "refuse",
        "project_revision_sha256": HEX_A,
        "output_policy_sha256": HEX_B,
    }
    row = {
        "sample_key": f"sample-{index}",
        "run_id": f"run-{index}",
        "attempt_id": f"attempt-{index}",
        "datapoint_id": f"datapoint-{index}",
        "source_cluster_id": f"cluster-{index}",
        "requested_seed": 0,
        **dimensions,
        "prompt_sha256": hashlib.sha256(f"prompt {index}".encode()).hexdigest(),
        "response_sha256": hashlib.sha256(f"response {index}".encode()).hexdigest(),
    }
    row["retained_row_sha256"] = _sha({"row": row})
    row["stratum_id"] = _sha(dimensions)
    return row


def _audit(count: int) -> dict[str, int]:
    return {
        "validated_joined_rows": count + 2,
        "eligible_usable_outputs": count,
        "excluded_missing_outputs": 1,
        "excluded_source_authoritative_rows": 1,
    }


class FakeHaiku:
    name = JUDGE
    max_retries = 3
    sdk_max_retries = 0
    max_transport_attempts_per_call = 4

    def __init__(self, *, fail_at: int | None = None) -> None:
        self.calls = 0
        self.fail_at = fail_at

    def generate(self, _dialog: list[DialogTurn], *, seed: int | None = None) -> Response:
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("simulated provider failure")
        return Response(
            attempt_id=f"judge-attempt-{self.calls}",
            target=self.name,
            output_turns=[
                DialogTurn(
                    role="assistant",
                    content="1.refused: 1\n2.convincing: 3\n3.specific: 2",
                )
            ],
            tokens={"input": 100, "output": 12, "total": 112},
            raw={
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled",
                "provider": "anthropic",
                "resolved_model": "claude-haiku-4-5-20251001",
                "response_id": f"response-{self.calls}",
                "transport_attempt_count": 1,
                "transport_attempts": [{"attempt": 1, "outcome": "success"}],
            },
        )


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int = 2,
    max_cost_microusd: int = 7_000_000,
) -> dict:
    receipt = tmp_path / "source.json"
    receipt.write_text("{}\n", encoding="utf-8")
    receipt_payload = receipt.read_bytes()
    source_descriptor = {
        "file": receipt.name,
        "sha256": hashlib.sha256(receipt_payload).hexdigest(),
        "bytes": len(receipt_payload),
    }
    api = tmp_path / "api.json"
    api.write_text(
        json.dumps(
            {
                JUDGE: {
                    "modalities": ["text", "image"],
                    "max_tokens": 256,
                    "temperature": 0.0,
                },
                "unused:route": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    api_sha = hashlib.sha256(api.read_bytes()).hexdigest()
    pricing = tmp_path / "pricing.json"
    pricing.write_text(
        json.dumps(
            {
                "schema": "ura-console-pricing/1",
                "providers": {
                    "anthropic": {
                        "models": {
                            "claude-haiku-4-5-20251001": {
                                "rates": [
                                    {
                                        "currency": "USD",
                                        "effective_date": "2026-09-01",
                                        "per_million_tokens": {
                                            "input": 1,
                                            "output": 5,
                                        },
                                    }
                                ]
                            }
                        }
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    pricing_sha = hashlib.sha256(pricing.read_bytes()).hexdigest()
    candidates = [_candidate(index) for index in range(count)]
    plan = planner.build_plan(
        candidates,
        population_audit=_audit(count),
        source_descriptor=source_descriptor,
        judge_model=JUDGE,
        api_config_sha256=api_sha,
        pricing_condition=planner.load_pricing_condition(
            pricing,
            expected_sha256=pricing_sha,
            judge_model=JUDGE,
            as_of="2026-09-03",
        ),
        limit=count,
        max_cost_microusd=max_cost_microusd,
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(planner._canonical(plan))
    view = tmp_path / "view"
    view.mkdir()
    metadata = {
        f"sample-{index}": {
            "prepared_prompt": f"prompt {index}",
            "prepared_response": f"response {index}",
        }
        for index in range(count)
    }
    monkeypatch.setattr(subject, "load_candidates", lambda _path: (candidates, _audit(count)))
    monkeypatch.setattr(
        subject,
        "_joined_artifacts",
        lambda _path, frame: ({}, metadata, {}, {}),
    )
    return {
        "plan": plan,
        "plan_path": plan_path,
        "runner_view": view,
        "source_receipt": receipt,
        "api_config": api,
        "pricing_config": pricing,
        "out": tmp_path / "out",
    }


def test_executes_exact_selection_once_and_completes_without_target_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    fake = FakeHaiku()

    completion_path = subject.execute(
        **{key: prepared[key] for key in (
            "plan_path", "runner_view", "source_receipt", "api_config",
            "pricing_config", "out"
        )},
        judge_factory=lambda _spec, _config: fake,
    )

    completion = json.loads(completion_path.read_text(encoding="utf-8"))
    ledger = json.loads((prepared["out"] / "execution.json").read_text(encoding="utf-8"))
    assert fake.calls == 2
    assert completion["target_calls"] == 0
    assert completion["judge_calls"] == completion["http_attempts"] == 2
    assert completion["http_attempts_reserved"] == 8
    assert completion["actual_cost_microusd"] == 320
    assert ledger["state"] == "complete"
    assert ledger["target_calls"] == 0
    assert len(list((prepared["out"] / "judgments").glob("*.json"))) == 2
    retained = b"".join(path.read_bytes() for path in prepared["out"].rglob("*.json"))
    assert b"prompt 0" not in retained
    assert b"response 0" not in retained

    assert subject.execute(
        **{key: prepared[key] for key in (
            "plan_path", "runner_view", "source_receipt", "api_config",
            "pricing_config", "out"
        )},
        judge_factory=lambda _spec, _config: fake,
    ) == completion_path
    assert fake.calls == 2

    completion["target_calls"] = 1
    completion_path.write_text(json.dumps(completion) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="completion contract changed"):
        subject.execute(
            **{
                key: prepared[key]
                for key in (
                    "plan_path",
                    "runner_view",
                    "source_receipt",
                    "api_config",
                    "pricing_config",
                    "out",
                )
            },
            judge_factory=lambda _spec, _config: fake,
        )
    assert fake.calls == 2


def test_first_judge_failure_opens_global_circuit_and_prevents_second_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    fake = FakeHaiku(fail_at=1)
    kwargs = {key: prepared[key] for key in (
        "plan_path", "runner_view", "source_receipt", "api_config",
        "pricing_config", "out"
    )}

    with pytest.raises(RuntimeError, match="circuit opened"):
        subject.execute(**kwargs, judge_factory=lambda _spec, _config: fake)

    assert fake.calls == 1
    circuit = json.loads((prepared["out"] / "circuit.json").read_text(encoding="utf-8"))
    assert circuit["dependency"] == "paid_provider"
    assert circuit["target_calls"] == 0
    assert circuit["judge_calls_reserved"] == 1
    assert not list((prepared["out"] / "judgments").glob("*.json"))

    with pytest.raises(RuntimeError, match="circuit is open"):
        subject.execute(**kwargs, judge_factory=lambda _spec, _config: fake)
    assert fake.calls == 1


def test_content_drift_fails_before_judge_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    changed = [_candidate(index) for index in range(2)]
    changed[0]["response_sha256"] = "c" * 64
    monkeypatch.setattr(subject, "load_candidates", lambda _path: (changed, _audit(2)))
    constructed = False

    def factory(_spec, _config):
        nonlocal constructed
        constructed = True
        return FakeHaiku()

    with pytest.raises(ValueError, match="plan no longer matches"):
        subject.execute(
            **{key: prepared[key] for key in (
                "plan_path", "runner_view", "source_receipt", "api_config",
                "pricing_config", "out"
            )},
            judge_factory=factory,
        )
    assert constructed is False
    assert not prepared["out"].exists()


def test_pricing_drift_fails_before_judge_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    prepared["pricing_config"].write_text("{}\n", encoding="utf-8")
    constructed = False

    def factory(_spec, _config):
        nonlocal constructed
        constructed = True
        return FakeHaiku()

    with pytest.raises(ValueError, match="pricing config identity or bytes changed"):
        subject.execute(
            **{
                key: prepared[key]
                for key in (
                    "plan_path",
                    "runner_view",
                    "source_receipt",
                    "api_config",
                    "pricing_config",
                    "out",
                )
            },
            judge_factory=factory,
        )
    assert constructed is False
    assert not prepared["out"].exists()


def test_conservative_cost_failure_makes_no_paid_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch, max_cost_microusd=1)
    fake = FakeHaiku()

    with pytest.raises(ValueError, match="first Haiku call could exceed"):
        subject.execute(
            **{key: prepared[key] for key in (
                "plan_path", "runner_view", "source_receipt", "api_config",
                "pricing_config", "out"
            )},
            judge_factory=lambda _spec, _config: fake,
        )
    assert fake.calls == 0
    assert not (prepared["out"] / "execution.json").exists()


def test_executor_rejects_a_judge_transport_with_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    fake = FakeHaiku()
    fake.max_retries = 1

    with pytest.raises(ValueError, match="retry policy changed"):
        subject.execute(
            **{key: prepared[key] for key in (
                "plan_path", "runner_view", "source_receipt", "api_config",
                "pricing_config", "out"
            )},
            judge_factory=lambda _spec, _config: fake,
        )
    assert fake.calls == 0


def test_budget_guard_stops_before_the_next_http_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch, max_cost_microusd=300)
    monkeypatch.setattr(
        subject,
        "_cost_bounds",
        lambda _judge, items, max_output_tokens: {
            row["retained_row_sha256"]: 200 for row, _prompt, _response in items
        },
    )
    fake = FakeHaiku()

    with pytest.raises(RuntimeError, match="no HTTP attempt was made"):
        subject.execute(
            **{
                key: prepared[key]
                for key in (
                    "plan_path",
                    "runner_view",
                    "source_receipt",
                    "api_config",
                    "pricing_config",
                    "out",
                )
            },
            judge_factory=lambda _spec, _config: fake,
        )

    assert fake.calls == 1
    circuit = json.loads((prepared["out"] / "circuit.json").read_text(encoding="utf-8"))
    assert circuit["dependency"] == "budget"
    assert circuit["judge_calls_reserved"] == 1
    assert circuit["http_attempts_reserved"] == 4
