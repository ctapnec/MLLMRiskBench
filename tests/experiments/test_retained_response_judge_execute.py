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


def _workspace_outputs(tmp_path, plan):
    from experiments.rig_web_app.storage import ConsoleDB
    db = ConsoleDB(tmp_path / "console.db")
    owners = [db.create_workspace("First outputs", "local"), db.create_workspace("Matched outputs", "api")]
    for index, selected in enumerate(plan["selected"]):
        response = selected["run_id"] + ":" + selected["attempt_id"]
        db.publish_workspace_results(owners[index % 2], assignments=[dict(
            assignment_id=response, model=selected["exact_model"], input_id="same-input", condition_id="condition",
            modality="text", framework="replay", corpus="sample", response_id=response, evidence_class="measured")],
            responses=[dict(response_id=response, assignment_id=response, condition_id="condition",
                outcome="usable", truncated=False, source_ref="original.jsonl:"+str(index+1))], judgments=[])
    return db, owners


@pytest.mark.parametrize("index_failure", [False, True])
def test_executor_publishes_exact_output_judgments_and_costs_without_repeating_calls(tmp_path, monkeypatch, index_failure):
    from experiments.rig_web_app.storage import ConsoleDB
    prepared = _prepared(tmp_path, monkeypatch)
    db, owners = _workspace_outputs(tmp_path, prepared["plan"])
    original = ConsoleDB.publish_workspace_costs
    if index_failure:
        def unavailable(*args, **kwargs):
            raise ValueError("private diagnostic not for status")
        monkeypatch.setattr(ConsoleDB, "publish_workspace_costs", unavailable)
    fake = FakeHaiku()
    kwargs = {key: prepared[key] for key in (
        "plan_path", "runner_view", "source_receipt", "api_config", "pricing_config", "out")}
    kwargs.update(judge_factory=lambda _s, _c: fake, workspace_ids=owners, console_db=db.path)
    completion = subject.execute(**kwargs)
    assert fake.calls == 2 and completion.is_file()
    status = prepared["out"] / "publication.json"
    assert "private diagnostic" not in status.read_text()
    if index_failure:
        assert json.loads(status.read_text())["status"] == "publication_pending"
        monkeypatch.setattr(ConsoleDB, "publish_workspace_costs", original)
    before = completion.read_bytes()
    subject.execute(**kwargs)
    assert fake.calls == 2 and completion.read_bytes() == before
    assert json.loads(status.read_text())["status"] == "published"
    for owner in owners:
        assert sum(row["count"] for row in db.workspace_judging_totals(owner) if row["status"] == "valid") == 1
        costs = db.workspace_cost_totals(owner)[0]
        assert (costs["attempts"], costs["cost_microusd"], costs["input_tokens"], costs["output_tokens"]) == (1, 160, 100, 12)
    assert len(db._query("SELECT * FROM campaign_judgments")) == 2
    db.close()


def test_publication_occurs_after_durable_artifact_before_next_judge_call(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    db, owners = _workspace_outputs(tmp_path, prepared["plan"])

    class Observed(FakeHaiku):
        def generate(self, dialog, *, seed=None):
            if self.calls:
                assert len(list((prepared["out"] / "judgments").glob("*.json"))) == 1
                assert len(db._query("SELECT * FROM campaign_judgments")) == 1
            return super().generate(dialog, seed=seed)

    subject.execute(**{key: prepared[key] for key in (
        "plan_path", "runner_view", "source_receipt", "api_config", "pricing_config", "out")},
        judge_factory=lambda _s, _c: Observed(), workspace_ids=owners, console_db=db.path)
    db.close()


def test_publication_does_not_guess_owner_from_matched_input(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    db, owners = _workspace_outputs(tmp_path, prepared["plan"])
    fake = FakeHaiku()
    subject.execute(**{key: prepared[key] for key in (
        "plan_path", "runner_view", "source_receipt", "api_config", "pricing_config", "out")},
        judge_factory=lambda _s, _c: fake, workspace_ids=owners[:1], console_db=db.path)
    assert fake.calls == 2
    assert len(db._query("SELECT * FROM campaign_judgments")) == 1
    assert db.workspace_judging_totals(owners[1]) == []
    assert json.loads((prepared["out"] / "publication.json").read_text())["pending_judgments"] == 1
    db.close()


@pytest.mark.parametrize("shared", [False, True])
def test_automatic_judge_publication_keeps_retry_usage_unknown(tmp_path, monkeypatch, shared):
    from types import SimpleNamespace
    from experiments.rig_web_app.workspace_retained_judging import RetainedJudgmentPublication
    prepared = _prepared(tmp_path, monkeypatch, count=1)
    subject.execute(**{key: prepared[key] for key in (
        "plan_path", "runner_view", "source_receipt", "api_config", "pricing_config", "out")},
        judge_factory=lambda _s, _c: FakeHaiku())
    db, owners = _workspace_outputs(tmp_path, prepared["plan"])
    path = next((prepared["out"] / "judgments").glob("*.json"))
    artifact = json.loads(path.read_text())
    artifact["judgment"]["raw"]["judge_call"]["transport_attempt_count"] = 2
    kwargs = {}
    if shared:
        budget = tmp_path / "budget"
        budget.mkdir()
        (budget / "plan.json").write_text(json.dumps(dict(planned_calls=[dict(
            call_id="physical-call", provider="anthropic", pool="judge", bound_microusd=5000)])))
        (budget / "ledger.json").write_text(json.dumps(dict(attempts={"physical-call": {
            "1": dict(state="unknown", actual_cost_microusd=None),
            "2": dict(state="settled", actual_cost_microusd=160)}})))
        kwargs = dict(shared_budget=SimpleNamespace(root=budget),
            shared_requests={artifact["retained_row_sha256"]: dict(call_id="physical-call")})
    publisher = RetainedJudgmentPublication(database=db.path, campaign_ids=owners,
        root=prepared["out"], plan=prepared["plan"], **kwargs)
    publisher.accept(artifact, path)
    publisher.close()
    costs = db._query("SELECT * FROM campaign_cost_attempts ORDER BY attempt_number")
    assert len(costs) == 2
    assert costs[0]["cost_microusd"] is None and costs[0]["input_tokens"] is None
    assert costs[1]["cost_microusd"] == 160 and costs[1]["input_tokens"] == 100
    assert costs[0]["exposure_microusd"] == (5000 if shared else None)
    db.close()


@pytest.mark.parametrize("retry", [False, True])
def test_workspace_indexes_real_executor_artifacts_by_output_without_new_calls(tmp_path, monkeypatch, retry):
    from experiments.rig_web_app.workspace_judgments import retained_judge_rows

    prepared = _prepared(tmp_path, monkeypatch)
    fake = FakeHaiku()
    subject.execute(**{key: prepared[key] for key in (
        "plan_path", "runner_view", "source_receipt", "api_config", "pricing_config", "out")},
        judge_factory=lambda _spec, _config: fake)
    plan = prepared["plan"]
    artifacts = [(str(path), json.loads(path.read_text()))
                 for path in sorted((prepared["out"] / "judgments").glob("*.json"))]
    slots, requests, attempts, owners = [], {}, {}, {}
    for row in plan["selected"]:
        key = row["retained_row_sha256"]
        slots.append(dict(call_id=key, provider="anthropic", pool="judge", bound_microusd=5000))
        requests[key] = {"call_id": key}
        attempts[key] = {"1": dict(state="settled", actual_cost_microusd=160)}
        owners[row["run_id"] + ":" + row["attempt_id"]] = "assignment-" + key
    if retry:
        for _, artifact in artifacts:
            artifact["judgment"]["raw"]["judge_call"]["transport_attempt_count"] = 2
            attempts[artifact["retained_row_sha256"]] = {
                "1": dict(state="unknown", actual_cost_microusd=None),
                "2": dict(state="settled", actual_cost_microusd=160)}
    kwargs = dict(output_assignments=owners, campaign_id="local", shared_requests=requests,
        budget_plan={"planned_calls": slots}, ledger={"attempts": attempts}, ledger_path="retained/ledger.json")
    rows = retained_judge_rows(plan, artifacts, **kwargs)
    assert fake.calls == 2
    assert {row["response_id"] for row in rows["judgments"]} == set(owners)
    assert all(row["status"] == "valid" and row["label"] for row in rows["judgments"])
    assert sum(row["cost_microusd"] or 0 for row in rows["costs"]) == 320
    assert sum(row["input_tokens"] or 0 for row in rows["costs"]) == 200
    assert len(rows["costs"]) == (4 if retry else 2)
    if retry:
        assert all(row["input_tokens"] is None for row in rows["costs"] if row["attempt_number"] == 1)
    changed = json.loads(json.dumps(plan))
    changed["judge_condition"].update(max_judge_calls=100, max_http_attempts=400)
    assert retained_judge_rows(changed, artifacts, **kwargs)["judgments"] == rows["judgments"]
    with pytest.raises(ValueError, match="matching output"):
        retained_judge_rows(plan, artifacts, **{**kwargs, "output_assignments": {"same-input-different-answer": "wrong"}})
    with pytest.raises(ValueError, match="Repeated"):
        retained_judge_rows(plan, [artifacts[0], artifacts[0]], **kwargs)
    bad = json.loads(json.dumps(artifacts))
    bad[0][1]["retained_row_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="contract changed"):
        retained_judge_rows(plan, bad, **kwargs)


def test_atomic_publication_from_two_threads_uses_distinct_temporary_files(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    rendezvous = threading.Barrier(2)
    original = subject._canonical

    def synchronized(value):
        rendezvous.wait(timeout=5)
        return original(value)

    monkeypatch.setattr(subject, "_canonical", synchronized)
    path = tmp_path / "progress.json"
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(subject._write_atomic, path, {"worker": n}) for n in range(2)]
        for future in futures:
            future.result(timeout=10)
    assert json.loads(path.read_text()) in ({"worker": 0}, {"worker": 1})
    assert list(tmp_path.iterdir()) == [path]


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
        "load_retained_metadata",
        lambda _path: metadata,
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


def test_matched_shared_local_judgment_executes_once_and_resumes_without_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from experiments import retained_response_judge_pair as pair_planner
    from experiments import retained_response_judge_pair_execute as paired

    prepared = _prepared(tmp_path, monkeypatch)
    api = prepared["api_config"]
    config = json.loads(api.read_text())
    config[JUDGE]["max_tokens"] = 512
    api.write_text(json.dumps(config) + "\n", encoding="utf-8")
    local_view = prepared["runner_view"]
    hosted_view = tmp_path / "hosted-view"
    hosted_view.mkdir()
    populations = {}
    metadata = {}
    for cohort, count, view in (("local", 1, local_view), ("hosted", 3, hosted_view)):
        rows = []
        meta = {}
        for index in range(count):
            row = _candidate(0)
            row.update({
                "sample_key": f"{cohort}-{index}",
                "run_id": f"{cohort}-run-{index}",
                "attempt_id": f"{cohort}-attempt-{index}",
                "exact_model": f"{cohort}:model-{index}",
                "source_policy_id": "policy",
                "source_policy_version": "1",
                "media_references_sha256": _sha([]),
                "response_sha256": hashlib.sha256(f"response {index}".encode()).hexdigest(),
            })
            row["input_identity_sha256"] = _sha({
                field: row[field] for field in planner._MATCH_IDENTITY_FIELDS
            })
            row["retained_row_sha256"] = _sha(row)
            rows.append(row)
            meta[row["sample_key"]] = {
                "prepared_prompt": "prompt 0", "prepared_response": f"response {index}"
            }
        populations[view] = rows
        metadata[view] = meta
    old_plan = prepared["plan"]
    condition = old_plan["judge_condition"]
    pricing = {field: condition[field] for field in (
        "pricing_config_sha256", "pricing_as_of", "pricing_effective_date",
        "pricing_currency", "input_microusd_per_token", "output_microusd_per_token"
    )}
    plan = pair_planner.build_pair_plan(
        populations[local_view], populations[hosted_view],
        local_population_audit=_audit(1), hosted_population_audit=_audit(3),
        source_descriptor=old_plan["source"], judge_model=JUDGE,
        api_config_sha256=hashlib.sha256(api.read_bytes()).hexdigest(),
        pricing_condition=pricing, limit=3, share_local_judgments=True,
    )
    prepared["plan_path"].write_bytes(planner._canonical(plan))
    monkeypatch.setattr(paired, "load_pair_candidate_views", lambda local, hosted: (
        (populations[local], _audit(len(populations[local]))),
        (populations[hosted], _audit(len(populations[hosted]))),
        {"local": metadata[local], "hosted": metadata[hosted]},
    ))
    fake = FakeHaiku()
    args = {key: prepared[key] for key in (
        "plan_path", "source_receipt", "api_config", "pricing_config", "out"
    )}
    args.update(local_runner_view=local_view, hosted_runner_view=hosted_view)
    completed = paired.execute(**args, judge_factory=lambda _spec, _config: fake)
    value = json.loads(completed.read_text())
    assert fake.calls == value["judge_calls"] == 4
    assert value["target_calls"] == 0
    assert value["actual_cost_microusd"] == 640
    assert len(list((prepared["out"] / "judgments").glob("*.json"))) == 4
    assert paired.execute(**args, judge_factory=lambda _spec, _config: fake) == completed
    assert fake.calls == 4


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
