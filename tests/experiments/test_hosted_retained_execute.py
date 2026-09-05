from __future__ import annotations

import copy
import hashlib
import json
import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_retained_execute as subject, run_matrix
from experiments.hosted_attempt_budget import create_budget, AttemptBudget
from test_retained_input_replay import _fixture, _RecordingMock
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker, retained_dialog
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.runner import Runner, retained_execution_admission, current_retained_execution_admission
from ura.data_models import DialogTurn
from ura.targets.api import OpenAITarget


def _setup(tmp_path, *, adaptive=True, outputs=None, tight=False):
    points, _original, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=adaptive)
    ids = [entry["origin"]["selection"]["input_identity_sha256"] for entry in value["entries"]]
    attacker = ReplayAttacker(**config, retained_input_ids=ids)
    target = OpenAITarget("gpt-5.5", max_tokens=128, max_retries=3, temperature=None)
    calls = []
    outputs = iter(outputs or ["I cannot help with that."] * len(ids))

    def create(**request):
        calls.append(copy.deepcopy(request))
        text = next(outputs)
        if isinstance(text, BaseException):
            raise text
        return SimpleNamespace(id="mock-response", model="gpt-5.5", system_fingerprint="mock-fp",
            choices=[SimpleNamespace(index=0, finish_reason="stop",
                                     message=SimpleNamespace(content=text, refusal=None))],
            usage=SimpleNamespace(prompt_tokens=7, completion_tokens=5, total_tokens=12))

    target._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    program = {"target": target.name, "provider": "openai", "max_output_tokens": 128}
    requests = {key: {"call_id": key, "request_sha256": subject._sha(target.build_request(
        retained_dialog(entry["rendered_input"]), seed=0)), "input_tokens": 32,
        "max_output_tokens": 128, "bound_microusd": 10000}
        for key, entry in zip(ids, value["entries"])}
    descriptor = create_budget(tmp_path / "money", provider_budgets_microusd={
        "anthropic": 90000000, "openai": 12500 * len(ids) if tight else 40000000},
        planned_calls=[{"call_id": key, "provider": "openai", "pool": "target", "bound_microusd": 10000}
                       for key in ids])
    budget = AttemptBudget(tmp_path / "money", descriptor["sha256"])
    admission = subject._Admission(program=program, job={"purpose": "measured_run", "input_ids": ids, "argv": []},
                                    budget=budget, attacker=attacker, requests=requests,
                                    prices={"input": "2", "output": "6"})
    return points, attacker, target, calls, admission


def _runner(attacker, target, admission):
    with retained_execution_admission(admission):
        return Runner(attacker, target, JudgeCascade([RuleJudge()]), AttackBudget(max_queries=2, max_turns=2),
                      [0], target_answer_retries=0, execution_stage="responses")


def test_target_money_settles_after_checkpoint_and_resume_never_reissues(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    checkpoint = tmp_path / "responses.jsonl"
    states = []

    def retain(record):
        states.append(admission.budget.snapshot()["pools"]["openai:target"]["unresolved_attempts"])
        Runner.append_checkpoint(checkpoint, record)

    first = _runner(attacker, target, admission)
    first.run(points, on_response=retain)
    assert len(calls) == 2 and states == [1, 1]
    assert admission.budget.snapshot()["pools"]["openai:target"]["settled_cost_microusd"] == 88
    second = _runner(attacker, target, admission)
    second.run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == len(second.responses) == 2
    assert current_retained_execution_admission() is None


def test_paid_empty_response_is_durable_then_opens_global_circuit_before_next_input(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=["", "must never run"])
    checkpoint = tmp_path / "responses.jsonl"
    with pytest.raises(RuntimeError, match="durable response"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(calls) == len(records) == 1
    assert (admission.budget.root / "paid-circuit.json").is_file()
    assert next(iter(records.values()))["response"]["raw"]["model_stability_status"] == "failed_output"
    assert admission.budget.snapshot()["pools"]["openai:target"]["unknown_usage_attempts"] == 1


def test_paid_target_cannot_call_without_response_checkpoint(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    with pytest.raises(ValueError, match="durable response checkpoint"):
        _runner(attacker, target, admission).run(points)
    assert calls == []


def test_request_change_fails_before_reservation_and_sdk(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    target.temperature = 0.5
    with pytest.raises(ValueError, match="request changed"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    assert calls == []
    assert admission.budget.snapshot()["pools"]["openai:target"]["unresolved_attempts"] == 0


class _HTTP500(Exception):
    status_code = 500


def test_status_retry_reserves_each_physical_attempt_and_holds_unknown_charge(tmp_path, monkeypatch):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, adaptive=False,
                                                       outputs=[_HTTP500("mock"), "usable"])
    _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2 and state["unknown_usage_attempts"] == 1
    assert state["reserved_exposure_microusd"] == 10000 and state["settled_cost_microusd"] == 44


def test_retry_cannot_spend_remaining_selected_first_calls(tmp_path, monkeypatch):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, tight=True,
                                                       outputs=[_HTTP500("mock"), "must never run"])
    with pytest.raises(Exception, match="retry cannot consume"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 1 and state["unstarted_first_commitments_microusd"] == 10000
    assert state["unknown_usage_attempts"] == 1


@pytest.mark.parametrize("surface,provider", [("anthropic-fable", "anthropic"),
    ("openai-responses", "openai"), ("kimi", "kimi"), ("moonshot", "kimi")])
def test_billing_provider_preserves_configured_surface_aliases(surface, provider):
    assert subject._billing_provider(surface) == provider


def test_partition_does_not_change_original_artifact_or_rerun_pilot(tmp_path):
    points, _original, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=True)
    before = Path(config["replay_artifact"]).read_bytes()
    ids = [row["origin"]["selection"]["input_identity_sha256"] for row in value["entries"]]
    generated = []
    for identity in ids:
        attacker = ReplayAttacker(**config, retained_input_ids=[identity])
        runner = Runner(attacker, _RecordingMock(), JudgeCascade([RuleJudge()]), AttackBudget(max_queries=1, max_turns=1),
                        [0], target_answer_retries=0)
        runner.run(points)
        generated += [attempt.params["retained_origin"]["selection"]["input_identity_sha256"] for attempt in runner.attempts]
    assert generated == ids and len(set(generated)) == len(ids)
    assert Path(config["replay_artifact"]).read_bytes() == before
    for invalid in ([ids[0], ids[0]], list(reversed(ids)), ["not-selected"]):
        with pytest.raises(ValueError, match="partition"):
            ReplayAttacker(**config, retained_input_ids=invalid)


def test_nonprefix_retained_pilot_is_one_original_cluster_not_extra_sample(tmp_path, monkeypatch):
    points, _audit = run_matrix.load_corpus_with_audit("synth", 0, 0, exclude_tool_conditioned=True)
    chosen = next(point for point in reversed(points) if point.modalities == ["text"] and point.expected_behavior == "refuse")
    _points, _cell, _plan, _bindings, value, config = _fixture(tmp_path, points=[chosen], corpus="synth")
    attacker = ReplayAttacker(**config, retained_input_ids=[value["entries"][0]["origin"]["selection"]["input_identity_sha256"]])
    sampled, audit = run_matrix.load_retained_replay_corpus("synth", 1, 0, attacker=attacker,
        sampling_policy=None, source_instance=run_matrix._default_source_instance("synth"))
    assert sampled == [chosen] and audit["selected_clusters"] == audit["limit"] == 1
    assert audit["pre_retained_loading_limit"] == 0
    assert audit["selection_method"] == "content_bound_retained_input_replay_v1"
    assert audit["selected_indices"] != [0]
    calls = _RecordingMock()
    runner = Runner(attacker, calls, JudgeCascade([RuleJudge()]), AttackBudget(max_queries=1, max_turns=1),
                    [0], target_answer_retries=0, execution_stage="responses")
    runner.run(sampled)
    assert len(calls._dialogs) == 1 and runner.attempts[0].datapoint_id == chosen.id


def test_scoped_cli_uses_exact_nonprefix_inputs_and_seals_one_mock_response(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("URA_"):
            monkeypatch.delenv(key)
    points, _audit = run_matrix.load_corpus_with_audit("synth", 0, 0)
    chosen = next(point for point in reversed(points) if point.modalities == ["text"] and point.expected_behavior == "refuse")
    _points, _cell, _plan, _bindings, value, config = _fixture(tmp_path, points=[chosen], corpus="synth")
    config["retained_input_ids"] = [value["entries"][0]["origin"]["selection"]["input_identity_sha256"]]
    config_path = tmp_path / "attacker.json"
    config_path.write_text(json.dumps({"replay": config}))
    calls = []

    class RecordingTarget(_RecordingMock):
        def generate(self, dialog, *, seed=None):
            calls.append(dialog)
            response = super().generate(dialog, seed=seed)
            return response.model_copy(update={"output_turns": [DialogTurn(role="assistant", content="I cannot assist with that request.")]})

    # This fixture bypasses monetary admission only for the existing mock CLI;
    # production admission rejects --dry-run and tests actual SDK funding above.
    admission = SimpleNamespace(validate_cli=lambda argv, args: None,
                                validate_runner=lambda runner: None,
                                attempt=lambda runner, attempt: nullcontext(),
                                response_checkpointed=lambda runner, attempt, response: None)
    monkeypatch.setattr(run_matrix, "build_target", lambda spec, **kwargs: RecordingTarget())
    out = tmp_path / "mock-run"
    with retained_execution_admission(admission):
        result = run_matrix.main(["--dry-run", "--corpora", "synth", "--limit", "1", "--judges", "rules",
            "--attackers", "replay", "--target-answer-retries", "0", "--attacker-config", str(config_path),
            "--attacker-config-sha256", hashlib.sha256(config_path.read_bytes()).hexdigest(), "--out", str(out)])
    assert result == 0 and len(calls) == 1
    manifests = [json.loads(path.read_text()) for path in out.glob("*.manifest.json")]
    audit = manifests[0]["config"]["run"]["sampling_audit"]
    assert audit["selected_ids"] == [chosen.id] and audit["selected_clusters"] == 1
    assert list(out.glob("*.complete.json"))


def test_fully_bound_program_still_cannot_skip_final_campaign_admission(tmp_path):
    with pytest.raises(ValueError, match="complete local-source program admission"):
        subject._validated_jobs({}, None)


def _program(tmp_path, monkeypatch):
    from test_hosted_campaign_budget import _api_config, _pricing, _budgets
    from experiments import hosted_campaign_budget as money, hosted_retained_inputs as materializer
    from experiments.hosted_request_tokens import count_request
    points, cell, _old_plan, _old_bindings, _value, _config = _fixture(tmp_path, adaptive=True)
    target_spec = "openai:gpt-5.5"
    api = _api_config()
    api[target_spec]["temperature"] = None

    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

    sources = {"api_config": save("api.json", api), "pricing": save("prices.json", _pricing()),
               "budgets": save("budgets.json", _budgets()), "media_index": save("media.json", {})}
    portable = lambda raw: {"file": Path(raw["path"]).name, "sha256": raw["sha256"], "bytes": raw["bytes"]}
    budget_projection = money.build_projection(api_config=api, pricing=_pricing(), budgets=_budgets(),
        descriptors={"api_config": portable(sources["api_config"]), "pricing_config": portable(sources["pricing"]),
                     "budgets": portable(sources["budgets"])}, pricing_as_of="2026-09-03")
    sources["budget_projection"] = save("projection.json", budget_projection)
    inventory = save("historical-inventory.json", {"fixture": "not a real complete local campaign"})
    monkeypatch.setattr(subject, "_validated_local_cells", lambda program: ([cell], inventory))
    bindings = {"budget": budget_projection, "budget_descriptor": portable(sources["budget_projection"]),
                "api_config": api, "api_descriptor": portable(sources["api_config"]),
                "media_index": {}, "local_inventory_descriptor": portable(inventory)}
    plan = materializer.build_plan(candidates=materializer.candidates_from_cells([cell]), target=target_spec, call_cap=2, **bindings)
    value = materializer.materialize_replay(plan, cells=[cell], source_corpora={cell["run_id"]: points},
                                            corpus="retained-corpus", **bindings)
    replay = save("real-shaped-replay.json", value)
    target = run_matrix.build_target(target_spec, api_config=api[target_spec])
    requests, jobs, slots = {}, [], []
    for index, entry in enumerate(value["entries"]):
        key = entry["origin"]["selection"]["input_identity_sha256"]
        call_id = "target-" + subject._sha({"target": target_spec, "input_id": key})
        request = target.build_request(retained_dialog(entry["rendered_input"]), seed=0)
        count = count_request(target, request, allow_network=False)
        requests[key] = {"call_id": call_id, "request_sha256": subject._sha(request), "token_count": count,
                         "input_tokens": count["input_tokens"], "max_output_tokens": 8192, "bound_microusd": 500000}
        requests[key]["judge_call_ids"] = {cohort: "judge-" + cohort + "-" + subject._sha({"target": target_spec, "input_id": key})
                                           for cohort in ("local", "hosted")}
        slots.append({"call_id": call_id, "provider": "openai", "pool": "target", "bound_microusd": 500000})
        slots += [{"call_id": value, "provider": "anthropic", "pool": "judge", "bound_microusd": 14848}
                  for value in requests[key]["judge_call_ids"].values()]
        config = save(f"attacker{index}.json", {"replay": {"replay_artifact": replay["path"],
            "replay_artifact_sha256": replay["sha256"], "retained_input_ids": [key]}})
        argv = ["--api", target_spec, "--api-config", sources["api_config"]["path"],
                "--api-config-sha256", sources["api_config"]["sha256"], "--corpora", "retained-corpus",
                "--attackers", "replay", "--judges", "rules,guardrail", "--seeds", "0", "--sample-seed", "0",
                "--target-answer-retries", "0", "--max-total-target-calls", "1", "--max-total-judge-calls", "1",
                "--max-total-http-attempts", "4", "--max-queries", "1", "--max-turns", "1",
                "--attacker-config", config["path"], "--attacker-config-sha256", config["sha256"],
                "--out", str(tmp_path / f"job{index}"), "--limit", "1" if index == 0 else "0"]
        if index == 0:
            argv.append("--diagnostic-canary")
        jobs.append({"name": f"job{index}", "input_ids": [key], "purpose": "diagnostic_canary" if index == 0 else "measured_run",
                     "argv": argv})
    descriptor = create_budget(tmp_path / "program-money", provider_budgets_microusd={
        "anthropic": 90000000, "openai": 40000000, "kimi": 15000000, "deepseek": 10000000}, planned_calls=slots)
    program = {"schema": subject.SCHEMA, "budget_plan_sha256": descriptor["sha256"], "sources": sources,
               "target": target_spec, "provider": "openai", "max_output_tokens": 8192,
               "pricing_as_of": "2026-09-03", "jobs": jobs, "requests": requests,
               "token_count_policy": subject.TOKEN_COUNT_POLICY,
               "replaced_descriptive_prerequisite": "authority.requires_exact_provider_token_counts",
               "predecessor_selection": {"schema": plan["schema"], "plan_id": plan["plan_id"], "sha256": subject._sha(plan)}}
    return program, AttemptBudget(tmp_path / "program-money", descriptor["sha256"])


def test_program_rebuilds_exact_selection_and_fixed_disjoint_pilot_before_any_client(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch)
    monkeypatch.setattr(OpenAITarget, "_get_client", lambda self: pytest.fail("program validation cannot construct SDK"))
    jobs = subject._validated_jobs(program, budget)
    assert len(jobs) == 2
    assert set(jobs[0].entries).isdisjoint(jobs[1].entries)
    assert budget.snapshot()["pools"]["openai:target"]["unstarted_first_commitments_microusd"] == 1000000


@pytest.mark.parametrize("mutation", ["repeat_pilot", "skip_input", "changed_request", "changed_count", "answer_retry",
                                     "unfinished_local", "invented_judge", "wrong_predecessor"])
def test_program_rejects_changed_selection_count_retry_or_unfinished_local(tmp_path, monkeypatch, mutation):
    program, budget = _program(tmp_path, monkeypatch)
    if mutation == "repeat_pilot":
        program["jobs"][1] = copy.deepcopy(program["jobs"][0])
    elif mutation == "skip_input":
        program["jobs"].pop()
    elif mutation == "changed_request":
        next(iter(program["requests"].values()))["request_sha256"] = "0" * 64
    elif mutation == "changed_count":
        next(iter(program["requests"].values()))["token_count"]["input_tokens"] += 1
    elif mutation == "answer_retry":
        argv = program["jobs"][0]["argv"]
        argv[argv.index("--target-answer-retries") + 1] = "1"
    elif mutation == "invented_judge":
        next(iter(program["requests"].values()))["judge_call_ids"]["hosted"] = "invented-output-hash"
    elif mutation == "wrong_predecessor":
        program["predecessor_selection"]["sha256"] = "a" * 64
    else:
        monkeypatch.setattr(subject, "_validated_local_cells", lambda program: (_ for _ in ()).throw(ValueError("RR incomplete")))
        monkeypatch.setattr(run_matrix, "build_target", lambda *args, **kwargs: pytest.fail("unfinished local source reached target factory"))
    with pytest.raises(ValueError):
        subject._validated_jobs(program, budget)
