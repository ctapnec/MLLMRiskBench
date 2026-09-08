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


def test_registered_count_uses_funded_starts_and_final_or_checkpointed_responses(tmp_path):
    points, attacker, target, _calls, admission = _setup(tmp_path)
    records = []
    runner = _runner(attacker, target, admission)
    runner.run(points, on_response=records.append)
    final_root = tmp_path / "final"
    checkpoint_root = tmp_path / "checkpoint"
    final_root.mkdir()
    checkpoint_root.mkdir()
    (final_root / "one.responses.jsonl").write_text(
        json.dumps(records[0]["response"]) + "\n"
    )
    missing = copy.deepcopy(records[1])
    missing["response"]["output_turns"] = []
    missing["response"]["raw"]["model_stability_status"] = "failed_output"
    Runner.append_checkpoint(
        checkpoint_root / "two.responses.checkpoint.jsonl", missing
    )
    program = {
        "target": target.name,
        "requests": admission.requests,
        "jobs": [
            {"argv": ["--out", str(final_root)]},
            {"argv": ["--out", str(checkpoint_root)]},
        ],
    }
    assert subject._retained_execution_counts(program, admission.budget) == (2, 1)


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


@pytest.mark.parametrize("read_rate,write_rate,cached,written,expected_cost", [
    ("0.5", None, 0, 0, 88),
    ("0.5", None, 2, 0, 82),
    (None, "3", 0, 1, 90),
    (None, "3", 1, 0, None),
    ("0.5", None, 0, 1, None),
])
def test_zero_cache_usage_needs_no_rate_and_resume_never_rebills(
    tmp_path, monkeypatch, read_rate, write_rate, cached, written, expected_cost,
):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(cache_read=read_rate, cache_write=write_rate)
    generate = target.generate

    def with_cache_usage(dialog, *, seed=None):
        response = generate(dialog, seed=seed)
        response.tokens.update(cached_input=cached, cache_write_input=written)
        return response

    monkeypatch.setattr(target, "generate", with_cache_usage)
    checkpoint = tmp_path / "responses.jsonl"
    _runner(attacker, target, admission).run(
        points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row),
    )
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert state["unresolved_attempts"] == 0
    if expected_cost is None:
        assert state["unknown_usage_attempts"] == 2
        assert state["reserved_exposure_microusd"] == 20000
    else:
        assert state["unknown_usage_attempts"] == 0
        assert state["settled_cost_microusd"] == expected_cost
    resumed = _runner(attacker, target, admission)
    resumed.run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == len(resumed.responses) == 2


def test_peak_funded_route_does_not_release_an_assumed_off_peak_discount(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(reservation_input="4", reservation_output="12",
                            settlement_input="4", settlement_output="12")
    _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2
    assert state["settled_cost_microusd"] == 176


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


def _program(
    tmp_path,
    monkeypatch,
    *,
    target_spec="openai:gpt-5.5",
    judge_rates=(1, 5),
):
    from test_hosted_campaign_budget import _api_config, _pricing, _budgets
    from experiments import hosted_campaign_budget as money, hosted_retained_inputs as materializer
    from experiments.hosted_request_tokens import count_request
    points, cell, _old_plan, _old_bindings, _value, _config = _fixture(tmp_path, adaptive=True)
    billing_provider = subject._billing_provider(target_spec.split(":", 1)[0])
    api = _api_config()
    api[target_spec]["temperature"] = None

    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

    pricing = _pricing()
    pricing["providers"]["anthropic"]["models"][money.JUDGE_MODEL]["rates"][0][
        "per_million_tokens"
    ].update(input=judge_rates[0], output=judge_rates[1])
    sources = {"api_config": save("api.json", api), "pricing": save("prices.json", pricing),
               "budgets": save("budgets.json", _budgets()), "media_index": save("media.json", {})}
    def portable(raw):
        return {"file": Path(raw["path"]).name, "sha256": raw["sha256"], "bytes": raw["bytes"]}
    budget_projection = money.build_projection(api_config=api, pricing=pricing, budgets=_budgets(),
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
    normalized, _api_artifact = run_matrix._load_api_config(
        sources["api_config"]["path"], [target_spec], sources["api_config"]["sha256"],
    )
    target = run_matrix.build_target(target_spec, api_config=normalized.get(target_spec))
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
        slots.append({"call_id": call_id, "provider": billing_provider, "pool": "target", "bound_microusd": 500000})
        judge_bound = int(
            money.JUDGE_MAX_INPUT_TOKENS * judge_rates[0]
            + money.JUDGE_MAX_OUTPUT_TOKENS * judge_rates[1]
        )
        slots += [{"call_id": value, "provider": "anthropic", "pool": "judge", "bound_microusd": judge_bound}
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
               "target": target_spec, "provider": billing_provider, "max_output_tokens": 8192,
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


def test_program_applies_peak_funded_deepseek_rates_to_settlement(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch, target_spec="deepseek:deepseek-v4-pro")
    jobs = subject._validated_jobs(program, budget)
    assert jobs[0].prices["reservation_input"] == "1.32"
    assert jobs[0].prices["reservation_output"] == "3.96"
    assert jobs[0].prices["settlement_input"] == "1.32"
    assert jobs[0].prices["settlement_output"] == "3.96"


def test_program_derives_judge_slot_floor_from_bound_projection_rates(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch, judge_rates=(0.5, 2))
    jobs = subject._validated_jobs(program, budget)
    assert len(jobs) == 2
    judge_slots = [
        budget.call(call_id)
        for request in program["requests"].values()
        for call_id in request["judge_call_ids"].values()
    ]
    assert {slot["bound_microusd"] for slot in judge_slots} == {7168}


def test_registered_execution_publishes_one_hosted_tmux_job(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch)
    program_path = tmp_path / "hosted-program.json"
    program_path.write_text(json.dumps(program))
    program_sha = hashlib.sha256(program_path.read_bytes()).hexdigest()
    work = tmp_path / "work"
    (work / "runs" / "engineering").mkdir(parents=True)
    control = work / "runs" / "engineering" / "hosted-gpt55"
    project = tmp_path / "project"
    project.mkdir()
    outputs = [Path(job["argv"][job["argv"].index("--out") + 1]) for job in program["jobs"]]
    monkeypatch.setattr(subject, "_validated_checkout", lambda root, commit: project)
    monkeypatch.setattr(subject, "execute", lambda **kwargs: outputs)
    monkeypatch.setattr(subject, "_retained_execution_counts", lambda value, money: (2, 2))

    observed = subject.execute_registered(
        program_path=program_path,
        program_sha256=program_sha,
        budget_root=budget.root,
        budget_plan_sha256=budget.expected_plan_sha256,
        project_root=project,
        expected_commit="a" * 40,
        work_root=work,
        control_root=control,
        tmux_socket="ura-hosted-gpt55",
        tmux_session="hosted-gpt55",
    )
    assert observed == outputs
    marker = json.loads((control / "ENGINEERING_ONLY.json").read_text())
    assert marker["hosted_calls_allowed"] is True
    assert marker["target_call_cap"] == 2
    report = json.loads((control / "model-execution.jsonl").read_text())
    assert report["attempted_calls"] == report["successful_generations"] == 2
    events = [json.loads(line) for line in (control / "task-log.jsonl").read_text().splitlines()]
    assert events[-2]["status"] == events[-1]["status"] == "passed"


def test_registered_execution_rejects_incomplete_local_source_before_job_or_client(
    tmp_path, monkeypatch,
):
    program, budget = _program(tmp_path, monkeypatch)
    program_path = tmp_path / "hosted-program.json"
    program_path.write_text(json.dumps(program))
    work = tmp_path / "work"
    (work / "runs" / "engineering").mkdir(parents=True)
    control = work / "runs" / "engineering" / "hosted-blocked"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(subject, "_validated_checkout", lambda root, commit: project)
    monkeypatch.setattr(
        subject,
        "_validated_jobs",
        lambda value, money: (_ for _ in ()).throw(ValueError("RR incomplete")),
    )
    monkeypatch.setattr(subject, "execute", lambda **kwargs: pytest.fail("paid executor reached"))
    with pytest.raises(ValueError, match="RR incomplete"):
        subject.execute_registered(
            program_path=program_path,
            program_sha256=hashlib.sha256(program_path.read_bytes()).hexdigest(),
            budget_root=budget.root,
            budget_plan_sha256=budget.expected_plan_sha256,
            project_root=project,
            expected_commit="a" * 40,
            work_root=work,
            control_root=control,
            tmux_socket="ura-hosted-blocked",
            tmux_session="hosted-blocked",
        )
    assert not control.exists()


@pytest.mark.parametrize("mutation", ["repeat_pilot", "skip_input", "changed_request", "changed_count", "answer_retry",
                                     "unfinished_local", "invented_judge", "wrong_predecessor", "measured_first"])
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
    elif mutation == "measured_first":
        program["jobs"].reverse()
    else:
        monkeypatch.setattr(subject, "_validated_local_cells", lambda program: (_ for _ in ()).throw(ValueError("RR incomplete")))
        monkeypatch.setattr(run_matrix, "build_target", lambda *args, **kwargs: pytest.fail("unfinished local source reached target factory"))
    with pytest.raises(ValueError):
        subject._validated_jobs(program, budget)


def _matched_funding(tmp_path, monkeypatch):
    from experiments import retained_response_judge as retained
    from experiments import retained_response_judge_execute as judging
    from experiments import retained_response_judge_pair as pairs
    from test_retained_input_replay import _matching_view, _runner
    from test_retained_response_judge_execute import JUDGE, _prepared
    from ura.runner import _portable_attempt_dump

    source_root = tmp_path / "original"
    source_root.mkdir()
    points, original, _plan, _bindings, value, config = _fixture(source_root, adaptive=True)
    prepared = _prepared(tmp_path, monkeypatch)
    api = json.loads(prepared["api_config"].read_bytes())
    api[JUDGE]["max_tokens"] = 512
    prepared["api_config"].write_bytes(judging._canonical(api))
    api_sha = hashlib.sha256(prepared["api_config"].read_bytes()).hexdigest()
    programs, slots, admissions, hosted_cells = [], [], {}, []

    class NamedMock(_RecordingMock):
        def generate(self, dialog, *, seed=None):
            return super().generate(dialog, seed=seed).model_copy(update={"target": self.name})

    for spec in ("openai:gpt-5.5", "openai:gpt-5.6-terra", "anthropic:claude-haiku-4-5"):
        mock = NamedMock()
        mock.name = spec
        runner = _runner(config, target=mock)
        runner.run(points, run_config={"attacker": "replay", "corpus": "retained-corpus",
                                      "project_revision": {"sha256": "c" * 64}})
        hosted_cells.append({"source_identity_validated": True, "run_id": runner.last_manifest.run_id,
            "model": spec, "manifest": runner.last_manifest.model_dump(mode="json"),
            "attempts": {a.id: _portable_attempt_dump(a) for a in runner.attempts}})
        entries, requests = {}, {}
        for entry in value["entries"]:
            key = entry["origin"]["selection"]["input_identity_sha256"]
            ids = {cohort: "judge-" + cohort + "-" + subject._sha({"target": spec, "input_id": key})
                   for cohort in ("local", "hosted")}
            entries[key] = entry
            requests[key] = {"judge_call_ids": ids}
            slots += [{"call_id": call_id, "provider": "anthropic", "pool": "judge", "bound_microusd": 14848}
                      for call_id in ids.values()]
        admissions[spec] = [SimpleNamespace(entries=entries, requests=requests)]
        programs.append({"target": spec})
    hosted_view = tmp_path / "hosted"
    hosted_view.mkdir()
    local_view = _matching_view(original)
    views = [_matching_view(cell) for cell in hosted_cells]
    hosted = (hosted_cells, {k: v for view in views for k, v in view[1].items()},
              {k: v for view in views for k, v in view[2].items()},
              {"policy_evaluable_samples": 3, "common_ineligible_evaluable_rows_excluded": 0})
    # Only the absent final campaign seal/read-only artifact boundary is
    # synthetic. Actual Runner Attempts, origin checks and paired join execute.
    monkeypatch.setattr(subject, "_validated_jobs", lambda program, budget: admissions[program["target"]])
    monkeypatch.setattr(retained, "_read_view", lambda path: hosted if path == hosted_view else local_view)
    (local_rows, local_audit), (hosted_rows, hosted_audit), _ = retained.load_pair_candidate_views(prepared["runner_view"], hosted_view)
    condition = prepared["plan"]["judge_condition"]
    pricing = {key: condition[key] for key in (
        "pricing_config_sha256", "pricing_as_of", "pricing_effective_date", "pricing_currency",
        "input_microusd_per_token", "output_microusd_per_token")}
    plan = pairs.build_pair_plan(local_rows, hosted_rows, local_population_audit=local_audit,
        hosted_population_audit=hosted_audit, source_descriptor=prepared["plan"]["source"],
        judge_model=JUDGE, api_config_sha256=api_sha, pricing_condition=pricing, limit=3, share_local_judgments=True)
    prepared["plan_path"].write_bytes(judging._canonical(plan))
    descriptor = create_budget(tmp_path / "funded-pairs", provider_budgets_microusd={"anthropic": 90000000}, planned_calls=slots)
    budget = AttemptBudget(tmp_path / "funded-pairs", descriptor["sha256"])
    kwargs = {key: prepared[key] for key in ("plan_path", "source_receipt", "api_config")}
    kwargs.update(programs=programs, budget=budget, plan_sha256=hashlib.sha256(prepared["plan_path"].read_bytes()).hexdigest(),
                  local_runner_view=prepared["runner_view"], hosted_runner_view=hosted_view)
    return prepared, plan, admissions, kwargs


def test_actual_retained_pair_outputs_bind_four_unique_slots_and_resume_once(tmp_path, monkeypatch):
    from experiments import retained_response_judge_pair_execute as paired
    from test_retained_judge_shared_budget import HookHaiku
    from experiments import retained_response_judge_execute as judging
    prepared, plan, _admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    requests = subject.build_matched_judge_requests(**kwargs)
    assert len(plan["pairs"]) == 3 and len(plan["selected"]) == len(requests) == 4
    assert sum(value["call_id"].startswith("judge-local-") for value in requests.values()) == 1
    assert len({value["call_id"] for value in requests.values()}) == 4
    assert subject.build_matched_judge_requests(**kwargs) == requests
    condition = plan["judge_condition"]
    config, _ = judging._load_api_config(prepared["api_config"], judge_model=condition["model"],
                                        expected_sha256=condition["api_config_sha256"])
    fake = HookHaiku(config)
    execute_kwargs = {key: prepared[key] for key in ("plan_path", "source_receipt", "api_config", "pricing_config", "out")}
    execute_kwargs.update(local_runner_view=kwargs["local_runner_view"], hosted_runner_view=kwargs["hosted_runner_view"],
                          shared_budget=kwargs["budget"], shared_requests=requests, judge_factory=lambda *_: fake)
    result = paired.execute(**execute_kwargs)
    assert fake.calls == fake.http_calls == 4
    assert paired.execute(**execute_kwargs) == result and fake.http_calls == 4
    pool = kwargs["budget"].snapshot()["pools"]["anthropic:judge"]
    assert pool["settled_attempts"] == 4
    assert pool["unstarted_first_commitments_microusd"] == 8 * 14848


@pytest.mark.parametrize("mutation", ["changed_origin", "missing_program", "duplicate_program", "underfunded_request"])
def test_matched_slot_binding_rejects_unfunded_or_changed_actual_input(tmp_path, monkeypatch, mutation):
    prepared, plan, admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    if mutation == "missing_program":
        kwargs["programs"].pop()
    elif mutation == "duplicate_program":
        kwargs["programs"].append(kwargs["programs"][0])
    elif mutation == "changed_origin":
        for admission in admissions[kwargs["programs"][0]["target"]]:
            admission.entries = copy.deepcopy(admission.entries)
            for entry in admission.entries.values():
                entry["origin"]["original_attempt"]["strategy"] = "different funded source"
    else:
        from experiments import retained_response_judge_execute as judging
        actual = judging.build_shared_request_receipts
        def oversized(*args, **named):
            receipts = actual(*args, **named)
            next(iter(receipts.values()))["input_tokens_estimate"] = 1000000
            return receipts
        monkeypatch.setattr(judging, "build_shared_request_receipts", oversized)
    with pytest.raises(ValueError, match="funded"):
        subject.build_matched_judge_requests(**kwargs)


def test_matched_slot_binding_revalidates_actual_source_artifacts_before_mapping(tmp_path, monkeypatch):
    _prepared, _plan, _admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    (tmp_path / "original" / "source.attempts.jsonl").write_text("changed original artifact\n")
    with pytest.raises(ValueError, match="source artifact bytes differ"):
        subject.build_matched_judge_requests(**kwargs)
