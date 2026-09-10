from __future__ import annotations

import copy
import hashlib
import json

import pytest

from experiments import retained_judge_partitioned_report as subject
from experiments import retained_response_judge as single
from experiments import retained_response_judge_execute as execute
from experiments import retained_response_judge_report as reports
from test_retained_response_judge_report import completed  # noqa: F401
from test_retained_response_judge_execute import FakeHaiku

_FAKE_GENERATE = FakeHaiku.generate


@pytest.fixture
def independent_batches(completed, tmp_path):  # noqa: F811
    args, pair_plan, views = completed
    sources = []
    api = args["plan_path"].parent / "api.json"
    # Reuse the real executor fixture's exact API/pricing files.
    candidates = list(args["plan_path"].parent.iterdir())
    api = next(p for p in candidates if p.is_file() and p.suffix == ".json"
               and isinstance(json.loads(p.read_bytes()), dict)
               and pair_plan["judge_condition"]["model"] in json.loads(p.read_bytes()))
    pricing = next(p for p in candidates if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()
                   == pair_plan["judge_condition"]["pricing_config_sha256"])
    condition = pair_plan["judge_condition"]
    for cohort in ("local", "hosted"):
        directory = tmp_path / (cohort + "-batch")
        directory.mkdir()
        population = [{k: r[k] for k in single._SELECTED_FIELDS - {"same_model_judge"}}
                      for r in pair_plan["selected"] if r["cohort"] == cohort]
        plan = single.build_plan(population, population_audit=pair_plan["population"][cohort],
            source_descriptor=pair_plan["source"], judge_model=condition["model"],
            api_config_sha256=condition["api_config_sha256"],
            pricing_condition={k: condition[k] for k in subject.CONDITION_FIELDS if k.startswith("pricing_")
                               or k in {"input_microusd_per_token", "output_microusd_per_token"}},
            limit=len(population))
        plan_path = directory / "plan.json"
        plan_path.write_bytes(execute._canonical(plan))
        fake = FakeHaiku()
        fake.generate = _FAKE_GENERATE.__get__(fake, FakeHaiku)
        def reconcile(_root, actual_plan, _source, cohort=cohort, plan=plan):
            assert actual_plan == plan
            return [(r, views[cohort][1][r["sample_key"]]["prepared_prompt"],
                        views[cohort][1][r["sample_key"]]["prepared_response"]) for r in plan["selected"]]
        execute.execute(plan_path=plan_path, runner_view=args["local_runner_view"] if cohort == "local" else args["hosted_runner_view"],
            source_receipt=args["source_receipt"], api_config=api, pricing_config=pricing,
            out=directory / "judging", judge_factory=lambda *_: fake, selection_reconciler=reconcile)
        assert fake.calls == len(population)
        sources.append({"plan_path": plan_path, "execution_root": directory / "judging"})
    return {k: v for k, v in args.items() if k != "execution_root"} | {"partitions": sources}


def test_compares_actual_independent_executions_without_rejudging_or_combined_ledger(independent_batches):
    args = independent_batches
    before = {p: p.read_bytes() for part in args["partitions"] for p in part["execution_root"].rglob("*") if p.is_file()}
    result = subject.build_report(**args)
    assert result["schema"] == subject.SCHEMA
    assert len(result["source_partitions"]) == 2 and "execution" not in result
    assert result["completion"]["new_judge_calls"] == 0
    assert result["completion"]["judge_calls"] == 4
    assert result["completion"]["actual_cost_microusd"] == 640
    assert result["summary"]["cohorts"] == {"local": 1, "hosted": 3}
    assert result["summary"]["comparison_pairs"] == 3 and result["summary"]["distinct_inputs"] == 1
    assert all(p.read_bytes() == raw for p, raw in before.items())
    reports.validate_report(result)
    from experiments.rig_web import RigWebApp
    from experiments.rig_web_app.reports import _validate_report_document
    _validate_report_document("judge_comparison", result)
    page = object.__new__(RigWebApp)._render_judge_comparison("Independent batches", result)
    assert "Completed source batches: 2; no new judge calls" in page
    assert "Source spending ledgers remain separate" in page
    assert "Input-balanced comparison: 1 distinct inputs" in page and "plan ceiling" not in page


@pytest.mark.parametrize("damage", ["missing_partition", "duplicate_partition", "changed_judgment", "incomplete_execution"])
def test_rejects_missing_ambiguous_or_changed_source_judging(independent_batches, damage):
    args = copy.deepcopy(independent_batches)
    if damage == "missing_partition":
        args["partitions"].pop()
    elif damage == "duplicate_partition":
        args["partitions"].append(args["partitions"][0])
    elif damage == "changed_judgment":
        p = next((args["partitions"][0]["execution_root"] / "judgments").iterdir())
        raw = json.loads(p.read_bytes())
        raw["input_tokens"] += 1
        p.write_bytes(execute._canonical(raw))
    else:
        (args["partitions"][0]["execution_root"] / "circuit.json").write_text("{}")
    with pytest.raises(ValueError):
        subject.build_report(**args)


@pytest.mark.parametrize("damage", ["label", "accounting", "source", "generation_count"])
def test_report_revalidates_outputs_accounting_and_generation_conditions(independent_batches, damage):
    result = subject.build_report(**independent_batches)
    if damage == "label":
        result["observations"][0]["haiku_label"] = "violation"
    elif damage == "accounting":
        result["completion"]["judge_calls"] += 1
    elif damage == "source":
        result["source_partitions"][0]["judgments"][0]["input_tokens"] += 1
    else:
        result["generation_conditions"]["conditions"][0]["rows"] += 1
    result["report_id"] = "retained-judge-comparison-" + reports._sha({k: v for k, v in result.items() if k != "report_id"})[:24]
    with pytest.raises(ValueError):
        reports.validate_report(result)
