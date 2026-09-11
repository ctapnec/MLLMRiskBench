"""The actual retained executor supplies artifacts; no provider SDK is used."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from experiments import retained_response_judge_execute as executor
from experiments import retained_response_judge_pair as planner
from experiments import retained_response_judge_pair_execute as paired
from experiments import retained_response_judge_report as subject
from test_retained_response_judge_execute import FakeHaiku, JUDGE, _prepared
from test_retained_response_judge_pair import _candidate, _population


@pytest.fixture
def completed(tmp_path, monkeypatch, request):
    prepared = _prepared(tmp_path, monkeypatch)
    config = json.loads(prepared["api_config"].read_bytes())
    config[JUDGE]["max_tokens"] = 512
    prepared["api_config"].write_bytes(executor._canonical(config))
    local = [_candidate(i, cohort="local", input_index=0) for i in range(getattr(request, "param", 1))]
    hosted = [_candidate(i, cohort="hosted", input_index=0, model=JUDGE if i == 2 else "openai:model") for i in range(3)]
    metadata, judgments, cells = {}, {}, {}
    for cohort, candidates in (("local", local), ("hosted", hosted)):
        metadata[cohort], judgments[cohort], cells[cohort] = {}, {}, []
        for row in candidates:
            row["risk"] = "jailbreak"
            row["prompt_sha256"] = hashlib.sha256(b"common prompt").hexdigest()
            answer = "retained answer " + row["sample_key"]
            row["response_sha256"] = hashlib.sha256(answer.encode()).hexdigest()
            row["input_identity_sha256"] = planner._sha({key: row[key] for key in planner._MATCH_IDENTITY_FIELDS})
            metadata[cohort][row["sample_key"]] = {"prepared_prompt": "common prompt", "prepared_response": answer}
            judgment = {"attempt_id": row["attempt_id"], "judge": "rules", "label": "safe", "score": 0,
                        "raw": {"cascade_confident": cohort == "local", "parsed": True, "effective_modality": "text"}}
            judgments[cohort][row["sample_key"]] = judgment
            cells[cohort].append({"run_id": row["run_id"], "judgments": [judgment],
                "manifest": {"config": {"run": {"model_spec": row["exact_model"], "corpus": row["corpus"], "attacker": row["framework"]}}},
                "responses": {row["attempt_id"]: {"tokens": {"input": 10, "output": 3},
                    "raw": {"finish_reason": "length", "generation": {"max_tokens": 4096, "num_ctx": 32768}}}}})
    old_condition = prepared["plan"]["judge_condition"]
    pricing = {key: old_condition[key] for key in ("pricing_config_sha256", "pricing_as_of", "pricing_effective_date",
        "pricing_currency", "input_microusd_per_token", "output_microusd_per_token")}
    plan = planner.build_pair_plan(local, hosted, local_population_audit=_population(len(local)), hosted_population_audit=_population(3),
        source_descriptor=prepared["plan"]["source"], judge_model=JUDGE,
        api_config_sha256=hashlib.sha256(prepared["api_config"].read_bytes()).hexdigest(),
        pricing_condition=pricing, limit=3, share_local_judgments=True)
    prepared["plan_path"].write_bytes(executor._canonical(plan))
    hosted_view = tmp_path / "hosted"
    hosted_view.mkdir()
    monkeypatch.setattr(paired, "load_pair_candidate_views", lambda *_: ((local, _population(len(local))), (hosted, _population(3)), metadata))
    fake = FakeHaiku()
    paired.execute(**{key: prepared[key] for key in ("plan_path", "source_receipt", "api_config", "pricing_config", "out")},
                   local_runner_view=prepared["runner_view"], hosted_runner_view=hosted_view, judge_factory=lambda *_: fake)
    assert fake.calls == len(plan["selected"])
    views = {cohort: (cells[cohort], metadata[cohort], judgments[cohort], {}) for cohort in ("local", "hosted")}
    monkeypatch.setattr(subject, "_read_view", lambda root: views["local" if root == prepared["runner_view"] else "hosted"])
    monkeypatch.setattr(subject, "_candidates_from_view", lambda cell_list, *_args, **_kwargs:
                        (local, _population(len(local))) if cell_list is cells["local"] else (hosted, _population(3)))
    monkeypatch.setattr(subject, "_judge_configuration_binding", lambda _: {"sha256": "c" * 64})
    monkeypatch.setattr(FakeHaiku, "generate", lambda *_args, **_kwargs: pytest.fail("report generated a provider call"))
    args = {"plan_path": prepared["plan_path"], "source_receipt": prepared["source_receipt"],
            "execution_root": prepared["out"], "local_runner_view": prepared["runner_view"], "hosted_runner_view": hosted_view}
    return args, plan, views


def test_report_uses_actual_executor_unique_outputs_and_preserves_abstentions(completed):
    args, plan, _ = completed
    before = {p: p.read_bytes() for p in args["execution_root"].rglob("*") if p.is_file()}
    report = subject.build_report(**args)
    assert report["summary"]["comparison_pairs"] == 3
    assert report["summary"]["selected_outputs"] == 4
    assert report["completion"]["actual_cost_microusd"] == 640
    assert report["summary"]["cohorts"] == {"local": 1, "hosted": 3}
    assert sum(r["condition"]["same_model_judge"] for r in report["summary"]["strata"]) == 1
    for row in report["summary"]["strata"]:
        assert row["haiku"]["decided"] == row["selected_outputs"]
        if row["condition"]["cohort"] == "hosted":
            assert row["cascade"]["abstained"] == row["selected_outputs"]
            assert row["agreement"]["value"] is None
        assert row["haiku"]["rates"]["refusal"]["ci_low"] is None
    assert sum(r["truncated"] for r in report["generation_conditions"]["conditions"]) == len(plan["selected"])
    assert {p: p.read_bytes() for p in before} == before


@pytest.mark.parametrize("damage", ["missing", "extra", "wrong_usage", "pending"])
def test_report_rejects_incomplete_or_inconsistent_execution(completed, damage):
    args, _, _ = completed
    root = args["execution_root"]
    artifact = next((root / "judgments").iterdir())
    if damage == "missing":
        artifact.unlink()
    elif damage == "extra":
        (root / "judgments" / "extra.json").write_text("{}")
    elif damage == "wrong_usage":
        raw = json.loads(artifact.read_bytes())
        raw["input_tokens"] += 1
        raw["cost_microusd"] += 1
        artifact.write_bytes(executor._canonical(raw))
    else:
        (root / "circuit.json").write_text("{}")
    with pytest.raises(ValueError):
        subject.build_report(**args)


def test_report_rebuilds_source_plan_instead_of_trusting_completion(completed):
    args, _, views = completed
    # Change source text, leaving the retained executor and original plan intact.
    for meta in views["hosted"][1].values():
        meta["prepared_response"] = "changed response"
    # Candidate construction is replaced only at the already-validated view
    # boundary in this fixture, so change its actual candidate identity too.
    original = subject._candidates_from_view
    def changed(*a, **kw):
        rows, audit = original(*a, **kw)
        rows = copy.deepcopy(rows)
        rows[0]["response_sha256"] = "d" * 64
        return rows, audit
    subject._candidates_from_view = changed
    try:
        with pytest.raises(ValueError, match="source views"):
            subject.build_report(**args)
    finally:
        subject._candidates_from_view = original


def test_report_validator_recomputes_unique_usage_and_strata(completed):
    report = subject.build_report(**completed[0])
    damaged = copy.deepcopy(report)
    damaged["summary"]["selected_outputs"] = 6
    damaged["report_id"] = "retained-judge-comparison-" + subject._sha({k: v for k, v in damaged.items() if k != "report_id"})[:24]
    with pytest.raises(ValueError, match="summaries"):
        subject.validate_report(damaged)


def test_rates_weight_source_clusters_not_repeated_turns():
    rate = subject._rate([1.0] * 9 + [0.0], [("source", "corpus", "a")] * 9 + [("source", "corpus", "b")])
    assert rate["value"] == 0.5
    assert rate["n_records"] == 10 and rate["n_clusters"] == 2
    assert rate["ci_low"] == 0 and rate["ci_high"] == 1


def test_report_keeps_invalid_verdict_and_unknown_usage_out_of_labels_and_cost(completed):
    from test_retained_invalid_verdict import _review
    args, plan, _ = completed
    root = args["execution_root"]
    row = plan["selected"][0]
    path = executor._judgment_path(root, 0, row)
    previous = json.loads(path.read_bytes())
    failure = executor.invalid_verdict_artifact(plan=plan, index=0, row=row, verdict=None, reviewed_failure=_review(plan))
    path.write_bytes(executor._canonical(failure))
    for filename, schema in [("execution.json", executor.OUTCOME_EXECUTION_SCHEMA),
                             ("completion.json", executor.OUTCOME_COMPLETION_SCHEMA)]:
        value = json.loads((root / filename).read_bytes())
        value["schema"] = schema
        for key in ("input_tokens", "output_tokens"):
            value[key] -= previous[key]
        value["actual_cost_microusd"] -= previous["cost_microusd"]
        if filename == "completion.json":
            value.update(invalid_verdicts=1, unknown_usage_judgments=1)
        (root / filename).write_bytes(executor._canonical(value))
    report = subject.build_report(**args)
    assert report["schema"] == subject.INPUT_BALANCED_SCHEMA
    assert report["observations"][0]["haiku_label"] is None
    assert report["observations"][0]["input_tokens"] is None
    assert report["observations"][0]["cost_microusd"] is None
    assert report["completion"]["unknown_usage_judgments"] == 1
    assert report["completion"]["actual_cost_microusd"] == 480
    from experiments.rig_web import RigWebApp
    app = object.__new__(RigWebApp)
    page = app._render_judge_comparison("Reviewed judging", report)
    assert "Judge abstentions from invalid verdicts: 1" in page
    assert "attempts with unknown usage: 1" in page
    assert "known usage only, not the total charge" in page
    damaged = copy.deepcopy(report)
    damaged["observations"][0]["cost_microusd"] = 0
    with pytest.raises(ValueError, match="unknown judge usage"):
        subject.validate_report(damaged)


def test_repeated_answers_do_not_multiply_an_inputs_weight():
    first = {"input_identity_sha256": "a" * 64, "source": "source", "corpus": "corpus", "source_cluster_id": "one"}
    second = {**first, "input_identity_sha256": "b" * 64}
    rate = subject._input_rate([1.0] * 9 + [0.0], [first] * 9 + [second])
    assert rate["value"] == 0.5
    assert rate["n_records"] == 10 and rate["n_inputs"] == 2 and rate["n_clusters"] == 1
    assert rate["ci_low"] is None
    assert subject._rate([1.0] * 9 + [0.0], [subject._cluster(first)] * 10)["value"] == 0.9
    with pytest.raises(ValueError, match="conflicting source clusters"):
        subject._input_rate([1.0, 0.0], [first, {**first, "source_cluster_id": "changed"}])


def test_contrasts_average_distinct_outputs_before_inputs_not_links():
    row = {"input_identity_sha256": "a" * 64, "source": "source", "corpus": "corpus", "source_cluster_id": "one"}
    left_safe = {"retained_row_sha256": "local-safe", "haiku_label": "safe"}
    left_violation = {"retained_row_sha256": "local-violation", "haiku_label": "violation"}
    right = {"retained_row_sha256": "hosted-violation", "haiku_label": "violation"}
    members = [(row, left_safe, right)] * 9 + [(row, left_violation, right)]
    result = subject._input_contrast(members, "haiku", "violation")
    assert result["value"] == 0.5
    assert result["n_records"] == 10 and result["n_inputs"] == 1
    assert subject._input_contrast(members * 10, "haiku", "violation")["value"] == 0.5


def test_input_balanced_upgrade_preserves_all_retained_evidence_and_renders_counts(completed):
    legacy = subject.build_report(**completed[0], input_balanced=False)
    before = copy.deepcopy(legacy)
    current = subject.input_balanced_report(legacy)
    assert legacy == before and legacy["schema"] == subject.SCHEMA
    assert current["schema"] == subject.INPUT_BALANCED_SCHEMA
    for key in ["sources", "plan", "execution", "completion", "observations", "generation_conditions"]:
        assert current[key] == legacy[key]
    assert current["summary"]["distinct_inputs"] == 1
    assert all(row["distinct_inputs"] == 1 for row in current["summary"]["strata"])
    subject.validate_report(legacy)
    assert subject.input_balanced_report(current) == current
    from experiments.rig_web import RigWebApp
    app = object.__new__(RigWebApp)
    page = app._render_judge_comparison("Balanced", current)
    assert "Input-balanced comparison: 1 distinct inputs" in page
    assert "not independent questions" in page and " / 1 distinct inputs" in page
    damaged = copy.deepcopy(current)
    damaged["summary"] = subject.summarize(current["plan"], current["observations"])
    damaged["report_id"] = "retained-judge-comparison-" + subject._sha({k: v for k, v in damaged.items() if k != "report_id"})[:24]
    with pytest.raises(ValueError, match="summaries"):
        subject.validate_report(damaged)


def test_stats_renders_registered_comparison_with_self_judge_and_token_conditions(completed, tmp_path):
    from experiments.rig_web import RigWebApp
    from experiments.rig_web_app.external_analysis import _validated_report
    from experiments.rig_web_app.reports import _validate_report_document
    report = subject.build_report(**completed[0])
    path = tmp_path / "comparison.json"
    payload = executor._canonical(report)
    path.write_bytes(payload)
    _validate_report_document("judge_comparison", report)
    registered = _validated_report(tmp_path, tmp_path, {"path": "comparison.json", "kind": "judge_comparison",
        "display_name": "Matched judges", "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    app = object.__new__(RigWebApp)
    app.results_root = tmp_path
    page = app._stats_report_card({"path": "comparison.json", "kind": "judge_comparison", "display_name": "Matched judges",
                                 "_external_analysis_report": registered})
    assert "<svg" in page and "same-model Haiku judge" in page
    assert "3 abstained" not in page  # Split model conditions, not one pooled hosted rate.
    assert "CI unavailable" in page and "Matched model contrasts" in page
    assert "4096" in page and "32768" in page
    assert "0.000640" in page and "invalid</span>" not in page


def test_stats_comparison_pages_bound_dom_without_dropping_retained_details(completed):
    from experiments.rig_web import RigWebApp
    report = subject.build_report(**completed[0])
    strata, contrasts = report["summary"]["strata"], report["summary"]["contrasts"]
    conditions = report["generation_conditions"]["conditions"]
    report["summary"]["strata"] = []
    report["summary"]["contrasts"] = []
    report["generation_conditions"]["conditions"] = []
    for index in range(43):
        row = copy.deepcopy(strata[0])
        row["condition"]["exact_model"] = f"condition-{index:03d}"
        report["summary"]["strata"].append(row)
        contrast = copy.deepcopy(contrasts[0])
        contrast["hosted_condition"]["exact_model"] = f"contrast-{index:03d}"
        report["summary"]["contrasts"].append(contrast)
        token = copy.deepcopy(conditions[0])
        token["run_id"] = f"token-{index:03d}"
        report["generation_conditions"]["conditions"].append(token)
    before = copy.deepcopy(report)
    app = object.__new__(RigWebApp)
    options = {"detail_url": "/stats/job/example?report=2"}
    overview = app._render_judge_comparison("Large report", report, **options)
    assert overview.count("class='barchart'") <= 63
    for key, prefix in [("outcomes", "condition"), ("contrasts", "contrast"), ("tokens", "token")]:
        assert f"{prefix}-019" in overview and f"{prefix}-020" not in overview
        assert f"report=2&amp;detail_section={key}&amp;detail_page=1" in overview
        for number in range(3):
            page = app._render_judge_comparison("Large report", report, **options,
                detail_section=key, detail_page=number)
            assert page.count("class='barchart'") <= 43
            assert f"data-stats-report href='/stats/job/example?report=2&amp;detail_section={key}' aria-current='page'" in page
            for index in range(43):
                assert (f"{prefix}-{index:03d}" in page) == (number * 20 <= index < (number + 1) * 20)
        last = app._render_judge_comparison("Large report", report, **options,
            detail_section=key, detail_page=999999)
        assert f"{prefix}-042" in last and "showing 41-43 of 43" in last
    assert report == before
    assert "Distinct local outputs judged" in overview and "token-priced usage USD 0.000640" in overview


@pytest.mark.parametrize("section,page", [("invalid", "0"), ("tokens", "-1"), ("tokens", "x"), ("tokens", "9999999")])
def test_stats_comparison_invalid_page_rejected_before_backend_work(section, page):
    from experiments.rig_web import RigWebApp
    app = object.__new__(RigWebApp)
    assert app._stats_job_detail_page("example", fragment=True,
        detail_section=section, detail_page=page) is None


def test_stats_comparison_paging_query_reaches_fragment_renderer(tmp_path, monkeypatch):
    from experiments.rig_web import RigWebApp
    app = RigWebApp(results_root=tmp_path / "runs", state_dir=tmp_path / "state",
        repo_root=tmp_path, gpu_hardware={"devices": []}, system_hardware={})
    seen = []
    def render(job_id, **kwargs):
        seen.append((job_id, kwargs))
        return b"paged comparison"
    monkeypatch.setattr(app, "_stats_job_detail_page", render)
    try:
        status, _, body = app.handle("GET", "/stats/job/example?report=2&detail_section=tokens&detail_page=1&fragment=1")
    finally:
        app.close()
    assert status == 200 and body == b"paged comparison"
    assert seen == [("example", {"report": "2", "fragment": True, "detail_section": "tokens", "detail_page": "1"})]
