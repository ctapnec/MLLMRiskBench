"""Compare independently completed judge batches without inventing an execution.

The comparison selector and its source views are revalidated. Every selected
answer must have one unambiguous, completed judgment under the same judge
condition. Source ledgers remain separate; only selected usage is summed.
"""
from __future__ import annotations

from collections import defaultdict
import copy
from pathlib import Path

from experiments import retained_response_judge as single
from experiments import retained_response_judge_pair as paired
from experiments import retained_response_judge_report as reports
from experiments import retained_response_judge_execute as execute
from experiments.generation_conditions import build_generation_conditions, validate_generation_conditions
from experiments.human_audit import _judge_configuration_binding

SCHEMA = "ura-retained-judge-comparison/4"
ALL_SCHEMA = "ura-retained-judge-comparison/5"
SELECTION_SCHEMA = "ura-retained-judge-population-selection/1"
LIMITATIONS = reports.OUTCOME_LIMITATIONS + reports.INPUT_LIMITATIONS + [
    "Judgments come from separately completed source executions; this report creates no combined execution or spending authority.",
    "Usage covers the distinct selected verdicts only, not all outputs or reservations in their source batches.",
]
CONDITION_FIELDS = ("model", "api_config_sha256", "answer_retries", "transport_retries",
    "pricing_config_sha256", "pricing_as_of", "pricing_effective_date", "pricing_currency",
    "input_microusd_per_token", "output_microusd_per_token")
ALL_LIMITATIONS = LIMITATIONS + [
    "Every eligible saved answer in the supplied views on their shared input identities is included; comparison links do not add judge calls.",
]


def build_population_selection(local_candidates, hosted_candidates, *, local_population_audit,
                               hosted_population_audit, source_descriptor, judge_condition):
    """Select all same-input answers for reporting, without execution authority."""
    edges, audit = paired._pair_edges(local_candidates, hosted_candidates, seed=0)
    if not edges:
        raise ValueError("population comparison has no shared input identities")
    condition = {key: judge_condition[key] for key in CONDITION_FIELDS}
    rows = {}
    links = []
    for edge in sorted(edges, key=lambda row: row["pair_id"]):
        link = {key: edge[key] for key in ("pair_id", "input_identity_sha256", "pair_stratum_id")}
        for cohort in ("local", "hosted"):
            row = {**edge[cohort], "cohort": cohort,
                   "same_model_judge": edge[cohort]["exact_model"] == condition["model"]}
            key = row["retained_row_sha256"]
            if key in rows and rows[key] != row:
                raise ValueError("population comparison has conflicting saved-answer identities")
            rows[key] = row
            link[cohort + "_retained_row_sha256"] = key
        links.append(link)
    value = {"schema": SELECTION_SCHEMA, "source": dict(source_descriptor),
        "judge_condition": condition, "selection": {"scope": "all_eligible_answers_on_shared_inputs",
            "sample_seed": 0, "new_target_calls": 0, "new_judge_calls": 0},
        "population": {"local": dict(local_population_audit), "hosted": dict(hosted_population_audit), **audit},
        "selected": sorted(rows.values(), key=lambda row: (row["cohort"], row["retained_row_sha256"])),
        "pairs": links}
    value["selection_id"] = "retained-judge-population-" + reports._sha(value)[:24]
    return value


def _comparison_plan(value):
    if not isinstance(value, dict) or value.get("schema") != SELECTION_SCHEMA:
        return paired.validate_pair_plan(value)
    if set(value) != {"schema", "source", "judge_condition", "selection", "population", "selected", "pairs", "selection_id"}:
        raise ValueError("population comparison selection fields differ")
    rows = value["selected"]
    if (not isinstance(rows, list) or not rows or any(not isinstance(row, dict)
        or set(row) != paired._BASE_ROW_FIELDS | {"cohort", "same_model_judge"} for row in rows)):
        raise ValueError("population comparison selected answers differ")
    grouped = {cohort: [{key: row[key] for key in paired._BASE_ROW_FIELDS}
                       for row in rows if row["cohort"] == cohort] for cohort in ("local", "hosted")}
    rebuilt = build_population_selection(grouped["local"], grouped["hosted"],
        local_population_audit=value["population"]["local"], hosted_population_audit=value["population"]["hosted"],
        source_descriptor=value["source"], judge_condition=value["judge_condition"])
    # Unmatched source inputs are outside this comparison, but stay in its frame audit.
    for key in ("unmatched_local_distinct_input_identities", "unmatched_hosted_distinct_input_identities"):
        count = value["population"].get(key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("population comparison unmatched input count is invalid")
        rebuilt["population"][key] = count
    rebuilt["selection_id"] = "retained-judge-population-" + reports._sha({k: v for k, v in rebuilt.items() if k != "selection_id"})[:24]
    if rebuilt != value:
        raise ValueError("population comparison dropped or changed matched answers or links")
    return value


def _validated_views(local_root, hosted_root, plan, source):
    if plan["schema"] != SELECTION_SCHEMA:
        return reports._validated_views(local_root, hosted_root, plan, source)
    local, hosted = reports._read_view(local_root.resolve(strict=True)), reports._read_view(hosted_root.resolve(strict=True))
    local_rows, local_audit = reports._candidates_from_view(*local, include_match_identity=True)
    hosted_rows, hosted_audit = reports._candidates_from_view(*hosted, include_match_identity=True, original_cells=local[0])
    rebuilt = build_population_selection(local_rows, hosted_rows, local_population_audit=local_audit,
        hosted_population_audit=hosted_audit, source_descriptor=source, judge_condition=plan["judge_condition"])
    if rebuilt != plan:
        raise ValueError("population comparison no longer includes all matching source answers")
    return {"local": local, "hosted": hosted}


def _plan(value):
    return single.validate_plan(value) if value.get("schema") == single.SCHEMA else paired.validate_pair_plan(value)


def _read_partition(plan_path: Path, execution_root: Path) -> dict:
    plan, plan_desc = execute._read_regular(plan_path, label="source judge plan", max_bytes=32 * 1024 * 1024)
    _plan(plan)
    root = execution_root.resolve(strict=True)
    if (root / "circuit.json").exists():
        raise ValueError("source judgment execution has an unresolved circuit")
    ledger, ledger_desc = execute._read_regular(root / "execution.json", label="source judge ledger", max_bytes=1024 * 1024)
    completion, completion_desc = execute._read_regular(root / "completion.json", label="source judge completion", max_bytes=1024 * 1024)
    expected = {execute._judgment_path(root, index, row).name for index, row in enumerate(plan["selected"])}
    if {p.name for p in (root / "judgments").iterdir()} != expected:
        raise ValueError("source judgment artifact inventory differs from its complete plan")
    judgments, descriptors = [], []
    for index, row in enumerate(plan["selected"]):
        value, descriptor = execute._read_regular(execute._judgment_path(root, index, row), label="source judgment", max_bytes=1024 * 1024)
        judgments.append(value)
        descriptors.append(descriptor)
    return {"plan": plan, "execution": ledger, "completion": completion, "judgments": judgments,
            "sources": {"plan": plan_desc, "execution": ledger_desc, "completion": completion_desc,
                        "judgments": descriptors}}


def _descriptor(value: dict, descriptor: dict) -> None:
    if (set(descriptor) != {"file", "sha256", "bytes"}
        or not isinstance(descriptor["file"], str) or Path(descriptor["file"]).name != descriptor["file"]
        or descriptor["bytes"] != len(execute._canonical(value))
        or descriptor["sha256"] != reports._sha(value)):
        raise ValueError("partitioned comparison source content differs from its descriptor")


def _joined_judgments(plan: dict, partitions: list[dict]) -> dict:
    selected = {row["retained_row_sha256"]: row for row in plan["selected"]}
    found, seen_partitions = {}, set()
    for partition in partitions:
        if set(partition) != {"plan", "execution", "completion", "judgments", "sources"}:
            raise ValueError("partitioned comparison source fields differ")
        source_plan = _plan(partition["plan"])
        sources = partition["sources"]
        if set(sources) != {"plan", "execution", "completion", "judgments"}:
            raise ValueError("partitioned comparison source descriptors are missing")
        for role in ("plan", "execution", "completion"):
            _descriptor(partition[role], sources[role])
        identity = sources["plan"]["sha256"], sources["execution"]["sha256"]
        if identity in seen_partitions:
            raise ValueError("partitioned comparison repeats one source execution")
        seen_partitions.add(identity)
        if any(source_plan["judge_condition"].get(k) != plan["judge_condition"].get(k) for k in CONDITION_FIELDS):
            raise ValueError("partitioned comparison changed the actual judge condition")
        ledger = execute._validate_ledger(partition["execution"], source_plan, sources["plan"]["sha256"])
        if ledger["state"] != "complete":
            raise ValueError("partitioned comparison requires completed source judging")
        execute._validate_completion(partition["completion"], plan=source_plan, ledger=ledger,
                                     plan_sha256=sources["plan"]["sha256"])
        if len(partition["judgments"]) != len(source_plan["selected"]) or len(sources["judgments"]) != len(partition["judgments"]):
            raise ValueError("partitioned comparison omits a source judgment artifact")
        usage = defaultdict(int)
        for index, (original, artifact, descriptor) in enumerate(zip(source_plan["selected"], partition["judgments"], sources["judgments"], strict=True)):
            _descriptor(artifact, descriptor)
            execute._validate_artifact(artifact, plan=source_plan, index=index, row=original)
            for key in ("input_tokens", "output_tokens", "cost_microusd"):
                usage[key] += artifact[key] or 0
            usage["http_attempts"] += execute._artifact_http_attempts(artifact)
            key = original["retained_row_sha256"]
            if key not in selected:
                continue
            wanted = selected[key]
            if any(original[field] != wanted[field] for field in single._SELECTED_FIELDS):
                raise ValueError("partitioned judgment belongs to another selected output")
            previous = found.get(key)
            if previous is not None and previous != artifact:
                raise ValueError("selected output has ambiguous completed judgments")
            found[key] = artifact
        for field, ledger_field in (("input_tokens", "input_tokens"), ("output_tokens", "output_tokens"),
                                    ("cost_microusd", "actual_cost_microusd"), ("http_attempts", "http_attempts_observed")):
            if usage[field] != ledger[ledger_field]:
                raise ValueError("source judgment artifacts do not reconcile with their paid ledger")
    if set(found) != set(selected):
        raise ValueError("partitioned comparison is missing a selected output judgment")
    return found


def _accounting(observations: list[dict]) -> dict:
    return {"schema": "ura-retained-judge-comparison-accounting/1", "new_judge_calls": 0,
            "judge_calls": len(observations), "http_attempts": sum(o["http_attempts"] for o in observations),
            "input_tokens": sum(o["input_tokens"] or 0 for o in observations),
            "output_tokens": sum(o["output_tokens"] or 0 for o in observations),
            "actual_cost_microusd": sum(o["cost_microusd"] or 0 for o in observations),
            "invalid_verdicts": sum(o["judge_status"] == "invalid_verdict" for o in observations),
            "unknown_usage_judgments": sum(o["usage_status"] == "unknown" for o in observations)}


def _verdict_fields(artifact: dict) -> dict:
    return {"haiku_label": reports._decision(artifact["judgment"], cascade=False),
            **{key: artifact[key] for key in ("input_tokens", "output_tokens", "cost_microusd")},
            "http_attempts": execute._artifact_http_attempts(artifact),
            "usage_status": "unknown" if artifact["cost_microusd"] is None else "reported",
            "judge_status": "invalid_verdict" if artifact["schema"] == execute.INVALID_JUDGMENT_SCHEMA else "valid_verdict"}


def build_report(*, plan_path: Path, partitions: list[dict], local_runner_view: Path,
                 hosted_runner_view: Path, source_receipt: Path) -> dict:
    plan, plan_desc = execute._read_regular(plan_path, label="comparison selection", max_bytes=32 * 1024 * 1024)
    _comparison_plan(plan)
    source = single._regular_descriptor(source_receipt, plan["source"]["sha256"])
    if source != plan["source"]:
        raise ValueError("comparison source receipt differs from its selection")
    views = _validated_views(local_runner_view, hosted_runner_view, plan, source)
    parts = [_read_partition(Path(p["plan_path"]), Path(p["execution_root"])) for p in partitions]
    artifacts = _joined_judgments(plan, parts)
    cells = {(cohort, c["run_id"]): c for cohort, view in views.items() for c in view[0]}
    observations, configurations, selected_attempts = [], {}, defaultdict(set)
    for row in plan["selected"]:
        original = views[row["cohort"]][2][row["sample_key"]]
        if original["attempt_id"] != row["attempt_id"]:
            raise ValueError("partitioned comparison changed the original cascade identity")
        key = row["cohort"], row["run_id"]
        if key not in configurations:
            configurations[key] = _judge_configuration_binding([cells[key]])["sha256"]
        observations.append({"retained_row_sha256": row["retained_row_sha256"],
            "cascade_label": reports._decision(original, cascade=True),
            "cascade_configuration_sha256": configurations[key],
            "cascade_judgment_sha256": reports._sha({k: v for k, v in original.items() if k != "_artifact_file"}),
            **_verdict_fields(artifacts[row["retained_row_sha256"]])})
        selected_attempts[key].add(row["attempt_id"])
    generation = []
    for key, attempts in selected_attempts.items():
        cell = cells[key]
        if not attempts <= cell["responses"].keys():
            raise ValueError("partitioned comparison selected a missing target output")
        generation.append({**cell, "responses": {key: cell["responses"][key] for key in sorted(attempts)}})
    all_answers = plan["schema"] == SELECTION_SCHEMA
    result = {"schema": ALL_SCHEMA if all_answers else SCHEMA, "status": "complete", "plan": plan, "plan_descriptor": plan_desc,
        "source_partitions": parts, "observations": observations, "completion": _accounting(observations),
        "summary": reports.summarize(plan, observations, input_balanced=True),
        "generation_conditions": build_generation_conditions(generation), "limitations": copy.deepcopy(ALL_LIMITATIONS if all_answers else LIMITATIONS),
        "uncertainty": {"method": "equal_source_cluster_bootstrap", "resamples": 2000, "seed": 0,
            "confidence": 0.95, "minimum_clusters": 2, "input_weighting": reports.INPUT_WEIGHTING}}
    result["report_id"] = "retained-judge-comparison-" + reports._sha(result)[:24]
    validate_report(result)
    return result


def validate_report(value: object) -> None:
    if (not isinstance(value, dict) or set(value) != {"schema", "status", "plan", "plan_descriptor", "source_partitions",
        "observations", "completion", "summary", "generation_conditions", "limitations", "uncertainty", "report_id"}
        or value["schema"] not in {SCHEMA, ALL_SCHEMA} or value["status"] != "complete"
        or not isinstance(value["source_partitions"], list) or not value["source_partitions"]):
        raise ValueError("invalid partitioned judge comparison")
    plan = _comparison_plan(value["plan"])
    all_answers = plan["schema"] == SELECTION_SCHEMA
    if (value["schema"] == ALL_SCHEMA) != all_answers:
        raise ValueError("population comparison report and selection scope differ")
    _descriptor(plan, value["plan_descriptor"])
    artifacts = _joined_judgments(plan, value["source_partitions"])
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != len(plan["selected"]):
        raise ValueError("partitioned comparison output counts differ")
    for row, observation in zip(plan["selected"], observations, strict=True):
        verdict = _verdict_fields(artifacts[row["retained_row_sha256"]])
        if (set(observation) != {"retained_row_sha256", "cascade_label", "cascade_configuration_sha256", "cascade_judgment_sha256", *verdict}
            or observation["retained_row_sha256"] != row["retained_row_sha256"]
            or any(observation[key] != val for key, val in verdict.items())
            or observation["cascade_label"] not in (*reports.LABELS, None)):
            raise ValueError("partitioned comparison verdict or output identity differs")
        for field in ("cascade_configuration_sha256", "cascade_judgment_sha256"):
            digest = observation[field]
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("partitioned comparison cascade identity is invalid")
    validate_generation_conditions(value["generation_conditions"], {row["run_id"] for row in plan["selected"]})
    expected, actual = defaultdict(int), defaultdict(int)
    for row in plan["selected"]:
        expected[row["run_id"]] += 1
    for condition in value["generation_conditions"]["conditions"]:
        actual[condition["run_id"]] += condition["rows"]
    if actual != expected:
        raise ValueError("partitioned comparison generation population differs")
    if (value["completion"] != _accounting(observations)
        or value["summary"] != reports.summarize(plan, observations, input_balanced=True)
        or value["limitations"] != (ALL_LIMITATIONS if all_answers else LIMITATIONS)
        or value["uncertainty"] != {"method": "equal_source_cluster_bootstrap", "resamples": 2000, "seed": 0,
            "confidence": 0.95, "minimum_clusters": 2, "input_weighting": reports.INPUT_WEIGHTING}
        or value["report_id"] != "retained-judge-comparison-" + reports._sha({k: v for k, v in value.items() if k != "report_id"})[:24]):
        raise ValueError("partitioned comparison summaries or content identity differ")
