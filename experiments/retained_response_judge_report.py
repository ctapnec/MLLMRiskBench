"""Read-only matched local/hosted judge comparisons from completed artifacts.

This report does not execute an evaluator. Original cascade decisions, Haiku
decisions and source-population coverage remain different observations.
"""
from __future__ import annotations

import argparse
import copy
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments.generation_conditions import (
    build_generation_conditions, validate_generation_conditions,
)
from experiments.human_audit import _judge_configuration_binding
from experiments.retained_response_judge import (
    _candidates_from_view, _read_view, _regular_descriptor, _sha,
)
from experiments.retained_response_judge_execute import (
    INVALID_JUDGMENT_SCHEMA, OUTCOME_EXECUTION_SCHEMA,
    _artifact_http_attempts, _judgment_path, _read_regular,
    _validate_artifact, _validate_completion, _validate_ledger, _write_new,
)
from experiments.retained_response_judge_pair import (
    SHARED_SCHEMA, build_pair_plan, validate_pair_plan,
)
from ura.data_models import Judgment
from ura.metrics import equal_cluster_bootstrap_ci, equal_cluster_mean

SCHEMA = "ura-retained-judge-comparison/1"
OUTCOME_SCHEMA = "ura-retained-judge-comparison/2"
INPUT_BALANCED_SCHEMA = "ura-retained-judge-comparison/3"
INPUT_WEIGHTING = "equal_input_within_equal_source_cluster"
INPUT_LIMITATIONS = [
    "Repeated outputs are averaged within each exact input before equal source-cluster weighting; they are not independent questions.",
    "Matched contrasts average distinct saved outputs on each side of an input; repeated comparison links never multiply a saved output's weight.",
]
LABELS = ("safe", "violation", "refusal", "over_refusal")
DIMENSIONS = (
    "cohort", "exact_model", "framework", "corpus", "source", "modality",
    "risk", "expected_behavior", "source_policy_id", "source_policy_version",
    "project_revision_sha256", "output_policy_sha256", "same_model_judge",
)
LIMITATIONS = [
    "Selected usable matched outputs only; not full-corpus model rankings.",
    "Source coverage is the supplied view's frame, not the selected cohort denominator.",
    "Original cascade and Haiku decisions are not human-validated ground truth.",
    "Physical media were not sent to Haiku; image judgments are text-reference/output proxies.",
    "Same-model Haiku judgments are marked and are not independent judge evidence.",
    "Shared local judgments are counted once; comparison links are not independent observations.",
    "Cost is token-priced successful-judgment usage, not an invoice or release of unknown retry holds.",
    "Target spending and missing-input coverage remain in the source campaign reports.",
]
OUTCOME_LIMITATIONS = LIMITATIONS + [
    "Invalid judge verdicts are abstentions, not safe or harmful labels, and are not answer-retried.",
    "Usage totals include only reported tokens; unknown-usage attempts remain separately counted and fully reserved.",
]


def _decision(value: Mapping[str, Any], *, cascade: bool) -> str | None:
    judgment = Judgment.model_validate(value)
    raw = judgment.raw
    decided = (raw.get("cascade_confident") is True if cascade
               else raw.get("parsed") is True)
    return judgment.label if decided and raw.get("parsed") is not False and judgment.label in LABELS else None


def _rate(values: list[float], clusters: list[tuple]) -> dict:
    count = len(set(clusters))
    bounds = (equal_cluster_bootstrap_ci(values, clusters, seed=0)
              if count >= 2 else (None, None))
    return {"value": equal_cluster_mean(values, clusters) if values else None,
            "ci_low": bounds[0], "ci_high": bounds[1],
            "n_records": len(values), "n_clusters": count}


def _cluster(row: Mapping[str, Any]) -> tuple:
    # Seeds/turns/attack variants from one source cluster stay together.
    return row["source"], row["corpus"], row["source_cluster_id"]


def _input_rate(values: list[float], rows: list[dict]) -> dict:
    groups: dict[str, list[float]] = defaultdict(list)
    clusters = {}
    for value, row in zip(values, rows, strict=True):
        identity, cluster = row["input_identity_sha256"], _cluster(row)
        if identity in clusters and clusters[identity] != cluster:
            raise ValueError("one comparison input has conflicting source clusters")
        clusters[identity] = cluster
        groups[identity].append(value)
    ordered = sorted(groups)
    result = _rate([sum(groups[key]) / len(groups[key]) for key in ordered],
                   [clusters[key] for key in ordered])
    return {**result, "n_records": len(values), "n_inputs": len(ordered)}


def _input_contrast(members: list[tuple[dict, dict, dict]], judge: str, event: str) -> dict:
    groups: dict[str, tuple[dict, dict, dict]] = {}
    for row, local, hosted in members:
        identity = row["input_identity_sha256"]
        original, left, right = groups.setdefault(identity, (row, {}, {}))
        if _cluster(original) != _cluster(row):
            raise ValueError("one contrast input has conflicting source clusters")
        left[local["retained_row_sha256"]] = float(local[judge + "_label"] == event)
        right[hosted["retained_row_sha256"]] = float(hosted[judge + "_label"] == event)
    rows, differences = [], []
    for identity in sorted(groups):
        row, left, right = groups[identity]
        rows.append(row)
        differences.append(sum(right.values()) / len(right) - sum(left.values()) / len(left))
    result = _input_rate(differences, rows)
    return {**result, "n_records": len(members)}


def summarize(plan: dict, observations: list[dict], *, input_balanced: bool = False) -> dict:
    by_id = {row["retained_row_sha256"]: (row, obs)
             for row, obs in zip(plan["selected"], observations, strict=True)}
    groups: dict[tuple, list[tuple[dict, dict]]] = defaultdict(list)
    for row, obs in by_id.values():
        key = tuple(row[field] for field in DIMENSIONS) + (obs["cascade_configuration_sha256"],)
        groups[key].append((row, obs))
    strata = []
    for key, members in sorted(groups.items()):
        identity = dict(zip((*DIMENSIONS, "cascade_configuration_sha256"), key, strict=True))
        result = {"condition": identity, "selected_outputs": len(members)}
        if input_balanced:
            result["distinct_inputs"] = len({r["input_identity_sha256"] for r, _ in members})
        for judge in ("cascade", "haiku"):
            decided = [(r, o) for r, o in members if o[judge + "_label"] is not None]
            clusters = [_cluster(r) for r, _ in decided]
            result[judge] = {
                "decided": len(decided), "abstained": len(members) - len(decided),
                "labels": {label: sum(o[judge + "_label"] == label for _, o in decided) for label in LABELS},
                "rates": {label: (_input_rate([float(o[judge + "_label"] == label) for _, o in decided], [r for r, _ in decided])
                                  if input_balanced else _rate([float(o[judge + "_label"] == label) for _, o in decided], clusters))
                          for label in LABELS},
            }
        shared = [(r, o) for r, o in members if o["cascade_label"] is not None and o["haiku_label"] is not None]
        agreement = [float(o["cascade_label"] == o["haiku_label"]) for _, o in shared]
        result["agreement"] = (_input_rate(agreement, [r for r, _ in shared]) if input_balanced
                               else _rate(agreement, [_cluster(r) for r, _ in shared]))
        result["agreement"]["excluded_abstentions"] = len(members) - len(shared)
        strata.append(result)

    pairs: dict[tuple, list[tuple[dict, dict, dict]]] = defaultdict(list)
    legacy = {(row.get("pair_id"), row["cohort"]): row["retained_row_sha256"] for row in plan["selected"]}
    for pair in plan["pairs"]:
        local_id = pair.get("local_retained_row_sha256") or legacy[pair["pair_id"], "local"]
        hosted_id = pair.get("hosted_retained_row_sha256") or legacy[pair["pair_id"], "hosted"]
        local, local_obs = by_id[local_id]
        hosted, hosted_obs = by_id[hosted_id]
        key = tuple(local[field] for field in DIMENSIONS) + tuple(hosted[field] for field in DIMENSIONS)
        key += (local_obs["cascade_configuration_sha256"], hosted_obs["cascade_configuration_sha256"])
        pairs[key].append((local, local_obs, hosted_obs))
    contrasts = []
    for key, members in sorted(pairs.items()):
        width = len(DIMENSIONS)
        event = "violation" if members[0][0]["expected_behavior"] == "refuse" else "over_refusal"
        result = {"local_condition": dict(zip(DIMENSIONS, key[:width], strict=True)),
                  "hosted_condition": dict(zip(DIMENSIONS, key[width:2 * width], strict=True)),
                  "local_cascade_configuration_sha256": key[-2],
                  "hosted_cascade_configuration_sha256": key[-1],
                  "pairs": len(members), "event": event, "direction": "hosted_minus_local"}
        for judge in ("cascade", "haiku"):
            comparable = [(r, a, b) for r, a, b in members if a[judge + "_label"] is not None and b[judge + "_label"] is not None]
            result[judge] = (_input_contrast(comparable, judge, event) if input_balanced else
                            _rate([float(b[judge + "_label"] == event) - float(a[judge + "_label"] == event)
                                   for _, a, b in comparable], [_cluster(r) for r, _, _ in comparable]))
            result[judge]["excluded_abstentions"] = len(members) - len(comparable)
        contrasts.append(result)
    result = {"strata": strata, "contrasts": contrasts,
            "selected_outputs": len(observations), "comparison_pairs": len(plan["pairs"]),
            "cohorts": {cohort: sum(row["cohort"] == cohort for row in plan["selected"])
                        for cohort in ("local", "hosted")}}
    if input_balanced:
        result["input_weighting"] = INPUT_WEIGHTING
        result["distinct_inputs"] = len({row["input_identity_sha256"] for row in plan["selected"]})
    return result


def input_balanced_report(report: dict) -> dict:
    """Derive a new analysis from a validated completed report, without any calls."""
    validate_report(report)
    value = copy.deepcopy(report)
    value["schema"] = INPUT_BALANCED_SCHEMA
    value["summary"] = summarize(value["plan"], value["observations"], input_balanced=True)
    outcomes = value["execution"]["schema"] == OUTCOME_EXECUTION_SCHEMA
    value["limitations"] = (OUTCOME_LIMITATIONS if outcomes else LIMITATIONS) + INPUT_LIMITATIONS
    value["uncertainty"]["input_weighting"] = INPUT_WEIGHTING
    value["report_id"] = "retained-judge-comparison-" + _sha({k: v for k, v in value.items() if k != "report_id"})[:24]
    validate_report(value)
    return value


def _validated_views(local_root: Path, hosted_root: Path, plan: dict, source: dict) -> dict:
    local, hosted = _read_view(local_root.resolve(strict=True)), _read_view(hosted_root.resolve(strict=True))
    local_candidates, local_audit = _candidates_from_view(*local, include_match_identity=True)
    hosted_candidates, hosted_audit = _candidates_from_view(*hosted, include_match_identity=True, original_cells=local[0])
    condition = plan["judge_condition"]
    rebuilt = build_pair_plan(
        local_candidates, hosted_candidates, local_population_audit=local_audit,
        hosted_population_audit=hosted_audit, source_descriptor=source,
        judge_model=condition["model"], api_config_sha256=condition["api_config_sha256"],
        pricing_condition={key: condition[key] for key in (
            "pricing_config_sha256", "pricing_as_of", "pricing_effective_date", "pricing_currency",
            "input_microusd_per_token", "output_microusd_per_token")},
        limit=plan["selection"]["requested_pair_limit"], seed=plan["selection"]["sample_seed"],
        max_cost_microusd=condition["max_cost_microusd"], share_local_judgments=plan["schema"] == SHARED_SCHEMA,
    )
    if rebuilt != plan:
        raise ValueError("matched comparison plan no longer matches its source views")
    return {"local": local, "hosted": hosted}


def build_report(*, plan_path: Path, execution_root: Path, local_runner_view: Path,
                 hosted_runner_view: Path, source_receipt: Path, input_balanced: bool = True) -> dict:
    raw_plan, plan_descriptor = _read_regular(plan_path, label="judge plan", max_bytes=32 * 1024 * 1024)
    plan = validate_pair_plan(raw_plan)
    source = _regular_descriptor(source_receipt, plan["source"]["sha256"])
    if source != plan["source"]:
        raise ValueError("source receipt differs from judge plan")
    root = execution_root.resolve(strict=True)
    if (root / "circuit.json").exists():
        raise ValueError("judge execution has an unresolved circuit")
    ledger, ledger_descriptor = _read_regular(root / "execution.json", label="judge ledger", max_bytes=1024 * 1024)
    _validate_ledger(ledger, plan, plan_descriptor["sha256"])
    if ledger["state"] != "complete":
        raise ValueError("judge execution is not complete")
    completion, completion_descriptor = _read_regular(root / "completion.json", label="judge completion", max_bytes=1024 * 1024)
    _validate_completion(completion, plan=plan, ledger=ledger, plan_sha256=plan_descriptor["sha256"])
    expected = {_judgment_path(root, index, row).name for index, row in enumerate(plan["selected"])}
    if {p.name for p in (root / "judgments").iterdir()} != expected:
        raise ValueError("judge artifact inventory differs from exact selected outputs")
    views = _validated_views(local_runner_view, hosted_runner_view, plan, source)
    cells = {(cohort, cell["run_id"]): cell for cohort, view in views.items() for cell in view[0]}
    configurations = {}
    observations, descriptors = [], []
    selected_attempts: dict[tuple, set] = defaultdict(set)
    for index, row in enumerate(plan["selected"]):
        artifact, descriptor = _read_regular(_judgment_path(root, index, row), label="judge artifact", max_bytes=1024 * 1024)
        _validate_artifact(artifact, plan=plan, index=index, row=row)
        original = views[row["cohort"]][2][row["sample_key"]]
        key = row["cohort"], row["run_id"]
        if key not in configurations:
            configurations[key] = _judge_configuration_binding([cells[key]])["sha256"]
        # LLMJudge leaves run_id unset; the executor binds the plan row and
        # sample key independently. Reject a contradictory ID when supplied.
        if (original["attempt_id"] != row["attempt_id"]
            or artifact["judgment"].get("run_id") not in (None, row["run_id"])):
            raise ValueError("same-output judgment identity differs")
        call_tokens = artifact["judgment"]["raw"]["judge_call"]["tokens"]
        if (call_tokens.get("input"), call_tokens.get("output")) != (artifact["input_tokens"], artifact["output_tokens"]):
            raise ValueError("judge artifact usage differs from the provider response")
        observation = {
            "retained_row_sha256": row["retained_row_sha256"],
            "cascade_label": _decision(original, cascade=True),
            "haiku_label": _decision(artifact["judgment"], cascade=False),
            "cascade_configuration_sha256": configurations[key],
            "cascade_judgment_sha256": _sha({k: v for k, v in original.items() if k != "_artifact_file"}),
            "input_tokens": artifact["input_tokens"], "output_tokens": artifact["output_tokens"],
            "cost_microusd": artifact["cost_microusd"], "http_attempts": _artifact_http_attempts(artifact),
        }
        if ledger["schema"] == OUTCOME_EXECUTION_SCHEMA:
            observation.update(usage_status="unknown" if artifact["cost_microusd"] is None else "reported",
                               judge_status="invalid_verdict" if artifact["schema"] == INVALID_JUDGMENT_SCHEMA else "valid_verdict")
        observations.append(observation)
        descriptors.append(descriptor)
        selected_attempts[key].add(row["attempt_id"])
    generation_cells = []
    for key, attempts in selected_attempts.items():
        cell = cells[key]
        if not attempts <= cell["responses"].keys():
            raise ValueError("selected output is absent from validated response artifacts")
        generation_cells.append({**cell, "responses": {a: cell["responses"][a] for a in sorted(attempts)}})
    report = {
        "schema": OUTCOME_SCHEMA if ledger["schema"] == OUTCOME_EXECUTION_SCHEMA else SCHEMA,
        "status": "complete", "plan": plan,
        "sources": {"plan": plan_descriptor, "execution": ledger_descriptor,
                    "completion": completion_descriptor, "judgments": descriptors},
        "execution": ledger, "completion": completion, "observations": observations,
        "summary": summarize(plan, observations),
        "generation_conditions": build_generation_conditions(generation_cells),
        "limitations": OUTCOME_LIMITATIONS if ledger["schema"] == OUTCOME_EXECUTION_SCHEMA else LIMITATIONS,
        "uncertainty": {"method": "equal_source_cluster_bootstrap", "resamples": 2000,
                        "seed": 0, "confidence": 0.95, "minimum_clusters": 2},
    }
    report["report_id"] = "retained-judge-comparison-" + _sha(report)[:24]
    validate_report(report)
    return input_balanced_report(report) if input_balanced else report


def validate_report(value: object) -> None:
    if isinstance(value, dict) and value.get("schema") == "ura-retained-judge-comparison/4":
        from experiments.retained_judge_partitioned_report import validate_report as validate_partitioned
        validate_partitioned(value)
        return
    if not isinstance(value, dict) or set(value) != {
        "schema", "status", "plan", "sources", "execution", "completion", "observations",
        "summary", "generation_conditions", "limitations", "uncertainty", "report_id",
    } or value["schema"] not in {SCHEMA, OUTCOME_SCHEMA, INPUT_BALANCED_SCHEMA} or value["status"] != "complete":
        raise ValueError("invalid matched judge comparison report")
    plan = validate_pair_plan(value["plan"])
    sources = value["sources"]
    if not isinstance(sources, dict) or set(sources) != {"plan", "execution", "completion", "judgments"}:
        raise ValueError("matched comparison source descriptors are missing")
    if not isinstance(sources["judgments"], list) or len(sources["judgments"]) != len(plan["selected"]):
        raise ValueError("matched comparison judgment descriptors differ")
    for descriptor in [sources[k] for k in ("plan", "execution", "completion")] + sources["judgments"]:
        if (not isinstance(descriptor, dict) or set(descriptor) != {"file", "sha256", "bytes"}
            or not isinstance(descriptor["file"], str) or Path(descriptor["file"]).name != descriptor["file"]
            or type(descriptor["bytes"]) is not int or descriptor["bytes"] < 1
            or not isinstance(descriptor["sha256"], str) or len(descriptor["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in descriptor["sha256"])):
            raise ValueError("invalid matched comparison source descriptor")
    ledger = _validate_ledger(value["execution"], plan, sources["plan"]["sha256"])
    balanced = value["schema"] == INPUT_BALANCED_SCHEMA
    outcomes = ledger["schema"] == OUTCOME_EXECUTION_SCHEMA
    if not balanced and outcomes != (value["schema"] == OUTCOME_SCHEMA):
        raise ValueError("judge outcome report and execution policies differ")
    if ledger["state"] != "complete":
        raise ValueError("matched comparison requires a completed execution")
    _validate_completion(value["completion"], plan=plan, ledger=ledger, plan_sha256=sources["plan"]["sha256"])
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != len(plan["selected"]):
        raise ValueError("matched comparison output counts differ")
    for row, obs in zip(plan["selected"], observations, strict=True):
        if not isinstance(obs, dict) or set(obs) != {
            "retained_row_sha256", "cascade_label", "haiku_label", "cascade_configuration_sha256",
            "cascade_judgment_sha256", "input_tokens", "output_tokens", "cost_microusd", "http_attempts",
        } | ({"usage_status", "judge_status"} if outcomes else set()) or obs["retained_row_sha256"] != row["retained_row_sha256"]:
            raise ValueError("matched comparison same-output join changed")
        if any(obs[k] not in (*LABELS, None) for k in ("cascade_label", "haiku_label")):
            raise ValueError("matched comparison label is invalid")
        if any(not isinstance(obs[k], str) or len(obs[k]) != 64 or any(c not in "0123456789abcdef" for c in obs[k])
               for k in ("cascade_configuration_sha256", "cascade_judgment_sha256")):
            raise ValueError("matched comparison original judge identity is invalid")
        if outcomes:
            if (obs["usage_status"] not in {"reported", "unknown"}
                or obs["judge_status"] not in {"valid_verdict", "invalid_verdict"}
                or obs["judge_status"] == "invalid_verdict" and obs["haiku_label"] is not None):
                raise ValueError("invalid judge verdict cannot contribute a safety label")
            if obs["usage_status"] == "unknown":
                if (obs["judge_status"] != "invalid_verdict"
                    or any(obs[k] is not None for k in ("input_tokens", "output_tokens", "cost_microusd"))
                    or type(obs["http_attempts"]) is not int or not 1 <= obs["http_attempts"] <= 4):
                    raise ValueError("unknown judge usage must remain null, not zero-priced")
                continue
        if (any(type(obs[k]) is not int or obs[k] < 0 for k in ("input_tokens", "output_tokens", "cost_microusd", "http_attempts"))
            or not 1 <= obs["http_attempts"] <= 4 or obs["cost_microusd"] != obs["input_tokens"] + obs["output_tokens"] * 5):
            raise ValueError("matched comparison usage is invalid")
    for source, target in (("input_tokens", "input_tokens"), ("output_tokens", "output_tokens"),
                           ("cost_microusd", "actual_cost_microusd"), ("http_attempts", "http_attempts_observed")):
        if sum(obs[source] for obs in observations if obs[source] is not None) != ledger[target]:
            raise ValueError("matched comparison unique-output usage does not reconcile")
    if outcomes and (value["completion"]["invalid_verdicts"] != sum(obs["judge_status"] == "invalid_verdict" for obs in observations)
        or value["completion"]["unknown_usage_judgments"] != sum(obs["usage_status"] == "unknown" for obs in observations)):
        raise ValueError("matched comparison invalid-verdict coverage differs")
    validate_generation_conditions(value["generation_conditions"], {row["run_id"] for row in plan["selected"]})
    actual_runs: dict[str, int] = defaultdict(int)
    expected_runs: dict[str, int] = defaultdict(int)
    for condition in value["generation_conditions"]["conditions"]:
        actual_runs[condition["run_id"]] += condition["rows"]
    for row in plan["selected"]:
        expected_runs[row["run_id"]] += 1
    if actual_runs != expected_runs:
        raise ValueError("matched comparison generation population differs")
    if (value["summary"] != summarize(plan, observations, input_balanced=balanced)
        or value["limitations"] != (OUTCOME_LIMITATIONS if outcomes else LIMITATIONS) + (INPUT_LIMITATIONS if balanced else [])
        or value["uncertainty"] != {"method": "equal_source_cluster_bootstrap", "resamples": 2000,
                                   "seed": 0, "confidence": 0.95, "minimum_clusters": 2,
                                   **({"input_weighting": INPUT_WEIGHTING} if balanced else {})}
        or value["report_id"] != "retained-judge-comparison-" + _sha({k: v for k, v in value.items() if k != "report_id"})[:24]):
        raise ValueError("matched comparison summaries or content identity differ")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-report", type=Path, help="Reweight a completed report without rereading or rerunning its source campaign")
    parser.add_argument("--out", type=Path, required=True)
    arguments = ("plan", "execution-root", "local-runner-view", "hosted-runner-view", "source-receipt")
    for argument in arguments:
        parser.add_argument("--" + argument, type=Path)
    args = parser.parse_args(argv)
    supplied = [getattr(args, key.replace("-", "_")) for key in arguments]
    if args.from_report:
        if any(supplied):
            parser.error("--from-report cannot be combined with campaign source arguments")
        previous, _ = _read_regular(args.from_report, label="completed comparison report", max_bytes=32 * 1024 * 1024)
        report = input_balanced_report(previous)
    else:
        if not all(supplied):
            parser.error("supply --from-report or all campaign source arguments")
        report = build_report(plan_path=args.plan, execution_root=args.execution_root,
                              local_runner_view=args.local_runner_view, hosted_runner_view=args.hosted_runner_view,
                              source_receipt=args.source_receipt)
    _write_new(args.out, report)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
