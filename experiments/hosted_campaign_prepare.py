"""Prepare funded hosted retained-input programs without generating answers.

The input request names already materialized retained replay artifacts and the
ordinary Runner arguments shared by every job. This command revalidates the
finished local campaign, counts each exact provider request, creates one shared
attempt budget, and emits one executable program per hosted target. It never
calls a generation endpoint.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments import hosted_campaign_budget as projection
from experiments import hosted_retained_execute as executor
from experiments.hosted_attempt_budget import AttemptBudget, create_budget
from experiments.hosted_request_tokens import count_request
from experiments.retained_response_judge_execute import _canonical, _write_new
from ura.adapters.replay import ReplayAttacker, retained_dialog


REQUEST_SCHEMA = "ura-hosted-retained-campaign-request/1"
RECEIPT_SCHEMA = "ura-hosted-retained-campaign-preparation/1"
_REPLAY_SCHEMA = "ura-retained-input-replay/1"
_CONTROLLED = frozenset(
    {
        "--api",
        "--api-config",
        "--api-config-sha256",
        "--attackers",
        "--attacker-config",
        "--attacker-config-sha256",
        "--corpora",
        "--diagnostic-canary",
        "--attestation-probe",
        "--dry-run",
        "--preflight-only",
        "--judges",
        "--limit",
        "--max-queries",
        "--max-turns",
        "--max-total-http-attempts",
        "--max-total-judge-calls",
        "--max-total-target-calls",
        "--out",
        "--sample-seed",
        "--seeds",
        "--target-answer-retries",
    }
)


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result:
        raise ValueError("hosted target needs a filesystem-safe identity")
    return result


def _full_descriptor(raw: object, *, label: str) -> tuple[dict, dict]:
    if not isinstance(raw, Mapping) or set(raw) != {"path", "sha256", "bytes"}:
        raise ValueError(f"{label} descriptor fields differ")
    value, observed = executor._bound(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value, observed


def _canonical_new_root(path_value: Path, *, label: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError(f"{label} must be a fresh canonical absolute directory")
    parent = path.parent.resolve(strict=True)
    if path != parent / path.name:
        raise ValueError(f"{label} must be a fresh canonical absolute directory")
    return path


def _canonical_existing_root(path_value: object, *, label: str) -> Path:
    if not isinstance(path_value, str):
        raise ValueError(f"{label} must be a canonical absolute directory")
    path = Path(path_value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or not path.is_dir()
    ):
        raise ValueError(f"{label} must be a canonical absolute directory")
    return path


def _common_argv(raw: object) -> list[str]:
    if (
        not isinstance(raw, list)
        or any(not isinstance(value, str) or not value for value in raw)
    ):
        raise ValueError("runner_common_argv must be a nonempty string list")
    for value in raw:
        if value in _CONTROLLED or any(value.startswith(flag + "=") for flag in _CONTROLLED):
            raise ValueError(f"runner_common_argv cannot override {value.split('=', 1)[0]}")
    return list(raw)


def _portable(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "file": Path(raw["path"]).name,
        "sha256": raw["sha256"],
        "bytes": raw["bytes"],
    }


def _validated_projection(
    *, request: Mapping[str, Any], sources: Mapping[str, dict], values: Mapping[str, dict]
) -> dict:
    expected = projection.build_projection(
        api_config=values["api_config"],
        pricing=values["pricing"],
        budgets=values["budgets"],
        descriptors={
            "api_config": _portable(sources["api_config"]),
            "pricing_config": _portable(sources["pricing"]),
            "budgets": _portable(sources["budgets"]),
        },
        pricing_as_of=request["pricing_as_of"],
    )
    if values["budget_projection"] != expected or expected["status"] != "budget_fit":
        raise ValueError("hosted budget projection is stale or no longer fits")
    return expected


def _pilot_ids(plan: Mapping[str, Any]) -> list[str]:
    selected = plan.get("selected")
    if not isinstance(selected, list) or not selected:
        raise ValueError("retained selection has no inputs")
    text = [row["input_identity_sha256"] for row in selected if row.get("modality") == "text"]
    image = [
        row["input_identity_sha256"]
        for row in selected
        if "image" in row.get("required_modalities", [])
    ]
    result = [*text[:3], *image[:2]]
    if not result:
        result = [selected[0]["input_identity_sha256"]]
    if len(selected) < 2:
        raise ValueError("hosted selection must leave at least one measured input")
    result = result[: len(selected) - 1]
    if len(result) != len(set(result)):
        raise ValueError("pilot input selection is not disjoint")
    return result


def _job_argv(
    *,
    common: Sequence[str],
    target: str,
    api_config: Mapping[str, Any],
    corpus: str,
    attacker_config: Mapping[str, Any],
    output: Path,
    count: int,
    pilot: bool,
) -> list[str]:
    argv = [
        *common,
        "--api",
        target,
        "--api-config",
        api_config["path"],
        "--api-config-sha256",
        api_config["sha256"],
        "--corpora",
        corpus,
        "--attackers",
        "replay",
        "--judges",
        "rules,guardrail",
        "--seeds",
        "0",
        "--sample-seed",
        "0",
        "--target-answer-retries",
        "0",
        "--max-total-target-calls",
        str(count),
        "--max-total-judge-calls",
        str(count),
        "--max-total-http-attempts",
        str(4 * count),
        "--max-queries",
        "1",
        "--max-turns",
        "1",
        "--attacker-config",
        attacker_config["path"],
        "--attacker-config-sha256",
        attacker_config["sha256"],
        "--out",
        str(output),
        "--limit",
        "1" if pilot else "0",
    ]
    if pilot:
        argv.append("--diagnostic-canary")
    return argv


def _replay_inventory(raw_routes: object) -> list[dict[str, Any]]:
    if not isinstance(raw_routes, list) or not raw_routes:
        raise ValueError("hosted preparation requires target routes")
    routes: list[dict[str, Any]] = []
    targets: set[str] = set()
    for raw in raw_routes:
        if not isinstance(raw, Mapping) or set(raw) != {"target", "replay_artifacts"}:
            raise ValueError("hosted preparation route fields differ")
        target = raw["target"]
        artifacts = raw["replay_artifacts"]
        if (
            not isinstance(target, str)
            or not target
            or target in targets
            or not isinstance(artifacts, list)
            or not artifacts
        ):
            raise ValueError("hosted preparation routes must be unique and nonempty")
        targets.add(target)
        loaded = []
        corpora: set[str] = set()
        for descriptor in artifacts:
            value, observed = _full_descriptor(descriptor, label="retained replay")
            corpus = value.get("corpus")
            if (
                value.get("schema") != _REPLAY_SCHEMA
                or value.get("status") != "no_call_materialized"
                or not isinstance(corpus, str)
                or not corpus
                or corpus in corpora
            ):
                raise ValueError("retained replay schema, state or corpus differs")
            corpora.add(corpus)
            attacker = ReplayAttacker(
                replay_artifact=observed["path"],
                replay_artifact_sha256=observed["sha256"],
            )
            loaded.append(
                {
                    "corpus": corpus,
                    "descriptor": observed,
                    "value": value,
                    "entries": copy.deepcopy(attacker._selected_entries),
                }
            )
        routes.append({"target": target, "replays": loaded})
    return routes


def _config_value(replay: Mapping[str, Any], ids: Sequence[str]) -> dict:
    return {
        "replay": {
            "replay_artifact": replay["descriptor"]["path"],
            "replay_artifact_sha256": replay["descriptor"]["sha256"],
            "retained_input_ids": list(ids),
        }
    }


def prepare_campaign(
    *,
    request: Mapping[str, Any],
    request_descriptor: Mapping[str, Any],
    out_root: Path,
    allow_network_counts: bool,
) -> dict:
    """Create programs and one shared zero-attempt monetary ledger."""
    if type(allow_network_counts) is not bool:
        raise ValueError("allow_network_counts must be an explicit boolean")
    required = {
        "schema",
        "results_root",
        "runner_view",
        "rr_analysis_root",
        "pricing_as_of",
        "sources",
        "routes",
        "runner_common_argv",
        "execution_root",
    }
    if not isinstance(request, Mapping) or set(request) != required or request["schema"] != REQUEST_SCHEMA:
        raise ValueError("hosted campaign preparation request fields differ")
    root = _canonical_new_root(out_root, label="hosted preparation root")
    execution_root = _canonical_existing_root(request["execution_root"], label="hosted execution root")
    common = _common_argv(request["runner_common_argv"])
    source_names = {
        "api_config",
        "pricing",
        "budgets",
        "budget_projection",
        "media_index",
        "historical_result",
    }
    if not isinstance(request["sources"], Mapping) or set(request["sources"]) != source_names:
        raise ValueError("hosted preparation source inventory differs")
    values, sources = {}, {}
    for name in sorted(source_names):
        values[name], sources[name] = _full_descriptor(
            request["sources"][name], label=name.replace("_", " ")
        )
    budget_projection = _validated_projection(request=request, sources=sources, values=values)
    routes = _replay_inventory(request["routes"])

    skeleton = {
        "results_root": request["results_root"],
        "runner_view": request["runner_view"],
        "rr_analysis_root": request["rr_analysis_root"],
        "sources": {"historical_result": sources["historical_result"]},
    }
    cells, historical_inventory = executor._validated_local_cells(skeleton)
    if not cells:
        raise ValueError("finished local campaign has no retained cells")

    from experiments import run_matrix

    normalized, _api_artifact = run_matrix._load_api_config(
        sources["api_config"]["path"],
        [route["target"] for route in routes],
        sources["api_config"]["sha256"],
    )
    route_budget = {row["target_spec"]: row for row in budget_projection["routes"]}
    programs: list[dict[str, Any]] = []
    configs: list[tuple[Path, dict]] = []
    slots: list[dict[str, Any]] = []
    count_methods: dict[str, int] = {}
    planned_paths: set[Path] = set()
    for route in routes:
        target_spec = route["target"]
        if target_spec not in route_budget:
            raise ValueError("hosted route is absent from the funded projection")
        funded = route_budget[target_spec]
        target = run_matrix.build_target(target_spec, api_config=normalized[target_spec])
        plans = [replay["value"]["plan"] for replay in route["replays"]]
        if any(plan != plans[0] for plan in plans[1:]):
            raise ValueError("one target's corpus replays do not share one input plan")
        plan = plans[0]
        if plan.get("target_condition", {}).get("target_spec") != target_spec:
            raise ValueError("retained replay target differs from its hosted route")
        selected_ids = [row["input_identity_sha256"] for row in plan.get("selected", [])]
        entries: dict[str, tuple[dict, dict]] = {}
        for replay in route["replays"]:
            for entry in replay["entries"]:
                identity = entry["origin"]["selection"]["input_identity_sha256"]
                if identity in entries:
                    raise ValueError("retained corpus replays overlap")
                entries[identity] = (replay, entry)
        if list(identity for identity in selected_ids if identity in entries) != selected_ids or set(entries) != set(selected_ids):
            raise ValueError("retained corpus replays do not cover the selected input plan exactly once")
        if len(selected_ids) > funded["paid_call_cap"]:
            raise ValueError("retained selection exceeds its funded target call cap")

        requests: dict[str, dict] = {}
        target_slots = []
        for identity in selected_ids:
            _replay, entry = entries[identity]
            body = target.build_request(retained_dialog(entry["rendered_input"]), seed=0)
            counted = count_request(target, body, allow_network=allow_network_counts)
            if counted["input_tokens"] > funded["maximum_input_tokens_per_call"]:
                raise ValueError("selected hosted request exceeds the projected input-token ceiling")
            method = counted["method"] + ":" + counted["method_id"]
            count_methods[method] = count_methods.get(method, 0) + 1
            call_id = "target-" + projection._sha({"target": target_spec, "input_id": identity})
            bound = executor._cost(
                counted["input_tokens"],
                funded["maximum_output_tokens_per_call"],
                {
                    "input": funded["reserved_input_usd_per_million_tokens"],
                    "output": funded["reserved_output_usd_per_million_tokens"],
                },
            )
            judge_ids = {
                cohort: "judge-" + cohort + "-" + projection._sha(
                    {"target": target_spec, "input_id": identity}
                )
                for cohort in ("local", "hosted")
            }
            requests[identity] = {
                "call_id": call_id,
                "request_sha256": projection._sha(body),
                "token_count": counted,
                "input_tokens": counted["input_tokens"],
                "max_output_tokens": funded["maximum_output_tokens_per_call"],
                "bound_microusd": bound,
                "judge_call_ids": judge_ids,
            }
            target_slots.append(
                {
                    "call_id": call_id,
                    "provider": funded["provider"],
                    "pool": "target",
                    "bound_microusd": bound,
                }
            )
        if sum(row["bound_microusd"] for row in target_slots) > funded["maximum_cost_microusd"]:
            raise ValueError("exact selected target requests exceed the route's funded projection")
        slots.extend(target_slots)
        judge = budget_projection["judge"]
        judge_bound = executor._cost(
            judge["maximum_input_tokens_per_call"],
            judge["maximum_output_tokens_per_call"],
            {
                "input": judge["input_usd_per_million_tokens"],
                "output": judge["output_usd_per_million_tokens"],
            },
        )
        for receipt in requests.values():
            slots.extend(
                {
                    "call_id": call_id,
                    "provider": "anthropic",
                    "pool": "judge",
                    "bound_microusd": judge_bound,
                }
                for call_id in receipt["judge_call_ids"].values()
            )

        slug = _slug(target_spec)
        pilot = _pilot_ids(plan)
        pilot_set = set(pilot)
        jobs: list[dict[str, Any]] = []
        config_rows: list[tuple[str, dict, list[str], bool]] = []
        for number, identity in enumerate(pilot, start=1):
            replay, _entry = entries[identity]
            config_rows.append((f"{slug}-pilot-{number:02d}", replay, [identity], True))
        for replay in route["replays"]:
            ids = [
                identity
                for identity in selected_ids
                if identity not in pilot_set and entries[identity][0] is replay
            ]
            if ids:
                config_rows.append(
                    (f"{slug}-measured-{_slug(replay['corpus'])}", replay, ids, False)
                )
        for name, replay, ids, is_pilot in config_rows:
            config_path = root / "attacker-configs" / f"{name}.json"
            config = _config_value(replay, ids)
            config_descriptor = {
                "path": str(config_path),
                "sha256": hashlib.sha256(_canonical(config)).hexdigest(),
                "bytes": len(_canonical(config)),
            }
            configs.append((config_path, config))
            output = execution_root / slug / name
            if output in planned_paths or output.exists() or output.is_symlink():
                raise ValueError("hosted Runner output path is duplicated or already exists")
            planned_paths.add(output)
            jobs.append(
                {
                    "name": name,
                    "input_ids": ids,
                    "purpose": "diagnostic_canary" if is_pilot else "measured_run",
                    "argv": _job_argv(
                        common=common,
                        target=target_spec,
                        api_config=sources["api_config"],
                        corpus=replay["corpus"],
                        attacker_config=config_descriptor,
                        output=output,
                        count=len(ids),
                        pilot=is_pilot,
                    ),
                }
            )
        programs.append(
            {
                "schema": executor.SCHEMA,
                "sources": copy.deepcopy(sources),
                "results_root": request["results_root"],
                "runner_view": request["runner_view"],
                "rr_analysis_root": request["rr_analysis_root"],
                "target": target_spec,
                "provider": funded["provider"],
                "max_output_tokens": funded["maximum_output_tokens_per_call"],
                "pricing_as_of": request["pricing_as_of"],
                "jobs": jobs,
                "requests": requests,
                "token_count_policy": executor.TOKEN_COUNT_POLICY,
                "replaced_descriptive_prerequisite": "authority.requires_exact_provider_token_counts",
                "predecessor_selection": {
                    "schema": plan["schema"],
                    "plan_id": plan["plan_id"],
                    "sha256": projection._sha(plan),
                },
            }
        )

    if len({row["call_id"] for row in slots}) != len(slots):
        raise ValueError("hosted target or judge slot identities collide")
    provider_budgets = projection._provider_budgets(values["budgets"])
    root.mkdir(mode=0o700)
    (root / "attacker-configs").mkdir(mode=0o700)
    (root / "programs").mkdir(mode=0o700)
    budget_descriptor = create_budget(
        root / "budget",
        provider_budgets_microusd={
            provider: row["configured_budget_microusd"]
            for provider, row in provider_budgets.items()
        },
        planned_calls=slots,
        protected_haiku_microusd=budget_projection["judge"]["maximum_cost_microusd"],
    )
    budget = AttemptBudget(root / "budget", budget_descriptor["sha256"])
    for path, value in configs:
        _write_new(path, value)
    program_descriptors = []
    for program in programs:
        program["budget_plan_sha256"] = budget_descriptor["sha256"]
        executor._validated_jobs(program, budget)
        path = root / "programs" / f"{_slug(program['target'])}.json"
        _write_new(path, program)
        program_descriptors.append(
            {
                "target": program["target"],
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
                "selected_target_calls": len(program["requests"]),
                "pilot_calls": sum(
                    len(job["input_ids"])
                    for job in program["jobs"]
                    if job["purpose"] != "measured_run"
                ),
            }
        )
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "prepared_no_generation_calls",
        "request": dict(request_descriptor),
        "local_inventory": historical_inventory,
        "budget": budget_descriptor,
        "programs": program_descriptors,
        "token_count_methods": dict(sorted(count_methods.items())),
        "token_count_http_attempts": sum(
            receipt["token_count"]["count_http_attempts"]
            for program in programs
            for receipt in program["requests"].values()
        ),
        "target_calls": 0,
        "judge_calls": 0,
        "generation_http_attempts": 0,
        "answer_retries": 0,
    }
    _write_new(root / "receipt.json", receipt)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--out-root", type=Path, required=True)
    parser.add_argument(
        "--allow-network-counts",
        action="store_true",
        help="allow provider token-count endpoints after the local campaign seal",
    )
    args = parser.parse_args(argv)
    request, descriptor = projection.load_bound_json(args.request, args.request_sha256)
    descriptor = {
        "path": str(args.request.resolve(strict=True)),
        "sha256": descriptor["sha256"],
        "bytes": descriptor["bytes"],
    }
    receipt = prepare_campaign(
        request=request,
        request_descriptor=descriptor,
        out_root=args.out_root,
        allow_network_counts=args.allow_network_counts,
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "programs": len(receipt["programs"]),
                "selected_target_calls": sum(
                    row["selected_target_calls"] for row in receipt["programs"]
                ),
                "token_count_http_attempts": receipt["token_count_http_attempts"],
                "generation_http_attempts": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
