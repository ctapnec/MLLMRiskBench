"""No-call, outcome-independent hosted subsets of exact retained local inputs.

This is a preparation handoff, not paid execution or campaign admission. The
revision-aware reader validates source grids. Selection never examines answer
text, verdicts, scores, or stop reasons. Adaptive inputs are replayed as retained
conversations; their attacks are not regenerated against the hosted target.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from itertools import groupby
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote_to_bytes

from experiments.hosted_campaign_budget import (
    SCHEMA as BUDGET_SCHEMA,
    CONFIGURED_SCHEMA as CONFIGURED_BUDGET_SCHEMA,
    _sha,
    _write_new,
    load_bound_json,
)
from experiments.retained_artifact_reader import load_cells


SCHEMA = "ura-hosted-retained-input-plan/1"
DISTINCT_SCHEMA = "ura-hosted-retained-input-plan/2"
COHORT_SCHEMA = "ura-hosted-retained-input-plan/3"
COHORT_SELECTION_SCHEMA = "ura-hosted-shared-input-cohort/1"
ALGORITHM = "seeded_balanced_whole_cluster_retained_input_prefix_v1"
_DIMENSIONS = ("corpus", "source", "framework", "modality", "risk", "expected_behavior")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"retained input lacks {label}")
    return value


def _digest(value: Any, label: str) -> str:
    value = _text(value, label)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"invalid {label} digest")
    return value


def _descriptor(path_value: Path, expected: str | None = None) -> dict:
    path = Path(path_value)
    if path.is_symlink():
        raise ValueError("retained input artifact must not be a symlink")
    path = path.resolve(strict=True)
    before = path.stat()
    if not path.is_file():
        raise ValueError("retained input artifact must be a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (expected is not None and digest.hexdigest() != expected)):
        raise ValueError("retained input artifact bytes changed")
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": after.st_size}


def _media_bindings(turns: list, media_index: Mapping[str, str]) -> list[dict]:
    """Verify supplied local bytes, without resolving remote URLs or guessing paths."""
    result = []
    for turn_index, turn in enumerate(turns):
        for media_index_in_turn, media in enumerate(turn.get("media") or []):
            digest = _digest(media.get("sha256"), "media")
            modality = media.get("modality")
            mime = media.get("mime")
            if (modality not in {"image", "audio", "video"}
                    or not isinstance(mime, str) or not mime.startswith(modality + "/")):
                raise ValueError("retained media lacks its exact modality/MIME identity")
            path, uri = media.get("path"), media.get("uri")
            if bool(path) == bool(uri):
                raise ValueError("retained media must have exactly one locator")
            if uri:
                if not isinstance(uri, str) or not uri.startswith("data:"):
                    raise ValueError("hosted handoff never fetches remote media")
                header, separator, body = uri.partition(",")
                if not separator or header[5:].split(";", 1)[0] != mime:
                    raise ValueError("inline media MIME identity changed")
                payload = (base64.b64decode(body, validate=True)
                           if header.endswith(";base64") else unquote_to_bytes(body))
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise ValueError("inline media bytes changed")
                binding = {"storage": "inline", "sha256": digest, "bytes": len(payload)}
            else:
                if path != "sha256:" + digest and not str(path).startswith("@media-root/"):
                    raise ValueError("retained media locator is not content-bound")
                if digest not in media_index:
                    raise ValueError("retained media requires an explicit local content index")
                binding = {"storage": "local", **_descriptor(Path(media_index[digest]), digest)}
            result.append({"turn_index": turn_index, "media_index": media_index_in_turn,
                           "modality": modality, "mime": mime, **binding})
    return result


def candidates_from_cells(cells: Sequence[Mapping[str, Any]]) -> list[dict]:
    """Use only input metadata from cells already accepted by the exact source reader.

    All Attempt rows participate, including rows with missing or poor answers.
    Input stamps may come directly from the source reader's reconstructed
    corpus, including when scoring failed. Older complete cells retain the same
    stamps in raw judgments. Outcomes and response objects are never consulted.
    """
    candidates: dict[str, dict] = {}
    for cell in cells:
        if cell.get("source_identity_validated") is not True:
            raise ValueError("hosted subset requires source-validated cells")
        manifest = cell["manifest"]
        run = manifest["config"]["run"]
        if not str(cell["model"]).startswith(("ollama:", "vllm:")):
            raise ValueError("hosted subset source must be a local target")
        corpus_sha = _digest(manifest["dataset_hashes"].get("corpus"), "converted corpus")
        artifacts = {key: _descriptor(path) for key, path in sorted(cell["artifacts"].items())}
        source = {"run_id": cell["run_id"], "local_model": cell["model"],
                  "artifacts_sha256": _sha(artifacts), "artifacts": artifacts,
                  "project_revision": copy.deepcopy(run["project_revision"])}
        judged_metadata = {row["attempt_id"]: row["raw"] for row in cell["judgments"]}
        metadata = cell.get("input_metadata", judged_metadata)
        if (not isinstance(metadata, Mapping) or set(metadata) != set(cell["attempts"])
                or any(not isinstance(raw, Mapping) for raw in metadata.values())
                or not set(judged_metadata) <= set(metadata)
                or len(judged_metadata) != len(cell["judgments"])):
            raise ValueError("retained inputs have an incomplete metadata join")
        for attempt_id, raw in judged_metadata.items():
            supplied = metadata[attempt_id]
            if any(supplied.get(key, supplied.get("risk") if key == "risk_category" else None)
                   != raw.get(key, raw.get("risk") if key == "risk_category" else None)
                   for key in ("source", "risk_category", "expected_behavior")):
                raise ValueError("retained input metadata disagrees with its source judgment stamps")
        for attempt_id, attempt in cell["attempts"].items():
            params, raw = attempt["params"], metadata[attempt_id]
            turns = attempt.get("rendered_input")
            if not isinstance(turns, list) or not turns:
                raise ValueError("retained Attempt has no exact rendered input")
            if attempt.get("seed") != 0 or isinstance(attempt.get("seed"), bool):
                raise ValueError("hosted follow-on requires retained seed 0")
            physical = sorted({media["modality"] for turn in turns
                               for media in (turn.get("media") or [])})
            if any(value not in {"image", "audio", "video"} for value in physical):
                raise ValueError("retained input has unsupported physical modality")
            identity = {
                "corpus": _text(run.get("corpus"), "corpus"),
                "converted_corpus_sha256": corpus_sha,
                "source": _text(params.get("planning_source", raw.get("source")), "source"),
                "framework": _text(attempt.get("attacker"), "framework"),
                "datapoint_id": _text(attempt.get("datapoint_id"), "datapoint ID"),
                "source_cluster_id": _text(params.get("source_cluster_id"), "source cluster"),
                "requested_seed": attempt["seed"], "turn_index": attempt["turn_index"],
                "modality": "+".join(physical) or "text",
                "required_modalities": ["text", *physical],
                "risk": _text(raw.get("risk_category", raw.get("risk")), "input risk"),
                "expected_behavior": _text(params.get("planning_expected_behavior",
                                                      raw.get("expected_behavior")), "behavior"),
                "source_policy": copy.deepcopy(params.get("planning_source_policy",
                                                           params.get("source_policy"))),
                "rendered_input_sha256": _sha(turns),
            }
            identity_sha = _sha(identity)
            candidate = candidates.setdefault(identity_sha, {
                **identity, "input_identity_sha256": identity_sha,
                "rendered_input": copy.deepcopy(turns), "local_sources": [],
            })
            membership = {**source, "attempt_id": attempt_id,
                          "attempt_sha256": _sha(attempt),
                          "attempt_params_sha256": _sha(params)}
            if membership in candidate["local_sources"]:
                raise ValueError("duplicate local retained input membership")
            candidate["local_sources"].append(membership)
    if not candidates:
        raise ValueError("retained view contains no local input candidates")
    for candidate in candidates.values():
        candidate["local_sources"].sort(key=lambda value: (value["run_id"], value["attempt_id"]))
    return [candidates[key] for key in sorted(candidates)]


def _select(candidates: list[dict], *, modalities: list[str], cap: int) -> tuple[list[dict], dict]:
    clusters: dict[str, list[dict]] = defaultdict(list)
    for row in candidates:
        key = _sha({field: row[field] for field in
                    ("corpus", "source", "framework", "source_cluster_id", "requested_seed")})
        clusters[key].append(row)
    eligible, excluded = {}, 0
    for key, rows in clusters.items():
        if all(set(row["required_modalities"]) <= set(modalities) for row in rows):
            eligible[key] = sorted(rows, key=lambda row: row["input_identity_sha256"])
        else:
            excluded += len(rows)
    strata: dict[str, list[str]] = defaultdict(list)
    for key, rows in eligible.items():
        stratum = _sha(sorted({_sha({field: row[field] for field in _DIMENSIONS}) for row in rows}))
        strata[stratum].append(key)
    order = sorted(strata, key=lambda key: _sha({"seed": 0, "stratum": key}))
    queues = {key: deque(sorted(strata[key], key=lambda cluster: _sha({"seed": 0, "cluster": cluster})))
              for key in order}
    selected, blocked_size = [], 0
    while any(queues.values()) and len(selected) < cap:
        for key in order:
            if not queues[key]:
                continue
            rows = eligible[queues[key].popleft()]
            if len(selected) + len(rows) > cap:
                blocked_size = len(rows)
                break
            selected.extend(rows)
            if len(selected) == cap:
                break
        if blocked_size:
            break
    return selected, {"unique_local_inputs": len(candidates),
                      "incompatible_modality_inputs": excluded,
                      "compatible_inputs": sum(map(len, eligible.values())),
                      "selected_inputs": len(selected), "unused_call_capacity": cap - len(selected),
                      "next_whole_cluster_size": blocked_size}


def select_distinct_requests(
    candidates: list[dict], *, modalities: list[str], cap: int,
    request_builder: Callable[[dict], Mapping[str, Any]],
    previous_request_sha256: Sequence[str] = (),
) -> dict:
    """No-call prefix priced in unique provider requests, preserving source aliases.

    Call separately for each fixed target configuration. The builder must be
    the target's ordinary offline request builder, with media bytes resolved
    through their validated content index. Its output is hashed but not saved.
    This preview is not a funded execution plan and cannot alter a retained /1
    source selection or authorize reuse of an answer under another source task.
    """
    if type(cap) is not int or cap < 1:
        raise ValueError("distinct request cap must be a positive integer")
    previous = {_digest(value, "previous provider request") for value in previous_request_sha256}
    seen_inputs = set()
    for row in candidates:
        identity = {key: value for key, value in row.items()
                    if key not in {"input_identity_sha256", "rendered_input", "local_sources"}}
        if (row["input_identity_sha256"] != _sha(identity)
                or row["rendered_input_sha256"] != _sha(row["rendered_input"])
                or row["input_identity_sha256"] in seen_inputs):
            raise ValueError("distinct request source input identity changed or was duplicated")
        seen_inputs.add(row["input_identity_sha256"])
    ordered, population = _select(candidates, modalities=modalities, cap=len(candidates))

    def cluster(row):
        return tuple(row[field] for field in
                     ("corpus", "source", "framework", "source_cluster_id", "requested_seed"))

    selected: dict[str, dict] = {}
    excluded, admitted_clusters, blocked_size = [], 0, 0
    for _cluster, source_rows in groupby(ordered, key=cluster):
        requests, old_inputs = {}, []
        for row in source_rows:
            body = request_builder(copy.deepcopy(row))
            if not isinstance(body, Mapping) or not body:
                raise ValueError("offline provider request builder returned no request")
            fingerprint = _sha(dict(body))
            if fingerprint in previous:
                old_inputs.append(row["input_identity_sha256"])
            else:
                requests.setdefault(fingerprint, []).append(copy.deepcopy(row))
        new_requests = set(requests) - selected.keys()
        if len(selected) + len(new_requests) > cap:
            blocked_size = len(new_requests)
            break
        excluded.extend(old_inputs)
        admitted_clusters += 1
        for fingerprint, aliases in requests.items():
            group = selected.setdefault(fingerprint, {
                "request_sha256": fingerprint, "representative_input_sha256": aliases[0]["input_identity_sha256"],
                "source_inputs": [],
            })
            group["source_inputs"].extend(aliases)
    result = {"schema": "ura-hosted-distinct-request-selection/1", "status": "no_call_selection_only",
        "paid_execution_authorized": False, "request_cap": cap,
        "previous_request_sha256": sorted(previous), "selected": list(selected.values()),
        "population": {"source_inputs": len(candidates),
            "incompatible_modality_inputs": population["incompatible_modality_inputs"],
            "selected_requests": len(selected),
            "selected_source_inputs": sum(len(value["source_inputs"]) for value in selected.values()),
            "previous_request_source_inputs": len(excluded), "admitted_source_clusters": admitted_clusters,
            "unused_call_capacity": cap - len(selected), "next_whole_cluster_new_requests": blocked_size},
        "excluded_previous_source_input_ids": excluded,
        "selection_policy": "seed0_whole_cluster_prefix_unique_provider_requests",
        "observed_output_used_for_selection": False}
    result["selection_id"] = "distinct-requests-" + _sha(result)[:24]
    return result


def build_plan(*, candidates: list[dict], budget: dict, budget_descriptor: dict,
               api_config: dict, api_descriptor: dict, target: str,
               media_index: Mapping[str, str], local_inventory_descriptor: dict,
               call_cap: int | None = None) -> dict:
    seen = set()
    for row in candidates:
        identity = {key: value for key, value in row.items()
                    if key not in {"input_identity_sha256", "rendered_input", "local_sources"}}
        if (row["input_identity_sha256"] != _sha(identity)
                or row["rendered_input_sha256"] != _sha(row["rendered_input"])
                or row["input_identity_sha256"] in seen):
            raise ValueError("retained input identity changed or was duplicated")
        seen.add(row["input_identity_sha256"])
    material = {key: value for key, value in budget.items() if key != "projection_id"}
    if (budget.get("schema") not in {BUDGET_SCHEMA, CONFIGURED_BUDGET_SCHEMA} or budget.get("status") != "budget_fit"
            or budget.get("projection_id") != "hosted-budget-" + _sha(material)[:24]):
        raise ValueError("hosted selection requires an unchanged fitting budget projection")
    if budget["sources"]["api_config"] != api_descriptor:
        raise ValueError("hosted API config differs from the budget binding")
    routes = [row for row in budget["routes"] if row["target_spec"] == target]
    if len(routes) != 1:
        raise ValueError("target has no unique funded route")
    route = routes[0]
    if route["answer_retries"] != 0 or route["transport_retries"] != 3:
        raise ValueError("hosted retries differ from the funded contract")
    cap = route["paid_call_cap"] if call_cap is None else call_cap
    if isinstance(cap, bool) or not isinstance(cap, int) or not 0 < cap <= route["paid_call_cap"]:
        raise ValueError("global input cap must not exceed the funded route cap")
    modalities = api_config[target].get("modalities")
    if (not isinstance(modalities, list) or not modalities or "text" not in modalities
            or any(item not in {"text", "image", "audio", "video"} for item in modalities)):
        raise ValueError("target must declare its exact supported modalities")
    selected, population = _select(candidates, modalities=modalities, cap=cap)
    entries = []
    for row in selected:
        entry = {key: copy.deepcopy(value) for key, value in row.items() if key != "rendered_input"}
        entry["media_bindings"] = _media_bindings(row["rendered_input"], media_index)
        entries.append(entry)
    value = {
        "schema": SCHEMA, "status": "no_call_selection_only",
        "authority": {"target_calls": 0, "judge_calls": 0, "paid_execution_authorized": False,
                      "requires_final_local_inventory_reconciliation": True,
                      "requires_exact_provider_token_counts": True,
                      "requires_paid_pilot_and_runtime_admission": True},
        "sources": {"budget": budget_descriptor, "api_config": api_descriptor,
                    "local_inventory": local_inventory_descriptor},
        "target_condition": {**copy.deepcopy(route), "selected_global_call_cap": cap,
                             "modalities": sorted(modalities),
                             "answer_retries": 0, "local_judges": ["rules", "guardrail"]},
        "selection": {"algorithm": ALGORITHM, "sample_seed": 0, "attack_seeds": [0],
                      "candidate_input_ids_sha256": _sha(sorted(row["input_identity_sha256"]
                                                               for row in candidates)),
                      "adaptive_attack_execution": "exact_retained_input_replay_only",
                      "observed_output_used_for_selection": False},
        "population": population,
        "selected_composition": {field: dict(sorted(Counter(row[field] for row in selected).items()))
                                 for field in _DIMENSIONS},
        "selected": entries,
    }
    value["plan_id"] = "hosted-inputs-" + _sha(value)[:24]
    return value


def provider_request_builder(target: Any, media_index: Mapping[str, str]) -> Callable[[dict], Mapping[str, Any]]:
    """Use the ordinary offline provider payload with content-verified local media."""
    from ura.adapters.replay import retained_dialog

    def build(row: dict) -> Mapping[str, Any]:
        delivered = copy.deepcopy(row["rendered_input"])
        for binding in _media_bindings(delivered, media_index):
            if binding["storage"] == "local":
                delivered[binding["turn_index"]]["media"][binding["media_index"]]["path"] = binding["path"]
        return target.build_request(retained_dialog(delivered), seed=0)

    return build


def build_distinct_plan(
    *, candidates: list[dict], predecessor: dict, predecessor_descriptor: dict,
    source_prefix_cap: int, call_cap: int, request_builder: Callable[[dict], Mapping[str, Any]],
    **bindings: Any,
) -> dict:
    """Extend an original source prefix, funding only new distinct provider requests.

    Source-prefix size and request cap are independent input-only bounds. All
    source memberships survive in the request groups; a representative controls
    physical generation only and does not erase other grading contexts.
    """
    if predecessor.get("schema") != SCHEMA:
        raise ValueError("distinct continuation requires an original retained input plan")
    if _descriptor(Path(predecessor_descriptor["path"])) != predecessor_descriptor:
        raise ValueError("distinct predecessor artifact changed")
    saved, _ = load_bound_json(Path(predecessor_descriptor["path"]), predecessor_descriptor["sha256"])
    if saved != predecessor:
        raise ValueError("distinct predecessor content differs")
    resolve_inputs(predecessor, candidates=candidates, **bindings)
    previous_rows = predecessor["selected"]
    if type(source_prefix_cap) is not int or source_prefix_cap <= len(previous_rows):
        raise ValueError("distinct continuation requires a larger whole-source prefix")
    target = predecessor["target_condition"]["target_spec"]
    modalities = bindings["api_config"][target]["modalities"]
    expanded, _population = _select(candidates, modalities=modalities, cap=source_prefix_cap)
    if [row["input_identity_sha256"] for row in expanded[:len(previous_rows)]] != [
        row["input_identity_sha256"] for row in previous_rows
    ]:
        raise ValueError("distinct continuation changed its original source prefix")
    by_id = {row["input_identity_sha256"]: row for row in candidates}
    previous_requests = [_sha(dict(request_builder(copy.deepcopy(by_id[row["input_identity_sha256"]]))))
                         for row in previous_rows]
    distinct = select_distinct_requests(
        expanded[len(previous_rows):], modalities=modalities, cap=call_cap,
        request_builder=request_builder, previous_request_sha256=previous_requests,
    )
    representatives = [by_id[group["representative_input_sha256"]] for group in distinct["selected"]]
    if not representatives:
        raise ValueError("distinct continuation contains no new provider requests")
    value = build_plan(candidates=representatives, target=target, call_cap=call_cap, **bindings)
    value.pop("plan_id")
    value["schema"] = DISTINCT_SCHEMA
    value["sources"]["predecessor_input_plan"] = copy.deepcopy(predecessor_descriptor)
    value["selection"].update(
        algorithm="seed0_whole_source_prefix_distinct_provider_request_extension_v1",
        candidate_input_ids_sha256=_sha(sorted(by_id)), source_prefix_cap=source_prefix_cap,
        previous_request_sha256=sorted(set(previous_requests)),
        request_groups=[{
            "request_sha256": group["request_sha256"],
            "representative_input_sha256": group["representative_input_sha256"],
            "source_input_ids": [row["input_identity_sha256"] for row in group["source_inputs"]],
        } for group in distinct["selected"]],
        source_memberships_are_not_independent_generations=True,
    )
    value["population"] = distinct["population"]
    value["plan_id"] = "hosted-inputs-" + _sha(value)[:24]
    return value


def build_shared_cohort(*, candidates: list[dict], excluded_input_ids: Sequence[str]) -> dict:
    """Freeze input-only exclusions once for every model, before new outcomes."""
    by_id = {row["input_identity_sha256"]: row for row in candidates}
    excluded = sorted(set(excluded_input_ids))
    if len(by_id) != len(candidates) or not set(excluded) <= by_id.keys():
        raise ValueError("shared cohort exclusions must name retained local inputs")
    value = {
        "schema": COHORT_SELECTION_SCHEMA,
        "algorithm": "seed0_shared_whole_cluster_prefix_excluding_previous_payloads",
        "candidate_input_ids_sha256": _sha(sorted(by_id)),
        "excluded_input_ids": excluded,
        "excluded_rendered_input_sha256": sorted({by_id[key]["rendered_input_sha256"] for key in excluded}),
        "observed_output_used_for_selection": False,
    }
    value["cohort_id"] = "shared-inputs-" + _sha(value)[:24]
    return value


def build_cohort_plan(
    *, candidates: list[dict], cohort: dict, cohort_descriptor: dict, target: str,
    prefix_start: int, prefix_stop: int, call_cap: int,
    request_builder: Callable[[dict], Mapping[str, Any]], **bindings: Any,
) -> dict:
    """Fund a whole-cluster slice of the same input prefix for every target.

    The prefix is selected without provider serialization or model outcomes.
    Physical request aliases are collapsed only after shared inputs are fixed.
    Successive funding batches cannot change that preselected population.
    """
    saved, observed = load_bound_json(Path(cohort_descriptor["path"]), cohort_descriptor["sha256"])
    if (saved != cohort or observed["bytes"] != cohort_descriptor["bytes"]
            or cohort != build_shared_cohort(candidates=candidates, excluded_input_ids=cohort["excluded_input_ids"])):
        raise ValueError("shared input cohort or local candidate population changed")
    if (type(prefix_start) is not int or type(prefix_stop) is not int
            or not 0 <= prefix_start < prefix_stop or type(call_cap) is not int or call_cap < 1):
        raise ValueError("shared cohort needs an increasing whole-prefix interval")
    def cluster(row):
        return tuple(row[field] for field in
                     ("corpus", "source", "framework", "source_cluster_id", "requested_seed"))
    excluded_payloads = set(cohort["excluded_rendered_input_sha256"])
    excluded_clusters = {cluster(row) for row in candidates if row["rendered_input_sha256"] in excluded_payloads}
    pool = [row for row in candidates if cluster(row) not in excluded_clusters]
    modalities = bindings["api_config"][target]["modalities"]
    input_body = lambda row: {"rendered_input": row["rendered_input"]}
    full = select_distinct_requests(pool, modalities=modalities, cap=prefix_stop, request_builder=input_body)
    if prefix_start:
        previous = select_distinct_requests(pool, modalities=modalities, cap=prefix_start, request_builder=input_body)
        if len(previous["selected"]) != prefix_start:
            raise ValueError("shared cohort batch start splits a whole source cluster")
    chosen = full["selected"][prefix_start:]
    if not chosen:
        raise ValueError("shared cohort interval contains no complete new input cluster")
    # A larger prefix can add source aliases to an earlier physical input.
    # Those aliases remain in the cohort; they do not trigger another generation.
    source_rows = [row for group in chosen for row in group["source_inputs"]]
    distinct = select_distinct_requests(source_rows, modalities=modalities, cap=len(source_rows),
                                        request_builder=request_builder)
    if len(distinct["selected"]) > call_cap:
        raise ValueError("shared input batch exceeds its funded physical request cap")
    by_id = {row["input_identity_sha256"]: row for row in candidates}
    representatives = [by_id[group["representative_input_sha256"]] for group in distinct["selected"]]
    value = build_plan(candidates=representatives, target=target, call_cap=call_cap, **bindings)
    value.pop("plan_id")
    value["schema"] = COHORT_SCHEMA
    value["sources"]["shared_input_cohort"] = copy.deepcopy(cohort_descriptor)
    value["selection"].update(
        algorithm="shared_input_prefix_batch_distinct_provider_requests_v1",
        candidate_input_ids_sha256=_sha(sorted(by_id)), prefix_start=prefix_start, prefix_stop=prefix_stop,
        selected_input_payload_sha256=[group["request_sha256"] for group in chosen],
        request_groups=[{
            "request_sha256": group["request_sha256"],
            "representative_input_sha256": group["representative_input_sha256"],
            "source_input_ids": [row["input_identity_sha256"] for row in group["source_inputs"]],
        } for group in distinct["selected"]],
        source_memberships_are_not_independent_generations=True,
    )
    value["population"] = {**distinct["population"], "input_prefix": full["population"],
                           "selected_input_payloads": len(chosen)}
    value["plan_id"] = "hosted-inputs-" + _sha(value)[:24]
    return value


def resolve_inputs(plan: dict, *, candidates: list[dict],
                   request_builder: Callable[[dict], Mapping[str, Any]] | None = None,
                   **bindings: Any) -> list[dict]:
    """Rebuild selection from validated sources before returning unchanged dialogues.

    This is still a no-call handoff. It never constructs an attacker or target.
    A later executor must use the returned media bindings to resolve portable
    locators and must retain the original input digest beside the delivered one.
    """
    if plan.get("schema") == COHORT_SCHEMA:
        if request_builder is None:
            raise ValueError("shared cohort requires the offline provider request builder")
        descriptor = plan["sources"]["shared_input_cohort"]
        cohort, _ = load_bound_json(Path(descriptor["path"]), descriptor["sha256"])
        expected = build_cohort_plan(
            candidates=candidates, cohort=cohort, cohort_descriptor=descriptor,
            target=plan["target_condition"]["target_spec"],
            prefix_start=plan["selection"]["prefix_start"], prefix_stop=plan["selection"]["prefix_stop"],
            call_cap=plan["target_condition"]["selected_global_call_cap"], request_builder=request_builder, **bindings)
    elif plan.get("schema") == DISTINCT_SCHEMA:
        if request_builder is None:
            raise ValueError("distinct input resolution requires the offline provider request builder")
        descriptor = plan["sources"]["predecessor_input_plan"]
        predecessor, _ = load_bound_json(Path(descriptor["path"]), descriptor["sha256"])
        expected = build_distinct_plan(
            candidates=candidates, predecessor=predecessor, predecessor_descriptor=descriptor,
            source_prefix_cap=plan["selection"]["source_prefix_cap"],
            call_cap=plan["target_condition"]["selected_global_call_cap"],
            request_builder=request_builder, **bindings,
        )
    else:
        expected = build_plan(candidates=candidates, target=plan["target_condition"]["target_spec"],
                              call_cap=plan["target_condition"]["selected_global_call_cap"], **bindings)
    if expected != plan:
        raise ValueError("retained hosted selection or source membership changed")
    checked = set()
    for row in plan["selected"]:
        for source in row["local_sources"]:
            for artifact in source["artifacts"].values():
                key = (artifact["path"], artifact["sha256"])
                if key not in checked:
                    if _descriptor(Path(artifact["path"]), artifact["sha256"]) != artifact:
                        raise ValueError("retained hosted source artifact changed")
                    checked.add(key)
    by_id = {row["input_identity_sha256"]: row for row in candidates}
    return [{"input_identity_sha256": row["input_identity_sha256"],
             "rendered_input": copy.deepcopy(by_id[row["input_identity_sha256"]]["rendered_input"]),
             "media_bindings": copy.deepcopy(row["media_bindings"]),
             "local_sources": copy.deepcopy(row["local_sources"])} for row in plan["selected"]]


def materialize_replay(
    plan: dict, *, cells: Sequence[Mapping[str, Any]], source_corpora: Mapping[str, Sequence[Any]],
    corpus: str, **bindings: Any,
) -> dict:
    """Prepare one source arm for mock replay, not admit a hosted execution.

    Full original converted populations are keyed by retained run ID. Their
    hashes bind source references and metadata; no gold fields are inferred from
    an answer or from a source evaluator's judgment.
    """
    from ura.adapters.replay import (
        RETAINED_REPLAY_SCHEMA, DISTINCT_RETAINED_REPLAY_SCHEMA, COHORT_RETAINED_REPLAY_SCHEMA,
        retained_dialog, retained_dialog_sha256, validate_retained_origin,
    )
    from ura.converters._common import canonical_converted_corpus_sha256
    from ura.data_models import DataPoint

    candidates = candidates_from_cells(cells)
    resolved = {row["input_identity_sha256"]: row for row in
                resolve_inputs(plan, candidates=candidates, **bindings)}
    by_run = {cell["run_id"]: cell for cell in cells}
    checked_corpora = {}
    entries = []
    for selected in plan["selected"]:
        if selected["corpus"] != corpus:
            continue
        source = selected["local_sources"][0]  # Stable input-only membership order.
        run_id = source["run_id"]
        cell = by_run[run_id]
        if run_id not in checked_corpora:
            if run_id not in source_corpora:
                raise ValueError("retained replay needs the exact original converted corpus")
            points = [point if isinstance(point, DataPoint) else DataPoint.model_validate(point)
                      for point in source_corpora[run_id]]
            if (canonical_converted_corpus_sha256(points)
                != cell["manifest"]["dataset_hashes"]["corpus"]
                or len({point.id for point in points}) != len(points)):
                raise ValueError("retained replay original converted corpus identity differs")
            checked_corpora[run_id] = {point.id: point for point in points}
        original = cell["attempts"][source["attempt_id"]]
        point = checked_corpora[run_id][original["datapoint_id"]]
        source_identity = point.model_dump(mode="json")
        if (source_identity["source"] != selected["source"]
            or source_identity["risk_category"] != selected["risk"]
            or source_identity["expected_behavior"] != selected["expected_behavior"]
            or source_identity["source_policy"] != selected["source_policy"]):
            raise ValueError("retained replay source input metadata differs")
        resolved_row = resolved[selected["input_identity_sha256"]]
        delivered = copy.deepcopy(resolved_row["rendered_input"])
        for binding in resolved_row["media_bindings"]:
            if binding["storage"] == "local":
                delivered[binding["turn_index"]]["media"][binding["media_index"]]["path"] = binding["path"]
        dialog = retained_dialog(delivered)
        origin = {
            "selection": copy.deepcopy(selected), "original_attempt": copy.deepcopy(original),
            "source_membership": copy.deepcopy(source),
            "source_datapoint_sha256": canonical_converted_corpus_sha256([point]),
            "delivered_input_sha256": retained_dialog_sha256(dialog),
            "plan_id": plan["plan_id"], "plan_sha256": _sha(plan),
        }
        validate_retained_origin(origin, dialog)
        entries.append({"origin": origin,
                        "rendered_input": [turn.model_dump(mode="json") for turn in dialog]})
    if not entries:
        raise ValueError("retained replay arm has no selected inputs")
    schema = {COHORT_SCHEMA: COHORT_RETAINED_REPLAY_SCHEMA,
              DISTINCT_SCHEMA: DISTINCT_RETAINED_REPLAY_SCHEMA}.get(plan["schema"], RETAINED_REPLAY_SCHEMA)
    value = {"schema": schema, "status": "no_call_materialized",
             "corpus": corpus, "plan": copy.deepcopy(plan), "entries": entries}
    value["replay_id"] = "retained-replay-" + _sha(value)[:24]
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-view", type=Path, required=True)
    for name in ("budget", "api-config", "local-inventory"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--media-index", type=Path)
    parser.add_argument("--media-index-sha256")
    parser.add_argument("--target", required=True)
    parser.add_argument("--global-input-cap", type=int)
    parser.add_argument("--materialize-corpus", help="write mock-only replay inputs for one selected arm")
    parser.add_argument("--source-corpora", type=Path,
                        help="exact original converted DataPoint lists keyed by retained run ID")
    parser.add_argument("--source-corpora-sha256")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    budget, budget_desc = load_bound_json(args.budget, args.budget_sha256)
    api, api_desc = load_bound_json(args.api_config, args.api_config_sha256)
    _inventory, inventory_desc = load_bound_json(args.local_inventory, args.local_inventory_sha256)
    if bool(args.media_index) != bool(args.media_index_sha256):
        parser.error("media index path and digest must be supplied together")
    media_index = (load_bound_json(args.media_index, args.media_index_sha256)[0]
                   if args.media_index else {})
    if (bool(args.source_corpora) != bool(args.source_corpora_sha256)
        or bool(args.materialize_corpus) != bool(args.source_corpora)):
        parser.error("materialization requires a corpus and bound original source corpora together")
    cells = load_cells(args.runner_view)
    candidates = candidates_from_cells(cells)
    plan = build_plan(candidates=candidates, budget=budget, budget_descriptor=budget_desc,
                      api_config=api, api_descriptor=api_desc, target=args.target,
                      local_inventory_descriptor=inventory_desc, media_index=media_index,
                      call_cap=args.global_input_cap)
    if args.materialize_corpus:
        value = materialize_replay(
            plan, cells=cells, corpus=args.materialize_corpus,
            source_corpora=load_bound_json(args.source_corpora, args.source_corpora_sha256)[0],
            budget=budget, budget_descriptor=budget_desc, api_config=api, api_descriptor=api_desc,
            local_inventory_descriptor=inventory_desc, media_index=media_index,
        )
        _write_new(args.out, value)
        print(json.dumps({"replay_id": value["replay_id"], "status": value["status"],
                          "selected_inputs": len(value["entries"]), "provider_calls": 0}))
        return 0
    _write_new(args.out, plan)
    print(json.dumps({"plan_id": plan["plan_id"], "status": plan["status"],
                      "selected_inputs": len(plan["selected"]), "provider_calls": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
