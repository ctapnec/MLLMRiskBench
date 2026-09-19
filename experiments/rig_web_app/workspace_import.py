"""Explicit retained-program publication, outside the HTTP page-read path.

This translates saved records, not experiment semantics. It neither reconstructs
corpora nor hashes model files, and makes no provider or judge calls.
"""

from __future__ import annotations

from .i18n import text as _ui_text

import hashlib
import json
from pathlib import Path

from experiments.generation_conditions import _first, _stop, _usage
from experiments.retained_outcomes import legacy_provider_policy_basis

from .workspace_costs import budget_attempt_rows


def generation_condition_id(program: dict) -> str:
    """Identify model settings, not the question or the config file's location."""
    source = Path(program["sources"]["api_config"]["path"])
    settings = json.loads(source.read_text(encoding="utf-8"))[program["target"]]
    # Authentication is not a generation condition and must not enter this index.
    settings = {
        key: value
        for key, value in settings.items()
        if key not in {"api_key", "api_key_env", "key_env", "authorization", "token"}
    }
    value = {
        "target": program["target"],
        "settings": settings,
        "max_output_tokens": program["max_output_tokens"],
    }
    identity = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    # This is a small metadata identifier, not file-content verification.
    return "generation-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def _jsonl(path: Path):
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            # A live append can be incomplete. Never index that partial row.
            if not line.endswith("\n"):
                break
            if line.strip():
                yield number, json.loads(line)


def _responses(job: dict):
    argv = job["argv"]
    out = Path(argv[argv.index("--out") + 1])
    observed = {}
    for path in sorted(out.glob("*.responses.checkpoint.jsonl")):
        for number, record in _jsonl(path):
            response = record["response"]
            key = (response["run_id"], response["attempt_id"])
            attempt = record["attempt"]
            if (attempt["run_id"], attempt["id"]) != key:
                raise ValueError(
                    _ui_text("workspace_import.checkpoint_response_does_not_match_its_attempt")
                )
            value = (attempt, response, f"{path}:{number}")
            if key in observed and observed[key][:2] != value[:2]:
                raise ValueError(
                    _ui_text("workspace_import.conflicting_retained_checkpoint_responses")
                )
            observed.setdefault(key, value)
    for path in sorted(out.glob("*.responses.jsonl")):
        attempts_path = path.with_name(
            path.name.removesuffix(".responses.jsonl") + ".attempts.jsonl"
        )
        attempts = {(row["run_id"], row["id"]): row for _, row in _jsonl(attempts_path)}
        for number, response in _jsonl(path):
            key = (response["run_id"], response["attempt_id"])
            if key in observed:
                if observed[key][:2] != (attempts[key], response):
                    raise ValueError(
                        _ui_text(
                            "workspace_import.final_response_differs_from_its_retained_checkpoint"
                        )
                    )
                continue
            observed[key] = (attempts[key], response, f"{path}:{number}")
    return observed.values()


def _program_groups(program: dict):
    """Keep the explicitly retained pre-repair prefix in the denominator.

    Recovery jobs can omit inputs whose answers are already in the declared
    predecessor checkpoint. Those are real retained records, not new jobs or
    new generations. The repaired input itself belongs to the current job.
    """
    assigned = {key for job in program["jobs"] for key in job["input_ids"]}
    for job in program["jobs"]:
        yield job["purpose"], job["input_ids"], _responses(job)
    prefixes = {}
    for repaired_input, recovery in program.get("adapter_recoveries", {}).items():
        owners = [job for job in program["jobs"] if repaired_input in job["input_ids"]]
        if len(owners) != 1:
            raise ValueError(_ui_text("workspace_import.retained_prefix_has_no_exact_recovery_job"))
        path = Path(recovery["checkpoint"]["path"])
        for number, record in _jsonl(path):
            attempt, response = record["attempt"], record["response"]
            key = attempt["params"]["retained_origin"]["selection"]["input_identity_sha256"]
            if key in assigned or key not in program["requests"]:
                continue
            if (attempt["run_id"], attempt["id"]) != (response["run_id"], response["attempt_id"]):
                raise ValueError(
                    _ui_text("workspace_import.retained_prefix_response_does_not_match_its_attempt")
                )
            if response.get("raw", {}).get("model_stability_status") == "failed_output":
                raise ValueError(
                    _ui_text(
                        "workspace_import.failed_predecessor_requires_explicit_recovery_selection"
                    )
                )
            value = (owners[0]["purpose"], attempt, response, f"{path}:{number}")
            if key in prefixes and prefixes[key][:3] != value[:3]:
                raise ValueError(
                    _ui_text("workspace_import.conflicting_retained_recovery_prefixes")
                )
            prefixes.setdefault(key, value)
    for key, (purpose, attempt, response, source) in prefixes.items():
        yield purpose, [key], [(attempt, response, source)]


def hosted_program_rows(
    program: dict,
    selections: list[dict],
    *,
    campaign_id: str,
    budget_plan: dict,
    ledger: dict,
    ledger_path: str,
    include_cost_bindings: bool = False,
) -> dict:
    """Index exactly the supplied program, including its unstarted assignments.

    The caller chooses the program and selection explicitly. Recoveries with
    multiple answers for one assignment need an explicit selection and are not
    silently reduced to the latest or most successful response.
    """
    choices = {row["input_identity_sha256"]: row for row in selections}
    requests = program["requests"]
    condition_id = generation_condition_id(program)
    if not requests.keys() <= choices.keys():
        raise ValueError(
            _ui_text("workspace_import.input_selection_does_not_cover_the_retained_program")
        )
    assignments, responses, bindings = {}, [], {}
    for purpose, input_ids, records in _program_groups(program):
        evidence = {
            "measured_run": "measured",
            "diagnostic_canary": "diagnostic",
            "attestation_probe": "diagnostic",
        }.get(purpose, "unknown")
        for input_id in input_ids:
            if input_id in assignments:
                raise ValueError(
                    _ui_text("workspace_import.input_is_assigned_to_multiple_program_jobs")
                )
            request, choice = requests[input_id], choices[input_id]
            assignments[input_id] = dict(
                assignment_id=request["call_id"],
                model=program["target"],
                input_id=input_id,
                condition_id=condition_id,
                modality=choice["modality"],
                framework=choice["framework"],
                corpus=choice["corpus"],
                response_id=None,
                evidence_class=evidence,
            )
            bindings[request["call_id"]] = dict(
                campaign_id=campaign_id,
                assignment_id=request["call_id"],
                model=program["target"],
                attempt_response_ids={},
                attempt_usage={},
            )
        for attempt, response, source in records:
            selection = attempt["params"]["retained_origin"]["selection"]
            input_id = selection["input_identity_sha256"]
            if input_id not in input_ids or response["target"] != program["target"]:
                raise ValueError(
                    _ui_text("workspace_import.response_is_outside_the_selected_program_job")
                )
            row, request = assignments[input_id], requests[input_id]
            if any(selection[key] != row[key] for key in ("modality", "framework", "corpus")):
                raise ValueError(
                    _ui_text(
                        "workspace_import.retained_response_input_metadata_differs_from_selection"
                    )
                )
            response_id = response["run_id"] + ":" + response["attempt_id"]
            if row["response_id"] is not None:
                raise ValueError(
                    _ui_text(
                        "workspace_import.multiple_outputs_require_explicit_recovery_selection"
                    )
                )
            row["response_id"] = response_id
            raw, tokens = response.get("raw") or {}, response.get("tokens") or {}
            legacy_policy = legacy_provider_policy_basis(response)
            policy = (
                raw.get("provider_refusal") is True
                or raw.get("provider_policy_rejection") is True
                or bool(legacy_policy)
            )
            usable = any(
                isinstance(turn.get("content"), str) and turn["content"].strip()
                for turn in response.get("output_turns", [])
            )
            failed = (
                raw.get("model_stability_status") == "failed_output"
                or raw.get("target_input_status") == "incompatible"
            )
            outcome = "policy" if policy else "missing" if failed or not usable else "usable"
            generation, audit = raw.get("generation") or {}, raw.get("call_audit") or {}
            responses.append(
                dict(
                    response_id=response_id,
                    assignment_id=row["assignment_id"],
                    condition_id=row["condition_id"],
                    outcome=outcome,
                    truncated=raw.get("output_truncated"),
                    source_ref=source,
                    output_allowance=generation.get("max_tokens", request["max_output_tokens"]),
                    context_tokens=generation.get("context_tokens"),
                    input_tokens=tokens.get("input"),
                    output_tokens=tokens.get("output"),
                    reasoning_tokens=tokens.get("reasoning"),
                    finish_reason=raw.get("finish_reason", audit.get("finish_reason")),
                    missing_category=raw.get("model_stability_category")
                    if outcome == "missing"
                    else None,
                )
            )
            if legacy_policy:
                responses[-1]["outcome_basis"] = legacy_policy
            # Only attach usage where the physical attempt is unambiguous.
            # Multi-attempt charges still publish; their reported ledger usage
            # is retained without copying the final answer onto earlier retries.
            retained = ledger["attempts"].get(request["call_id"], {})
            if set(retained) == {"1"} and raw.get("transport_attempt_count") == 1:
                binding = bindings[request["call_id"]]
                binding["attempt_response_ids"]["1"] = response_id
                binding["attempt_usage"]["1"] = {
                    name: tokens[key]
                    for name, key in (
                        ("input_tokens", "input"),
                        ("output_tokens", "output"),
                        ("reasoning_tokens", "reasoning"),
                    )
                    if key in tokens
                }
    if assignments.keys() != requests.keys():
        raise ValueError(
            _ui_text("workspace_import.program_jobs_do_not_cover_the_assigned_requests")
        )
    costs = budget_attempt_rows(budget_plan, ledger, bindings=bindings, source_ref=ledger_path)
    rows = dict(
        assignments=list(assignments.values()),
        responses=responses,
        judgments=[],
        costs=costs.get(campaign_id, []),
    )
    if include_cost_bindings:
        rows["cost_bindings"] = bindings
    return rows


def publish_hosted_program(
    db,
    campaign_id: str,
    *,
    program: dict,
    selections: list[dict],
    budget_plan: dict,
    ledger: dict,
    ledger_path: str,
) -> dict:
    """Idempotent publication; no selection, execution, charging or new judging."""
    db.require_workspace(campaign_id)
    rows = hosted_program_rows(
        program,
        selections,
        campaign_id=campaign_id,
        budget_plan=budget_plan,
        ledger=ledger,
        ledger_path=ledger_path,
    )
    db.publish_workspace_results(
        campaign_id, **{key: rows[key] for key in ("assignments", "responses", "judgments")}
    )
    db.publish_workspace_costs(campaign_id, rows["costs"])
    return {key: len(value) for key, value in rows.items()}


class HostedWorkspacePublication:
    """Refresh only changed, explicitly admitted programs in the collection process.

    HTTP page reads never run this publisher. File sizes/timestamps detect new
    checkpoint data; they are not an assertion of scientific source validity.
    Admission remains with the collector and Runner. Publication failure does
    not cancel independently running target requests.
    """

    def __init__(
        self,
        db,
        campaign_id: str,
        *,
        programs: list[dict],
        selections: list[list[dict]],
        budget_root: Path,
    ):
        db.require_workspace(campaign_id)
        self.db, self.campaign_id = db, campaign_id
        self.programs, self.selections = programs, selections
        self.budget_root = budget_root
        self.budget_plan = json.loads((budget_root / "plan.json").read_text(encoding="utf-8"))
        self.signatures: dict[int, tuple] = {}
        self.cost_bindings: dict[int, dict] = {}
        self.cost_signatures: dict[int, dict] = {}
        self.ledger_signature: tuple | None = None
        self.ledger: dict = {}
        self.results: dict[int, dict] = {}

    @staticmethod
    def _signature(program: dict) -> tuple:
        paths = set()
        for job in program["jobs"]:
            argv = job["argv"]
            out = Path(argv[argv.index("--out") + 1])
            for pattern in (
                "*.responses.checkpoint.jsonl",
                "*.responses.jsonl",
                "*.attempts.jsonl",
            ):
                paths.update(out.glob(pattern))
        for recovery in program.get("adapter_recoveries", {}).values():
            paths.add(Path(recovery["checkpoint"]["path"]))
        return tuple(
            (str(path), item.st_size, item.st_mtime_ns)
            for path in sorted(paths)
            for item in (path.stat(),)
        )

    def refresh(self, progress: dict) -> dict:
        states = {}
        for row in progress["jobs"]:
            states.setdefault(row["program"], []).append((row["job"], row["status"]))
        ledger_path = self.budget_root / "ledger.json"
        try:
            item = ledger_path.stat()
            ledger_signature = (item.st_size, item.st_mtime_ns, item.st_ino)
            if ledger_signature != self.ledger_signature:
                self.ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                self.ledger_signature = ledger_signature
        except (OSError, ValueError) as exc:
            return dict(
                status="publication_pending",
                campaign_id=self.campaign_id,
                error_type=type(exc).__name__,
                programs=[],
            )
        for index, program in enumerate(self.programs):
            try:
                signature = (tuple(states.get(index, ())), self._signature(program))
                cost_signature = {
                    request["call_id"]: self.ledger["attempts"].get(request["call_id"], {})
                    for request in program["requests"].values()
                }
                source_changed = self.signatures.get(index) != signature
                if not source_changed and self.cost_signatures.get(index) == cost_signature:
                    continue
                if source_changed:
                    rows = hosted_program_rows(
                        program,
                        self.selections[index],
                        campaign_id=self.campaign_id,
                        budget_plan=self.budget_plan,
                        ledger=self.ledger,
                        ledger_path=str(ledger_path),
                        include_cost_bindings=True,
                    )
                    bindings = rows.pop("cost_bindings")
                    self.db.publish_workspace_results(
                        self.campaign_id,
                        **{key: rows[key] for key in ("assignments", "responses", "judgments")},
                    )
                    counts = {key: len(value) for key, value in rows.items()}
                else:
                    bindings = self.cost_bindings[index]
                    rows = dict(
                        costs=budget_attempt_rows(
                            self.budget_plan,
                            self.ledger,
                            bindings=bindings,
                            source_ref=str(ledger_path),
                        ).get(self.campaign_id, [])
                    )
                    counts = {
                        key: self.results[index][key]
                        for key in ("assignments", "responses", "judgments")
                    }
                    counts["costs"] = len(rows["costs"])
                self.db.publish_workspace_costs(self.campaign_id, rows["costs"])
                if not self.db.healthy:
                    raise RuntimeError(_ui_text("workspace_import.campaign_index_is_unavailable"))
                self.signatures[index] = signature
                self.cost_bindings[index] = bindings
                self.cost_signatures[index] = cost_signature
                self.results[index] = dict(status="published", **counts)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
                self.results[index] = dict(
                    self.results.get(index, {}),
                    status="publication_pending",
                    error_type=type(exc).__name__,
                )
        return dict(
            status="published"
            if all(row["status"] == "published" for row in self.results.values())
            else "publication_pending",
            campaign_id=self.campaign_id,
            programs=[dict(program=index, **row) for index, row in sorted(self.results.items())],
        )


def _local_artifact_paths(source: dict) -> tuple[dict, dict | None]:
    artifacts = {key: Path(value["path"]) for key, value in source["artifacts"].items()}
    if "scoring_completion" not in artifacts:
        return artifacts, None
    completion = json.loads(artifacts["scoring_completion"].read_text(encoding="utf-8"))
    if completion["generation_run_id"] != source["run_id"]:
        raise ValueError(
            _ui_text("workspace_import.separate_scoring_belongs_to_another_generation")
        )
    # These are explicitly retained source paths, not a directory scan or a
    # reconstruction of the original corpus. Final exports can be partial.
    for role, suffix in (
        ("manifest", ".manifest.json"),
        ("attempts", ".attempts.jsonl"),
        ("responses", ".responses.jsonl"),
        ("judgments", ".jsonl"),
        ("response_checkpoint", ".responses.checkpoint.jsonl"),
    ):
        matches = [
            path for path in artifacts.values() if path.name.endswith(source["run_id"] + suffix)
        ]
        if len(matches) != 1:
            raise ValueError(
                (
                    _ui_text("workspace_import.separate_scoring_needs_one_retained")
                    + f"{role}"
                    + " source"
                )
            )
        artifacts[role] = matches[0]
    return artifacts, completion


def local_generation_condition(run: dict) -> str:
    if not run.get("model_spec", "").startswith(("ollama:", "vllm:")):
        settings = {
            k: v
            for k, v in (run.get("api_config") or {}).items()
            if k not in {"api_key", "api_key_env", "key_env", "authorization", "token"}
        }
        value = dict(
            target=run["model_spec"],
            settings=settings,
            max_output_tokens=settings.get("max_tokens"),
        )
        return (
            "generation-"
            + hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()[:24]
        )
    settings = {
        key: run.get(key)
        for key in (
            "model_spec",
            "local_identity",
            "dtype",
            "resolved_quantization",
            "target_answer_retries",
            "project_revision",
            "engine_runtime",
        )
    }
    return (
        "local-generation-"
        + hashlib.sha256(
            json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]
    )


def local_judge_condition(run: dict) -> str:
    settings = {
        key: run.get(key)
        for key in (
            "judge_names",
            "judge_model",
            "guardrail_model",
            "guardrail_revision",
            "judge_local_identity",
            "approximate_common_metrics",
        )
    }
    return (
        "local-cascade-"
        + hashlib.sha256(
            json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]
    )


def local_response_row(response: dict, condition: str, reference: str) -> dict:
    identity = response["run_id"] + ":" + response["attempt_id"]
    raw, tokens = response.get("raw") or {}, response.get("tokens") or {}
    visible = any(
        isinstance(t.get("content"), str) and t["content"].strip()
        for t in response.get("output_turns", [])
    )
    failed = (
        raw.get("model_stability_status") == "failed_output"
        or raw.get("target_input_status") == "incompatible"
    )
    generation, stop = raw.get("generation") or {}, _stop(raw)
    truncated = raw.get("output_truncated")
    if truncated is None and stop in {"truncated", "normal_stop"}:
        truncated = stop == "truncated"
    policy = (
        raw.get("provider_refusal") is True
        or raw.get("provider_policy_rejection") is True
        or bool(legacy_provider_policy_basis(response))
    )
    prefix = "local-" if response["target"].startswith(("ollama:", "vllm:")) else "direct-"
    return dict(
        response_id=identity,
        assignment_id=prefix + identity,
        condition_id=condition,
        outcome="policy" if policy else "missing" if failed or not visible else "usable",
        truncated=truncated,
        source_ref=reference,
        context_tokens=_first(generation, ("context_tokens", "max_model_len", "num_ctx")),
        output_allowance=_first(generation, ("max_output_tokens", "max_tokens", "num_predict")),
        input_tokens=_usage(tokens, ("input", "prompt")),
        output_tokens=_usage(tokens, ("output", "completion")),
        reasoning_tokens=tokens.get("reasoning"),
        finish_reason=_first(raw, ("finish_reason", "done_reason", "stop_reason")),
        missing_category=(
            raw.get("model_stability_category")
            or raw.get("target_input_category")
            or ("empty_output" if not visible else None)
        )
        if failed or not visible
        else None,
    )


def local_run_rows(source: dict, selections: dict[str, dict]) -> dict:
    """Index an explicitly selected native local run, including missing outputs.

    Selection keys are native attempt IDs. Historical and corrected runs keep
    their own assignments; this function never picks a newer or better answer.
    """
    model, run_id = source["local_model"], source["run_id"]
    if not model.startswith(("vllm:", "ollama:")):
        raise ValueError(
            _ui_text("workspace_import.local_publication_requires_a_local_target_identity")
        )
    artifacts, completion = _local_artifact_paths(source)
    manifest = json.loads(artifacts["manifest"].read_text(encoding="utf-8"))
    run = manifest["config"]["run"]
    attempts = {row["id"]: row for _, row in _jsonl(artifacts["attempts"])}
    responses = {}
    for number, row in _jsonl(artifacts["responses"]):
        if row["run_id"] != run_id or row["target"] != model or row["attempt_id"] not in attempts:
            raise ValueError(_ui_text("workspace_import.native_local_response_ownership_differs"))
        if row["attempt_id"] in responses:
            raise ValueError(_ui_text("workspace_import.duplicate_native_local_output"))
        responses[row["attempt_id"]] = (row, f"{artifacts['responses']}:{number}")
    if completion is not None:
        for number, record in _jsonl(artifacts["response_checkpoint"]):
            row, attempt = record["response"], record["attempt"]
            key = row["attempt_id"]
            if (
                row["run_id"] != run_id
                or row["target"] != model
                or (attempt["run_id"], attempt["id"]) != (run_id, key)
                or attempt["target"] != model
                or (key in attempts and attempt != attempts[key])
            ):
                raise ValueError(
                    _ui_text("workspace_import.native_local_response_checkpoint_ownership_differs")
                )
            attempts.setdefault(key, attempt)
            if key in responses and responses[key][0] != row:
                raise ValueError(
                    _ui_text("workspace_import.local_final_output_differs_from_its_checkpoint")
                )
            responses.setdefault(key, (row, f"{artifacts['response_checkpoint']}:{number}"))
    if not selections.keys() <= attempts.keys():
        raise ValueError(_ui_text("workspace_import.local_selection_has_no_native_attempt"))
    condition = local_generation_condition(run)
    evidence = {
        "measured_run": "measured",
        "diagnostic_canary": "diagnostic",
        "attestation_probe": "diagnostic",
        "preflight": "preflight",
    }.get(run.get("execution_purpose"), "unknown")
    assignments, outputs, judgments = [], [], []
    for attempt_id, choice in selections.items():
        attempt = attempts[attempt_id]
        if (
            attempt["run_id"] != run_id
            or attempt["target"] != model
            or choice["corpus"] != run["corpus"]
        ):
            raise ValueError(_ui_text("workspace_import.native_local_attempt_ownership_differs"))
        identity = run_id + ":" + attempt_id
        response_id = identity if attempt_id in responses else None
        assignments.append(
            dict(
                assignment_id="local-" + identity,
                model=model,
                input_id=choice["input_identity_sha256"],
                condition_id=condition,
                modality=choice["modality"],
                framework=choice["framework"],
                corpus=choice["corpus"],
                response_id=response_id,
                evidence_class=evidence,
            )
        )
        if response_id is None:
            continue
        response, reference = responses[attempt_id]
        outputs.append(local_response_row(response, condition, reference))
    judge_id = local_judge_condition(run)
    records = [
        (row, f"{artifacts['judgments']}:{number}", judge_id)
        for number, row in _jsonl(artifacts["judgments"])
    ]
    if completion is not None:
        recovered_judge = judge_id + "-" + completion["judging_revision"]["expected_commit"][:12]
        checkpoint = completion.get("checkpoint")
        if checkpoint is not None:
            for number, record in _jsonl(Path(checkpoint["path"])):
                response = record["response"]
                if responses.get(response["attempt_id"], (None,))[0] != response:
                    raise ValueError(
                        _ui_text("workspace_import.separate_judgment_changed_its_retained_output")
                    )
                records.append(
                    (record["judgment"], f"{checkpoint['path']}:{number}", recovered_judge)
                )
        for descriptor in completion.get("evaluator_failures", []):
            row = json.loads(Path(descriptor["path"]).read_text(encoding="utf-8"))
            if row["generation_run_id"] != run_id or row["attempt_id"] not in responses:
                raise ValueError(
                    _ui_text("workspace_import.invalid_evaluator_record_has_no_retained_output")
                )
            if row["attempt_id"] in selections:
                judgments.append(
                    dict(
                        response_id=run_id + ":" + row["attempt_id"],
                        judge_id=recovered_judge,
                        status="invalid",
                        label=None,
                        source_ref=descriptor["path"],
                    )
                )
    seen = {row["response_id"].removeprefix(run_id + ":") for row in judgments}
    for row, reference, actual_judge in records:
        attempt_id = row["attempt_id"]
        if attempt_id not in selections:
            continue
        if row["run_id"] != run_id or attempt_id not in responses or attempt_id in seen:
            raise ValueError(
                _ui_text("workspace_import.local_judgment_has_no_unique_retained_output")
            )
        seen.add(attempt_id)
        raw = row.get("raw") or {}
        missing = raw.get("policy_evaluation_status") in {
            "model_nonresponse",
            "target_input_incompatible",
        }
        judgments.append(
            dict(
                response_id=run_id + ":" + attempt_id,
                judge_id=actual_judge,
                status="missing" if missing else "valid",
                label=None if missing else row["label"],
                source_ref=reference,
            )
        )
    from .workspace_judge_settings import local_settings

    for row in judgments:
        row["judge_settings"] = local_settings(
            run=run,
            revision=(
                completion["judging_revision"]["expected_commit"]
                if row["judge_id"] != judge_id
                else None
            ),
        )
    return dict(assignments=assignments, responses=outputs, judgments=judgments)
