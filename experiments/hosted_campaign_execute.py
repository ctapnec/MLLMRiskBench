"""Collect the selected funded hosted programs in parallel, then hand off judging.

Pass the exact prepared/attested program files, not a new random selection.
The shared budget, Runner retry policy and response checkpoints remain
authoritative. Run this detached command on the rig, including from Rig Web.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from experiments import hosted_retained_execute as retained
from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_campaign_budget import load_bound_json, _sha
from experiments.hosted_dispatch import dispatch_admitted
from experiments.retained_response_judge_execute import _write_atomic, _write_new
from ura.artifact_checks import artifact_verification_cli


def collect_campaign(*, programs: Sequence[tuple[Path, str]], budget_root: Path,
                     budget_plan_sha256: str, project_root: Path, expected_commit: str,
                     out: Path, workers_per_provider: int = 2,
                     workspace_id: str = "", console_db: Path | None = None) -> dict:
    """Validate shared sources once, then collect without co-resident judges."""
    retained._validated_checkout(project_root, expected_commit)
    if not programs or len({str(path.resolve()) for path, _sha256 in programs}) != len(programs):
        raise ValueError("Select each funded program exactly once")
    if out.exists() or out.is_symlink() or not out.is_absolute() or out.parent.resolve(strict=True) != out.parent:
        raise ValueError("Campaign collection needs a fresh resolved output directory")
    if type(workers_per_provider) is not int or not 1 <= workers_per_provider <= 8:
        raise ValueError("Workers per provider must be an integer from 1 to 8")
    if bool(workspace_id) != (console_db is not None):
        raise ValueError("Campaign publication requires both workspace ID and console database")
    budget = AttemptBudget(budget_root, budget_plan_sha256)
    contexts, admitted, references, call_ids = {}, [], [], set()
    prepared_programs = []
    for path, sha256 in programs:
        program, descriptor = load_bound_json(path, sha256)
        key = _sha({name: program.get(name) for name in ("results_root", "runner_view", "rr_analysis_root")}
            | {"historical_result": program.get("sources", {}).get("historical_result")})
        if key not in contexts:
            contexts[key] = retained._validated_local_cells(program)
        jobs = retained._validated_jobs(program, budget, local_context=contexts[key])
        ids = {request["call_id"] for admission in jobs for request in admission.requests.values()}
        if call_ids & ids:
            raise ValueError("Selected programs overlap the same funded target calls")
        call_ids.update(ids)
        admitted.append(jobs)
        prepared_programs.append(program)
        references.append({"path": str(path.resolve()), **descriptor, "target": program["target"]})
    out.mkdir(mode=0o700)
    _write_new(out / "selection.json", dict(programs=references, assigned_target_inputs=len(call_ids),
        workers_per_provider=workers_per_provider, budget_root=str(budget_root),
        budget_plan_sha256=budget_plan_sha256, stage="target_collection", judgments="deferred"))
    database, publisher, publication = None, None, None
    try:
        if workspace_id:
            from experiments.rig_web_app.storage import ConsoleDB
            from experiments.rig_web_app.workspace_import import HostedWorkspacePublication
            database = ConsoleDB(console_db, repo_root=project_root)
            publisher = HostedWorkspacePublication(database, workspace_id, programs=prepared_programs,
                selections=[jobs[0].attacker._retained["plan"]["selected"] for jobs in admitted],
                budget_root=budget_root)

        def progress_changed(progress):
            nonlocal publication
            if publisher is not None:
                publication = publisher.refresh(progress)
                progress = dict(progress, publication=publication)
            _write_atomic(out / "progress.json", progress)

        if publisher is not None:
            progress_changed(dict(jobs=[dict(program=p, job=j, status="pending")
                for p, jobs in enumerate(admitted) for j in range(len(jobs))]))
        rows = dispatch_admitted(admitted, workers_per_provider=workers_per_provider, responses_only=True,
            on_progress=progress_changed)
        if publisher is not None:
            progress_changed(dict(jobs=rows))
    finally:
        if database is not None:
            database.close()
    complete = all(row["status"] == "collected" for row in rows)
    result = dict(status="responses_collected_awaiting_judging" if complete else "collection_needs_continuation",
        jobs=rows, assigned_target_inputs=len(call_ids), judgments="not_executed_by_collection",
        selection_changed=False, automatic_answer_retries_added=0)
    if publication is not None:
        result["publication"] = publication
    _write_new(out / "result.json", result)
    return result


@artifact_verification_cli
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, required=True, action="append")
    parser.add_argument("--program-sha256", required=True, action="append")
    parser.add_argument("--budget-root", type=Path, required=True)
    parser.add_argument("--budget-plan-sha256", required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers-per-provider", type=int, default=2, choices=range(1, 9))
    parser.add_argument("--workspace-id", default=os.environ.get("URA_CAMPAIGN_WORKSPACE_ID", ""),
        help="Publish the admitted collection into this existing campaign workspace")
    parser.add_argument("--console-db", type=Path, default=os.environ.get("URA_CAMPAIGN_CONSOLE_DB"),
        help="Rig Web SQLite index; paired with --workspace-id")
    parser.add_argument("--verify-artifact-sha256", action="store_true",
        help="Opt in to full retained-file checksum revalidation")
    args = parser.parse_args(argv)
    if len(args.program) != len(args.program_sha256):
        parser.error("Supply one matching digest for each program, in the same order")
    result = collect_campaign(programs=list(zip(args.program, args.program_sha256)),
        budget_root=args.budget_root, budget_plan_sha256=args.budget_plan_sha256,
        project_root=args.project_root, expected_commit=args.expected_commit,
        out=args.out, workers_per_provider=args.workers_per_provider,
        workspace_id=args.workspace_id, console_db=args.console_db)
    print(json.dumps({key: value for key, value in result.items() if key != "jobs"}, sort_keys=True))
    return 0 if result["status"] == "responses_collected_awaiting_judging" else 1


if __name__ == "__main__":
    raise SystemExit(main())
