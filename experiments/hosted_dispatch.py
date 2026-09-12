"""Provider-limited execution of already admitted hosted Runner jobs.

Selection, source validation and funding happen before dispatch. Workers inherit
that read-only preparation, retain Runner checkpoints, and use the existing
per-request budget and transport-retry handling. No local campaign is scheduled
here, and collection never waits for a different program's judging stage.
"""
from __future__ import annotations

from collections import Counter
from contextlib import nullcontext
import multiprocessing
from pathlib import Path
from typing import Callable, Sequence


def run_admission(admission, *, responses_only: bool) -> str:
    from experiments import run_matrix
    from experiments.hosted_retained_execute import _retained_execution_counts
    from ura.hosted_scheduling import HostedJudgingDeferred, hosted_responses_only
    from ura.runner import retained_execution_admission

    with retained_execution_admission(admission):
        try:
            with hosted_responses_only() if responses_only else nullcontext():
                code = run_matrix.main(admission.job["argv"])
        except HostedJudgingDeferred:
            if not responses_only:
                raise
        else:
            if code != 0:
                raise RuntimeError("Runner is unfinished; retain and resume its checkpoints")
    scoped = {**admission.program, "jobs": [admission.job], "requests": admission.requests}
    attempted, _usable, saved = _retained_execution_counts(scoped, admission.budget, include_saved=True)
    if attempted != len(admission.requests) or saved != len(admission.requests):
        raise RuntimeError("Runner has not retained the complete assigned input selection")
    return str(Path(run_matrix.build_parser().parse_args(admission.job["argv"]).out))


def _child(send, admission, responses_only, worker):
    try:
        output = worker(admission, responses_only=responses_only)
        send.send({"status": "collected" if responses_only else "complete", "output": output})
    except BaseException as exc:
        # Native artifacts/logs retain the detailed failure. Do not copy a raw
        # provider exception (which can contain request data) into UI state.
        send.send({"status": "failed", "error_type": type(exc).__name__})
    finally:
        send.close()


def _pause_reason(admission) -> str | None:
    from experiments.hosted_retained_execute import target_pause

    if (admission.budget.root / "paid-circuit.json").exists():
        return "campaign_spending_paused"
    provider = admission.program["provider"]
    if any(row["provider"] == provider for row in admission.budget.provider_funding_stops()):
        return "provider_funding_stop"
    pause = target_pause(admission.budget, admission.program["target"])
    return str(pause["category"]) if pause is not None else None


def dispatch_admitted(
    programs: Sequence[Sequence], *, workers_per_provider: int = 2,
    responses_only: bool = True, on_progress: Callable[[dict], None] | None = None,
    _worker=run_admission, _pause=_pause_reason,
) -> list[dict]:
    """Run the fixed programs with isolated workers and provider-local limits.

    A program's pilot/canary jobs remain ordered before its measured jobs.
    Independent providers and admitted measured jobs can overlap. One failed
    program does not cancel another provider; its own unstarted jobs are retained
    as pending, not silently tried with a fresh selection. The caller publishes
    the returned states and owns any explicit continuation.

    This process controller runs on the POSIX rig. It must be invoked as a
    detached command, not forked from a web request thread.
    """
    if type(workers_per_provider) is not int or not 1 <= workers_per_provider <= 8:
        raise ValueError("Workers per provider must be an integer from 1 to 8")
    if type(responses_only) is not bool or not programs or any(not jobs for jobs in programs):
        raise ValueError("Dispatch needs nonempty admitted programs and an explicit execution stage")
    if "fork" not in multiprocessing.get_all_start_methods():
        raise RuntimeError("Provider-parallel retained execution requires the POSIX rig")
    context = multiprocessing.get_context("fork")
    from experiments.hosted_retained_execute import _billing_provider
    tasks = []
    outputs = set()
    for program_index, admissions in enumerate(programs):
        measured = False
        route = admissions[0].program
        if ":" not in str(route["target"]) or str(route["target"]).startswith(("vllm:", "ollama:", "mock:")):
            raise ValueError("Provider dispatch accepts hosted targets only")
        for job_index, admission in enumerate(admissions):
            purpose = admission.job["purpose"]
            if purpose not in {"attestation_probe", "diagnostic_canary", "measured_run"}:
                raise ValueError("Unknown admitted job purpose")
            if admission.program["provider"] != route["provider"] or admission.program["target"] != route["target"]:
                raise ValueError("One admitted program cannot change provider or target")
            if measured and purpose != "measured_run":
                raise ValueError("Readiness jobs must precede measured jobs")
            measured |= purpose == "measured_run"
            argv = admission.job["argv"]
            output = argv[argv.index("--out") + 1]
            if output in outputs:
                raise ValueError("Concurrent jobs cannot share one Runner output directory")
            outputs.add(output)
            tasks.append(dict(program=program_index, job=job_index,
                name=admission.job["name"], target=route["target"], provider=_billing_provider(route["provider"]),
                purpose=purpose, status="pending", output=output, admission=admission))
    active = {}

    def public():
        return [{key: value for key, value in row.items() if key != "admission"} for row in tasks]

    def publish():
        if on_progress is not None:
            on_progress(dict(jobs=public(), workers_per_provider=workers_per_provider,
                responses_only=responses_only, active_by_provider=dict(Counter(
                    tasks[index]["provider"] for index in active))))

    try:
        while any(row["status"] == "pending" for row in tasks) or active:
            changed = False
            for index, (process, receive) in list(active.items()):
                if process.is_alive():
                    continue
                process.join()
                try:
                    result = receive.recv() if receive.poll() and process.exitcode == 0 else {
                        "status": "failed", "error_type": "WorkerExitedWithoutResult"}
                except EOFError:
                    result = {"status": "failed", "error_type": "WorkerExitedWithoutResult"}
                receive.close()
                process.close()
                tasks[index].update(result)
                del active[index]
                changed = True
            occupied = Counter(tasks[index]["provider"] for index in active)
            failed_programs = {row["program"] for row in tasks if row["status"] in {"failed", "paused"}}
            unfinished_pilots = Counter(row["program"] for row in tasks
                if row["purpose"] != "measured_run" and row["status"] in {"pending", "running"})
            active_pilots = {row["program"] for row in tasks
                if row["purpose"] != "measured_run" and row["status"] == "running"}
            for index, row in enumerate(tasks):
                if row["status"] != "pending":
                    continue
                if row["program"] in failed_programs:
                    row.update(status="paused", reason="prior_program_job_unfinished")
                    changed = True
                    continue
                # Readiness/canary stages stay serial. Only admitted measured
                # jobs fan out, after every pilot in their own program ends.
                if row["program"] in active_pilots or (
                        row["purpose"] == "measured_run" and unfinished_pilots[row["program"]]):
                    continue
                if occupied[row["provider"]] >= workers_per_provider:
                    continue
                reason = _pause(row["admission"])
                if reason:
                    row.update(status="paused", reason=reason)
                    failed_programs.add(row["program"])
                    changed = True
                    continue
                receive, send = context.Pipe(duplex=False)
                process = context.Process(target=_child,
                    args=(send, row["admission"], responses_only, _worker))
                try:
                    process.start()
                except BaseException:
                    receive.close()
                    send.close()
                    raise
                send.close()
                active[index] = (process, receive)
                row["status"] = "running"
                if row["purpose"] != "measured_run":
                    active_pilots.add(row["program"])
                occupied[row["provider"]] += 1
                changed = True
            if changed:
                publish()
            if active:
                # Wait on real child handles. No corpus/ledger scan or busy loop.
                from multiprocessing.connection import wait
                wait([process.sentinel for process, _receive in active.values()], timeout=1)
        return public()
    finally:
        for process, receive in active.values():
            if process.is_alive():
                process.terminate()
            process.join()
            receive.close()
            process.close()
