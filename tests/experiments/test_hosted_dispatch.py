"""Rig-only isolated scheduling checks; no models, SDK clients or paid calls."""
from collections import Counter
from contextlib import nullcontext
import json
import multiprocessing
from types import SimpleNamespace
import time

import pytest

from experiments import hosted_dispatch as subject


pytestmark = pytest.mark.skipif("forkserver" not in multiprocessing.get_all_start_methods(), reason="POSIX rig dispatcher")


def admission(root, provider, name, *, purpose="measured_run", fail=False):
    return SimpleNamespace(program={"provider": provider, "target": provider + ":example"},
        job={"name": name, "purpose": purpose, "argv": ["--out", str(root / name)]},
        events=root, fail=fail)


def worker(job, *, responses_only):
    begin = time.monotonic_ns()
    time.sleep(0.2)
    end = time.monotonic_ns()
    (job.events / (job.job["name"] + ".json")).write_text(json.dumps({
        "start": begin, "end": end, "provider": job.program["provider"],
        "responses_only": responses_only, "argv": job.job["argv"]}))
    if job.fail:
        raise RuntimeError("Sensitive provider payload must not enter scheduler metadata")
    return job.job["argv"][1]


def test_parallel_providers_respect_two_slots_without_changing_inputs(tmp_path):
    programs = [[admission(tmp_path, provider, provider + str(i)) for i in range(4)]
        for provider in ("openai", "google")]
    progress = []
    result = subject.dispatch_admitted(programs, _worker=worker, _pause=lambda _: None,
        on_progress=progress.append)
    assert len(result) == 8 and {row["status"] for row in result} == {"collected"}
    events = [json.loads(path.read_text()) for path in tmp_path.glob("*.json")]
    timeline = sorted((row[key], delta, row["provider"]) for row in events
        for key, delta in (("start", 1), ("end", -1)))
    active, maximum = Counter(), Counter()
    overlap = False
    for _stamp, delta, provider in timeline:
        active[provider] += delta
        maximum[provider] = max(maximum[provider], active[provider])
        overlap |= all(active[name] > 0 for name in ("openai", "google"))
    assert maximum == {"openai": 2, "google": 2} and overlap
    assert all(row["responses_only"] is True for row in events)
    assert {tuple(row["argv"]) for row in events} == {
        tuple(job.job["argv"]) for jobs in programs for job in jobs}
    assert all("admission" not in row for value in progress for row in value["jobs"])


def test_pilots_finish_in_order_before_own_measured_jobs(tmp_path):
    jobs = [admission(tmp_path, "openai", "probe", purpose="attestation_probe"),
        admission(tmp_path, "openai", "canary", purpose="diagnostic_canary"),
        admission(tmp_path, "openai", "measured1"), admission(tmp_path, "openai", "measured2")]
    result = subject.dispatch_admitted([jobs], _worker=worker, _pause=lambda _: None)
    events = {name: json.loads((tmp_path / (name + ".json")).read_text()) for name in
        ("probe", "canary", "measured1", "measured2")}
    assert events["probe"]["end"] <= events["canary"]["start"]
    assert events["canary"]["end"] <= min(events["measured1"]["start"], events["measured2"]["start"])
    assert {row["status"] for row in result} == {"collected"}


def test_failed_pilot_leaves_own_work_pending_but_other_provider_finishes(tmp_path):
    programs = [[admission(tmp_path, "openai", "bad", purpose="diagnostic_canary", fail=True),
        admission(tmp_path, "openai", "never")], [admission(tmp_path, "google", "good")]]
    result = subject.dispatch_admitted(programs, _worker=worker, _pause=lambda _: None)
    assert [row["status"] for row in result] == ["failed", "paused", "collected"]
    assert not (tmp_path / "never.json").exists()
    assert "Sensitive" not in json.dumps(result)


def test_provider_pause_prevents_calls_without_holding_other_provider(tmp_path):
    result = subject.dispatch_admitted([[admission(tmp_path, "openai", "paused")],
        [admission(tmp_path, "google", "running")]], _worker=worker,
        _pause=lambda job: "provider_funding_stop" if job.program["provider"] == "openai" else None)
    assert [row["status"] for row in result] == ["paused", "collected"]
    assert not (tmp_path / "paused.json").exists()


@pytest.mark.parametrize("value", [0, 9, True, 1.5])
def test_invalid_parallelism_is_rejected_before_calls(tmp_path, value):
    with pytest.raises(ValueError, match="Workers per provider"):
        subject.dispatch_admitted([[admission(tmp_path, "openai", "a")]], workers_per_provider=value)
    assert not list(tmp_path.iterdir())


def test_duplicate_output_and_local_targets_cannot_enter_dispatch(tmp_path):
    job = admission(tmp_path, "openai", "same")
    with pytest.raises(ValueError, match="share one Runner output"):
        subject.dispatch_admitted([[job], [job]])
    local = admission(tmp_path, "ollama", "local")
    with pytest.raises(ValueError, match="hosted targets only"):
        subject.dispatch_admitted([[local]])


def test_real_worker_requires_complete_accounting_after_deferred_judging(tmp_path, monkeypatch):
    from experiments import run_matrix, hosted_retained_execute
    from ura import runner
    from ura.hosted_scheduling import HostedJudgingDeferred

    job = admission(tmp_path, "openai", "real")
    job.requests = {"input-1": {}}
    job.budget = object()
    monkeypatch.setattr(runner, "retained_execution_admission", lambda value: nullcontext())
    monkeypatch.setattr(run_matrix, "main", lambda argv: (_ for _ in ()).throw(HostedJudgingDeferred()))
    monkeypatch.setattr(run_matrix, "build_parser", lambda: SimpleNamespace(
        parse_args=lambda argv: SimpleNamespace(out=argv[1])))
    monkeypatch.setattr(hosted_retained_execute, "_retained_execution_counts", lambda *_, **kw: (0, 0, 0))
    with pytest.raises(RuntimeError, match="complete assigned input selection"):
        subject.run_admission(job, responses_only=True)
    monkeypatch.setattr(hosted_retained_execute, "_retained_execution_counts", lambda *_, **kw: (1, 0, 0))
    with pytest.raises(RuntimeError, match="complete assigned input selection"):
        subject.run_admission(job, responses_only=True)
    monkeypatch.setattr(hosted_retained_execute, "_retained_execution_counts", lambda *_, **kw: (1, 0, 1))
    assert subject.run_admission(job, responses_only=True) == str(tmp_path / "real")
    with pytest.raises(HostedJudgingDeferred):
        subject.run_admission(job, responses_only=False)


def test_worker_crash_is_failed_not_an_unfinished_wait(tmp_path):
    result = subject.dispatch_admitted([[admission(tmp_path, "openai", "crash")]],
        _worker=crash_worker, _pause=lambda _: None)
    assert result[0]["status"] == "failed"
    assert result[0]["error_type"] == "WorkerExitedWithoutResult"


def crash_worker(job, *, responses_only):
    import os
    os._exit(7)


def admitted_metadata_worker(job, *, responses_only):
    assert responses_only is True
    assert set(job.requests) == set(job.entries)
    assert all(job.budget.reserved_attempt_count(row["call_id"]) == 0 for row in job.requests.values())
    return job.job["argv"][1]


def test_real_admission_and_budget_transfer_without_reconstructing_sources(tmp_path):
    from test_hosted_retained_execute import _setup

    _points, _attacker, _target, calls, job = _setup(tmp_path)
    job.job.update(name="transferred", argv=["--out", str(tmp_path / "out")])
    result = subject.dispatch_admitted([[job]], _worker=admitted_metadata_worker, _pause=lambda _: None)
    assert result[0]["status"] == "collected"
    assert result[0]["output"] == str(tmp_path / "out")
    assert calls == []
