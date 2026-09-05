from __future__ import annotations

import json
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import retained_artifact_reader as subject


COMMIT = "a" * 40
TREE = "b" * 40


def _grid(root: Path, *, commit: str = COMMIT) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "run.grid.json").write_text("{}", encoding="utf-8")
    manifest = {"config": {"run": {"project_revision": {
        "expected_commit": commit, "observed_commit": commit, "head_tree": TREE,
    }}}}
    (root / "cell.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _cell(root: Path, *, run_id: str = "run") -> dict:
    return {
        "run_id": run_id,
        "manifest_path": str(root / "cell.manifest.json"),
        "complete_path": str(root / "cell.complete.json"),
        "artifacts": {"responses": str(root / "cell.responses.jsonl")},
    }


def test_partitions_preserve_exact_revision_and_separate_grid_roots(tmp_path):
    first = _grid(tmp_path / "first")
    second = _grid(tmp_path / "second", commit="c" * 40)
    assert subject.grid_partitions(tmp_path) == [
        (first, COMMIT, TREE), (second, "c" * 40, TREE),
    ]


@pytest.mark.parametrize("name", ["x.grid.lock", "x.cell.lock", "x.error.json"])
def test_partitions_refuse_running_or_failed_trees(tmp_path, name):
    _grid(tmp_path)
    (tmp_path / name).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="running or failed"):
        subject.grid_partitions(tmp_path)


@pytest.mark.parametrize("name", [
    "x.manifest.json", "x.attempts.jsonl", "x.responses.jsonl", "x.complete.json",
])
def test_partitions_refuse_orphans(tmp_path, name):
    _grid(tmp_path / "completed")
    (tmp_path / name).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="orphan"):
        subject.grid_partitions(tmp_path)


def test_partitions_refuse_nested_grids_and_changed_revision(tmp_path):
    _grid(tmp_path)
    _grid(tmp_path / "nested")
    with pytest.raises(ValueError, match="overlap"):
        subject.grid_partitions(tmp_path)
    manifest_path = tmp_path / "nested" / "cell.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["config"]["run"]["project_revision"]["observed_commit"] = "c" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="exact verified"):
        subject.grid_partitions(tmp_path / "nested")


@pytest.mark.parametrize("untrusted", ["ancestor", "tree"])
def test_source_admission_precedes_checkout_or_worker(tmp_path, monkeypatch, untrusted):
    _grid(tmp_path)
    calls = []

    def git(repository, *args):
        calls.append(args)
        if args[0] == "merge-base" and untrusted == "ancestor":
            raise ValueError("not an ancestor")
        if args == ("rev-parse", f"{COMMIT}^{{tree}}"):
            return "c" * 40 if untrusted == "tree" else TREE
        return COMMIT

    monkeypatch.setattr(subject, "_git", git)
    with pytest.raises(ValueError, match="ancestor|trusted Git history"):
        subject.read_partitions(tmp_path, joined=False, code_repository=tmp_path)
    assert all(args[0] != "worktree" for args in calls)


@pytest.mark.parametrize("worker_fails", [False, True])
def test_reader_uses_exact_source_and_removes_only_its_private_checkout(
    tmp_path, monkeypatch, worker_fails,
):
    _grid(tmp_path)
    git_calls = []
    worker_requests = []

    def git(repository, *args):
        git_calls.append((repository, args))
        return TREE if args == ("rev-parse", f"{COMMIT}^{{tree}}") else COMMIT

    def run(argv, **kwargs):
        assert argv == [subject.sys.executable, "-c", subject._WORKER]
        assert kwargs["cwd"].name == "source"
        assert kwargs["env"]["PYTHONPATH"] == str(kwargs["cwd"] / "src")
        assert "FAKE_API_KEY" not in kwargs["env"]
        request = json.loads(kwargs["input"])
        worker_requests.append(request)
        assert request["commit"] == COMMIT
        assert request["tree"] == TREE
        assert request["results"] == str(tmp_path)
        assert "def _portable_media_references" in request["media_export_source"]
        return SimpleNamespace(
            returncode=int(worker_fails), stderr="original validator refused",
            stdout=json.dumps({"validator_commit": COMMIT, "cells": [_cell(tmp_path)]}),
        )

    monkeypatch.setattr(subject, "_git", git)
    monkeypatch.setattr(subject.subprocess, "run", run)
    monkeypatch.setenv("FAKE_API_KEY", "test-placeholder")
    if worker_fails:
        with pytest.raises(ValueError, match="original validator refused"):
            subject.read_partitions(tmp_path, joined=False, code_repository=tmp_path)
    else:
        result = subject.read_partitions(tmp_path, joined=False, code_repository=tmp_path)
        assert result[0]["cells"][0]["manifest_path"] == tmp_path / "cell.manifest.json"
        assert isinstance(result[0]["cells"][0]["artifacts"]["responses"], Path)
    assert len(worker_requests) == 1
    added = next(args[-2] for _, args in git_calls if args[:2] == ("worktree", "add"))
    removed = next(args[-1] for _, args in git_calls if args[:2] == ("worktree", "remove"))
    assert added == removed
    assert Path(removed) != tmp_path
    assert Path(removed).name == "source"
    assert not Path(removed).parent.exists()
    assert (tmp_path / "cell.manifest.json").exists()


def test_joined_reader_retains_strata_and_rejects_duplicate_identity(tmp_path, monkeypatch):
    partitions = [
        {"cells": [{"run_id": "one"}], "joined": [None, {"a": {}}, {"a": {}}, {
            "policy_evaluable_samples": 1, "common_ineligible_evaluable_rows_excluded": 2,
        }]},
        {"cells": [{"run_id": "two"}], "joined": [None, {"b": {}}, {"b": {}}, {
            "policy_evaluable_samples": 1, "common_ineligible_evaluable_rows_excluded": 0,
        }]},
    ]
    monkeypatch.setattr(subject, "read_partitions", lambda *a, **k: partitions)
    cells, metadata, judgments, audit = subject.load_joined(tmp_path)
    assert [cell["run_id"] for cell in cells] == ["one", "two"]
    assert set(metadata) == set(judgments) == {"a", "b"}
    assert audit == {"policy_evaluable_samples": 2, "common_ineligible_evaluable_rows_excluded": 2}
    partitions[1]["joined"][1] = {"a": {}}
    partitions[1]["joined"][2] = {"a": {}}
    with pytest.raises(ValueError, match="duplicate joined"):
        subject.load_joined(tmp_path)


def test_haiku_reader_and_reconciliation_use_historical_join(tmp_path, monkeypatch):
    from experiments import retained_response_judge as judge

    _grid(tmp_path)
    expected = ([{"run_id": "one"}], {"sample": {"prepared_response": "answer"}}, {}, {})
    monkeypatch.setattr(subject, "load_joined", lambda root: expected)
    monkeypatch.setattr(judge, "_joined_artifacts", lambda *a, **k: pytest.fail("current-only join"))
    assert judge._read_view(tmp_path) == expected
    assert judge.load_retained_metadata(tmp_path) == expected[1]


def test_level2_cli_explicit_historical_reader(tmp_path, monkeypatch):
    from experiments import level2_report

    calls = []
    cells = [{"run_id": "historical"}]
    monkeypatch.setattr(subject, "load_cells", lambda root, **kwargs: calls.append((root, kwargs)) or cells)
    monkeypatch.setattr(level2_report, "_load_cells", lambda *a, **k: pytest.fail("current-only reader"))

    def report(received, native):
        assert received == cells
        assert native == []
        return {"report_id": "test", "common": {"estimates": [], "n_estimate_rows": 0},
                "native": {"n_native_runs": 0}}

    monkeypatch.setattr(level2_report, "build_level2_report", report)
    monkeypatch.setattr(level2_report, "_csv_text", lambda value: "csv\n")
    monkeypatch.setattr(level2_report, "_markdown_text", lambda value: "md\n")
    assert level2_report.main([
        "--results", str(tmp_path), "--historical-code-repository", str(tmp_path),
        "--out-json", str(tmp_path / "report.json"), "--out-csv", str(tmp_path / "report.csv"),
        "--out-md", str(tmp_path / "report.md"),
    ]) == 0
    assert calls == [(tmp_path, {"code_repository": tmp_path})]


def _level1_inputs(tmp_path):
    revision = {
        "expected_commit": COMMIT, "observed_commit": COMMIT, "head_tree": TREE,
        "harness_source_sha256": "c" * 64,
        "driver_source_sha256": hashlib.sha256(b"driver").hexdigest(),
    }
    plan = {"plan_id": "plan", "bindings": {"project_revision": revision}}
    # Retained eligibility descriptors carry a basename, not an absolute path.
    artifact = (plan, "d" * 64, "plan.json", 100, 1)
    envelopes = [{"envelope": {"bindings": {"project_revision": dict(revision)}}}]
    return {"plan": artifact}, envelopes


@pytest.mark.parametrize("bad_identity", ["mixed", "ancestor", "tree"])
def test_level1_source_admission_precedes_worker(tmp_path, monkeypatch, bad_identity):
    plans, envelopes = _level1_inputs(tmp_path)
    calls = []
    if bad_identity == "mixed":
        envelopes[0]["envelope"]["bindings"]["project_revision"]["expected_commit"] = "e" * 40
        envelopes[0]["envelope"]["bindings"]["project_revision"]["observed_commit"] = "e" * 40

    def git(repository, *args):
        calls.append(args)
        if args[0] == "merge-base" and bad_identity == "ancestor":
            raise ValueError("not an ancestor")
        if args == ("rev-parse", f"{COMMIT}^{{tree}}"):
            return "f" * 40 if bad_identity == "tree" else TREE
        return COMMIT

    monkeypatch.setattr(subject, "_git", git)
    with pytest.raises(ValueError, match="one exact|ancestor|trusted Git history"):
        subject.load_level1_results([tmp_path], plans, envelopes,
                                   eligibility_paths=[tmp_path / "plan.json"], code_repository=tmp_path)
    assert all(args[0] != "worktree" for args in calls)


@pytest.mark.parametrize("worker_fails", [False, True])
def test_level1_reader_preserves_partial_lifecycle_and_cleans_own_checkout(
    tmp_path, monkeypatch, worker_fails,
):
    plans, envelopes = _level1_inputs(tmp_path)
    calls = []

    def git(repository, *args):
        calls.append(args)
        return TREE if args == ("rev-parse", f"{COMMIT}^{{tree}}") else COMMIT

    def run(argv, **kwargs):
        assert argv == [subject.sys.executable, "-c", subject._LEVEL1_WORKER]
        assert kwargs["cwd"].name == "source"
        assert "FAKE_API_KEY" not in kwargs["env"]
        request = json.loads(kwargs["input"])
        assert request["commit"] == COMMIT
        assert request["tree"] == TREE
        assert request["results"] == [str(tmp_path)]
        assert request["plans"] == json.loads(json.dumps(list(plans.values())))
        assert request["eligibility_paths"] == [str(tmp_path / "plan.json")]
        assert request["envelopes"] == envelopes
        cells = [
            [["model", "good", "replay"], {"status": "complete", "validated_cell": _cell(tmp_path)}],
            [["model", "failed", "replay"], {"status": "error", "execution_started": True}],
        ]
        return SimpleNamespace(
            returncode=int(worker_fails), stderr="original lifecycle validator refused",
            stdout=json.dumps({"validator_commit": COMMIT,
                               "grids": {"plan": {"grid_status": "partial", "cells": cells}},
                               "request_errors": [{"scope": "request-only"}]}),
        )

    monkeypatch.setattr(subject, "_git", git)
    monkeypatch.setattr(subject.subprocess, "run", run)
    monkeypatch.setenv("FAKE_API_KEY", "test-placeholder")
    if worker_fails:
        with pytest.raises(ValueError, match="original lifecycle validator refused"):
            subject.load_level1_results([tmp_path], plans, envelopes,
                                       eligibility_paths=[tmp_path / "plan.json"], code_repository=tmp_path)
    else:
        grids, errors = subject.load_level1_results(
            [tmp_path], plans, envelopes, code_repository=tmp_path,
            eligibility_paths=[tmp_path / "plan.json"],
        )
        assert grids["plan"]["grid_status"] == "partial"
        assert grids["plan"]["cells"][("model", "failed", "replay")]["status"] == "error"
        cell = grids["plan"]["cells"][("model", "good", "replay")]["validated_cell"]
        assert cell["manifest_path"] == tmp_path / "cell.manifest.json"
        assert errors == [{"scope": "request-only"}]
    added = next(args[-2] for args in calls if args[:2] == ("worktree", "add"))
    removed = next(args[-1] for args in calls if args[:2] == ("worktree", "remove"))
    assert added == removed
    assert not Path(removed).parent.exists()


@pytest.mark.parametrize("changed", [None, "plan", "envelope", "grid", "manifest"])
def test_level1_worker_validates_exact_source_even_for_request_only_failures(
    tmp_path, monkeypatch, capsys, changed,
):
    from experiments import level1_evidence
    from ura import runner

    plans, envelopes = _level1_inputs(tmp_path)
    revision = plans["plan"][0]["bindings"]["project_revision"]
    validated_cell = _cell(tmp_path)
    validated_cell["manifest"] = {"config": {"run": {"project_revision": dict(revision)}}}
    grids = {"plan": {"request": {"project_revision": dict(revision)}, "cells": {
        ("model", "good", "replay"): {"validated_cell": validated_cell},
        ("model", "failed", "replay"): {"status": "error"},
    }}}
    revision_objects = {
        "plan": revision,
        "envelope": envelopes[0]["envelope"]["bindings"]["project_revision"],
        "grid": grids["plan"]["request"]["project_revision"],
        "manifest": validated_cell["manifest"]["config"]["run"]["project_revision"],
    }
    if changed:
        revision_objects[changed]["harness_source_sha256"] = "e" * 64
    request = {"results": [str(tmp_path)], "plans": list(plans.values()),
               "eligibility_paths": [str(tmp_path / "plan.json")],
               "envelopes": envelopes, "commit": COMMIT, "tree": TREE}
    monkeypatch.setattr(subject.sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(level1_evidence, "_plan_artifact", lambda path: plans["plan"])
    monkeypatch.setattr(level1_evidence, "_discover_request_envelopes", lambda *args: envelopes)
    monkeypatch.setattr(level1_evidence, "_load_results", lambda *args: (grids, ["request-error"]))
    lifecycle_calls = []
    monkeypatch.setattr(level1_evidence, "_bind_request_lifecycle",
                        lambda *args: lifecycle_calls.append(args))
    monkeypatch.setattr(runner, "_harness_source_identity", lambda: {"sha256": "c" * 64})
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"driver"
                        if str(path) == "experiments/run_matrix.py" else original_read(path))
    if changed:
        with pytest.raises(ValueError, match="exact validator checkout"):
            exec(subject._LEVEL1_WORKER, {})
    else:
        exec(subject._LEVEL1_WORKER, {})
        output = json.loads(capsys.readouterr().out)
        assert output["request_errors"] == ["request-error"]
        assert len(output["grids"]["plan"]["cells"]) == 2
        assert len(lifecycle_calls) == 1


def test_level1_cli_explicit_historical_reader_keeps_current_accounting(tmp_path, monkeypatch):
    from experiments import level1_evidence

    plans, envelopes = _level1_inputs(tmp_path)
    validated = {"plan": {"cells": {("model", "corpus", "replay"): {"status": "error"}}}}
    calls = []
    monkeypatch.setattr(level1_evidence, "_plan_artifact", lambda path: plans["plan"])
    monkeypatch.setattr(level1_evidence, "_discover_request_envelopes", lambda *args: envelopes)
    monkeypatch.setattr(level1_evidence, "_load_results", lambda *args: pytest.fail("current-only reader"))
    monkeypatch.setattr(subject, "load_level1_results", lambda *args, **kwargs:
                        calls.append((args, kwargs)) or (validated, []))
    monkeypatch.setattr(level1_evidence, "_bind_live_attestations", lambda *args: {})

    def current_accounting(artifacts, grids, errors, live, received_envelopes):
        assert artifacts == [plans["plan"]]
        assert grids is validated
        assert received_envelopes is envelopes
        return {"evidence_id": "current-accounting", "planning_strata": [], "counts": {
            "prospective_request_units": {"requested": 1}, "planning_strata": {"requested": 1},
            "execution_units": {"requested": 1}}, "availability": {
                "live_attestation": {"status": "test"}, "analysis_inclusion": {"status": "test"}}}

    monkeypatch.setattr(level1_evidence, "build_level1_evidence", current_accounting)
    assert level1_evidence.main([
        "--eligibility", str(tmp_path / "plan.json"), "--results", str(tmp_path),
        "--historical-code-repository", str(tmp_path),
        "--out-json", str(tmp_path / "report.json"), "--out-csv", str(tmp_path / "report.csv"),
    ]) == 0
    assert len(calls) == 1
    assert calls[0][1] == {"code_repository": tmp_path,
                         "eligibility_paths": [tmp_path / "plan.json"]}
