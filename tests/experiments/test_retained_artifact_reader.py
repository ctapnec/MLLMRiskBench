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
# Dispatch tests replace the entire source loader. The real checksum bridge is
# exercised against file readers in test_artifact_checks, not these join stubs.
CHECKSUM_REQUEST = {
    "verify_artifact_sha256": False,
    "artifact_check_bridge": (
        "def _configure_historical_artifact_checks(verify):\n"
        " return {'mode': 'metadata_and_records', 'unchanged_historical_full_checks': False}\n"
    ),
}


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


@pytest.mark.parametrize("frame", ["common", "source_task"])
@pytest.mark.parametrize("worker_fails", [False, True])
def test_reader_uses_exact_source_and_removes_only_its_private_checkout(
    tmp_path, monkeypatch, worker_fails, frame,
):
    _grid(tmp_path)
    git_calls = []
    worker_requests = []
    ipc_calls = []
    decode_ipc = subject._decode_validator_ipc
    monkeypatch.setattr(subject, "_decode_validator_ipc",
                        lambda payload: ipc_calls.append(len(payload)) or decode_ipc(payload))

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
        assert request["frame"] == frame
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
            subject.read_partitions(tmp_path, joined=False, frame=frame, code_repository=tmp_path)
    else:
        result = subject.read_partitions(tmp_path, joined=False, frame=frame, code_repository=tmp_path)
        assert result[0]["cells"][0]["manifest_path"] == tmp_path / "cell.manifest.json"
        assert isinstance(result[0]["cells"][0]["artifacts"]["responses"], Path)
    assert len(worker_requests) == 1
    assert len(ipc_calls) == (0 if worker_fails else 1)
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


def test_source_task_joined_reader_selects_frame_and_repository(tmp_path, monkeypatch):
    calls = []
    partitions = [{"cells": [{"run_id": "source-task"}], "joined": [
        {}, {"sample": {"source_task_family": "classification"}}, {"sample": {}}, {
            "policy_evaluable_samples": 1,
            "common_eligible_rows_excluded_from_source_task_frame": 3,
        },
    ]}]
    monkeypatch.setattr(subject, "read_partitions", lambda *args, **kwargs:
                        calls.append((args, kwargs)) or partitions)
    result = subject.load_joined(tmp_path, frame="source_task", code_repository=tmp_path)
    assert calls == [((tmp_path,), {
        "joined": True, "frame": "source_task", "code_repository": tmp_path,
    })]
    assert result[1]["sample"]["source_task_family"] == "classification"
    assert result[3] == {
        "policy_evaluable_samples": 1,
        "common_eligible_rows_excluded_from_source_task_frame": 3,
    }


@pytest.mark.parametrize("entrypoint", ["load_joined", "read_partitions"])
def test_joined_reader_rejects_unknown_frame_before_source_operations(tmp_path, monkeypatch, entrypoint):
    monkeypatch.setattr(subject, "grid_partitions", lambda *args: pytest.fail("opened source artifacts"))
    kwargs = {"joined": True} if entrypoint == "read_partitions" else {}
    with pytest.raises(ValueError, match="unknown human-audit frame"):
        getattr(subject, entrypoint)(tmp_path, frame="both", **kwargs)


@pytest.mark.parametrize("frame,eligibility,changed", [
    (None, [True, False], False),
    ("source_task", [True, False], False),
    ("source_task", [False], False),
    ("common", [False], False),
    ("source_task", [True], False),
    ("source_task", [False], True),
])
def test_joined_worker_dispatches_frame_after_exact_source_validation(
    tmp_path, monkeypatch, capsys, frame, eligibility, changed,
):
    from experiments import figure_results, human_audit
    from ura import runner

    revision = {
        "expected_commit": COMMIT, "observed_commit": COMMIT, "head_tree": TREE,
        "harness_source_sha256": "e" * 64 if changed else "c" * 64,
        "driver_source_sha256": hashlib.sha256(b"driver").hexdigest(),
    }
    cells = [{"manifest": {"config": {"run": {"project_revision": revision}}},
              "judgments": [{"raw": {"common_metrics_eligible": value,
                                     "policy_evaluable_turn": True}}
                            for value in eligibility]}]
    calls = []
    selected_frame = frame or "common"
    selected_eligibility = selected_frame == "common"
    selected_count = eligibility.count(selected_eligibility)
    excluded = ("common_ineligible_evaluable_rows_excluded" if selected_frame == "common"
                else "common_eligible_rows_excluded_from_source_task_frame")
    expected_audit = {"policy_evaluable_samples": selected_count,
                      excluded: len(eligibility) - selected_count}
    expected_join = [{"original_judge": {"sample": "safe"}},
                     {"sample": {"frame": selected_frame}}, {"sample": {}}, expected_audit]

    def original_join(root, *, frame):
        assert calls == ["source cells"]
        assert root == tmp_path
        assert frame == selected_frame
        assert human_audit._portable_media_references([]) == "current exporter"
        calls.append("original source join")
        return expected_join

    monkeypatch.setattr(figure_results, "_load_cells", lambda root:
                        calls.append("source cells") or cells)
    monkeypatch.setattr(figure_results, "_read_object", figure_results._read_object)
    monkeypatch.setattr(human_audit, "_joined_artifacts", original_join)
    # Register the attribute with monkeypatch before worker exec replaces it.
    monkeypatch.setattr(human_audit, "_portable_media_references", lambda turns: "old exporter")
    monkeypatch.setattr(runner, "_harness_source_identity", lambda: {"sha256": "c" * 64})
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"driver"
                        if str(path) == "experiments/run_matrix.py" else original_read(path))
    request = {
        "results": str(tmp_path), "commit": COMMIT, "tree": TREE, "joined": True,
        "media_export_source": 'def _portable_media_references(turns): return "current exporter"',
    }
    if frame is not None:
        request["frame"] = frame
    monkeypatch.setattr(subject.sys, "stdin", io.StringIO(json.dumps({**request, **CHECKSUM_REQUEST})))
    if changed:
        with pytest.raises(ValueError, match="exact validator checkout"):
            exec(subject._WORKER, {})
        assert calls == ["source cells"]
    else:
        exec(subject._WORKER, {})
        result = json.loads(capsys.readouterr().out)
        assert result["joined"] == (expected_join if selected_count else [{}, {}, {}, expected_audit])
        assert result["validator_commit"] == COMMIT
        assert calls == (["source cells", "original source join"] if selected_count else ["source cells"])


def test_haiku_reader_and_reconciliation_use_historical_join(tmp_path, monkeypatch):
    from experiments import retained_response_judge as judge

    _grid(tmp_path)
    cells = [{"run_id": "one", "judgments": []}]
    metadata = {"sample": {"prepared_response": "answer"}}
    binding = {"sha256": "b" * 64}
    audit = {"frame": "common", "policy_evaluable_samples": 1, "judge_configuration_binding": binding}
    partition = {"cells": cells, "validator_commit": COMMIT,
                 "joined_by_configuration": {binding["sha256"]: [{}, metadata, {"sample": {}}, audit]}}
    calls = []
    def read(root, **kwargs):
        assert root == tmp_path
        calls.append(kwargs)
        return [partition]
    monkeypatch.setattr(subject, "read_partitions", read)
    monkeypatch.setattr(judge, "_joined_artifacts", lambda *a, **k: pytest.fail("current-only join"))
    result = judge._read_view(tmp_path)
    assert result[:3] == (cells, metadata, {"sample": {}})
    assert result[3]["source_configuration_audits"][0]["configuration_audits"] == {binding["sha256"]: audit}
    assert judge.load_retained_metadata(tmp_path) == metadata
    assert calls == [{"joined": True, "frame": "common", "separate_judge_configurations": True}] * 2


@pytest.mark.parametrize("failure", [None, "full-grid", "omit-row", "orphan-prediction", "wrong-config", "zero-results"])
def test_grouped_worker_validates_full_grid_before_exact_disjoint_source_joins(
    tmp_path, monkeypatch, capsys, failure,
):
    from experiments import figure_results, human_audit
    from ura import runner

    revision = {
        "expected_commit": COMMIT, "observed_commit": COMMIT, "head_tree": TREE,
        "harness_source_sha256": "c" * 64,
        "driver_source_sha256": hashlib.sha256(b"driver").hexdigest(),
    }
    cells = []
    for index in range(2):
        run_id = f"run-{index}"
        cells.append({
            "run_id": run_id,
            "manifest": {"config": {"run": {"project_revision": revision}},
                         "group": str(index + 1) * 64},
            "artifacts": {"judgments": tmp_path / f"{run_id}.jsonl"},
            "judgments": [{"run_id": run_id, "attempt_id": "attempt", "raw": {
                "model": "model", "common_metrics_eligible": True,
                "policy_evaluable_turn": True,
            }}],
        })
    calls = []
    bridge = {"commit": "d" * 40, "module": "experiments/retained_artifact_reader.py",
              "sha256": "e" * 64}
    if failure == "zero-results":
        cells[1]["aggregate_results"] = []
        legacy_source = '''def _completed_cell(path):
    attempts = responses = judgments = [1]
    aggregate_results = []
    parsed_judgments = ["source typed nondecision"]
    if not attempts or not responses or not judgments or not aggregate_results:
        raise ValueError("empty core/result artifact")
    return path
'''
        namespace = {}
        exec(legacy_source, namespace)
        legacy_cell = namespace["_completed_cell"]
        getsource = subject.inspect.getsource
        monkeypatch.setattr(subject.inspect, "getsource", lambda value:
                            legacy_source if value is legacy_cell else getsource(value))
        monkeypatch.setattr(human_audit, "_completed_cell", legacy_cell)
        monkeypatch.setattr(figure_results, "_zero_result_guardrail_abstention_population",
                            lambda rows: rows == ["source typed nondecision"])

    def original_inventory(root):
        assert root == tmp_path
        calls.append("full original grid validation")
        if failure == "full-grid":
            raise ValueError("original full-grid validator refused")
        if failure == "zero-results":
            assert human_audit._completed_cell(root) == root
        return {"judgments": [cell["artifacts"]["judgments"] for cell in cells]}, cells

    def original_join(root, *, frame):
        assert calls[:2] == ["source cells", "full original grid validation"]
        assert frame == "common"
        roles, selected = human_audit._validated_artifacts(root)
        assert len(selected) == 1
        cell = selected[0]
        assert roles == {"judgments": [cell["artifacts"]["judgments"]]}
        calls.append(cell["run_id"])
        key = human_audit._record_key(cell["judgments"][0])
        metadata = {key: {"run_id": cell["run_id"]}}
        predictions = ({"rules": {key: "violation"}, "cascade_authoritative": {key: "violation"}}
                       if cell["run_id"] == "run-0"
                       else {"rules": {}, "cascade_authoritative": {}})
        if failure == "omit-row":
            metadata = {}
            predictions = {}
        if failure == "orphan-prediction":
            predictions["rules"]["unjoined"] = "safe"
        audit = {"judge_configuration_binding": {"sha256": (
            "f" * 64 if failure == "wrong-config" else cell["manifest"]["group"]
        )}}
        return predictions, metadata, {key: {} for key in metadata}, audit

    monkeypatch.setattr(figure_results, "_load_cells", lambda root: calls.append("source cells") or cells)
    monkeypatch.setattr(figure_results, "_read_object", figure_results._read_object)
    monkeypatch.setattr(human_audit, "_validated_artifacts", original_inventory)
    monkeypatch.setattr(human_audit, "_joined_artifacts", original_join)
    monkeypatch.setattr(human_audit, "_judge_configuration_binding", lambda selected:
                        {"sha256": selected[0]["manifest"]["group"]})
    monkeypatch.setattr(human_audit, "_portable_media_references", lambda turns: "old exporter")
    monkeypatch.setattr(runner, "_harness_source_identity", lambda: {"sha256": "c" * 64})
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"driver"
                        if str(path) == "experiments/run_matrix.py" else original_read(path))
    request = {
        "results": str(tmp_path), "commit": COMMIT, "tree": TREE, "joined": True,
        "frame": "common", "separate_judge_configurations": True,
        "audit_join_bridge": bridge,
        "media_export_source": 'def _portable_media_references(turns): return "current exporter"',
    }
    monkeypatch.setattr(subject.sys, "stdin", io.StringIO(json.dumps({**request, **CHECKSUM_REQUEST})))
    if failure not in (None, "zero-results"):
        with pytest.raises(ValueError, match="full-grid validator|omit or add|join differs"):
            exec(subject._WORKER, {})
    else:
        exec(subject._WORKER, {})
        result = json.loads(capsys.readouterr().out)
        assert "joined" not in result
        assert [cell["run_id"] for cell in result["analysis_cells"]] == ["run-0", "run-1"]
        groups = result["joined_by_configuration"]
        assert set(groups) == {"1" * 64, "2" * 64}
        assert groups["1" * 64][0]["rules"] == {"run-0|model|attempt": "violation"}
        assert groups["2" * 64][0]["cascade_authoritative"] == {}
        assert set(groups["2" * 64][1]) == {"run-1|model|attempt"}
        assert calls == ["source cells", "full original grid validation", "run-0", "run-1"]
        if failure == "zero-results":
            compatibility = result["audit_join_compatibility"]
            assert compatibility["bridge"] == bridge
            assert compatibility["original_source_commit"] == COMMIT
            assert compatibility["original_figure_grid_validation"] == "passed_before_compatibility"
            assert compatibility["zero_result_run_ids"] == ["run-1"]
            assert compatibility["unchanged_original_transfer_validator_claimed"] is False
            assert human_audit._completed_cell is legacy_cell
    assert human_audit._validated_artifacts is original_inventory


@pytest.mark.parametrize("joined,frame,separate", [
    (False, "common", True), (True, "source_task", True), (True, "common", 1),
])
def test_configuration_separation_rejects_invalid_mode_before_source_access(
    tmp_path, monkeypatch, joined, frame, separate,
):
    monkeypatch.setattr(subject, "grid_partitions", lambda *args: pytest.fail("opened source"))
    with pytest.raises(ValueError, match="configuration separation"):
        subject.read_partitions(tmp_path, joined=joined, frame=frame,
                                separate_judge_configurations=separate)


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
    ipc_calls = []
    decode_ipc = subject._decode_validator_ipc
    monkeypatch.setattr(subject, "_decode_validator_ipc",
                        lambda payload: ipc_calls.append(len(payload)) or decode_ipc(payload))

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
    assert len(ipc_calls) == (0 if worker_fails else 1)


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
    monkeypatch.setattr(subject.sys, "stdin", io.StringIO(json.dumps({**request, **CHECKSUM_REQUEST})))
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


def test_validator_ipc_accepts_many_validated_records_without_changing_artifact_limit():
    from ura.strict_json import DEFAULT_MAX_JSON_NODES, strict_json_loads

    # Two individually small records cross the persisted *single-artifact*
    # ceiling when combined in one validator IPC envelope.
    count = DEFAULT_MAX_JSON_NODES // 2
    payload = '{"cells":[[' + ','.join(["0"] * count) + '],[' + ','.join(["1"] * count) + ']]}'
    with pytest.raises(ValueError, match="exceeds 2000000 value nodes"):
        strict_json_loads(payload)
    decoded = subject._decode_validator_ipc(payload)
    assert [len(row) for row in decoded["cells"]] == [count, count]
    assert DEFAULT_MAX_JSON_NODES == 2_000_000
    assert subject._MAX_VALIDATOR_IPC_NODES == 32_000_000
    assert subject._MAX_VALIDATOR_IPC_BYTES == 512 * 1024 * 1024


def test_validator_ipc_node_budget_remains_finite(monkeypatch):
    monkeypatch.setattr(subject, "_MAX_VALIDATOR_IPC_NODES", 8)
    assert subject._decode_validator_ipc("[0,1,2,3,4,5,6]") == list(range(7))
    with pytest.raises(ValueError, match="exceeds 8 value nodes"):
        subject._decode_validator_ipc("[0,1,2,3,4,5,6,7]")


def test_validator_ipc_counts_utf8_bytes_before_decoding(monkeypatch):
    monkeypatch.setattr(subject, "_MAX_VALIDATOR_IPC_BYTES", 5)
    assert subject._decode_validator_ipc('"a"') == "a"
    monkeypatch.setattr(subject, "strict_json_loads", lambda *args, **kwargs: pytest.fail("decoded over-byte IPC"))
    with pytest.raises(ValueError, match="aggregate byte limit"):
        subject._decode_validator_ipc('"\U0001f642"')


@pytest.mark.parametrize("payload, message", [
    ('{"duplicate":0,"duplicate":1}', "duplicate JSON object key"),
    ('{"nonfinite":NaN}', "non-standard JSON numeric constant"),
    ('{"overflow":1e999}', "non-finite number"),
    ("[" * 65 + "0" + "]" * 65, "nesting exceeds 64"),
])
def test_validator_ipc_retains_strict_json_checks(payload, message):
    with pytest.raises(ValueError, match=message):
        subject._decode_validator_ipc(payload)
