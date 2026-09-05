"""No-GPU checks for yielding a sealed cell before another vLLM initialization."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from experiments import run_matrix
from ura.targets.api import MockTarget


def _condition(**updates):
    value = {"model_specs": ["vllm:Org/Model"], "attacker_names": ["replay"],
             "deferred_local_judging": True, "new_complete": 1,
             "accounted_cells": 1, "requested_cells": 2}
    value.update(updates)
    return value


@pytest.mark.parametrize("updates", [
    {"new_complete": 0},
    {"accounted_cells": 2},
    {"requested_cells": 1},
    {"deferred_local_judging": False},
    {"model_specs": ["ollama:local-model"]},
    {"model_specs": ["vllm:first", "vllm:second"]},
    {"attacker_names": ["replay", "pyrit"]},
])
def test_early_yield_requires_new_sealed_cell_and_existing_child_scope(monkeypatch, updates):
    monkeypatch.setenv(run_matrix._VLLM_GRID_CHILD_ENV, "1")
    assert run_matrix._should_yield_vllm_grid_child(**_condition())
    assert not run_matrix._should_yield_vllm_grid_child(**_condition(**updates))


def test_normal_parent_or_library_call_never_early_yields(monkeypatch):
    monkeypatch.delenv(run_matrix._VLLM_GRID_CHILD_ENV, raising=False)
    assert not run_matrix._should_yield_vllm_grid_child(**_condition())


def test_real_matrix_yields_after_seal_then_skips_existing_cell_without_calls(tmp_path, monkeypatch):
    calls, closed = [], []

    class CountedTarget(MockTarget):
        def generate(self, dialog, *, seed=None):
            calls.append(seed)
            return super().generate(dialog, seed=seed)

        def close(self):
            closed.append("target")

    monkeypatch.setattr(run_matrix, "build_target", lambda *args, **kwargs: CountedTarget())
    # Exercise the real matrix's persistence/resume boundary with synthetic
    # inference. The policy unit checks above cover actual vLLM-only eligibility;
    # no GPU, paid model or historical source admission is mocked into success.
    decisions = []

    def yield_first(**kwargs):
        decisions.append(kwargs)
        return kwargs["new_complete"] == 1 and kwargs["accounted_cells"] < kwargs["requested_cells"]

    monkeypatch.setattr(run_matrix, "_should_yield_vllm_grid_child", yield_first)
    out = tmp_path / "run"
    argv = ["--dry-run", "--corpora", "synth", "--limit", "1", "--seeds", "0",
            "--attackers", "replay,crescendo", "--judges", "rules",
            "--max-queries", "2", "--max-turns", "2", "--out", str(out)]
    assert run_matrix.main(argv) == run_matrix._VLLM_GRID_RECYCLE_EXIT
    assert calls == [0]
    assert closed == ["target"]
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []
    assert run_matrix._ACTIVE_ENGINE_RUNTIME_SELECTION is None
    assert not list(out.glob("*.lock"))
    grid_path = next(out.glob("*.grid.json"))
    first = json.loads(grid_path.read_text())
    assert first["status"] == "running"
    assert first["requested_cells"] == 2
    assert len(first["cells"]) == 1
    assert first["cells"][0]["status"] == "complete"
    marker = out / first["cells"][0]["completion_marker"]
    marker_bytes = marker.read_bytes()
    envelopes = {path.name: path.read_bytes() for path in out.glob("*.request-envelope.json")}
    assert len(envelopes) == 1
    assert not list(out.glob("*.error.json"))

    assert run_matrix.main(argv) == 0
    assert len(calls) == sum(json.loads(path.read_text())["n_responses"]
                             for path in out.glob("*.complete.json"))
    assert closed == ["target", "target"]
    assert marker.read_bytes() == marker_bytes
    assert {path.name: path.read_bytes() for path in out.glob("*.request-envelope.json")} == envelopes
    final = json.loads(grid_path.read_text())
    assert final["status"] == "complete"
    assert final["n_existing_complete"] == final["n_new_complete"] == 1
    assert final["n_errors"] == 0
    assert len(final["cells"]) == final["requested_cells"] == 2
    assert decisions[-1]["accounted_cells"] == 2


def test_child_recycling_keeps_existing_finite_progress_bound(tmp_path, monkeypatch):
    calls = []

    def child(command, *, env, check):
        calls.append(command)
        (tmp_path / f"cell-{len(calls)}.complete.json").write_text("{}")
        return SimpleNamespace(returncode=run_matrix._VLLM_GRID_RECYCLE_EXIT)

    monkeypatch.setattr(run_matrix.subprocess, "run", child)
    argv = ["--local", "vllm:Org/Model", "--out", str(tmp_path)]
    assert run_matrix._run_recyclable_vllm_grid(argv, out=tmp_path, cell_bound=2) == 1
    assert len(calls) == 5  # response owner plus scoring owner for each cell
    assert all(command[2:] == argv for command in calls)


def test_recycle_status_without_new_durable_completion_stops(tmp_path, monkeypatch):
    calls = []
    (tmp_path / "old.complete.json").write_text("{}")

    def child(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=run_matrix._VLLM_GRID_RECYCLE_EXIT)

    monkeypatch.setattr(run_matrix.subprocess, "run", child)
    assert run_matrix._run_recyclable_vllm_grid([], out=tmp_path, cell_bound=2) == 75
    assert len(calls) == 1
