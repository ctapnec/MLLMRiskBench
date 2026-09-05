"""No-GPU proofs of the existing checkpoint's target/judge process handoff."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from experiments import run_matrix
from ura.data_models import DialogTurn, RunManifest
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.runner import Runner
from ura.targets.api import MockTarget


def _matrix(tmp_path, monkeypatch):
    events = []
    allocation = {"target": False}

    class Target(MockTarget):
        def preflight_base(self):
            events.append("target_preflight")
            allocation["target"] = True

        def generate(self, dialog, *, seed=None):
            assert allocation["target"]
            events.append("target_call")
            response = super().generate(dialog, seed=seed)
            return response.model_copy(update={"output_turns": [
                DialogTurn(role="assistant", content="I cannot assist with that request.")
            ]})

        def close(self):
            # Reproduce the lifecycle defect: official close does not reclaim
            # the process's target allocation. Only a new process can do so.
            events.append("target_close")

    class Judge(RuleJudge):
        def preflight(self):
            assert not allocation["target"], "judge loaded beside retained target"
            events.append("judge_preflight")

    monkeypatch.setattr(run_matrix, "build_target", lambda *a, **kw: Target())
    monkeypatch.setattr(run_matrix, "build_judges", lambda *a, **kw: JudgeCascade([Judge()]))
    # Synthetic paths exercise actual planning, checkpoints, budget recovery,
    # identity validation and publication; policy tests separately cover vLLM.
    monkeypatch.setattr(run_matrix, "_uses_post_factum_local_judging", lambda **kw: True)
    monkeypatch.setattr(run_matrix, "_recyclable_vllm_child", lambda **kw: True)
    out = tmp_path / "run"
    argv = ["--dry-run", "--corpora", "synth", "--limit", "2", "--seeds", "0",
            "--attackers", "replay", "--judges", "rules", "--max-queries", "1",
            "--max-turns", "1", "--max-total-target-calls", "4", "--out", str(out)]
    return out, argv, events, allocation


def test_response_phase_exits_then_judges_without_loading_or_repeating_target(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    assert run_matrix.main(argv) == run_matrix._VLLM_GRID_RESPONSE_PHASE_EXIT
    assert events.count("target_preflight") == 1
    assert events.count("target_call") == 2
    assert "judge_preflight" not in events
    assert allocation["target"]  # retained until the modeled process boundary
    assert not list(out.glob("*.complete.json"))
    assert not list(out.glob("*.lock"))
    assert not list(out.glob("*.error.json"))
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []
    assert run_matrix._response_checkpoint_count(out) == 2
    sidecar = next(out.glob("*.responses.checkpoint.jsonl"))
    retained = Runner.load_response_checkpoint(sidecar)
    grid = json.loads(next(out.glob("*.grid.json")).read_text())
    assert grid["status"] == "running"
    budget_path = next(out.glob("*.budget.json"))
    first_budget = json.loads(budget_path.read_text())
    envelopes = {p.name: p.read_bytes() for p in out.glob("*.request-envelope.json")}

    allocation["target"] = False  # OS reclaimed the exited target child
    assert run_matrix.main(argv) == 0
    assert events.count("target_preflight") == 1
    assert events.count("target_call") == 2
    assert events.count("judge_preflight") == 1
    assert json.loads(budget_path.read_text()) == first_budget
    assert {p.name: p.read_bytes() for p in out.glob("*.request-envelope.json")} == envelopes
    responses = [json.loads(line) for line in next(out.glob("*.responses.jsonl")).read_text().splitlines()]
    assert {r["attempt_id"]: r for r in responses} == {
        aid: record["response"] for aid, record in retained.items()
    }
    assert len(list(out.glob("*.complete.json"))) == 1
    assert not sidecar.exists()
    assert json.loads(next(out.glob("*.grid.json")).read_text())["status"] == "complete"


def test_partial_response_checkpoint_loads_target_only_for_missing_row(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    assert run_matrix.main(argv) == 76
    sidecar = next(out.glob("*.responses.checkpoint.jsonl"))
    first = sidecar.read_bytes().splitlines(keepends=True)[0]
    sidecar.write_bytes(first)  # a crash retained only this durable response
    allocation["target"] = False
    assert run_matrix.main(argv) == 76
    assert events.count("target_preflight") == 2
    assert events.count("target_call") == 3
    assert sidecar.read_bytes().startswith(first)
    assert run_matrix._response_checkpoint_count(out) == 2
    allocation["target"] = False
    assert run_matrix.main(argv) == 0
    assert events.count("target_call") == 3
    assert events.count("judge_preflight") == 1


def test_corrupted_restored_identity_cannot_load_target_or_judge(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    assert run_matrix.main(argv) == 76
    sidecar = next(out.glob("*.responses.checkpoint.jsonl"))
    rows = [json.loads(line) for line in sidecar.read_text().splitlines()]
    rows[0]["response"]["target"] = "another-target"
    sidecar.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(ValueError, match="linkage/accounting"):
        run_matrix._response_checkpoint_count(out)
    allocation["target"] = False
    assert run_matrix.main(argv) == 1
    assert events.count("target_preflight") == 1
    assert events.count("target_call") == 2
    assert "judge_preflight" not in events
    assert not list(out.glob("*.complete.json"))


def test_failed_target_preflight_does_not_charge_a_generation(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    target_type = type(run_matrix.build_target())

    def broken_preflight(self):
        raise RuntimeError("fixture initialization failure")

    monkeypatch.setattr(target_type, "preflight_base", broken_preflight)
    assert run_matrix.main(argv) == 1
    assert json.loads(next(out.glob("*.budget.json")).read_text())["target_calls"] == 0
    assert "target_call" not in events
    assert "judge_preflight" not in events
    assert "target_close" in events
    assert not list(out.glob("*.lock"))


def test_synthetic_canary_restores_realized_responses_without_target_load(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    argv[argv.index("--limit") + 1] = "1"
    argv.append("--diagnostic-canary")
    assert run_matrix.main(argv) == 76
    sidecar = next(out.glob("*.responses.checkpoint.jsonl"))
    response = next(iter(Runner.load_response_checkpoint(sidecar).values()))["response"]
    allocation["target"] = False
    assert run_matrix.main(argv) == 0
    assert events.count("target_preflight") == events.count("target_call") == 1
    persisted = json.loads(next(out.glob("*.responses.jsonl")).read_text())
    assert persisted == response
    manifest = json.loads(next(out.glob("*.manifest.json")).read_text())
    assert manifest["config"]["realized_identities"]["target"]["observations"] == 1


def test_synthetic_probe_cannot_be_promoted_to_live_attestation(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    argv.append("--attestation-probe")
    with pytest.raises(SystemExit) as failure:
        run_matrix.main(argv)
    assert failure.value.code == 2
    assert events == []


def test_judge_child_preserves_target_phase_start_not_its_new_timestamp(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)

    class Clock(datetime):
        instant = datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            return cls.instant

    monkeypatch.setattr(run_matrix, "datetime", Clock)
    assert run_matrix.main(argv) == 76
    path = next(out.glob("*.manifest.json"))
    old_start = json.loads(path.read_text())["started_at"]
    assert old_start == "2026-09-05T10:00:00+00:00"
    Clock.instant = datetime(2026, 9, 5, 11, 0, tzinfo=timezone.utc)
    allocation["target"] = False
    assert run_matrix.main(argv) == 0
    assert json.loads(path.read_text())["started_at"] == old_start
    assert events.count("target_preflight") == 1


@pytest.mark.parametrize("changed", ["run_id", "code_version", "schema_version", "config"])
def test_response_phase_start_rejects_mismatched_plan_identity(tmp_path, changed):
    planned = RunManifest(run_id="run-example", code_version="example-code",
                          started_at="2026-09-05T11:00:00+00:00",
                          config={"components": {"target": "expected"}})
    saved = planned.model_dump(mode="json")
    saved["started_at"] = "2026-09-05T10:00:00+00:00"
    saved[changed] = {"components": {"target": "other"}} if changed == "config" else "other"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(saved))
    with pytest.raises(ValueError, match="differs from the exact planned cell"):
        run_matrix._restore_response_phase_start(path, planned)


@pytest.mark.parametrize("flag", ["--attestation-probe", "--diagnostic-canary"])
def test_probe_and_canary_use_same_process_boundary_but_runtime_attackers_do_not(tmp_path, monkeypatch, flag):
    monkeypatch.delenv(run_matrix._VLLM_GRID_CHILD_ENV, raising=False)
    argv = ["--local", "vllm:Org/Model", "--corpora", "synth", "--attackers", "replay",
            "--judges", "rules,guardrail", "--out", str(tmp_path), flag]
    assert run_matrix._vllm_grid_process_recycling(argv) == (tmp_path, 1)
    argv[argv.index("replay")] = "pyrit"
    assert run_matrix._vllm_grid_process_recycling(argv) is None


def test_response_handoff_without_new_durable_rows_stops(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(run_matrix.subprocess, "run", lambda *a, **kw: (
        calls.append(a) or SimpleNamespace(returncode=76)))
    assert run_matrix._run_recyclable_vllm_grid([], out=tmp_path, cell_bound=2) == 76
    assert len(calls) == 1


def test_parent_accepts_strict_response_progress_before_any_completion(tmp_path, monkeypatch):
    out, argv, events, allocation = _matrix(tmp_path, monkeypatch)
    assert run_matrix.main(argv) == 76
    sidecar = next(out.glob("*.responses.checkpoint.jsonl"))
    payload = sidecar.read_bytes()
    sidecar.unlink()
    calls = []

    def child(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            sidecar.write_bytes(payload)
            return SimpleNamespace(returncode=76)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(run_matrix.subprocess, "run", child)
    assert run_matrix._run_recyclable_vllm_grid(argv, out=out, cell_bound=1) == 0
    assert len(calls) == 2
    assert all(command[2:] == argv for command in calls)
