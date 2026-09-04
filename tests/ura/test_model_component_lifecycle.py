"""Regression coverage for process-owned model component teardown."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import run_matrix
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.targets.api import MockTarget


def _multi_corpus_vllm_args(out: Path) -> list[str]:
    return [
        "--local",
        "vllm:Org/Model",
        "--corpora",
        "first,second",
        "--attackers",
        "replay",
        "--judges",
        "rules,guardrail",
        "--out",
        str(out),
    ]


def test_multi_cell_vllm_grid_recycles_only_after_durable_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "run"
    calls: list[tuple[list[str], dict[str, str]]] = []

    def child(command, *, env, check):
        assert check is False
        calls.append((list(command), dict(env)))
        out.mkdir(exist_ok=True)
        if len(calls) == 1:
            (out / "first.complete.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    monkeypatch.delenv(run_matrix._VLLM_GRID_CHILD_ENV, raising=False)
    monkeypatch.setattr(run_matrix.subprocess, "run", child)
    monkeypatch.setattr(
        run_matrix,
        "_main",
        lambda _argv: pytest.fail("the recycling parent must not load a model"),
    )

    argv = _multi_corpus_vllm_args(out)
    assert run_matrix.main(argv) == 0
    assert len(calls) == 2
    assert all(call[0][2:] == argv for call in calls)
    assert all(
        call[1][run_matrix._VLLM_GRID_CHILD_ENV] == "1" for call in calls
    )


def test_multi_cell_vllm_grid_stops_when_failed_child_made_no_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def child(_command, *, env, check):
        nonlocal calls
        assert env[run_matrix._VLLM_GRID_CHILD_ENV] == "1"
        assert check is False
        calls += 1
        return SimpleNamespace(returncode=1)

    monkeypatch.delenv(run_matrix._VLLM_GRID_CHILD_ENV, raising=False)
    monkeypatch.setattr(run_matrix.subprocess, "run", child)

    assert run_matrix.main(_multi_corpus_vllm_args(tmp_path / "run")) == 1
    assert calls == 1


def test_run_matrix_closes_target_and_judge_after_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Component:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            events.append(self.name)

    def partial(_argv: object) -> int:
        run_matrix._track_model_component(Component("target"))
        run_matrix._track_model_component(Component("judge"))
        return 1

    monkeypatch.setattr(run_matrix, "_main", partial)

    assert run_matrix.main([]) == 1
    assert events == ["judge", "target"]
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []


def test_cleanup_failure_does_not_mask_partial_result_or_leak_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_locator = "/operator/private/model/snapshot"

    class FailingComponent:
        def close(self) -> None:
            raise RuntimeError(f"failed while closing {private_locator}")

    def partial(_argv: object) -> int:
        run_matrix._track_model_component(FailingComponent())
        return 1

    monkeypatch.setattr(run_matrix, "_main", partial)

    assert run_matrix.main([]) == 1
    stderr = capsys.readouterr().err
    assert "model component cleanup failed" in stderr
    assert "RuntimeError" in stderr
    assert private_locator not in stderr
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []


def test_cleanup_failure_turns_nominal_success_into_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingComponent:
        def close(self) -> None:
            raise RuntimeError("fixture cleanup failure")

    def successful(_argv: object) -> int:
        run_matrix._track_model_component(FailingComponent())
        return 0

    monkeypatch.setattr(run_matrix, "_main", successful)

    assert run_matrix.main([]) == 1
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []


def test_cleanup_failure_still_closes_every_independent_component(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class HealthyComponent:
        def close(self) -> None:
            events.append("healthy")

    class FailingComponent:
        def close(self) -> None:
            events.append("failing")
            raise RuntimeError("fixture cleanup failure")

    def successful(_argv: object) -> int:
        run_matrix._track_model_component(HealthyComponent())
        run_matrix._track_model_component(FailingComponent())
        return 0

    monkeypatch.setattr(run_matrix, "_main", successful)

    assert run_matrix.main([]) == 1
    assert events == ["failing", "healthy"]
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []


@pytest.mark.parametrize("interrupt_name", ["SIGTERM", "SIGINT"])
def test_posix_signal_during_cleanup_is_deferred_until_all_teardown_finishes(
    monkeypatch: pytest.MonkeyPatch,
    interrupt_name: str,
) -> None:
    events: list[str] = []
    installed_handlers: dict[int, object] = {}
    prior_handlers: dict[int, object] = {}
    sigterm = run_matrix.signal.SIGTERM
    sigint = run_matrix.signal.SIGINT
    interrupt = getattr(run_matrix.signal, interrupt_name)

    def install_handler(signum: int, handler: object) -> None:
        assert signum in {sigterm, sigint}
        installed_handlers[signum] = handler

    monkeypatch.setattr(run_matrix, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(
        run_matrix.signal,
        "getsignal",
        lambda signum: prior_handlers.setdefault(signum, object()),
    )
    monkeypatch.setattr(run_matrix.signal, "signal", install_handler)

    class Selection:
        def abort(self) -> None:
            events.append("selection-abort")

    class OlderComponent:
        def close(self) -> None:
            events.append("older-close")

    class SignalledComponent:
        def close(self) -> None:
            events.append("signalled-close-start")
            handler = installed_handlers[interrupt]
            assert callable(handler)
            handler(interrupt, None)
            events.append("signalled-close-end")

    def successful(_argv: object) -> int:
        run_matrix._ACTIVE_ENGINE_RUNTIME_SELECTION = Selection()
        run_matrix._track_model_component(OlderComponent())
        run_matrix._track_model_component(SignalledComponent())
        return 0

    monkeypatch.setattr(run_matrix, "_main", successful)

    assert run_matrix.main([]) == 128 + interrupt
    assert events == [
        "signalled-close-start",
        "signalled-close-end",
        "older-close",
        "selection-abort",
    ]
    assert installed_handlers == prior_handlers
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []
    assert run_matrix._ACTIVE_ENGINE_RUNTIME_SELECTION is None


def test_real_dry_matrix_tracks_constructed_target_and_cascade_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class ClosableMockTarget(MockTarget):
        def close(self) -> None:
            events.append("target")

    class ClosableRuleJudge(RuleJudge):
        def close(self) -> None:
            events.append("judge")

    target = ClosableMockTarget()
    stage = ClosableRuleJudge()
    monkeypatch.setattr(
        run_matrix,
        "build_target",
        lambda *_args, **_kwargs: target,
    )
    monkeypatch.setattr(
        run_matrix,
        "build_judges",
        lambda *_args, **_kwargs: JudgeCascade([stage]),
    )

    assert run_matrix.main([
        "--dry-run",
        "--corpora", "synth",
        "--limit", "1",
        "--seeds", "0",
        "--attackers", "replay",
        "--judges", "rules",
        "--max-queries", "1",
        "--max-turns", "1",
        "--out", str(tmp_path / "run"),
    ]) == 0

    assert events == ["judge", "target"]
    assert run_matrix._ACTIVE_MODEL_COMPONENTS == []
