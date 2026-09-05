from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.local_campaign import vllm_stability_phase6 as subject


def _unit() -> subject.Unit:
    return subject.Unit("unit", "lane", None, {
        "modality": "text",
        "base_argv": [
            "--local", "vllm:target", "--local-config", "/local.json",
            "--local-config-sha256", "a" * 64, "--guardrail-device", "cuda:1",
            "--corpora", "synth", "--limit", "100", "--group", "model,source",
        ],
    }, 1)


def _kwargs(tmp_path: Path) -> dict:
    return {
        "python": Path("/fixture/python"), "work_root": tmp_path,
        "control_root": tmp_path / "runs/engineering/controller",
        "project_revision": Path("/revision.json"), "project_revision_sha256": "b" * 64,
        "scope": "scope", "recovery_path": None, "recovery_sha256": None,
        "expected_commit": "c" * 40, "framework_lock_id": "d" * 64,
        "admission_sha256": "e" * 64, "tmux_socket": "fixture", "tmux_session": "fixture",
    }


@pytest.mark.parametrize("preflight", [False, True])
def test_runtime_args_default_bytes_and_explicit_longer_bounds(preflight: bool) -> None:
    base = ["--corpora", "synth", "--limit", "100"]
    args = {"out": Path("/result"), "scope": "scope", "target_cap": 2,
            "attestation": {"path": "/attestation.json", "sha256": "f" * 64},
            "preflight": preflight}
    expected = [*base]
    if not preflight:
        expected.extend([
            "--execution-scope-id", "scope", "--live-attestation", "/attestation.json",
            "--live-attestation-sha256", "f" * 64, "--live-attestation-max-age-hours", "24",
        ])
    expected.extend([
        "--max-total-target-calls", "2", "--max-total-judge-calls", "0",
        "--max-total-http-attempts", "0", "--deadline-seconds", "86400", "--out", "/result",
    ])
    if preflight:
        expected.append("--preflight-only")
    assert subject._runtime_args(base, **args) == expected
    longer = subject._runtime_args(
        base, **args, deadline_seconds=259200, live_attestation_max_age_hours=96,
    )
    assert subject._option(longer, "--deadline-seconds") == "259200"
    if not preflight:
        assert subject._option(longer, "--live-attestation-max-age-hours") == "96"
    else:
        assert "--live-attestation-max-age-hours" not in longer
    assert base == ["--corpora", "synth", "--limit", "100"]


@pytest.mark.parametrize("base_device", [None, "cuda:0", "cuda:1"])
def test_probe_inherits_explicit_guardrail_device_without_changing_default(base_device) -> None:
    unit = _unit()
    base = subject._base_argv(unit, project_revision=Path("/revision.json"),
                              project_revision_sha256="b" * 64)
    if base_device is None:
        index = base.index("--guardrail-device")
        del base[index:index + 2]
    else:
        base = subject._replace_option(base, "--guardrail-device", base_device)
    argv = subject._probe_args(unit, base=base, out=Path("/probe"), scope="scope")
    assert subject._option(argv, "--guardrail-device") == (base_device or "cuda:1")
    assert subject._option(argv, "--deadline-seconds") == "3600"


@pytest.mark.parametrize("overrides", [{}, {
    "measured_wall_time_seconds": 259200,
    "live_attestation_max_age_hours": 96,
    "scoring_device": "cuda:0",
}])
def test_run_unit_binds_longer_measured_envelope_timeout_and_one_scoring_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict,
) -> None:
    unit = _unit()
    kwargs = _kwargs(tmp_path)
    expected_device = overrides.get("scoring_device", "cuda:1")
    expected_deadline = overrides.get("measured_wall_time_seconds", 86400)
    expected_age = overrides.get("live_attestation_max_age_hours", 24)
    acquisitions, runs, events = {}, {}, []

    def attest(value, *, base, unit_root, scope, **unused):
        assert value == unit
        argv = subject._probe_args(value, base=base, out=unit_root / "probe", scope=scope)
        assert subject._option(argv, "--guardrail-device") == expected_device
        return {"path": "/attestation.json", "sha256": "f" * 64}

    def acquire(argv, *, lane_root, timeout, **unused):
        assert timeout == 86400
        acquisitions[lane_root.name] = list(argv)
        return ["--model-acquisition-store", "/sealed-store"]

    def run(argv, *, log, timeout, **unused):
        argv = list(argv)
        runs[log.name] = (argv, timeout)
        log.write_text("ok\n")
        if log.name in {"canary.run.log", "preflight.run.log"}:
            output = Path(subject._option(argv, "--out"))
            output.mkdir()
            name = ("eligibility-test.eligibility.json" if log.name == "canary.run.log"
                    else "lane-projection-test.lane-projection.json")
            (output / name).write_text("{}\n")
        if log.name == "measured.run.log":
            assert events == ["start"]
        return 0

    def counts(*, lane_root, **unused):
        (lane_root / "level1.json").write_text("{}\n")
        return 1, 1, 0

    monkeypatch.setattr(subject, "_derive_attestation", attest)
    monkeypatch.setattr(subject, "_acquisition_args", acquire)
    monkeypatch.setattr(subject, "_run", run)
    monkeypatch.setattr(subject, "_level1_counts", counts)
    monkeypatch.setattr(subject, "register_external_measured_start", lambda *a, **k: events.append("start"))
    monkeypatch.setattr(subject, "register_external_measured_terminal", lambda *a, **k: events.append("terminal"))
    result = subject._run_unit(unit, **kwargs, **overrides)
    assert result["status"] == "complete"
    assert events == ["start", "terminal"]
    for stage in ("canary", "preflight", "measured"):
        acquired = acquisitions[f"{stage}-acquisition"]
        argv, timeout = runs[f"{stage}.run.log"]
        assert argv[3:] == [*acquired, "--model-acquisition-store", "/sealed-store"]
        assert subject._option(acquired, "--guardrail-device") == expected_device
        assert subject._option(acquired, "--deadline-seconds") == str(
            86400 if stage == "canary" else expected_deadline
        )
        assert timeout == (expected_deadline if stage == "measured" else 86400)
        if stage != "preflight":
            assert subject._option(acquired, "--live-attestation-max-age-hours") == str(
                24 if stage == "canary" else expected_age
            )
    state = json.loads((kwargs["control_root"] / "units/unit/state.json").read_text())
    assert state["runner_argv"] == runs["measured.run.log"][0][3:]
    assert subject._option(unit.spec["base_argv"], "--guardrail-device") == "cuda:1"


@pytest.mark.parametrize("field,value", [
    ("measured_wall_time_seconds", value) for value in (0, -1, True, 259200.0, float("inf"), "259200")
] + [
    ("live_attestation_max_age_hours", value)
    for value in (0, -1, True, float("inf"), float("nan"), 8761, "96")
] + [
    ("scoring_device", value) for value in ("", "cuda:-1", "cuda:0 ", 0)
])
def test_invalid_driver_bounds_and_device_fail_before_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value,
) -> None:
    monkeypatch.setattr(subject, "_base_argv", lambda *a, **k: pytest.fail("prepared a model request"))
    kwargs = _kwargs(tmp_path)
    with pytest.raises(ValueError, match="wall time|live-attestation max age|scoring device"):
        subject._run_unit(_unit(), **kwargs, **{field: value})
    assert not kwargs["control_root"].exists()
