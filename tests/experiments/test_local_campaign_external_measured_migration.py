"""One-time compatibility migration remains local-campaign-owned."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.local_campaign.migrate_external_measured import (
    migrate_external_measured_v1,
)
from experiments.rig_web_app import external_measured as external_module
from experiments.rig_web_app.external_measured import (
    load_external_measured_job,
    register_external_measured_start,
)


COMMIT = "a" * 40
LOCK = "b" * 64
GATE5 = "c" * 64


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return path


def _v1_source(
    results: Path,
    *,
    job_id: str,
    lane: str,
    start_overrides: dict[str, object] | None = None,
    terminal: tuple[float, int] | None = None,
) -> tuple[Path, Path, dict[str, object]]:
    output = results / "thesis" / "runner" / lane
    output.mkdir(parents=True, exist_ok=True)
    argv = [
        "--local",
        "vllm:model@revision",
        "--attackers",
        "deepteam",
        "--corpora",
        "strongreject_official",
        "--out",
        str(output.resolve()),
    ]
    _retained, argv_sha256 = external_module._validated_argv(argv)
    registration: dict[str, object] = {
        "schema": "ura-external-measured-job/1",
        "event": "start",
        "job_id": job_id,
        "command": "run_matrix",
        "run_kind": "measured",
        "sanitized_argv": argv,
        "argv_sha256": argv_sha256,
        "out_dir": str(output.resolve()),
        "expected_commit": COMMIT,
        "framework_lock_id": LOCK,
        "gate5_sha256": GATE5,
        "tmux": {
            "launcher": "tmux",
            "socket": "ura-old-socket",
            "session": "ura-old-session",
        },
        "started_at": 1_800_000_000.0,
        "registration_authority": "operational_only",
        "thesis_empirical_evidence": False,
    }
    if start_overrides:
        for name, value in start_overrides.items():
            if name.startswith("tmux."):
                tmux = registration["tmux"]
                assert isinstance(tmux, dict)
                tmux[name.removeprefix("tmux.")] = value
            else:
                registration[name] = value
    start_path = _write(
        results / "external-measured-jobs" / job_id / "registration.json",
        registration,
    )
    if terminal is not None:
        ended_at, exit_code = terminal
        _write(
            start_path.parent / "terminal.json",
            {
                "schema": "ura-external-measured-job-terminal/1",
                "event": "terminal",
                "job_id": job_id,
                "ended_at": ended_at,
                "state": "complete" if exit_code == 0 else "failed",
                "exit_code": exit_code,
            },
        )
    return output, start_path, registration


def test_v1_measured_registration_migrates_without_mutating_source(
    tmp_path: Path,
) -> None:
    results = tmp_path / "runs"
    output = results / "thesis" / "runner" / "lane"
    output.mkdir(parents=True)
    job_id = "external-measured-lane"
    argv = [
        "--local",
        "vllm:model@revision",
        "--attackers",
        "deepteam",
        "--corpora",
        "strongreject_official",
        "--out",
        str(output.resolve()),
    ]
    _retained, argv_sha256 = external_module._validated_argv(argv)
    old_registration = _write(
        results / "external-measured-jobs" / job_id / "registration.json",
        {
            "schema": "ura-external-measured-job/1",
            "event": "start",
            "job_id": job_id,
            "command": "run_matrix",
            "run_kind": "measured",
            "sanitized_argv": argv,
            "argv_sha256": argv_sha256,
            "out_dir": str(output.resolve()),
            "expected_commit": COMMIT,
            "framework_lock_id": LOCK,
            "gate5_sha256": GATE5,
            "tmux": {
                "launcher": "tmux",
                "socket": "ura-old-socket",
                "session": "ura-old-session",
            },
            "started_at": 1_800_000_000.0,
            "registration_authority": "operational_only",
            "thesis_empirical_evidence": False,
        },
    )
    old_terminal = _write(
        old_registration.parent / "terminal.json",
        {
            "schema": "ura-external-measured-job-terminal/1",
            "event": "terminal",
            "job_id": job_id,
            "ended_at": 1_800_000_010.0,
            "state": "complete",
            "exit_code": 0,
        },
    )
    registration_bytes = old_registration.read_bytes()
    terminal_bytes = old_terminal.read_bytes()

    assert migrate_external_measured_v1(results) == (1, 0)
    migrated = load_external_measured_job(results, job_id)
    assert migrated is not None
    assert migrated.admission_sha256 == GATE5
    assert migrated.argv_sha256 == argv_sha256
    assert migrated.state == "complete" and migrated.exit_code == 0
    assert old_registration.read_bytes() == registration_bytes
    assert old_terminal.read_bytes() == terminal_bytes

    # Interrupted batches are safely resumable and exact existing rows are not
    # rewritten or duplicated.
    assert migrate_external_measured_v1(results) == (0, 1)


def test_differing_v2_start_is_not_terminalized_before_collision_rejection(
    tmp_path: Path,
) -> None:
    results = tmp_path / "runs"
    job_id = "external-measured-collision"
    output, _source, registration = _v1_source(
        results,
        job_id=job_id,
        lane="collision",
        terminal=(1_800_000_010.0, 0),
    )
    argv = registration["sanitized_argv"]
    assert isinstance(argv, list)
    v2_start = register_external_measured_start(
        results,
        job_id=job_id,
        command="run_matrix",
        run_kind_name="measured",
        sanitized_argv=argv,
        out_dir=output.resolve(),
        expected_commit=COMMIT,
        framework_lock_id=LOCK,
        admission_sha256="d" * 64,
        tmux_socket="ura-old-socket",
        tmux_session="ura-old-session",
        started_at=1_800_000_000.0,
    )
    before = v2_start.read_bytes()

    with pytest.raises(ValueError, match="collision differs"):
        migrate_external_measured_v1(results)

    assert v2_start.read_bytes() == before
    assert not (v2_start.parent / "terminal.json").exists()


@pytest.mark.parametrize(
    ("overrides", "label"),
    [
        ({"argv_sha256": "0" * 64}, "argv digest"),
        ({"tmux.socket": 7}, "numeric tmux"),
        ({"gate5_sha256": 7}, "numeric digest"),
        ({"started_at": "1800000000"}, "string timestamp"),
    ],
)
def test_invalid_v1_scalar_or_digest_is_not_coerced_into_v2(
    tmp_path: Path,
    overrides: dict[str, object],
    label: str,
) -> None:
    results = tmp_path / "runs"
    job_id = "external-measured-invalid"
    _v1_source(
        results,
        job_id=job_id,
        lane="invalid",
        start_overrides=overrides,
    )

    with pytest.raises(ValueError, match="invalid v1 start"):
        migrate_external_measured_v1(results)

    assert load_external_measured_job(results, job_id, probe_session=False) is None, label
    assert not (results / "external-measured-jobs-v2").exists()


def test_terminal_before_start_is_rejected_before_v2_start_publication(
    tmp_path: Path,
) -> None:
    results = tmp_path / "runs"
    job_id = "external-measured-backward-time"
    _v1_source(
        results,
        job_id=job_id,
        lane="backward-time",
        terminal=(1_799_999_999.0, 0),
    )

    with pytest.raises(ValueError, match="invalid v1 terminal"):
        migrate_external_measured_v1(results)

    assert load_external_measured_job(results, job_id, probe_session=False) is None
    assert not (results / "external-measured-jobs-v2").exists()


def test_complete_source_batch_is_validated_before_any_v2_write(
    tmp_path: Path,
) -> None:
    results = tmp_path / "runs"
    _v1_source(
        results,
        job_id="external-a-valid",
        lane="valid-first",
    )
    _v1_source(
        results,
        job_id="external-z-invalid",
        lane="invalid-last",
        start_overrides={"argv_sha256": "0" * 64},
    )

    with pytest.raises(ValueError, match="invalid v1 start"):
        migrate_external_measured_v1(results)

    assert not (results / "external-measured-jobs-v2").exists()


def test_exact_existing_v2_start_accepts_one_later_v1_terminal(
    tmp_path: Path,
) -> None:
    results = tmp_path / "runs"
    job_id = "external-measured-late-terminal"
    output, _source, registration = _v1_source(
        results,
        job_id=job_id,
        lane="late-terminal",
        terminal=(1_800_000_010.0, 0),
    )
    argv = registration["sanitized_argv"]
    assert isinstance(argv, list)
    register_external_measured_start(
        results,
        job_id=job_id,
        command="run_matrix",
        run_kind_name="measured",
        sanitized_argv=argv,
        out_dir=output.resolve(),
        expected_commit=COMMIT,
        framework_lock_id=LOCK,
        admission_sha256=GATE5,
        tmux_socket="ura-old-socket",
        tmux_session="ura-old-session",
        started_at=1_800_000_000.0,
    )

    assert migrate_external_measured_v1(results) == (0, 1)
    migrated = load_external_measured_job(results, job_id, probe_session=False)
    assert migrated is not None
    assert migrated.ended_at == 1_800_000_010.0 and migrated.exit_code == 0
    assert migrate_external_measured_v1(results) == (0, 1)
