from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import ura.project_revision as project_revision_module
from experiments import project_revision as revision_cli
from experiments import rig_check, run_matrix
from ura.project_revision import (
    create_project_revision,
    current_project_revision,
    diagnostic_project_revision_binding,
    load_project_revision_file,
    project_revision_binding,
    project_revision_bytes,
    recheck_project_revision,
    validate_project_revision,
    validate_project_revision_binding,
    write_project_revision,
)


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    root = tmp_path / "repo"
    driver = root / "experiments" / "run_matrix.py"
    harness = root / "src" / "ura" / "runner.py"
    driver.parent.mkdir(parents=True)
    harness.parent.mkdir(parents=True)
    driver.write_text("DRIVER = 1\n", encoding="utf-8")
    harness.write_text("HARNESS = 1\n", encoding="utf-8")
    (harness.parent / "helper.py").write_text("HELPER = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        "/runs/\n/experiments/source-instances.json\n",
        encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "fixture")
    return root, driver, harness, _git(root, "rev-parse", "HEAD")


def _alternate_valid_receipt(receipt: dict) -> dict:
    alternate = json.loads(json.dumps(receipt))
    alternate["source"]["driver_source"]["sha256"] = "f" * 64
    body = {key: item for key, item in alternate.items() if key != "revision_id"}
    from ura.eligibility import canonical_json_sha256

    alternate["revision_id"] = (
        "project-revision-" + canonical_json_sha256(body)[:24]
    )
    return validate_project_revision(alternate)


def test_clean_exact_receipt_round_trip_and_cli_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, driver, harness, revision = _repo(tmp_path)
    # Ordinary operator-local JSON configuration is intentionally allowed.
    (root / "experiments" / "source-instances.json").write_text("{}\n", encoding="utf-8")
    (root / "runs" / "thesis").mkdir(parents=True)
    (root / "runs" / "thesis" / "result.json").write_text("{}\n", encoding="utf-8")
    receipt = create_project_revision(
        revision, driver, harness_module_path=harness
    )
    path = write_project_revision(tmp_path / "receipts", receipt)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    loaded, descriptor = load_project_revision_file(
        path, digest, driver, harness_module_path=harness
    )
    binding = project_revision_binding(loaded, descriptor)
    assert binding["expected_commit"] == revision
    assert binding["observed_commit"] == revision
    assert binding["mode"] == "verified"
    assert validate_project_revision(receipt) == receipt

    monkeypatch.setattr(revision_cli, "create_project_revision", lambda *_a, **_kw: receipt)
    monkeypatch.setattr(
        revision_cli, "load_project_revision_file",
        lambda *_a, **_kw: (loaded, descriptor),
    )
    out = tmp_path / "cli"
    assert revision_cli.main(["--expected-revision", revision, "--out", str(out)]) == 0
    cli_path = next(out.glob("*.project-revision.json"))
    assert revision_cli.main([
        "--validate", str(cli_path), "--sha256",
        hashlib.sha256(cli_path.read_bytes()).hexdigest(),
    ]) == 0


@pytest.mark.parametrize(
    "mode", ["tracked", "staged", "untracked_python", "ignored_python"]
)
def test_project_revision_rejects_executable_or_tracked_dirt(
    tmp_path: Path, mode: str,
) -> None:
    root, driver, harness, revision = _repo(tmp_path)
    if mode == "tracked":
        driver.write_text("DRIVER = 2\n", encoding="utf-8")
    elif mode == "staged":
        driver.write_text("DRIVER = 2\n", encoding="utf-8")
        _git(root, "add", "experiments/run_matrix.py")
    elif mode == "untracked_python":
        (root / "experiments" / "shadow.py").write_text("BAD = 1\n", encoding="utf-8")
    else:
        with (root / ".gitignore").open("a", encoding="utf-8") as handle:
            handle.write("/src/ura/shadow.py\n")
        _git(root, "add", ".gitignore")
        _git(root, "commit", "-qm", "ignore fixture")
        revision = _git(root, "rev-parse", "HEAD")
        (root / "src" / "ura" / "shadow.py").write_text("BAD = 1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        current_project_revision(
            driver, expected_revision=revision, harness_module_path=harness
        )


def test_project_revision_rejects_wrong_root_revision_and_tamper(tmp_path: Path) -> None:
    root, driver, harness, revision = _repo(tmp_path)
    other_root, _other_driver, other_harness, _ = _repo(tmp_path / "other")
    assert other_root != root
    with pytest.raises(ValueError, match="different Git roots"):
        current_project_revision(
            driver, expected_revision=revision, harness_module_path=other_harness
        )
    with pytest.raises(ValueError, match="revision mismatch"):
        current_project_revision(
            driver, expected_revision="0" * 40, harness_module_path=harness
        )
    with pytest.raises(ValueError, match="full 40-hex"):
        current_project_revision(
            driver, expected_revision=revision.upper(), harness_module_path=harness
        )
    with pytest.raises(ValueError, match="must not be padded"):
        current_project_revision(
            driver, expected_revision=f" {revision}", harness_module_path=harness
        )
    receipt = create_project_revision(revision, driver, harness_module_path=harness)
    receipt["source"]["driver_source"]["sha256"] = "f" * 64
    body = {key: item for key, item in receipt.items() if key != "revision_id"}
    from ura.eligibility import canonical_json_sha256

    receipt["revision_id"] = "project-revision-" + canonical_json_sha256(body)[:24]
    with pytest.raises(ValueError, match="source bytes differ"):
        recheck_project_revision(receipt, driver, harness_module_path=harness)


def test_binding_is_strict_and_revision_changes_experiment_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostic = diagnostic_project_revision_binding("a" * 64, "b" * 64)
    assert validate_project_revision_binding(diagnostic) == diagnostic
    with pytest.raises(ValueError):
        validate_project_revision_binding({**diagnostic, "forged": True})
    with pytest.raises(ValueError):
        validate_project_revision_binding(diagnostic, allow_not_required=False)

    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    assert run_matrix.main([
        "--dry-run", "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--out", str(out_a),
    ]) == 0
    original = run_matrix.diagnostic_project_revision_binding
    monkeypatch.setattr(run_matrix, "diagnostic_project_revision_binding", lambda *_a: original(
        "c" * 64, "d" * 64
    ))
    monkeypatch.setattr(run_matrix, "_harness_source_identity", lambda: {
        "algorithm": "sha256_relative_path_size_file_digest_v1",
        "sha256": "c" * 64,
        "file_count": 1,
        "bytes": 1,
    })
    monkeypatch.setattr(run_matrix, "_source_tree_digest", lambda _path: (
        "d" * 64, 1
    ))
    assert run_matrix.main([
        "--dry-run", "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--out", str(out_b),
    ]) == 0
    grid_a = json.loads(next(out_a.glob("*.grid.json")).read_text(encoding="utf-8"))
    grid_b = json.loads(next(out_b.glob("*.grid.json")).read_text(encoding="utf-8"))
    assert grid_a["grid_id"] != grid_b["grid_id"]
    assert grid_a["request"]["project_revision"] != grid_b["request"]["project_revision"]


def test_non_dry_gate_requires_receipt_before_target_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructions = 0

    def forbidden(*_args, **_kwargs):
        nonlocal constructions
        constructions += 1
        raise AssertionError("target construction must not be reached")

    monkeypatch.setattr(run_matrix, "build_target", forbidden)
    with pytest.raises(SystemExit) as exc:
        run_matrix.main([
            "--preflight-only", "--api", "fixture-target", "--judges", "rules",
            "--corpora", "synth", "--limit", "1", "--out", str(tmp_path / "out"),
        ])
    assert exc.value.code == 2
    assert constructions == 0


def test_receipt_loader_rejects_digest_mismatch_and_duplicate_keys(
    tmp_path: Path,
) -> None:
    _root, driver, harness, revision = _repo(tmp_path)
    receipt = create_project_revision(revision, driver, harness_module_path=harness)
    path = write_project_revision(tmp_path / "receipts", receipt)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="sha256 mismatch"):
        load_project_revision_file(
            path, "0" * 64, driver,
            recheck_checkout=False, harness_module_path=harness,
        )
    with pytest.raises(ValueError, match="exactly 64 lowercase"):
        load_project_revision_file(
            path, digest.upper(), driver,
            recheck_checkout=False, harness_module_path=harness,
        )

    duplicate_payload = (
        b'{"schema":"ura-project-revision/1",' + project_revision_bytes(receipt)[1:]
    )
    duplicate_path = tmp_path / "duplicate.project-revision.json"
    duplicate_path.write_bytes(duplicate_payload)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_project_revision_file(
            duplicate_path,
            hashlib.sha256(duplicate_payload).hexdigest(),
            driver,
            recheck_checkout=False,
            harness_module_path=harness,
        )


def test_receipt_loader_rejects_symlink(
    tmp_path: Path,
) -> None:
    _root, driver, harness, revision = _repo(tmp_path)
    receipt = create_project_revision(revision, driver, harness_module_path=harness)
    path = write_project_revision(tmp_path / "receipts", receipt)
    link = tmp_path / "linked.project-revision.json"
    try:
        os.symlink(path, link)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable for this test account")
    with pytest.raises(ValueError, match="non-symlink"):
        load_project_revision_file(
            link,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            driver,
            recheck_checkout=False,
            harness_module_path=harness,
        )


def test_receipt_loader_rejects_same_size_valid_inode_swap_before_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, driver, harness, revision = _repo(tmp_path)
    receipt_a = create_project_revision(revision, driver, harness_module_path=harness)
    receipt_b = _alternate_valid_receipt(receipt_a)
    payload_a = project_revision_bytes(receipt_a)
    payload_b = project_revision_bytes(receipt_b)
    assert len(payload_a) == len(payload_b)
    candidate = tmp_path / "candidate.project-revision.json"
    replacement = tmp_path / "replacement.project-revision.json"
    candidate.write_bytes(payload_a)
    replacement.write_bytes(payload_b)
    digest_a = hashlib.sha256(payload_a).hexdigest()
    original_open = project_revision_module.os.open
    parsed = 0
    rechecked = 0

    def swap_then_open(path, flags, *args):
        if Path(path) == candidate and replacement.exists():
            candidate.unlink()
            replacement.replace(candidate)
        return original_open(path, flags, *args)

    def forbidden_parse(*_args, **_kwargs):
        nonlocal parsed
        parsed += 1
        raise AssertionError("a swapped receipt must not reach JSON parsing")

    def forbidden_recheck(*_args, **_kwargs):
        nonlocal rechecked
        rechecked += 1
        raise AssertionError("a swapped receipt must not reach checkout recheck")

    monkeypatch.setattr(project_revision_module.os, "open", swap_then_open)
    monkeypatch.setattr(project_revision_module, "_strict_json_object", forbidden_parse)
    monkeypatch.setattr(project_revision_module, "recheck_project_revision", forbidden_recheck)
    with pytest.raises(ValueError, match="changed while it was opened"):
        load_project_revision_file(
            candidate,
            digest_a,
            driver,
            harness_module_path=harness,
        )
    assert parsed == 0
    assert rechecked == 0


def test_receipt_loader_rejects_hardlinks_and_oversize_files(
    tmp_path: Path,
) -> None:
    _root, driver, harness, revision = _repo(tmp_path)
    receipt = create_project_revision(revision, driver, harness_module_path=harness)
    path = write_project_revision(tmp_path / "receipts", receipt)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    hardlink = tmp_path / "hardlinked.project-revision.json"
    try:
        os.link(path, hardlink)
    except OSError:
        pytest.skip("hardlink creation is unavailable for this test account")
    with pytest.raises(ValueError, match="one regular non-symlink"):
        load_project_revision_file(
            hardlink,
            digest,
            driver,
            recheck_checkout=False,
            harness_module_path=harness,
        )
    hardlink.unlink()

    oversize = tmp_path / "oversize.project-revision.json"
    oversize.write_bytes(b"x" * (project_revision_module._MAX_RECEIPT_BYTES + 1))
    with pytest.raises(ValueError, match="size bound"):
        load_project_revision_file(
            oversize,
            hashlib.sha256(oversize.read_bytes()).hexdigest(),
            driver,
            recheck_checkout=False,
            harness_module_path=harness,
        )


def test_swapped_project_receipt_stops_run_matrix_before_any_model_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, driver, harness, revision = _repo(tmp_path)
    receipt_a = create_project_revision(revision, driver, harness_module_path=harness)
    receipt_b = _alternate_valid_receipt(receipt_a)
    payload_a = project_revision_bytes(receipt_a)
    payload_b = project_revision_bytes(receipt_b)
    assert len(payload_a) == len(payload_b)
    candidate = tmp_path / "run-candidate.project-revision.json"
    replacement = tmp_path / "run-replacement.project-revision.json"
    candidate.write_bytes(payload_a)
    replacement.write_bytes(payload_b)
    digest_a = hashlib.sha256(payload_a).hexdigest()
    original_open = project_revision_module.os.open
    constructions: list[str] = []

    def swap_then_open(path, flags, *args):
        if Path(path) == candidate and replacement.exists():
            candidate.unlink()
            replacement.replace(candidate)
        return original_open(path, flags, *args)

    def forbidden(name: str):
        def reject(*_args, **_kwargs):
            constructions.append(name)
            raise AssertionError(f"{name} constructor must not run")

        return reject

    monkeypatch.setattr(project_revision_module.os, "open", swap_then_open)
    monkeypatch.setattr(run_matrix, "build_target", forbidden("target"))
    monkeypatch.setattr(run_matrix, "build_judges", forbidden("judges"))
    monkeypatch.setattr(run_matrix, "get_attacker", forbidden("attacker"))
    out = tmp_path / "run-output"
    with pytest.raises(SystemExit) as exc:
        run_matrix.main([
            "--preflight-only",
            "--api",
            "openai:fixture-target",
            "--judges",
            "rules",
            "--attackers",
            "replay",
            "--corpora",
            "synth",
            "--limit",
            "1",
            "--project-revision",
            str(candidate),
            "--project-revision-sha256",
            digest_a,
            "--out",
            str(out),
        ])

    assert exc.value.code == 2
    assert constructions == []
    assert not list(out.glob("*.complete.json"))


def test_publication_boundary_recheck_prevents_completion_and_final_grid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_revision_args,
) -> None:
    from ura.targets.api import MockTarget

    monkeypatch.setattr(run_matrix, "build_target", lambda *_a, **_kw: MockTarget())
    checks = 0

    def drift_after_cell_start(*_args, **_kwargs):
        nonlocal checks
        checks += 1
        if checks >= 2:
            raise ValueError("simulated checkout drift")
        return _args[0]

    monkeypatch.setattr(run_matrix, "recheck_project_revision", drift_after_cell_start)
    target_spec = "openai:fixture-model"
    api_config = tmp_path / "api-targets.json"
    api_config.write_text(json.dumps({target_spec: {
        "modalities": ["text"],
        "max_tokens": 64,
        "temperature": 0.0,
    }}), encoding="utf-8")
    out = tmp_path / "run"
    result = run_matrix.main([
        "--attestation-probe", "--execution-scope-id", "test-scope",
        "--api", target_spec, "--api-config", str(api_config),
        "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1",
        "--max-queries", "1", "--max-turns", "1",
        "--max-total-target-calls", "100",
        "--max-total-judge-calls", "100",
        "--max-total-http-attempts", "100",
        "--deadline-seconds", "3600",
        "--out", str(out), *project_revision_args,
    ])

    assert result == 1
    assert checks >= 2
    assert not list(out.glob("*.complete.json"))
    grid = json.loads(next(out.glob("*.grid.json")).read_text(encoding="utf-8"))
    assert grid["status"] == "running"


def test_rig_check_dry_omits_and_non_dry_retains_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_revision_args,
) -> None:
    from ura.targets.api import MockTarget

    monkeypatch.setattr(run_matrix, "build_target", lambda *_a, **_kw: MockTarget())
    dry_out = tmp_path / "dry"
    assert rig_check.main([
        "--dry-run", "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--out", str(dry_out),
    ]) == 0
    assert not list(dry_out.glob("*.project-revision.json"))

    target_spec = "openai:fixture-model"
    api_config = tmp_path / "rig-api-targets.json"
    api_config.write_text(json.dumps({target_spec: {
        "modalities": ["text"],
        "max_tokens": 64,
        "temperature": 0.0,
    }}), encoding="utf-8")
    live_out = tmp_path / "live"
    assert rig_check.main([
        "--api", target_spec, "--api-config", str(api_config),
        "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1",
        "--max-total-target-calls", "100",
        "--max-total-judge-calls", "100",
        "--max-total-http-attempts", "100",
        "--deadline-seconds", "3600",
        "--out", str(live_out), *project_revision_args,
    ]) == 0
    retained = list(live_out.glob("*.project-revision.json"))
    assert len(retained) == 1
    assert retained[0].name == project_revision_args.binding["file"]


def test_cli_modules_reach_help_without_pythonpath() -> None:
    # Regression: `python -m experiments.<cli>` must place src/ on sys.path
    # itself.  Three documented runbook commands imported ura before any
    # bootstrap ran and failed from a clean shell.
    repo_root = Path(__file__).resolve().parents[2]
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    for module in (
        "experiments.project_revision",
        "experiments.export_jalmbench",
        "experiments.export_vlsbench",
    ):
        completed = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, f"{module}: {completed.stderr}"
