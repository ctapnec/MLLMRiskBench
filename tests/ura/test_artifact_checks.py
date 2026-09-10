import hashlib

import pytest

from ura.artifact_checks import artifact_sha256_enabled, artifact_verification, check_artifact_sha256


def test_default_does_not_open_artifact_bytes(tmp_path, monkeypatch):
    path = tmp_path / "retained.jsonl"
    path.write_text("retained content")
    monkeypatch.setattr(type(path), "open", lambda *a, **k: pytest.fail("unrequested checksum read"))
    check_artifact_sha256(path, "a" * 64)
    assert artifact_sha256_enabled() is False


def test_explicit_check_detects_same_size_changed_bytes_and_resets(tmp_path):
    path = tmp_path / "retained.jsonl"
    path.write_bytes(b"original")
    digest = hashlib.sha256(b"original").hexdigest()
    with artifact_verification(verify_sha256=True):
        check_artifact_sha256(path, digest)
        path.write_bytes(b"modified")
        with pytest.raises(ValueError, match="sha256 mismatch"):
            check_artifact_sha256(path, digest)
    assert artifact_sha256_enabled() is False


def test_verification_scope_resets_after_failure():
    with pytest.raises(RuntimeError):
        with artifact_verification(verify_sha256=True):
            raise RuntimeError("failed reader")
    assert artifact_sha256_enabled() is False
    with pytest.raises(ValueError, match="boolean"):
        with artifact_verification(verify_sha256="yes"):
            pytest.fail("nonboolean option admitted")


def test_existing_hosted_artifact_descriptor_reuses_recorded_digest(tmp_path, monkeypatch):
    from experiments.hosted_retained_inputs import _descriptor

    path = tmp_path / "retained.jsonl"
    path.write_bytes(b"retained bytes")
    original = _descriptor(path)
    monkeypatch.setattr(type(path), "open", lambda *a, **k: pytest.fail("bulk file was reopened"))
    assert _descriptor(path, original["sha256"]) == original


def test_hosted_artifact_explicit_full_check_rejects_same_size_change(tmp_path):
    from experiments.hosted_retained_inputs import _descriptor

    path = tmp_path / "retained.jsonl"
    path.write_bytes(b"original")
    original = _descriptor(path)
    path.write_bytes(b"modified")
    with artifact_verification(verify_sha256=True):
        with pytest.raises(ValueError, match="bytes changed"):
            _descriptor(path, original["sha256"])


def test_cli_flag_scopes_optional_checks_and_restores_default():
    from ura.artifact_checks import artifact_verification_cli

    @artifact_verification_cli
    def command(argv):
        return artifact_sha256_enabled()

    assert command([]) is False
    assert command(["--verify-artifact-sha256"]) is True
    assert artifact_sha256_enabled() is False


@pytest.mark.parametrize("legacy_assignment", [False, True])
def test_historical_readers_skip_only_hash_comparisons(tmp_path, monkeypatch, legacy_assignment):
    from experiments import figure_results, transfer_matrix
    from experiments.retained_artifact_reader import _configure_historical_artifact_checks
    if legacy_assignment:
        # The real 31e8521 reader stored its computed digest in a local variable.
        import inspect
        original_source = inspect.getsource
        function = transfer_matrix._artifact_path
        source = original_source(function).replace(
            "    if artifact_sha256_enabled() and hashlib.sha256(payload).hexdigest() != expected_hash:",
            "    observed_hash = hashlib.sha256(payload).hexdigest()\n    if observed_hash != expected_hash:")
        assert source != original_source(function)
        monkeypatch.setattr(inspect, "getsource", lambda value: source if value is function else original_source(value))

    # Preserve module state even though the historical bridge is normally used
    # only inside a short-lived, isolated reader subprocess.
    for module, names in ((figure_results, ("_resolve_artifact", "_grid_allowlist")),
                          (transfer_matrix, ("_artifact_path",))):
        for name in (*names, "artifact_sha256_enabled"):
            monkeypatch.setattr(module, name, getattr(module, name))
    artifact = tmp_path / "result.jsonl"
    artifact.write_bytes(b"{}\n")
    descriptor = {"file": artifact.name, "sha256": "a" * 64, "bytes": 3, "records": 1}
    marker = tmp_path / "cell.complete.json"
    with artifact_verification(verify_sha256=True):
        with pytest.raises(ValueError, match="digest mismatch"):
            figure_results._resolve_artifact(marker, {"artifacts": {"results": descriptor}}, "results")
    report = _configure_historical_artifact_checks(False)
    monkeypatch.setattr(figure_results, "_sha256_file", lambda *a: pytest.fail("historical file hash"))
    assert figure_results._resolve_artifact(marker, {"artifacts": {"results": descriptor}}, "results") == artifact
    assert transfer_matrix._artifact_path(tmp_path, descriptor, marker=marker, role="results") == artifact
    assert report == {"mode": "metadata_and_records", "unchanged_historical_full_checks": False}
    with pytest.raises(ValueError, match="record-count mismatch"):
        figure_results._resolve_artifact(marker, {"artifacts": {"results": {**descriptor, "records": 2}}}, "results")
    with pytest.raises(ValueError, match="byte-count mismatch"):
        figure_results._resolve_artifact(marker, {"artifacts": {"results": {**descriptor, "bytes": 4}}}, "results")


def test_console_reindex_checksum_option_is_explicit(tmp_path, monkeypatch):
    from experiments.rig_web import RigWebApp

    app = RigWebApp(repo_root=tmp_path, results_root=tmp_path / "runs", state_dir=tmp_path / "state")
    try:
        modes = []
        monkeypatch.setattr(app, "reindex_all", lambda **kw: modes.append(kw["verify_sha"]) or {})
        assert app.handle("POST", "/db/reindex", {})[0] == 303
        assert app.handle("POST", "/db/reindex", {"verify_artifact_sha256": "on"})[0] == 303
        assert modes == [False, True]
        page = app._db_card("")
        assert "name='verify_artifact_sha256'" in page
        assert "name='verify_artifact_sha256' checked" not in page
    finally:
        app.close()


@pytest.mark.parametrize("name", ["figures", "transfer_matrix"])
def test_analysis_forms_and_cli_expose_explicit_artifact_checks(name, capsys):
    import importlib
    from experiments.rig_web_app.catalog import _commands
    command = _commands()[name]
    assert any(param.flag == "--verify-artifact-sha256" and param.kind == "flag" for param in command.params)
    with pytest.raises(SystemExit) as stopped:
        importlib.import_module(command.module).main(["--verify-artifact-sha256", "--help"])
    assert stopped.value.code == 0
    assert "--verify-artifact-sha256" in capsys.readouterr().out
