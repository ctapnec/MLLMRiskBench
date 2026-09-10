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
