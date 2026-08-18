from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments import engine_runtime_config


def _receipt(engine: str) -> dict:
    return {"runtime_id": f"engine-runtime-{engine:0<24}"}


def test_builder_keeps_interpreter_locators_out_of_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private = str(tmp_path / "operator-private" / "pyrit" / "bin" / "python")
    monkeypatch.setenv("URA_TEST_PYRIT_PYTHON", private)
    monkeypatch.setattr(
        engine_runtime_config,
        "inspect_engine_runtime",
        lambda interpreter, engine, **_kwargs: (
            _receipt(engine) if interpreter == private else pytest.fail("wrong locator")
        ),
    )
    out = tmp_path / "runtime.json"
    assert engine_runtime_config.main([
        "--runtime", "pyrit=URA_TEST_PYRIT_PYTHON",
        "--out", str(out),
    ]) == 0
    stdout = capsys.readouterr().out
    assert private not in stdout
    public = json.loads(stdout)
    raw = out.read_bytes()
    assert public["sha256"] == hashlib.sha256(raw).hexdigest()
    private_config = json.loads(raw)
    assert private_config["runtimes"]["pyrit"]["interpreter"] == private


def test_builder_rejects_duplicate_engines_before_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("URA_TEST_FIRST", str(tmp_path / "first"))
    monkeypatch.setenv("URA_TEST_SECOND", str(tmp_path / "second"))
    monkeypatch.setattr(
        engine_runtime_config,
        "inspect_engine_runtime",
        lambda *_args, **_kwargs: pytest.fail("inspection must remain zero-call"),
    )
    with pytest.raises(ValueError, match="only once"):
        engine_runtime_config.main([
            "--runtime", "pyrit=URA_TEST_FIRST",
            "--runtime", "pyrit=URA_TEST_SECOND",
            "--out", str(tmp_path / "runtime.json"),
        ])


def test_builder_is_create_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = str(tmp_path / "venv" / "bin" / "python")
    monkeypatch.setenv("URA_TEST_PYRIT_PYTHON", private)
    monkeypatch.setattr(
        engine_runtime_config,
        "inspect_engine_runtime",
        lambda _interpreter, engine, **_kwargs: _receipt(engine),
    )
    out = tmp_path / "runtime.json"
    out.write_text("operator-owned", encoding="utf-8")
    with pytest.raises(FileExistsError):
        engine_runtime_config.main([
            "--runtime", "pyrit=URA_TEST_PYRIT_PYTHON",
            "--out", str(out),
        ])
    assert out.read_text(encoding="utf-8") == "operator-owned"
