from __future__ import annotations

import json
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
import ura.cli as cli_module
from ura.adapters.nanogcg import NanoGCGAttacker
from ura.adapters.engines import get_attacker


def test_attacker_factory_forwards_constructor_configuration() -> None:
    attacker = get_attacker(
        "nanogcg",
        suffix=" suffix",
        suffix_source="fixture",
        model_revision="0123456789abcdef",
    )
    assert isinstance(attacker, NanoGCGAttacker)
    assert attacker.suffix == " suffix"
    assert attacker.suffix_source == "fixture"


def test_attacker_config_rejects_literal_secrets(tmp_path: Path) -> None:
    config = tmp_path / "attackers.json"
    config.write_text(
        json.dumps({"promptfoo": {"api_key": "must-not-enter-manifest"}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="literal secret-like"):
        run_matrix._load_attacker_config(str(config), ["promptfoo"])


def test_run_matrix_applies_and_persists_attacker_config(tmp_path: Path) -> None:
    config = tmp_path / "attackers.json"
    config_value = {
        "nanogcg": {
            "suffix": " suffix",
            "suffix_source": "fixture",
            "model_revision": "0123456789abcdef",
        }
    }
    config.write_text(json.dumps(config_value), encoding="utf-8")
    out = tmp_path / "run"
    result = run_matrix.main([
        "--dry-run",
        "--attackers",
        "nanogcg",
        "--attacker-config",
        str(config),
        "--judges",
        "rules",
        "--corpora",
        "synth",
        "--limit",
        "1",
        "--max-queries",
        "1",
        "--max-turns",
        "1",
        "--out",
        str(out),
    ])

    assert result == 0
    grid = json.loads(next(out.glob("*.grid.json")).read_text(encoding="utf-8"))
    assert grid["request"]["attacker_configs"] == config_value
    assert len(grid["request"]["attacker_config_artifact"]["sha256"]) == 64
    manifest = json.loads(
        next(out.glob("*.manifest.json")).read_text(encoding="utf-8")
    )
    assert manifest["config"]["run"]["attacker_config"] == config_value["nanogcg"]


def test_matrix_rejects_native_importer_as_runner_replay(tmp_path: Path) -> None:
    out = tmp_path / "native"
    result = run_matrix.main([
        "--dry-run",
        "--attackers",
        "fuzzyai",
        "--judges",
        "rules",
        "--corpora",
        "synth",
        "--limit",
        "1",
        "--out",
        str(out),
    ])
    assert result == 1
    error = json.loads(next(out.glob("*.error.json")).read_text(encoding="utf-8"))
    assert "native-artifact integration" in error["message"]


def test_smoke_cli_rejects_external_engine_before_creating_output(
    tmp_path: Path,
) -> None:
    out = tmp_path / "smoke"
    result = cli_module.main([
        "run",
        "--corpus",
        "synth",
        "--attacker",
        "nanogcg",
        "--target",
        "mock",
        "--judges",
        "rules",
        "--out",
        str(out),
        "--n",
        "1",
    ])
    assert result == 1
    assert not out.exists()
