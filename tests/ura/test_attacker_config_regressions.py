from __future__ import annotations

import hashlib
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
    config_artifact = grid["request"]["attacker_config_artifact"]
    assert set(config_artifact) == {
        "file", "sha256", "bytes", "normalized_selected_sha256",
    }
    assert config_artifact["file"] == config.name
    assert len(config_artifact["sha256"]) == 64
    assert str(config.resolve()) not in json.dumps(grid)
    manifest = json.loads(
        next(out.glob("*.manifest.json")).read_text(encoding="utf-8")
    )
    assert manifest["config"]["run"]["attacker_config"] == config_value["nanogcg"]


def test_attacker_config_formatting_does_not_change_selected_grid_identity(
    tmp_path: Path,
) -> None:
    value = {"nanogcg": {
        "suffix": " suffix",
        "suffix_source": "fixture",
        "model_revision": "0123456789abcdef",
    }}
    identities: list[tuple[str, str]] = []
    for index, indent in enumerate((None, 4)):
        config = tmp_path / f"attackers-{index}.json"
        config.write_text(json.dumps(value, indent=indent), encoding="utf-8")
        out = tmp_path / f"run-{index}"
        assert run_matrix.main([
            "--dry-run", "--attackers", "nanogcg",
            "--attacker-config", str(config), "--judges", "rules",
            "--corpora", "synth", "--limit", "1", "--max-queries", "1",
            "--max-turns", "1", "--out", str(out),
        ]) == 0
        grid = json.loads(next(out.glob("*.grid.json")).read_text(encoding="utf-8"))
        plan = json.loads(next(out.glob("*.eligibility.json")).read_text(
            encoding="utf-8"
        ))
        identities.append((grid["grid_id"], plan["plan_id"]))

    assert identities[0] == identities[1]


def test_t3mp3st_bundle_path_is_operational_not_persisted_identity(
    tmp_path: Path,
) -> None:
    bundle_bytes = b'{"format_version":"fixture"}\n'
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    normalized_identities: list[str] = []
    for index in range(2):
        bundle = tmp_path / f"host-path-{index}" / "bundle.json"
        bundle.parent.mkdir()
        bundle.write_bytes(bundle_bytes)
        config = tmp_path / f"t3-config-{index}.json"
        config.write_text(json.dumps({
            "t3mp3st": {
                "upstream_revision": "a" * 40,
                "source_provider": "local",
                "source_model": "planner",
                "response_artifact": str(bundle),
                "response_artifact_sha256": digest,
            }
        }), encoding="utf-8")

        operational, artifact = run_matrix._load_attacker_config(
            str(config), ["t3mp3st"]
        )
        assert operational["t3mp3st"]["response_artifact"] == str(bundle)
        portable = run_matrix._portable_attacker_configs(operational)
        assert "response_artifact" not in portable["t3mp3st"]
        assert portable["t3mp3st"]["response_artifact_identity"] == {
            "sha256": digest,
            "bytes": len(bundle_bytes),
        }
        assert str(bundle) not in json.dumps(portable)
        assert artifact is not None
        normalized_identities.append(str(artifact["normalized_selected_sha256"]))

    assert normalized_identities[0] == normalized_identities[1]


def test_harmbench_bundle_path_is_operational_not_persisted_identity(
    tmp_path: Path,
) -> None:
    bundle_bytes = b'{"format_version":"fixture"}\n'
    digest = hashlib.sha256(bundle_bytes).hexdigest()
    normalized_identities: list[str] = []
    for index in range(2):
        bundle = tmp_path / f"harmbench-host-path-{index}" / "bundle.json"
        bundle.parent.mkdir()
        bundle.write_bytes(bundle_bytes)
        config = tmp_path / f"harmbench-config-{index}.json"
        config.write_text(json.dumps({
            "harmbench": {
                "methods": ["PEZ"],
                "upstream_revision": "b" * 40,
                "replay_artifact": str(bundle),
                "replay_artifact_sha256": digest,
            }
        }), encoding="utf-8")

        operational, artifact = run_matrix._load_attacker_config(
            str(config), ["harmbench"]
        )
        assert operational["harmbench"]["replay_artifact"] == str(bundle)
        portable = run_matrix._portable_attacker_configs(operational)
        assert "replay_artifact" not in portable["harmbench"]
        assert portable["harmbench"]["replay_artifact_identity"] == {
            "sha256": digest,
            "bytes": len(bundle_bytes),
        }
        assert str(bundle) not in json.dumps(portable)
        assert artifact is not None
        normalized_identities.append(str(artifact["normalized_selected_sha256"]))

    assert normalized_identities[0] == normalized_identities[1]


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
    error = json.loads(
        (out / "attacker-input-contract.error.json").read_text(encoding="utf-8")
    )
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
