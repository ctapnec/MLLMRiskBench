"""Regression coverage for logical source arms and construct-faithful metrics."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from ura.converters import JailBreakVConverter, MLLMGuardConverter
from ura.converters._common import CorpusFormatError
from ura.source_metrics import validate_scored_source_metrics


_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _write_jbb(path: Path, *, goal: str) -> None:
    path.write_text(
        "Index,Goal,Target,Behavior,Category,Source\n"
        f"1,{goal},Sure,behavior-1,Privacy,Original\n",
        encoding="utf-8",
    )


def test_source_config_runs_two_instances_of_one_converter_without_path_leakage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harmful = tmp_path / "harmful-behaviors.csv"
    benign = tmp_path / "benign-behaviors.csv"
    _write_jbb(harmful, goal="harmful request")
    _write_jbb(benign, goal="benign request")
    monkeypatch.setenv("URA_TEST_JBB_HARMFUL", str(harmful))
    monkeypatch.setenv("URA_TEST_JBB_BENIGN", str(benign))

    config = tmp_path / "sources.json"
    config.write_text(json.dumps({
        "jbb-harmful": {
            "converter": "jailbreakbench",
            "path_env": "URA_TEST_JBB_HARMFUL",
            "source_label": "JBB Behaviors",
            "split": "harmful",
        },
        "jbb-benign": {
            "converter": "jailbreakbench",
            "path_env": "URA_TEST_JBB_BENIGN",
            "source_label": "JBB Behaviors",
            "split": "benign",
        },
    }, sort_keys=True), encoding="utf-8")

    out = tmp_path / "run"
    assert run_matrix.main([
        "--dry-run",
        "--attackers", "replay",
        "--judges", "rules,llm",
        "--corpora", "jbb-harmful,jbb-benign",
        "--source-config", str(config),
        "--limit", "1",
        "--max-queries", "1",
        "--max-turns", "1",
        "--out", str(out),
    ]) == 0

    grid = json.loads(next(out.glob("grid-*.grid.json")).read_text(encoding="utf-8"))
    request = grid["request"]
    assert request["source_instances"]["jbb-harmful"] == {
        "converter": "jailbreakbench",
        "synth": False,
        "path_env": "URA_TEST_JBB_HARMFUL",
        "path_env_required": True,
        "source_label": "JBB Behaviors",
        "split": "harmful",
    }
    assert request["source_instances"]["jbb-benign"]["split"] == "benign"
    assert request["source_config_artifact"]["file"] == "sources.json"
    assert request["source_config_artifact"]["sha256"] == hashlib.sha256(
        config.read_bytes()
    ).hexdigest()
    persisted_sources = json.dumps({
        "source_instances": request["source_instances"],
        "source_config_artifact": request["source_config_artifact"],
    }, sort_keys=True)
    assert str(harmful) not in persisted_sources
    assert str(benign) not in persisted_sources

    audits = [
        json.loads(path.read_text(encoding="utf-8"))["config"]["run"][
            "sampling_audit"
        ]
        for path in out.glob("*.manifest.json")
    ]
    assert {audit["source_locator"]["split"] for audit in audits} == {
        "harmful", "benign",
    }
    assert all(str(tmp_path) not in json.dumps(audit) for audit in audits)


def test_source_config_requires_environment_indirection_and_supports_inventory_superset(
    tmp_path: Path,
) -> None:
    direct = tmp_path / "direct.json"
    direct.write_text(json.dumps({
        "arm": {"converter": "jailbreakbench", "path": "private/source.csv"}
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        run_matrix._load_source_config(str(direct), ["arm"])

    unused = tmp_path / "unused.json"
    unused.write_text(json.dumps({
        "arm": {
            "converter": "jailbreakbench",
            "path_env": "URA_ARM_PATH",
        },
        "other": {
            "converter": "jailbreakbench",
            "path_env": "URA_OTHER_PATH",
        }
    }), encoding="utf-8")
    selected, artifact = run_matrix._load_source_config(str(unused), ["arm"])
    assert set(selected) == {"arm"}
    assert selected["arm"]["path_env"] == "URA_ARM_PATH"
    selected_identity = run_matrix._selected_config_artifact_identity(artifact)
    changed = json.loads(unused.read_text(encoding="utf-8"))
    changed["other"]["path_env"] = "URA_CHANGED_UNUSED_PATH"
    unused.write_text(json.dumps(changed), encoding="utf-8")
    selected_after_unused_edit, artifact_after_unused_edit = (
        run_matrix._load_source_config(str(unused), ["arm"])
    )
    assert selected_after_unused_edit == selected
    assert run_matrix._selected_config_artifact_identity(
        artifact_after_unused_edit
    ) == selected_identity
    assert artifact_after_unused_edit["sha256"] != artifact["sha256"]

    changed["arm"]["path_env"] = "URA_CHANGED_SELECTED_PATH"
    unused.write_text(json.dumps(changed), encoding="utf-8")
    _, artifact_after_selected_edit = run_matrix._load_source_config(
        str(unused), ["arm"]
    )
    assert run_matrix._selected_config_artifact_identity(
        artifact_after_selected_edit
    ) != selected_identity


def test_mllmguard_hallucination_requires_truthfulness_metric_before_calls(
    tmp_path: Path,
) -> None:
    image = tmp_path / "probe.png"
    image.write_bytes(_PNG)
    source = tmp_path / "hallucination.json"
    source.write_text(json.dumps([{
        "id": "h1",
        "Prompt": "What object is shown?",
        "file_name": image.name,
        "Category I": "Hallucination",
    }]), encoding="utf-8")

    point = MLLMGuardConverter().parse(source)[0]
    assert point.expected_behavior == "safe_answer"
    assert point.meta["common_metrics_eligible"] is False
    assert point.meta["required_metric"] == (
        "mllmguard_hallucination_truthfulness"
    )
    assert point.meta["source_metric_semantics"] == (
        "GuardRank_hallucination_component_not_false-refusal_rate"
    )
    assert "RoBERTa-large" in point.meta["source_metric_runtime"]
    with pytest.raises(
        ValueError, match="mllmguard_hallucination_truthfulness"
    ):
        validate_scored_source_metrics([point])


def test_jailbreakv_never_silently_downgrades_to_text_only(tmp_path: Path) -> None:
    source = tmp_path / "JailBreakV_28K.csv"
    source.write_text(
        "id,jailbreak_query,image_path\n1,unsafe request,\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusFormatError, match="required image_path"):
        JailBreakVConverter().parse(source)

    image = tmp_path / "probe.png"
    image.write_bytes(_PNG)
    source.write_text(
        f"id,jailbreak_query,image_path\n1,unsafe request,{image.name}\n",
        encoding="utf-8",
    )
    point = JailBreakVConverter().parse(source)[0]
    assert point.modalities == ["text", "image"]
    assert point.dialog_history[0].media == point.media
