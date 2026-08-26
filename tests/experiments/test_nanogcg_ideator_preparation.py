"""Focused regressions for attributable NanoGCG and IDEATOR preparation."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import framework_runtime_installer as runtime_installer
from experiments import ideator_vlbreakbench_prepare as ideator_prepare
from experiments import nanogcg_capture, run_matrix
from experiments.rig_web_app.builder_models import BuilderModelsMixin
from experiments.run_matrix import _select_corpus
from ura.adapters._engine_common import ExternalEngineConformanceError
from ura.adapters.base import AttackBudget
from ura.adapters.ideator import IDEATORAttacker
from ura.adapters.ideator_manifest import validate_manifest as validate_generic_ideator_manifest
from ura.adapters.nanogcg import NanoGCGAttacker
from ura.data_models import DataPoint, DialogTurn, RiskCategory
from ura.model_acquisition_runtime import build_runtime_plan


_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _datapoint(identifier: str, text: str) -> DataPoint:
    return DataPoint(
        id=identifier,
        source="advbench",
        modalities=["text"],
        dialog_history=[DialogTurn(role="user", content=text)],
        payload_text=text,
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _source_binding(
    *, source_id: str, source_text: str, split: str, index: int
) -> dict[str, object]:
    return {
        "source_id": source_id,
        "source_text_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "upstream_split": split,
        "upstream_index": index,
        "upstream_record_sha256": hashlib.sha256(
            f"{split}:{index}".encode("utf-8")
        ).hexdigest(),
        "upstream_image_path": (
            f"vlbreakbench_{split}/redteam_image_{index}.png"
        ),
    }


def _v2_manifest(image_paths: list[Path]) -> dict[str, object]:
    pairs: list[dict[str, object]] = []
    for (split, index), image in zip(
        ideator_prepare.EXPECTED_MATCHES, image_paths, strict=True
    ):
        pairs.append({
            "image_path": str(image),
            "image_sha256": hashlib.sha256(_PNG).hexdigest(),
            "source_id": ideator_prepare.ADVBENCH_SOURCE_ID,
            "source_text_sha256": ideator_prepare.ADVBENCH_SOURCE_TEXT_SHA256,
            "text": f"official mapped prompt {split} {index}",
            "upstream_image_path": (
                f"vlbreakbench_{split}/redteam_image_{index}.png"
            ),
            "upstream_index": index,
            "upstream_record_sha256": hashlib.sha256(
                f"record:{split}:{index}".encode("utf-8")
            ).hexdigest(),
            "upstream_split": split,
        })
    unsigned = {
        "dataset": ideator_prepare._official_dataset_descriptor(),
        "format_version": ideator_prepare.FORMAT_VERSION,
        "generator_source": ideator_prepare._generator_source_descriptor(),
        "runner_selection": ideator_prepare._runner_selection_descriptor(),
        "seed_pairs": pairs,
        "source_mapping": {
            "matched_records": 8,
            "matching_policy": "exact_utf8_query_v1",
            "official_records": 3654,
            "source_artifact": dict(ideator_prepare.ADVBENCH_ARTIFACT),
            "source_corpus": "advbench_harmful",
            "source_records": 520,
        },
    }
    return {
        **unsigned,
        "content_sha256": ideator_prepare.json_sha256(unsigned),
    }


def test_exact_whole_cluster_args_select_only_advbench_245() -> None:
    rows = [
        SimpleNamespace(id=f"advbench:{index}", meta={}) for index in range(520)
    ]
    selected, indices, clusters, _population = _select_corpus(
        "advbench_harmful", rows, 1, 105
    )
    assert indices == [245]
    assert clusters == ["advbench:245"]
    assert [row.id for row in selected] == ["advbench:245"]
    wrong, wrong_indices, _clusters, _population = _select_corpus(
        "advbench_harmful", rows, 1, 574
    )
    assert wrong_indices == [200]
    assert [row.id for row in wrong] == ["advbench:200"]


def test_ideator_v2_filters_pairs_by_exact_source_and_text(tmp_path: Path) -> None:
    current_text = "exact admitted source query"
    other_text = "different source query"
    images = []
    for index in range(3):
        image = tmp_path / f"pair-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    attacker = IDEATORAttacker(
        seed_pairs=[
            ("current pair one", str(images[0])),
            ("unrelated pair", str(images[1])),
            ("current pair two", str(images[2])),
        ],
        seed_pair_source_bindings=[
            _source_binding(
                source_id="advbench:245", source_text=current_text, split="base", index=720
            ),
            {
                **_source_binding(
                    source_id="advbench:999",
                    source_text=other_text,
                    split="custom",
                    index=721,
                ),
                "upstream_image_path": "images/alternate-721.png",
            },
            _source_binding(
                source_id="advbench:245",
                source_text=current_text,
                split="challenge",
                index=2160,
            ),
        ],
    )
    datapoint = _datapoint("advbench:245", current_text)
    budget = AttackBudget(max_queries=2, max_turns=2, seed=0)
    attempts = list(attacker.generate(datapoint, budget))
    assert [attempt.rendered_input[-1].content for attempt in attempts] == [
        "current pair one",
        "current pair two",
    ]
    assert all(attempt.params["mode"] == "source_mapped_seed_v2" for attempt in attempts)
    assert all(
        attempt.params["sampling_policy"] == "exact_source_ordered_prefix_v2"
        for attempt in attempts
    )
    assert [attempt.params["source_binding"]["upstream_index"] for attempt in attempts] == [
        720,
        2160,
    ]

    with pytest.raises(ExternalEngineConformanceError, match="differs"):
        attacker.plan_target_inputs(
            _datapoint("advbench:245", current_text + " mutated"), budget
        )


def test_vlbreakbench_license_is_separate_from_unlicensed_generator_source(
    tmp_path: Path,
) -> None:
    images = []
    for index in range(8):
        image = tmp_path / f"official-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    manifest = _v2_manifest(images)
    validated = ideator_prepare.validate_manifest(manifest)
    assert validated["dataset"]["license"] == "apache-2.0"
    assert validated["generator_source"]["license_declared"] is False
    assert validated["generator_source"]["license_spdx"] is None
    import ura.adapters.ideator as ideator_module

    assert "research licence" not in (ideator_module.__doc__ or "").lower()

    mutated = deepcopy(manifest)
    mutated["generator_source"]["commit"] = "9" * 40
    unsigned = {key: value for key, value in mutated.items() if key != "content_sha256"}
    mutated["content_sha256"] = ideator_prepare.json_sha256(unsigned)
    assert validate_generic_ideator_manifest(mutated) == mutated
    with pytest.raises(ValueError, match="campaign IDEATOR generator source"):
        ideator_prepare.validate_manifest(mutated)

    mutated = deepcopy(manifest)
    mutated["source_mapping"]["source_artifact"]["sha256"] = "b" * 64
    unsigned = {key: value for key, value in mutated.items() if key != "content_sha256"}
    mutated["content_sha256"] = ideator_prepare.json_sha256(unsigned)
    assert validate_generic_ideator_manifest(mutated) == mutated
    with pytest.raises(ValueError, match="campaign IDEATOR source artifact"):
        ideator_prepare.validate_manifest(mutated)

    mutated = deepcopy(manifest)
    mutated["dataset"]["revision"] = "8" * 40
    unsigned = {key: value for key, value in mutated.items() if key != "content_sha256"}
    mutated["content_sha256"] = ideator_prepare.json_sha256(unsigned)
    assert validate_generic_ideator_manifest(mutated) == mutated
    with pytest.raises(ValueError, match="campaign IDEATOR dataset release"):
        ideator_prepare.validate_manifest(mutated)

    mutated = deepcopy(manifest)
    mutated["seed_pairs"][0]["upstream_index"] = 721
    mutated["seed_pairs"][0]["upstream_image_path"] = (
        "vlbreakbench_base/redteam_image_721.png"
    )
    unsigned = {key: value for key, value in mutated.items() if key != "content_sha256"}
    mutated["content_sha256"] = ideator_prepare.json_sha256(unsigned)
    assert validate_generic_ideator_manifest(mutated) == mutated
    with pytest.raises(ValueError, match="campaign IDEATOR exact matched rows"):
        ideator_prepare.validate_manifest(mutated)


def test_builder_hands_v2_source_bindings_to_runner(tmp_path: Path) -> None:
    class Builder(BuilderModelsMixin):
        repo_root = tmp_path
        results_root = tmp_path

        @staticmethod
        def _split_list(raw: str) -> list[str]:
            return [item.strip() for item in raw.split(",") if item.strip()]

        @staticmethod
        def _canonical_json_bytes(value: object) -> bytes:
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    images = []
    for index in range(8):
        image = tmp_path / f"builder-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    manifest = _v2_manifest(images)
    manifest_path = tmp_path / "ideator-v2.json"
    raw = json.dumps(manifest, sort_keys=True).encode()
    manifest_path.write_bytes(raw)
    entries = Builder()._prepared_attacker_entries({
        "attackers": "ideator",
        "ideator_manifest": str(manifest_path),
        "ideator_manifest_sha": hashlib.sha256(raw).hexdigest(),
        "ideator_pair_limit": "0",
    })
    ideator = entries["ideator"]
    assert len(ideator["seed_pairs"]) == 8
    assert len(ideator["seed_pair_source_bindings"]) == 8
    assert {
        binding["source_id"] for binding in ideator["seed_pair_source_bindings"]
    } == {"advbench:245"}

    alternate = deepcopy(manifest)
    alternate["dataset"].update({
        "repo_id": "Example/AlternatePairs",
        "revision": "7" * 40,
        "license": "cc-by-4.0",
    })
    alternate["generator_source"].update({
        "repo": "https://example.invalid/ideator-fork",
        "commit": "6" * 40,
        "tree": "5" * 40,
    })
    alternate["runner_selection"] = {
        "corpus_name": "alternate_arm",
        "limit": 0,
        "sample_seed": 17,
        "selected_source_ids": ["alternate:1", "alternate:2"],
    }
    alternate["source_mapping"] = {
        "matched_records": 2,
        "matching_policy": "exact_utf8_query_v1",
        "official_records": 2,
        "source_artifact": {
            "bytes": 42,
            "file": "alternate.csv",
            "records": 2,
            "sha256": "4" * 64,
        },
        "source_corpus": "alternate_arm",
        "source_records": 2,
    }
    alternate["seed_pairs"] = [
        {
            **deepcopy(manifest["seed_pairs"][index]),
            "source_id": f"alternate:{index + 1}",
            "source_text_sha256": str(index + 1) * 64,
            "upstream_split": "custom",
            "upstream_index": index,
            "upstream_image_path": f"images/pair-{index}.png",
        }
        for index in range(2)
    ]
    unsigned = {key: value for key, value in alternate.items() if key != "content_sha256"}
    alternate["content_sha256"] = ideator_prepare.json_sha256(unsigned)
    assert validate_generic_ideator_manifest(alternate) == alternate
    with pytest.raises(ValueError, match="campaign IDEATOR"):
        ideator_prepare.validate_manifest(alternate)

    alternate_path = tmp_path / "ideator-alternate-v2.json"
    alternate_raw = json.dumps(alternate, sort_keys=True).encode()
    alternate_path.write_bytes(alternate_raw)
    alternate_entry = Builder()._prepared_attacker_entries({
        "attackers": "ideator",
        "ideator_manifest": str(alternate_path),
        "ideator_manifest_sha": hashlib.sha256(alternate_raw).hexdigest(),
        "ideator_pair_limit": "0",
    })["ideator"]
    assert [
        binding["source_id"]
        for binding in alternate_entry["seed_pair_source_bindings"]
    ] == ["alternate:1", "alternate:2"]


def _capture_inputs() -> tuple[SimpleNamespace, dict, dict, dict, dict]:
    args = SimpleNamespace(
        device="cuda:0",
        model_id=nanogcg_capture.MODEL_ID,
        model_revision=nanogcg_capture.MODEL_REVISION,
        torch_dtype="float16",
    )
    source = {
        "runner_selection": {
            "corpus_name": "advbench_harmful",
            "limit": 1,
            "sample_seed": 105,
            "selected_source_ids": ["advbench:245"],
        },
        "source_artifact": {"file": "source.csv", "sha256": "1" * 64},
        "source_row": {"datapoint_id": "advbench:245", "goal_sha256": "2" * 64},
    }
    gcg = {"num_steps": 20, "search_width": 64, "seed": 0, "topk": 64}
    framework = {"lock_id": "3" * 64, "version": "0.3.0"}
    project = {"revision_id": "project-revision-" + "4" * 24}
    return args, source, gcg, framework, project


def test_nanogcg_worker_derives_surrogate_plan_and_all_four_bindings() -> None:
    args, source, gcg, framework, project = _capture_inputs()
    selection = nanogcg_capture._runtime_selection(
        args,
        source=source,
        gcg_config=gcg,
        framework=framework,
        project=project,
    )
    plan = build_runtime_plan(selection)
    assert plan["resources"] == [{
        "file_policy": "complete_repository_snapshot",
        "repo_id": nanogcg_capture.MODEL_ID,
        "resource_id": plan["resources"][0]["resource_id"],
        "revision": nanogcg_capture.MODEL_REVISION,
        "roles": ["nanogcg_surrogate"],
    }]
    assert set(selection.input_bindings) == {
        "nanogcg_config",
        "nanogcg_framework_runtime",
        "nanogcg_project_revision",
        "nanogcg_source_row",
    }
    changed = deepcopy(source)
    changed["runner_selection"]["sample_seed"] = 106
    changed_selection = nanogcg_capture._runtime_selection(
        args,
        source=changed,
        gcg_config=gcg,
        framework=framework,
        project=project,
    )
    assert changed_selection.selection_sha256 != selection.selection_sha256


def test_nanogcg_runtime_receipt_resolves_an_adopted_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_root = tmp_path / "framework-envs"
    state_root = tmp_path / "framework-state"
    store_root = env_root / ".store"
    store_root.mkdir(parents=True)
    state_root.mkdir()
    entry = {
        "name": "nanogcg",
        "version": "0.3.0",
        "env_slug": "nanogcg-0.3.0-py312",
        "runtime": "python",
    }
    lock = {"lock_id": "b" * 64}
    adopted = store_root / f"{entry['env_slug']}-{'a' * 16}"
    adopted.mkdir()
    (env_root / entry["env_slug"]).symlink_to(
        Path(".store") / adopted.name, target_is_directory=True
    )
    receipt = runtime_installer._receipt(
        entry,
        lock,
        {"inventory_sha256": "c" * 64, "distribution_count": 1},
        {
            "schema": runtime_installer.CONTENT_SEAL_SCHEMA,
            "sha256": "d" * 64,
            "file_count": 1,
            "byte_count": 1,
        },
    )
    raw = runtime_installer._canonical_json(receipt)
    (adopted / runtime_installer.RECEIPT_NAME).write_bytes(raw)
    monkeypatch.setattr(nanogcg_capture, "verify_one", lambda *_args: None)
    monkeypatch.setattr(
        nanogcg_capture,
        "canonical_python_interpreter",
        lambda *_args: Path(nanogcg_capture.sys.executable),
    )
    args = SimpleNamespace(
        framework_env_root=str(env_root),
        framework_state_root=str(state_root),
    )

    _layout, binding = nanogcg_capture._verified_framework_runtime(
        args,
        lock=lock,
        framework={"entry": entry, "binding": {"lock_id": lock["lock_id"]}},
    )

    assert binding["receipt"] == receipt
    assert binding["receipt_sha256"] == hashlib.sha256(raw).hexdigest()
    assert not (store_root / f"{entry['env_slug']}-{lock['lock_id'][:16]}").exists()


def test_nanogcg_capture_rejects_a_stored_plan_other_than_its_derived_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, source, _gcg, framework_binding, project = _capture_inputs()
    framework = {"binding": framework_binding, "entry": {}}
    monkeypatch.setattr(nanogcg_capture, "_source_selection", lambda _args: source)
    monkeypatch.setattr(
        nanogcg_capture,
        "_project",
        lambda _args: ({"repository": {}}, project),
    )
    monkeypatch.setattr(
        nanogcg_capture,
        "_framework_binding",
        lambda _path: ({}, framework),
    )
    monkeypatch.setattr(
        nanogcg_capture,
        "_verified_framework_runtime",
        lambda *_args, **_kwargs: (object(), {}),
    )
    monkeypatch.setattr(nanogcg_capture, "load_plan", lambda *_args, **_kwargs: {})
    lock = Path(nanogcg_capture.__file__).with_name("framework_runtime_lock.json")
    argv = [
        "--source", "ignored.csv",
        "--framework-lock", str(lock),
        "--framework-env-root", str(tmp_path),
        "--framework-state-root", str(tmp_path),
        "--project-revision", "ignored.json",
        "--project-revision-sha256", "5" * 64,
        "--model-acquisition-plan", str(tmp_path / "plan.json"),
        "--model-acquisition-plan-sha256", "6" * 64,
        "--model-acquisition-receipt", str(tmp_path / "receipt.json"),
        "--model-acquisition-receipt-sha256", "7" * 64,
        "--model-acquisition-store", str(tmp_path),
        "--artifact-out", str(tmp_path / "capture.json"),
        "--attacker-config-out", str(tmp_path / "config.json"),
    ]
    with pytest.raises(ValueError, match="differs from the derived request"):
        nanogcg_capture.main(argv)


def test_nanogcg_capture_config_passes_runner_as_truthful_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("URA_PROJECT_REVISION_MANIFEST", raising=False)
    monkeypatch.delenv("URA_PROJECT_REVISION_SHA256", raising=False)
    selected_source_id = run_matrix.load_corpus("synth", 1)[0].id
    captured_target = "A deliberately non-default captured continuation"
    config = nanogcg_capture._replay_config(
        " attributable suffix",
        "8" * 64,
        captured_source_id=selected_source_id,
        captured_target=captured_target,
    )
    assert set(config["nanogcg"]) == {
        "captured_source_id",
        "captured_surrogate_id",
        "captured_surrogate_revision",
        "captured_target",
        "suffix",
        "suffix_source",
    }
    assert not ({"model_id", "model_revision"} & set(config["nanogcg"]))
    attacker = NanoGCGAttacker(**config["nanogcg"])
    attempt = list(attacker.generate(
        _datapoint(selected_source_id, "request"), AttackBudget()
    ))[0]
    assert attempt.params["surrogate_model_id"] == nanogcg_capture.MODEL_ID
    assert attempt.params["resolved_surrogate_revision"] == nanogcg_capture.MODEL_REVISION
    assert attempt.params["captured_source_id"] == selected_source_id
    assert attempt.params["target_continuation"] == captured_target

    config_path = tmp_path / "nanogcg-replay.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    assert run_matrix.main([
        "--dry-run",
        "--api", "mock",
        "--attackers", "nanogcg",
        "--attacker-config", str(config_path),
        "--judges", "rules",
        "--corpora", "synth",
        "--limit", "1",
        "--out", str(tmp_path / "run"),
    ]) == 0


def test_nanogcg_six_field_replay_shape_is_documented_exactly() -> None:
    config = nanogcg_capture._replay_config(
        " attributable suffix",
        "8" * 64,
        captured_source_id="advbench:245",
        captured_target="exact captured target",
    )["nanogcg"]
    expected = {
        "captured_source_id",
        "captured_surrogate_id",
        "captured_surrogate_revision",
        "captured_target",
        "suffix",
        "suffix_source",
    }
    assert set(config) == expected

    project = Path(__file__).parents[2]
    runbook = (project / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    section = runbook.split("#### NanoGCG: sealed suffix capture, then replay", 1)[
        1
    ].split("#### IDEATOR: exact VLBreakBench mapping, then Build or CLI replay", 1)[0]
    for field in expected:
        assert f'"{field}"' in section
    readme = " ".join((project / "README.md").read_text(encoding="utf-8").split())
    assert "six-field attacker config" in readme
    assert "four-field attacker config" not in readme


def test_ideator_cli_emits_create_only_ordinary_runner_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = []
    for index in range(8):
        image = tmp_path / f"cli-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    manifest = _v2_manifest(images)
    monkeypatch.setattr(
        ideator_prepare,
        "build_manifest",
        lambda **_kwargs: manifest,
    )
    manifest_path = tmp_path / "prepared" / "ideator-v2.json"
    config_path = tmp_path / "prepared" / "attacker-config.json"
    argv = [
        "--base-json", "unused-base.json",
        "--challenge-json", "unused-challenge.json",
        "--dataset-root", "unused-dataset",
        "--advbench", "unused-advbench.csv",
        "--prepared-image-dir", str(tmp_path / "prepared" / "images"),
        "--out", str(manifest_path),
        "--attacker-config-out", str(config_path),
    ]
    assert ideator_prepare.main(argv) == 0
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert set(config) == {"ideator"}
    assert set(config["ideator"]) == {
        "pair_limit",
        "seed_pair_image_digests",
        "seed_pair_manifest_sha256",
        "seed_pair_source_bindings",
        "seed_pairs",
    }
    assert config["ideator"]["pair_limit"] == 0
    assert len(config["ideator"]["seed_pairs"]) == 8
    assert config["ideator"]["seed_pair_manifest_sha256"] == hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    assert config["ideator"]["seed_pair_image_digests"] == [
        hashlib.sha256(_PNG).hexdigest()
    ] * 8
    assert "seed_pair_image_sha256" not in config["ideator"]
    loaded, descriptor = run_matrix._load_attacker_config(
        str(config_path),
        ["ideator"],
        hashlib.sha256(config_path.read_bytes()).hexdigest(),
    )
    assert loaded == config
    assert descriptor is not None
    attacker = IDEATORAttacker(**loaded["ideator"])
    images[0].write_bytes(_PNG + b"changed-after-preparation")
    with pytest.raises(ExternalEngineConformanceError, match="declared digest"):
        attacker.plan_target_inputs(
            _datapoint(ideator_prepare.ADVBENCH_SOURCE_ID, "irrelevant after drift"),
            AttackBudget(max_queries=8, max_turns=8, seed=0),
        )

    incomplete = deepcopy(config["ideator"])
    incomplete.pop("seed_pair_image_digests")
    with pytest.raises(ValueError, match="must be supplied together"):
        IDEATORAttacker(**incomplete)

    with pytest.raises(FileExistsError, match="existing manifest output"):
        ideator_prepare.main(argv)


def test_ideator_pair_limit_is_valid_for_every_mapped_source(tmp_path: Path) -> None:
    images = []
    for index in range(8):
        image = tmp_path / f"multi-source-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    manifest = _v2_manifest(images)
    manifest["runner_selection"]["selected_source_ids"] = [
        "advbench:245",
        "advbench:246",
    ]
    for pair in manifest["seed_pairs"][4:]:
        pair["source_id"] = "advbench:246"
    unsigned = {
        key: value for key, value in manifest.items() if key != "content_sha256"
    }
    manifest["content_sha256"] = ideator_prepare.json_sha256(unsigned)

    with pytest.raises(ValueError, match="inventory for a selected source row"):
        ideator_prepare.materialize_runner_attacker_config(
            manifest,
            manifest_sha256="a" * 64,
            pair_limit=5,
        )
    config = ideator_prepare.materialize_runner_attacker_config(
        manifest,
        manifest_sha256="a" * 64,
        pair_limit=4,
    )
    assert config["ideator"]["pair_limit"] == 4


def test_ideator_nonzero_pair_limit_requires_config_output(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires --attacker-config-out"):
        ideator_prepare.main([
            "--base-json", "unused-base.json",
            "--challenge-json", "unused-challenge.json",
            "--dataset-root", "unused-dataset",
            "--advbench", "unused-advbench.csv",
            "--prepared-image-dir", str(tmp_path / "images"),
            "--out", str(tmp_path / "manifest.json"),
            "--pair-limit", "1",
        ])


def test_ideator_failed_write_preserves_foreign_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "race.json"
    original_open = Path.open

    class RacingHandle:
        def __init__(self, handle: object) -> None:
            self.handle = handle

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *_args: object) -> None:
            self.handle.close()

        def fileno(self) -> int:
            return self.handle.fileno()

        def write(self, _payload: bytes) -> None:
            target.unlink()
            with original_open(target, "wb") as replacement:
                replacement.write(b"foreign replacement")
            raise OSError("simulated write failure")

    def racing_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
        handle = original_open(path, mode, *args, **kwargs)
        return RacingHandle(handle) if path == target and mode == "xb" else handle

    monkeypatch.setattr(Path, "open", racing_open)
    with pytest.raises(OSError, match="simulated write failure"):
        ideator_prepare._write_create_only(target, b"owned output")
    assert target.read_bytes() == b"foreign replacement"


def test_ideator_second_output_failure_preserves_replaced_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    images = []
    for index in range(8):
        image = tmp_path / f"outer-race-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    monkeypatch.setattr(
        ideator_prepare,
        "build_manifest",
        lambda **_kwargs: _v2_manifest(images),
    )
    manifest_path = tmp_path / "manifest.json"
    config_path = tmp_path / "config.json"
    actual_write = ideator_prepare._write_create_only
    writes = 0

    def racing_write(path: Path, payload: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 1:
            actual_write(path, payload)
            path.unlink()
            path.write_bytes(b"foreign replacement")
            return
        raise OSError("simulated config failure")

    monkeypatch.setattr(ideator_prepare, "_write_create_only", racing_write)
    with pytest.raises(OSError, match="simulated config failure"):
        ideator_prepare.main([
            "--base-json", "unused-base.json",
            "--challenge-json", "unused-challenge.json",
            "--dataset-root", "unused-dataset",
            "--advbench", "unused-advbench.csv",
            "--prepared-image-dir", str(tmp_path / "prepared-images"),
            "--out", str(manifest_path),
            "--attacker-config-out", str(config_path),
        ])
    assert manifest_path.read_bytes() == b"foreign replacement"


def test_ideator_build_uses_shared_v2_materialization_and_pair_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import experiments.rig_web_app.builder_models as builder_models

    images = []
    for index in range(8):
        image = tmp_path / f"shared-{index}.png"
        image.write_bytes(_PNG)
        images.append(image)
    manifest = _v2_manifest(images)
    manifest_path = tmp_path / "shared-v2.json"
    manifest_raw = json.dumps(manifest, sort_keys=True).encode("utf-8")
    manifest_path.write_bytes(manifest_raw)

    class Builder(BuilderModelsMixin):
        repo_root = tmp_path
        results_root = tmp_path

        @staticmethod
        def _split_list(raw: str) -> list[str]:
            return [item.strip() for item in raw.split(",") if item.strip()]

        @staticmethod
        def _canonical_json_bytes(value: object) -> bytes:
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    called = 0
    shared = builder_models.materialize_runner_attacker_config

    def observed(*args: object, **kwargs: object):  # noqa: ANN202
        nonlocal called
        called += 1
        return shared(*args, **kwargs)

    monkeypatch.setattr(
        builder_models,
        "materialize_runner_attacker_config",
        observed,
    )
    entry = Builder()._prepared_attacker_entries({
        "attackers": "ideator",
        "ideator_manifest": str(manifest_path),
        "ideator_manifest_sha": hashlib.sha256(manifest_raw).hexdigest(),
        "ideator_pair_limit": "3",
    })["ideator"]
    assert called == 1
    assert entry["pair_limit"] == 3
    assert len(entry["seed_pairs"]) == 8


def test_ideator_and_t3mp3st_runbook_paths_are_executable_not_placeholders() -> None:
    project = Path(__file__).parents[2]
    runbook = (project / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    ideator = runbook.split(
        "#### IDEATOR: exact VLBreakBench mapping, then Build or CLI replay",
        1,
    )[1].split("#### T3MP3ST: capture, then replay", 1)[0]
    assert "<exact VLBreakBench snapshot root>" not in ideator
    assert "hf download wang021/VLBreakBench --repo-type dataset" in ideator
    assert ideator_prepare.DATASET_REVISION in ideator
    assert "--attacker-config-out \"$URA_IDEATOR_ATTACKER_CONFIG\"" in ideator
    assert "--pair-limit 0" in ideator
    assert "--attacker-config-sha256" in ideator
    assert "path-free manifest SHA-256" in ideator
    assert "one declared digest per image" in ideator

    t3mp3st = runbook.split("#### T3MP3ST: capture, then replay", 1)[1].split(
        "#### HarmBench: capture, then replay",
        1,
    )[0]
    assert "verify_receipt_snapshots" in t3mp3st
    assert "'$URA_T3_VLLM_BIN' serve '$URA_T3_QWEN_SNAPSHOT'" in t3mp3st
    assert "--served-model-name Qwen/Qwen3-VL-8B-Instruct" in t3mp3st
    assert "tmux new-session -d -s \"$URA_T3_VLLM_SESSION\"" in t3mp3st
    for session in ("URA_T3_VLLM_SESSION", "URA_T3_SESSION"):
        probe = f'tmux has-session -t "${session}" 2>/dev/null'
        assert f"if {probe}; then" in t3mp3st
        assert f"{probe} || exit 1" in t3mp3st
        assert f"{probe} || \\\n  tmux new-session" not in t3mp3st
    assert "Refusing to reuse existing session" in t3mp3st
    assert "Refusing to reuse an existing listener" in t3mp3st
    assert "served model identity mismatch" in t3mp3st
