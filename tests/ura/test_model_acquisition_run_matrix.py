from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from experiments import run_matrix
from ura.model_acquisition import load_plan
from ura.model_acquisition_runtime import (
    validate_model_acquisition_role_projection,
)


REVISION = "a" * 40


def _nano_config(path: Path, *, suffix: str | None = None) -> Path:
    config: dict[str, object] = {
        "model_id": "Org/Surrogate",
        "model_revision": REVISION,
    }
    if suffix is not None:
        config.update({"suffix": suffix, "suffix_source": "fixture"})
    path.write_text(
        json.dumps({"nanogcg": config}),
        encoding="utf-8",
    )
    return path


def _preflight_plan_args(
    tmp_path: Path,
    project_revision_args: list[str],
    *,
    attacker_config: Path,
) -> list[str]:
    return [
        "--preflight-only",
        *project_revision_args,
        "--api",
        "mock",
        "--attackers",
        "nanogcg",
        "--attacker-config",
        str(attacker_config),
        "--judges",
        "rules",
        "--corpora",
        "synth",
        "--limit",
        "1",
        "--out",
        str(tmp_path / "run"),
    ]


def _forbid_component_constructors(
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    calls: list[str] = []

    def reject(name: str):
        def blocked(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"{name} constructor must not run")

        return blocked

    monkeypatch.setattr(run_matrix, "get_attacker", reject("attacker"))
    monkeypatch.setattr(run_matrix, "build_target", reject("target"))
    monkeypatch.setattr(run_matrix, "build_judges", reject("judges"))
    return calls


def test_plan_only_writes_exact_plan_before_any_component_constructor(
    tmp_path: Path,
    project_revision_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _nano_config(tmp_path / "attackers.json")
    private_plans = (tmp_path / "private-plans").resolve()
    private_plans.mkdir()
    calls = _forbid_component_constructors(monkeypatch)

    result = run_matrix.main([
        *_preflight_plan_args(
            tmp_path,
            project_revision_args,
            attacker_config=config,
        ),
        "--model-acquisition-plan-only",
        "--model-acquisition-plan-dir",
        str(private_plans),
    ])

    assert result == 0
    assert calls == []
    plan_path = next(private_plans.glob("*.plan.json"))
    plan = load_plan(
        plan_path,
        expected_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
    )
    assert plan["resources"][0]["roles"] == ["nanogcg_surrogate"]
    assert plan["resources"][0]["repo_id"] == "Org/Surrogate"
    assert "launch_ticket_sha256" not in plan["bindings"]
    assert "source_config_sha256" in plan["bindings"]
    assert "source_conformance_sha256" in plan["bindings"]


@pytest.mark.parametrize("failure", ["missing", "tampered"])
def test_receipt_admission_failure_has_zero_component_constructors(
    tmp_path: Path,
    project_revision_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    config = _nano_config(tmp_path / "attackers.json")
    private_plans = (tmp_path / "private-plans").resolve()
    private_plans.mkdir()
    base_args = _preflight_plan_args(
        tmp_path,
        project_revision_args,
        attacker_config=config,
    )
    assert run_matrix.main([
        *base_args,
        "--model-acquisition-plan-only",
        "--model-acquisition-plan-dir",
        str(private_plans),
    ]) == 0
    plan_path = next(private_plans.glob("*.plan.json"))
    plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    store = (tmp_path / "managed-store").resolve()
    store.mkdir()
    receipt = (tmp_path / "private-receipt.json").resolve()
    if failure == "tampered":
        receipt.write_text("{}\n", encoding="utf-8")
        receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
    else:
        receipt_sha = "0" * 64
    calls = _forbid_component_constructors(monkeypatch)

    result = run_matrix.main([
        *base_args,
        "--model-acquisition-plan",
        str(plan_path.resolve()),
        "--model-acquisition-plan-sha256",
        plan_sha,
        "--model-acquisition-receipt",
        str(receipt),
        "--model-acquisition-receipt-sha256",
        receipt_sha,
        "--model-acquisition-store",
        str(store),
    ])

    assert result == 1
    assert calls == []
    errors = list((tmp_path / "run").glob("*.request.error.json"))
    assert errors
    payload = json.loads(errors[-1].read_text(encoding="utf-8"))
    assert payload["failure"]["phase"] == "model_acquisition_admission"


def test_dry_run_rejects_live_nanogcg_before_plan_or_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _nano_config(tmp_path / "attackers.json")
    private_plans = (tmp_path / "private-plans").resolve()
    private_plans.mkdir()
    calls = _forbid_component_constructors(monkeypatch)
    monkeypatch.setenv("HF_TOKEN", "must-not-survive")
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "must-not-survive")

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
        "--model-acquisition-plan-only",
        "--model-acquisition-plan-dir",
        str(private_plans),
        "--out",
        str(tmp_path / "dry"),
    ])

    assert result == 1
    assert calls == []
    assert list(private_plans.iterdir()) == []
    assert "HF_TOKEN" not in os.environ
    assert "HUGGING_FACE_HUB_TOKEN" not in os.environ


def test_ordinary_dry_run_never_enters_hf_admission_and_emits_empty_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admissions: list[str] = []
    before_hf_modules = {
        name for name in sys.modules if name.startswith("huggingface_hub")
    }

    def forbidden_admission(*_args, **_kwargs):
        admissions.append("called")
        raise AssertionError("dry-run must not admit a Hugging Face runtime")

    monkeypatch.setattr(
        run_matrix,
        "admit_managed_model_runtime",
        forbidden_admission,
    )
    monkeypatch.setenv("HF_TOKEN", "must-be-removed")
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "must-be-removed")
    out = tmp_path / "dry"
    assert run_matrix.main([
        "--dry-run",
        "--attackers",
        "replay",
        "--judges",
        "rules",
        "--corpora",
        "synth",
        "--limit",
        "1",
        "--out",
        str(out),
    ]) == 0

    assert admissions == []
    assert "HF_TOKEN" not in os.environ
    assert "HUGGING_FACE_HUB_TOKEN" not in os.environ
    assert {
        name for name in sys.modules if name.startswith("huggingface_hub")
    } == before_hf_modules
    grid = json.loads(next(out.glob("*.grid.json")).read_text(encoding="utf-8"))
    assert grid["request"]["model_acquisition"]["status"] == "not_required"
    assert grid["request"]["model_acquisition_execution"]["selection"][
        "resources"
    ] == []
    manifest = json.loads(
        next(out.glob("*.manifest.json")).read_text(encoding="utf-8")
    )
    projection = validate_model_acquisition_role_projection(
        manifest["config"]["run"]["model_acquisition"]
    )
    assert projection["scope"] == "cell"
    assert projection["resources"] == []
    assert projection["exceptions"] == []


def test_real_source_arm_cannot_be_reclassified_as_synthetic(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "source-instances.json"
    registry.write_text(
        json.dumps({
            "harmbench_text": {"converter": "synth", "synth": True}
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cannot be reclassified as synthetic"):
        run_matrix._load_source_config(str(registry), ["harmbench_text"])

    with pytest.raises(ValueError, match="requires an explicit --source-config"):
        run_matrix._load_source_config("", ["harmbench_text"])


def test_persisted_model_error_scrubs_case_separator_json_and_uri_paths(
    tmp_path: Path,
) -> None:
    checkpoint = (tmp_path / "Private Checkpoint" / "Model").resolve()
    spec = "vllm:" + str(checkpoint)
    digest = "e" * 64
    persisted = "vllm:local-checkpoint@sha256:" + digest
    spellings = [
        str(checkpoint).swapcase(),
        str(checkpoint).replace("\\", "/").swapcase(),
        json.dumps(str(checkpoint), ensure_ascii=False)[1:-1].swapcase(),
        checkpoint.as_uri().swapcase(),
    ]

    rendered = run_matrix._artifact_safe_model_error(
        RuntimeError(" | ".join(spellings)),
        spec,
        persisted,
    )

    assert rendered.count("local-checkpoint@sha256:" + digest) == len(spellings)
    for spelling in spellings:
        assert spelling.casefold() not in rendered.casefold()


@pytest.mark.parametrize(
    ("kind", "directory", "prefix", "environment", "loader"),
    [
        (
            "source",
            ".private-source-configs",
            "source",
            "URA_PRIVATE_TRANSIENT_SOURCE_CONFIG",
            "source",
        ),
        (
            "attacker",
            ".private-attacker-configs",
            "attacker",
            "URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG",
            "attacker",
        ),
    ],
)
def test_private_source_and_attacker_configs_are_exact_read_once_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    directory: str,
    prefix: str,
    environment: str,
    loader: str,
) -> None:
    payload = (
        {"synth": {"converter": "synth", "synth": True}}
        if kind == "source"
        else {"replay": {}}
    )
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    private_dir = tmp_path / directory
    private_dir.mkdir()
    path = private_dir / f"selected-{prefix}-{digest[:24]}-{'1' * 16}.json"
    path.write_bytes(raw)
    monkeypatch.setenv(environment, str(path.resolve()))

    if loader == "source":
        _config, artifact = run_matrix._load_source_config(
            str(path.resolve()), ["synth"], digest
        )
    else:
        _config, artifact = run_matrix._load_attacker_config(
            str(path.resolve()), ["replay"], digest
        )

    assert not path.exists()
    assert artifact is not None
    assert artifact["sha256"] == digest
    assert str(tmp_path) not in json.dumps(artifact)


def test_content_addressed_json_rejects_same_size_inode_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = (tmp_path / "approved.json").resolve()
    replacement = (tmp_path / "replacement.json").resolve()
    approved = b'{"value":"a"}\n'
    substituted = b'{"value":"b"}\n'
    assert len(approved) == len(substituted)
    source.write_bytes(approved)
    replacement.write_bytes(substituted)
    expected = hashlib.sha256(approved).hexdigest()
    real_open = run_matrix.os.open
    swapped = False

    def swap_before_open(path, flags, *args, **kwargs):  # noqa: ANN001
        nonlocal swapped
        if Path(path) == source and not swapped:
            swapped = True
            replacement.replace(source)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(run_matrix.os, "open", swap_before_open)
    with pytest.raises(ValueError, match="changed while it was opened"):
        run_matrix._read_content_addressed_json(
            str(source),
            expected,
            flag_name="--approved",
            max_bytes=4096,
        )
    assert swapped is True


def test_content_addressed_read_and_retention_reject_hardlinks(
    tmp_path: Path,
) -> None:
    payload = b'{"approved":true}\n'
    digest = hashlib.sha256(payload).hexdigest()
    source = (tmp_path / "approved.json").resolve()
    source.write_bytes(payload)
    alias = tmp_path / "approved-alias.json"
    os.link(source, alias)

    with pytest.raises(ValueError, match="one regular file"):
        run_matrix._read_content_addressed_json(
            str(source),
            digest,
            flag_name="--approved",
            max_bytes=4096,
        )
    with pytest.raises(ValueError, match="one regular file"):
        run_matrix._retain_content_addressed_input(
            tmp_path,
            str(source),
            digest,
            stem="approved",
        )

    alias.unlink()
    value, descriptor = run_matrix._read_content_addressed_json(
        str(source),
        digest,
        flag_name="--approved",
        max_bytes=4096,
    )
    assert value == {"approved": True}
    assert descriptor == {
        "file": source.name,
        "sha256": digest,
        "bytes": len(payload),
    }

    out = tmp_path / "return"
    out.mkdir()
    retained = run_matrix._retain_content_addressed_bytes(
        out,
        payload,
        digest,
        stem="approved",
    )
    assert retained.parent == out.resolve()
    assert retained.read_bytes() == payload
    assert retained.lstat().st_nlink == 1

    retained_alias = tmp_path / "retained-alias.json"
    os.link(retained, retained_alias)
    with pytest.raises(ValueError, match="one regular file"):
        run_matrix._retain_content_addressed_bytes(
            out,
            payload,
            digest,
            stem="approved",
        )


def test_content_addressed_partial_create_removes_only_its_exact_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"approved":true}\n'
    digest = hashlib.sha256(payload).hexdigest()
    out = tmp_path / "return"
    out.mkdir()
    destination = out / f"approved-{digest[:24]}.json"

    def fail_sync(_descriptor: int) -> None:
        raise OSError("injected fsync failure")

    monkeypatch.setattr(run_matrix.os, "fsync", fail_sync)
    with pytest.raises(ValueError, match="cannot be retained"):
        run_matrix._retain_content_addressed_bytes(
            out,
            payload,
            digest,
            stem="approved",
        )
    assert not destination.exists()
