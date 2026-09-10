from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from experiments import run_matrix
from ura.model_acquisition import ModelAcquisitionError, hub_requirement
from ura.model_acquisition_runtime import (
    ModelRequirementSet,
    build_runtime_selection,
    validate_model_acquisition_role_projection,
    validate_runtime_plan,
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
        "--target-answer-retries",
        "0",
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


def _guardrail_preflight_plan_args(
    tmp_path: Path,
    project_revision_args: list[str],
) -> list[str]:
    return [
        "--preflight-only",
        *project_revision_args,
        "--api",
        "mock",
        "--target-answer-retries",
        "0",
        "--attackers",
        "replay",
        "--judges",
        "guardrail",
        "--guardrail-model",
        "Org/Guardrail",
        "--guardrail-revision",
        REVISION,
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


def test_plan_only_rejects_live_nanogcg_before_plan_or_admission(
    tmp_path: Path,
    project_revision_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _nano_config(tmp_path / "attackers.json")
    private_plans = (tmp_path / "private-plans").resolve()
    private_plans.mkdir()
    calls = _forbid_component_constructors(monkeypatch)
    admissions: list[str] = []

    def reject_admission(*_args, **_kwargs):
        admissions.append("called")
        raise AssertionError("live NanoGCG must fail before acquisition planning")

    monkeypatch.setattr(run_matrix, "collect_run_requirements", reject_admission)

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

    assert result == 1
    assert calls == []
    assert admissions == []
    assert list(private_plans.iterdir()) == []
    errors = list((tmp_path / "run").glob("*.request.error.json"))
    assert errors
    payload = json.loads(errors[-1].read_text(encoding="utf-8"))
    assert payload["failure"]["phase"] == "configuration_preflight"


def test_plan_only_rejects_nanogcg_live_model_fields_with_suffix_before_admission(
    tmp_path: Path,
    project_revision_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _nano_config(tmp_path / "attackers.json", suffix=" sealed suffix")
    private_plans = (tmp_path / "private-plans").resolve()
    private_plans.mkdir()
    calls = _forbid_component_constructors(monkeypatch)
    admissions: list[str] = []

    def reject_admission(*_args, **_kwargs):
        admissions.append("called")
        raise AssertionError("NanoGCG replay metadata must not enter acquisition")

    monkeypatch.setattr(run_matrix, "collect_run_requirements", reject_admission)

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

    assert result == 1
    assert calls == []
    assert admissions == []
    assert list(private_plans.iterdir()) == []
    errors = list((tmp_path / "run").glob("*.request.error.json"))
    assert errors
    payload = json.loads(errors[-1].read_text(encoding="utf-8"))
    assert payload["failure"]["phase"] == "configuration_preflight"


@pytest.mark.parametrize("failure", ["missing", "tampered"])
def test_receipt_admission_failure_has_zero_component_constructors(
    tmp_path: Path,
    project_revision_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    private_plans = (tmp_path / "private-plans").resolve()
    private_plans.mkdir()
    base_args = _guardrail_preflight_plan_args(tmp_path, project_revision_args)
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


def test_plan_only_preserves_canary_purpose_and_rejects_preflight_plan(
    tmp_path: Path,
    project_revision_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _forbid_component_constructors(monkeypatch)
    common = [
        *project_revision_args,
        "--api",
        "mock",
        "--target-answer-retries",
        "0",
        "--attackers",
        "replay",
        "--judges",
        "guardrail",
        "--guardrail-model",
        "Org/Guardrail",
        "--guardrail-revision",
        REVISION,
        "--corpora",
        "synth",
        "--limit",
        "1",
        "--sample-seed",
        "0",
        "--seeds",
        "0",
        "--max-queries",
        "1",
        "--max-turns",
        "1",
        "--max-total-target-calls",
        "1",
        "--max-total-judge-calls",
        "1",
        "--max-total-http-attempts",
        "1",
        "--deadline-seconds",
        "60",
    ]

    def derive(name: str, purpose_args: list[str]) -> tuple[dict, dict, Path]:
        private_plans = (tmp_path / f"{name}-plans").resolve()
        private_plans.mkdir()
        out = (tmp_path / f"{name}-run").resolve()
        assert run_matrix.main([
            *purpose_args,
            *common,
            "--model-acquisition-plan-only",
            "--model-acquisition-plan-dir",
            str(private_plans),
            "--out",
            str(out),
        ]) == 0
        plan_path = next(private_plans.glob("*.plan.json"))
        envelope_path = next(out.glob("*.request-envelope.json"))
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        assert plan["bindings"]["request_envelope_sha256"] == hashlib.sha256(
            envelope_path.read_bytes()
        ).hexdigest()
        return plan, envelope, plan_path

    canary_plan, canary_envelope, _canary_path = derive(
        "canary",
        [
            "--diagnostic-canary",
            "--execution-scope-id",
            "test-scope",
            "--live-attestation-max-age-hours",
            "1",
        ],
    )
    preflight_plan, preflight_envelope, _preflight_path = derive(
        "preflight",
        ["--preflight-only"],
    )

    assert calls == []
    assert canary_envelope["request"]["execution_purpose"] == "diagnostic_canary"
    assert preflight_envelope["request"]["execution_purpose"] == "preflight_only"
    assert (
        canary_plan["bindings"]["request_envelope_sha256"]
        != preflight_plan["bindings"]["request_envelope_sha256"]
    )
    assert canary_plan["plan_id"] != preflight_plan["plan_id"]

    canary_selection = build_runtime_selection(
        ModelRequirementSet(
            tuple(
                hub_requirement(role, resource["repo_id"], resource["revision"])
                for resource in canary_plan["resources"]
                for role in resource["roles"]
            ),
            (),
        ),
        input_bindings={
            key: value
            for key, value in canary_plan["bindings"].items()
            if key != "selection_sha256"
        },
    )
    assert (
        canary_selection.selection_sha256
        == canary_plan["bindings"]["selection_sha256"]
    )
    assert validate_runtime_plan(canary_plan, selection=canary_selection) == canary_plan
    with pytest.raises(
        ModelAcquisitionError,
        match="resources or immutable selection bindings differ",
    ):
        validate_runtime_plan(preflight_plan, selection=canary_selection)


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


def test_private_ideator_images_are_child_owned_across_console_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
        "+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
    artifact_dir = tmp_path / ".private-attacker-artifacts"
    artifact_dir.mkdir()
    image_digest = hashlib.sha256(png).hexdigest()
    private_image = artifact_dir / (
        f"selected-ideator-image-0000-{image_digest[:24]}-{'2' * 16}.json"
    )
    private_image.write_bytes(png)
    external_image = tmp_path / "operator-image.png"
    external_image.write_bytes(png)

    payload = {
        "ideator": {
            "seed_pairs": [
                ["private pair", str(private_image.resolve())],
                ["operator pair", str(external_image.resolve())],
            ],
            "seed_pair_image_sha256": [image_digest, image_digest],
        }
    }
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    config_dir = tmp_path / ".private-attacker-configs"
    config_dir.mkdir()
    config = config_dir / f"selected-attacker-{digest[:24]}-{'3' * 16}.json"
    config.write_bytes(raw)
    monkeypatch.setenv(
        "URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG", str(config.resolve())
    )
    registered: list[tuple[object, tuple[object, ...]]] = []
    monkeypatch.setattr(
        run_matrix.atexit,
        "register",
        lambda callback, *args: registered.append((callback, args)),
    )

    loaded, artifact = run_matrix._load_attacker_config(
        str(config.resolve()), ["ideator"], digest
    )

    assert not config.exists()
    assert loaded["ideator"]["seed_pairs"][0][1] == str(private_image.resolve())
    assert artifact is not None and str(tmp_path) not in json.dumps(artifact)
    assert len(registered) == 1
    callback, args = registered[0]
    callback(*args)
    assert not private_image.exists()
    assert external_image.read_bytes() == png


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
