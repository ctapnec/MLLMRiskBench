from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from experiments.local_campaign import generate as controller_generate
from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    EXTERNAL_BINDINGS,
    LEGACY_A05_EXTERNAL_BINDINGS,
    MAX_PHASE3_DOWNLOAD_BYTES,
    PHASE3_BINDINGS_ADDED_AFTER_A05,
    PRE_RR_EXTERNAL_BINDINGS,
    RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719,
    ControllerGenerationError,
    external_binding_keys_from_templates,
    render_controller_set,
    validate_binding_document,
    verify_controller_set,
)
from experiments.local_campaign.rebind import (
    MIGRATION_REVISION_BINDINGS,
    main as rebind_main,
)


def _valid_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for index, key in enumerate(sorted(EXTERNAL_BINDINGS), start=1001):
        if key == "EXPECTED_COMMIT":
            value = "1" * 40
        elif key == "PHASE3_DOWNLOADED_BYTES":
            value = "0"
        elif key.endswith("_BYTES"):
            value = str(index)
        elif key.endswith("SHA256"):
            value = "2" * 64
        elif key.endswith("_TAG"):
            value = "20260822T120000Z"
        elif key == "CONTROLLER_INSTALL_ROOT":
            value = "/home/ura/.ura-controller-active"
        elif key == "PROJECT_ROOT":
            value = "/home/ura/MLLMRiskBench"
        elif key == "WORK_ROOT":
            value = "/mnt/stor/data/ura-work"
        elif key.endswith("_ROOT"):
            value = f"/mnt/stor/data/ura-work/runs/engineering/{key.lower()}"
        elif key.endswith("_PATH"):
            value = f"/bound/{key.lower()}.json"
        elif key.endswith("_NAME"):
            value = f"{key.lower()}.json"
        else:  # pragma: no cover - the explicit schema must classify every key
            raise AssertionError(f"test fixture has no semantic value for {key}")
        values[key] = value
    return values


def _document(values: dict[str, str] | None = None) -> dict[str, object]:
    return {"schema": BINDINGS_SCHEMA, "values": values or _valid_values()}


def _write_document(path: Path, values: dict[str, str]) -> Path:
    path.write_text(json.dumps(_document(values)), encoding="utf-8")
    return path


def test_external_binding_inventory_is_exact_and_reviewed() -> None:
    assert external_binding_keys_from_templates() == EXTERNAL_BINDINGS
    assert len(EXTERNAL_BINDINGS) == 58
    assert len(PRE_RR_EXTERNAL_BINDINGS) == 54

    missing = _valid_values()
    missing.pop("PHASE3_REQUEST_BYTES")
    with pytest.raises(ControllerGenerationError, match="missing=.*PHASE3_REQUEST_BYTES"):
        validate_binding_document(_document(missing))

    extra = _valid_values()
    extra["UNREVIEWED_SHELL_FRAGMENT"] = "safe-looking"
    with pytest.raises(ControllerGenerationError, match="extra=.*UNREVIEWED_SHELL_FRAGMENT"):
        validate_binding_document(_document(extra))


@pytest.mark.parametrize(
    ("marker", "message"),
    (
        ("@@UNREVIEWED_MARKER@@", "template binding inventory differs"),
        ("@@not-a-valid-marker@@", "unresolved template marker"),
    ),
)
def test_unknown_or_malformed_template_markers_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker: str,
    message: str,
) -> None:
    source_templates = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    mutated_templates = tmp_path / "templates"
    shutil.copytree(source_templates, mutated_templates)
    target = mutated_templates / "launch_chain.sh.in"
    target.write_text(
        target.read_text(encoding="utf-8") + f"\n# {marker}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(controller_generate, "_template_dir", lambda: mutated_templates)
    bindings = _write_document(tmp_path / "bindings.json", _valid_values())
    with pytest.raises(ControllerGenerationError, match=message):
        render_controller_set(bindings, tmp_path / "render")


def test_malformed_support_template_marker_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_templates = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    mutated_templates = tmp_path / "templates"
    shutil.copytree(source_templates, mutated_templates)
    target = mutated_templates / "verify_controller_set.sh.in"
    target.write_text(
        target.read_text(encoding="utf-8") + "\n# @@bad-support-marker@@\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(controller_generate, "_template_dir", lambda: mutated_templates)
    values = _valid_values()
    rendered, _ = controller_generate._render_all(values)
    with pytest.raises(ControllerGenerationError, match="support-template marker"):
        controller_generate._render_support(
            "verify_controller_set.sh.in",
            values,
            rendered,
            {
                "INVENTORY_NAME": "controller-inventory.tsv",
                "INVENTORY_SHA256": "3" * 64,
                "INVENTORY_BYTES": "1",
            },
        )


def test_binding_values_reject_shell_python_and_control_injection() -> None:
    unsafe = "\"'`$;|&<>(){}[]*?!\\\n\r\t\x01\x7f"
    for character in unsafe:
        values = _valid_values()
        values["HISTORICAL_PROMPT_PROJECT_NAME"] = f"safe{character}name.json"
        with pytest.raises(ControllerGenerationError, match="unsafe|basename"):
            validate_binding_document(_document(values))

    values = _valid_values()
    values["PROJECT_ROOT"] = "/home/ura/ok';touch/tmp/injected"
    with pytest.raises(ControllerGenerationError, match="unsafe"):
        validate_binding_document(_document(values))


@pytest.mark.parametrize(
    "path",
    (
        "relative/path",
        "/home/ura/../escape",
        "/home/ura/./project",
        "/home//ura/project",
        "//home/ura/project",
        "/home/ura/project/",
        "/",
    ),
)
def test_binding_paths_are_canonical_absolute_posix(path: str) -> None:
    values = _valid_values()
    values["PROJECT_ROOT"] = path
    with pytest.raises(ControllerGenerationError, match="canonical absolute POSIX path|unsafe"):
        validate_binding_document(_document(values))


def test_controller_install_root_is_the_atomic_active_link() -> None:
    values = _valid_values()
    values["CONTROLLER_INSTALL_ROOT"] = "/home/ura"
    with pytest.raises(ControllerGenerationError, match=".ura-controller-active"):
        validate_binding_document(_document(values))


@pytest.mark.parametrize(
    "tag",
    (
        "20260230T120000Z",
        "20261301T120000Z",
        "20260822T246000Z",
        "20260822T120060Z",
        "20260822-120000Z",
    ),
)
def test_binding_tags_are_real_utc_datetimes(tag: str) -> None:
    values = _valid_values()
    values["PHASE3_GUARD_TAG"] = tag
    with pytest.raises(ControllerGenerationError, match="UTC campaign tag|real UTC datetime"):
        validate_binding_document(_document(values))


@pytest.mark.parametrize("size", ("0", "01", "-1", "+1", "1_0", "1.0"))
def test_artifact_byte_bindings_are_canonical_positive_integers(size: str) -> None:
    values = _valid_values()
    values["PHASE3_REQUEST_BYTES"] = size
    with pytest.raises(ControllerGenerationError, match="canonical positive integer|unsafe"):
        validate_binding_document(_document(values))


@pytest.mark.parametrize(
    "size",
    ("00", "01", "-1", str(MAX_PHASE3_DOWNLOAD_BYTES + 1)),
)
def test_downloaded_bytes_are_canonical_nonnegative_and_capped(size: str) -> None:
    values = _valid_values()
    values["PHASE3_DOWNLOADED_BYTES"] = size
    with pytest.raises(ControllerGenerationError, match="canonical nonnegative|8 GiB|unsafe"):
        validate_binding_document(_document(values))

    values["PHASE3_DOWNLOADED_BYTES"] = str(MAX_PHASE3_DOWNLOAD_BYTES)
    assert validate_binding_document(_document(values))["PHASE3_DOWNLOADED_BYTES"] == str(
        MAX_PHASE3_DOWNLOAD_BYTES
    )


def test_launch_chain_binds_every_fresh_phase3_artifact_identity() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "launch_chain.sh.in"
    ).read_text(encoding="utf-8")
    required = {
        "PHASE3_REQUEST_BYTES",
        "PHASE3_ACQUISITION_BYTES",
        "PHASE3_FIT_LOG_BYTES",
        "PHASE3_GPU_BEFORE_SHA256",
        "PHASE3_GPU_BEFORE_BYTES",
        "PHASE3_GPU_AFTER_SHA256",
        "PHASE3_GPU_AFTER_BYTES",
        "PHASE3_PLAN_BYTES",
        "PHASE3_ACQUISITION_RECEIPT_BYTES",
        "PHASE3_FIT_RESULT_BYTES",
        "PHASE3_ENVELOPE_BYTES",
        "PHASE3_PROJECTION_BYTES",
        "PHASE3_ELIGIBILITY_BYTES",
        "PROJECT_RECEIPT_BYTES",
        "PHASE3_DOWNLOADED_BYTES",
    }
    for key in required:
        assert f"@@{key}@@" in source
    assert "PHASE3_GPU_INVENTORY_SHA256" not in source
    assert 'acquisition["downloaded_bytes"] != 0' not in source
    for stale_size in (2214, 2399, 2026, 1709, 2035, 1578, 2947, 7879, 17653):
        assert f"size={stale_size}" not in source


@pytest.mark.parametrize(
    ("key", "replacement"),
    (
        ("PHASE3_REQUEST_BYTES", None),
        ("PHASE3_DOWNLOADED_BYTES", "1"),
    ),
)
def test_changed_byte_binding_invalidates_an_existing_render(
    tmp_path: Path,
    key: str,
    replacement: str | None,
) -> None:
    values = _valid_values()
    binding_path = _write_document(tmp_path / "bindings.json", values)
    output = tmp_path / "render"
    render_controller_set(binding_path, output)
    launch = (output / "launch_chain_1111111.sh").read_text(encoding="utf-8")
    if key == "PHASE3_REQUEST_BYTES":
        assert f"size={values[key]}," in launch
    else:
        assert f'acquisition["downloaded_bytes"] != {values[key]}' in launch

    values[key] = replacement or str(int(values[key]) + 1)
    _write_document(binding_path, values)
    with pytest.raises(ControllerGenerationError, match="generated controller set diverges"):
        verify_controller_set(binding_path, output)


def test_rebind_performs_only_the_exact_controlled_a05_migration(
    tmp_path: Path,
) -> None:
    current = _valid_values()
    legacy = {
        key: value
        for key, value in current.items()
        if key not in (
            PHASE3_BINDINGS_ADDED_AFTER_A05
            | RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719
        )
    }
    legacy["CONTROLLER_INSTALL_ROOT"] = "/home/ura"
    legacy["PHASE3_GPU_INVENTORY_SHA256"] = "3" * 64
    assert frozenset(legacy) == LEGACY_A05_EXTERNAL_BINDINGS
    base = _write_document(tmp_path / "legacy.json", legacy)

    incomplete_args = [
        "--base",
        str(base),
        "--out",
        str(tmp_path / "incomplete.json"),
        "--set",
        f"PROJECT_RECEIPT_BYTES={current['PROJECT_RECEIPT_BYTES']}",
    ]
    with pytest.raises(SystemExit, match="requires an explicit replacement for every"):
        rebind_main(incomplete_args)

    output = tmp_path / "migrated.json"
    args = ["--base", str(base), "--out", str(output)]
    args.extend(
        (
            "--set",
            f"CONTROLLER_INSTALL_ROOT={current['CONTROLLER_INSTALL_ROOT']}",
        )
    )
    for key in sorted(PHASE3_BINDINGS_ADDED_AFTER_A05):
        args.extend(("--set", f"{key}={current[key]}"))
    for key in sorted(RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719):
        args.extend(("--set", f"{key}={current[key]}"))
    for key in sorted(MIGRATION_REVISION_BINDINGS - PHASE3_BINDINGS_ADDED_AFTER_A05):
        args.extend(("--set", f"{key}={current[key]}"))
    assert rebind_main(args) == 0
    migrated = json.loads(output.read_text(encoding="utf-8"))
    assert validate_binding_document(migrated) == current
    assert "PHASE3_GPU_INVENTORY_SHA256" not in migrated["values"]

    injected = dict(legacy)
    injected["UNREVIEWED"] = "safe"
    bad_base = _write_document(tmp_path / "legacy-extra.json", injected)
    with pytest.raises(SystemExit, match="unknown=.*UNREVIEWED"):
        rebind_main(
            [
                "--base",
                str(bad_base),
                "--out",
                str(tmp_path / "should-not-exist.json"),
                "--set",
                "PHASE3_REQUEST_BYTES=1",
            ]
        )


def test_rebind_requires_rr_roots_and_current_project_identity_for_pre_rr_migration(
    tmp_path: Path,
) -> None:
    current = _valid_values()
    pre_rr = {
        key: value for key, value in current.items()
        if key not in RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719
    }
    assert frozenset(pre_rr) == PRE_RR_EXTERNAL_BINDINGS
    base = _write_document(tmp_path / "pre-rr.json", pre_rr)
    current.update({
        "EXPECTED_COMMIT": "4" * 40,
        "PROJECT_RECEIPT_PATH": "/bound/current-project-receipt.json",
        "PROJECT_RECEIPT_SHA256": "5" * 64,
        "PROJECT_RECEIPT_BYTES": "4242",
    })
    required = RR_EVIDENCE_BINDINGS_ADDED_AFTER_5719 | MIGRATION_REVISION_BINDINGS

    for omitted in sorted(required):
        args = [
            "--base", str(base),
            "--out", str(tmp_path / f"missing-{omitted.lower()}.json"),
        ]
        for key in sorted(required - {omitted}):
            args.extend(("--set", f"{key}={current[key]}"))
        with pytest.raises(
            SystemExit, match=rf"requires an explicit replacement.*{omitted}"
        ):
            rebind_main(args)

    output = tmp_path / "current.json"
    args = ["--base", str(base), "--out", str(output)]
    for key in sorted(required):
        args.extend(("--set", f"{key}={current[key]}"))
    assert rebind_main(args) == 0
    migrated = json.loads(output.read_text(encoding="utf-8"))
    assert validate_binding_document(migrated) == current
