from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import ModuleType

import pytest

from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    CONTROLLERS,
    DERIVED_BINDINGS,
    render_controller_set,
)


def _template_tokens() -> set[str]:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    return {
        match
        for controller in CONTROLLERS
        for match in token.findall(
            (root / controller.template).read_text(encoding="utf-8")
        )
    } - DERIVED_BINDINGS


def _bindings(path: Path) -> Path:
    values = {name: f"value-{name.lower()}" for name in _template_tokens()}
    values["EXPECTED_COMMIT"] = "1" * 40
    for name in tuple(values):
        if name.endswith("SHA256"):
            values[name] = "2" * 64
        elif name == "PHASE3_DOWNLOADED_BYTES":
            values[name] = "0"
        elif name.endswith("_BYTES"):
            values[name] = "1"
        elif name.endswith("_TAG"):
            values[name] = "20260822T120000Z"
        elif name == "CONTROLLER_INSTALL_ROOT":
            values[name] = "/bound/.ura-controller-active"
        elif name.endswith(("_PATH", "_ROOT")):
            values[name] = f"/bound/{name.lower()}"
    path.write_text(
        json.dumps({"schema": BINDINGS_SCHEMA, "values": values}),
        encoding="utf-8",
    )
    return path


@pytest.fixture(scope="module")
def phase8(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    root = tmp_path_factory.mktemp("phase8-lifecycle")
    output = root / "rendered"
    render_controller_set(_bindings(root / "bindings.json"), output)
    path = output / "phase8_human_audit.py"
    spec = importlib.util.spec_from_file_location("phase8_lifecycle_test_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _descriptor(kind: str, index: int) -> dict[str, object]:
    return {
        "path": f"/runner/lane/{kind}-{index}.json",
        "sha256": f"{index + 1:064x}",
        "bytes": index + 1,
    }


def _groups(
    *, grids: int = 0, envelopes: int = 0, eligibility: int = 0, errors: int = 0
) -> dict[str, list[dict[str, object]]]:
    counts = {
        "runner_grid_artifacts": grids,
        "runner_request_envelopes": envelopes,
        "runner_eligibility_artifacts": eligibility,
        "runner_error_artifacts": errors,
    }
    return {
        field: [_descriptor(field, index) for index in range(count)]
        for field, count in counts.items()
    }


def _status(
    phase8: ModuleType,
    *,
    terminal: str,
    lifecycle: str,
    grid_statuses: list[str],
    groups: dict[str, list[dict[str, object]]],
) -> str:
    kinds = phase8.lifecycle_artifact_kinds(
        grid_statuses=grid_statuses, artifact_groups=groups
    )
    return phase8.lifecycle_authorization_status(
        terminal_state=terminal,
        lifecycle_state=lifecycle,
        artifact_kinds=kinds,
    )


def test_phase8_reconstructs_lifecycle_from_exact_artifact_kinds(
    phase8: ModuleType,
) -> None:
    assert _status(
        phase8,
        terminal="measured_complete",
        lifecycle="complete",
        grid_statuses=["complete"],
        groups=_groups(grids=1, envelopes=1, eligibility=1),
    ) == "complete_runner_grid"
    assert _status(
        phase8,
        terminal="failed",
        lifecycle="partial",
        grid_statuses=["partial"],
        groups=_groups(grids=1, envelopes=1, eligibility=1, errors=1),
    ) == "partial_runner_grid"
    assert _status(
        phase8,
        terminal="failed",
        lifecycle="failed",
        grid_statuses=[],
        groups=_groups(envelopes=1, errors=1),
    ) == "failed_after_runner_request"
    assert _status(
        phase8,
        terminal="failed",
        lifecycle="failed",
        grid_statuses=["running"],
        groups=_groups(grids=1, errors=1),
    ) == "failed_after_runner_request"


def test_phase8_does_not_promote_non_request_files_by_generic_count(
    phase8: ModuleType,
) -> None:
    for groups in (_groups(errors=1), _groups(eligibility=1)):
        assert sum(len(rows) for rows in groups.values()) == 1
        assert _status(
            phase8,
            terminal="failed",
            lifecycle="failed",
            grid_statuses=[],
            groups=groups,
        ) == "pre_runner_failure_no_request_artifact"

    with pytest.raises(phase8.Phase8Error, match="status/artifact inventory differs"):
        phase8.lifecycle_artifact_kinds(
            grid_statuses=[], artifact_groups=_groups(grids=1)
        )
    with pytest.raises(phase8.Phase8Error, match="exact artifact kinds"):
        _status(
            phase8,
            terminal="failed",
            lifecycle="partial",
            grid_statuses=["partial"],
            groups=_groups(grids=1, eligibility=1, errors=1),
        )

    source = Path(phase8.__file__).read_text(encoding="utf-8")
    assert "runner_artifact_count" not in source


def test_phase8_capacity_reserves_exact_twenty_disjoint_clusters(
    phase8: ModuleType,
) -> None:
    assert phase8.INPUT_SCHEMA == "ura-phase8-human-audit-inputs/2"
    exact = phase8.plan_phase8_capacity(
        common_available_unique_clusters=21,
        source_task_available_unique_clusters=1,
        common_requested_unique_clusters=1,
        source_task_requested_unique_clusters=1,
    )
    assert exact == {
        "schema": "ura-phase8-human-audit-capacity/1",
        "status": "cardinality_sufficient_for_requests_and_qualification_reserve",
        "common_available_unique_clusters": 21,
        "common_requested_unique_clusters": 1,
        "common_remaining_disjoint_unique_clusters": 20,
        "source_task_available_unique_clusters": 1,
        "source_task_requested_unique_clusters": 1,
        "qualification_required_unique_clusters": 20,
    }

    with pytest.raises(
        phase8.Phase8Error,
        match=r"leaves 19 disjoint qualification clusters; exactly 20 are required",
    ):
        phase8.plan_phase8_capacity(
            common_available_unique_clusters=20,
            source_task_available_unique_clusters=1,
            common_requested_unique_clusters=1,
            source_task_requested_unique_clusters=1,
        )


def test_phase8_capacity_requires_the_exact_source_task_sample(
    phase8: ModuleType,
) -> None:
    with pytest.raises(
        phase8.Phase8Error,
        match=r"source-task frame cannot supply the exact requested sample",
    ):
        phase8.plan_phase8_capacity(
            common_available_unique_clusters=21,
            source_task_available_unique_clusters=1,
            common_requested_unique_clusters=1,
            source_task_requested_unique_clusters=2,
        )
    with pytest.raises(phase8.Phase8Error, match="exact integer"):
        phase8.plan_phase8_capacity(
            common_available_unique_clusters=True,
            source_task_available_unique_clusters=1,
            common_requested_unique_clusters=1,
            source_task_requested_unique_clusters=1,
        )


def test_phase8_revalidates_capacity_against_phase7_success_view(
    phase8: ModuleType,
) -> None:
    source = Path(phase8.__file__).read_text(encoding="utf-8")
    builder = source[
        source.index("def build_input_manifest(") : source.index(
            "def prepare_input_manifest("
        )
    ]
    semantic = source[
        source.index("def semantic_revalidate(") : source.index(
            "def sanitized_environment("
        )
    ]
    execution = source[
        source.index("def execute_preparation(") : source.index(
            "def execute_entry("
        )
    ]
    assert 'audit_runner_root = phase7_support["runner_view"]' in builder
    assert "observed_audit_frame_cluster_counts(" in builder
    assert "revalidate_bound_audit_runner_view(" in builder
    assert '"capacity": capacity' in builder
    assert 'audit_runner_root = support["runner_view"]' in semantic
    assert "observed_audit_frame_cluster_counts(" in semantic
    assert "revalidate_bound_audit_runner_view(" in semantic
    assert "authorized Phase 8 capacity differs" in semantic
    assert 'runner_root = support["audit_runner_root"]' in execution
    assert execution.count("\n    revalidate_execution_view()\n") == 5


def test_phase8_rejects_count_preserving_independent_view_substitution(
    phase8: ModuleType,
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "runner"
    lane_root = source_root / "lane-a"
    lane_root.mkdir(parents=True)
    source = lane_root / "cell.jsonl"
    source.write_bytes(b'{"bound":true}\n')
    view_root = tmp_path / "read-only-runner-view"
    target = view_root / "lane-a" / "cell.jsonl"
    target.parent.mkdir(parents=True)
    target.write_bytes(source.read_bytes())
    os.chmod(target, 0o400)
    source_stat = source.stat()
    target_stat = target.stat()
    inventory = [
        {
            "relative_path": "lane-a/cell.jsonl",
            "source": phase8.descriptor(source),
            "view": phase8.descriptor(target),
            "source_file_identity": {
                "device": source_stat.st_dev,
                "inode": source_stat.st_ino,
            },
            "view_file_identity": {
                "device": target_stat.st_dev,
                "inode": target_stat.st_ino,
            },
            "independent_copy": True,
            "source_view_samefile": False,
            "view_mode": target_stat.st_mode & 0o777,
            "view_link_count": target_stat.st_nlink,
        }
    ]
    receipt = {
        "schema": "ura-phase7-runner-input-view/3",
        "status": "complete",
        "source_runner_root": str(source_root.resolve()),
        "view_root": str(view_root.resolve()),
        "included_measured_lanes": ["lane-a"],
        "regular_files_copied": 1,
        "logical_bytes": source.stat().st_size,
        "source_files_modified": False,
        "permitted_view_outputs": [],
        "file_inventory": inventory,
        "file_inventory_sha256": phase8.sha256_bytes(phase8.canonical(inventory)),
    }
    assert (
        phase8.validate_phase7_runner_view(
            receipt,
            expected_source_root=source_root,
            expected_view_root=view_root,
            expected_measured_lanes=["lane-a"],
        )
        == view_root.resolve()
    )
    assert not source.samefile(target)

    payload = target.read_bytes()
    os.chmod(target, 0o600)
    target.unlink()
    substitution = view_root / "transfer_matrix-shadow.jsonl"
    substitution.write_bytes(payload)
    assert len([path for path in view_root.rglob("*") if path.is_file()]) == 1
    assert substitution.stat().st_size == receipt["logical_bytes"]
    with pytest.raises(phase8.Phase8Error):
        phase8.validate_phase7_runner_view(
            receipt,
            expected_source_root=source_root,
            expected_view_root=view_root,
            expected_measured_lanes=["lane-a"],
        )

    rendered_source = Path(phase8.__file__).read_text(encoding="utf-8")
    completion_validator = rendered_source[
        rendered_source.index("def validate_phase7_completion(") :
        rendered_source.index("def required_env(")
    ]
    assert "runner_view_root = validate_phase7_runner_view(" in completion_validator
