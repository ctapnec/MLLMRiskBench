from __future__ import annotations

import importlib.util
import json
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
