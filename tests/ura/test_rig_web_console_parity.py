"""Console/CLI parity regressions for the rig console (audit wave P1).

Every lane the Build page composes must be the documented CLI lane: an
explicit --limit on every non-dry lane, the runbook's --group, the
tool-conditioned exclusion, the measured resume flags, the receipt locators
the CLI reads from the exported campaign shell, the argparse-required markers
on the Run page, and no console-only attacker that run_matrix rejects after
launch.  Every app instance uses temporary state and results directories.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from experiments.level2_report import _REQUIRED_GROUP_KEYS
from experiments.rig_web import COMMANDS, COMMAND_GROUPS, RigWebApp, build_argv
from experiments.rig_web_app.catalog import (
    _CLI_DEFAULT_GROUP,
    _CLI_ONLY_ATTACKERS,
    _GROUP_KEYS,
    _LOCAL_BUDGET_HELP,
    _PARAM_HELP,
    _RUNBOOK_GROUP,
    _SOURCE_RESTRICTED_ATTACKERS,
    _SUGGEST_STATIC,
)
from experiments.rig_web_app.ui import _BUILDER_SCRIPT
from ura.sampling import (
    DEFAULT_SAMPLING_POLICY,
    SOURCE_ORDER_CLUSTER_PREFIX,
)


def _app(tmp_path: Path) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    return RigWebApp(results_root=results, state_dir=tmp_path / "state")


def _operator_registry_app(tmp_path: Path) -> RigWebApp:
    """An isolated repo root carrying the example hosted/source registries."""

    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    app = RigWebApp(results_root=results, state_dir=tmp_path / "state", repo_root=repo)
    checkout = Path(__file__).resolve().parents[2]
    for source, destination in (
        (
            checkout / "experiments" / "rig" / "api-targets.example.json",
            repo / "experiments" / "rig" / "api-targets.example.json",
        ),
        (
            checkout / "experiments" / "rig" / "source-instances.example.json",
            repo / "experiments" / "source-instances.json",
        ),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    return app


def _opening_tag(document: str, marker: str) -> str:
    marker_at = document.index(marker)
    start = document.rfind("<", 0, marker_at)
    return document[start : document.index(">", marker_at) + 1]


_INPUT_TAG = re.compile(r"<input\b[^>]*>")


def _tag_attr(tag: str, name: str) -> str | None:
    match = re.search(rf"\b{name}='([^']*)'", tag)
    return match.group(1) if match else None


def _builder_form_defaults(page: str) -> dict[str, str]:
    """The Build form's rendered defaults as an untouched browser submits them.

    Checked radios/checkboxes, text/number/hidden values, and each select's
    selected option inside the builder <form>; the hidden corpora/api/local/
    attackers/judges fields are filled from the checked boxes exactly as the
    page's submit handler does.
    """

    start = page.rfind("<form", 0, page.index("id='builder'"))
    form_html = page[start:page.index("</form>", start)]
    assert "<form" not in form_html[5:] and "<script" not in form_html
    form: dict[str, str] = {}
    lists: dict[str, list[str]] = {
        "judges": [], "attackers": [], "corpora": [], "api": [], "local": [],
    }
    boxes = {"judgebox": ("data-judge", "judges"), "fwbox": ("data-fw", "attackers"),
             "armbox": ("data-arm", "corpora")}
    for tag in _INPUT_TAG.findall(form_html):
        name = _tag_attr(tag, "name")
        classes = (_tag_attr(tag, "class") or "").split()
        kind = _tag_attr(tag, "type") or "text"
        checked = " checked" in tag
        box = next((boxes[cls] for cls in classes if cls in boxes), None)
        if box is not None:
            if checked:
                lists[box[1]].append(_tag_attr(tag, box[0]) or "")
        elif "modelbox" in classes:
            if checked:
                lists[_tag_attr(tag, "data-kind") or "api"].append(
                    _tag_attr(tag, "data-model") or ""
                )
        elif name:
            if kind in {"checkbox", "radio"}:
                if checked:
                    form[name] = _tag_attr(tag, "value") or "on"
            elif kind in {"text", "number", "hidden"}:
                form.setdefault(name, _tag_attr(tag, "value") or "")
    for select in re.finditer(r"<select\b([^>]*)>(.*?)</select>", form_html, re.S):
        name = _tag_attr(select.group(1), "name")
        options = re.findall(r"<option value='([^']*)'([^>]*)>", select.group(2))
        if name and options:
            chosen = next((v for v, attrs in options if " selected" in attrs), options[0][0])
            form.setdefault(name, chosen)
    for key, values in lists.items():
        form[key] = ",".join(values)
    return form


def _bind_campaign_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Real receipt/attestation fixture files with exact digests in the env."""

    project = tmp_path / "r.json"
    source = tmp_path / "s.json"
    attestation = tmp_path / "a.json"
    project.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    source.write_text('{"schema":"fixture-source"}\n', encoding="utf-8")
    attestation.write_text('{"schema":"fixture-attestation"}\n', encoding="utf-8")
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", hashlib.sha256(project.read_bytes()).hexdigest())
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(source))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", hashlib.sha256(source.read_bytes()).hexdigest())
    return {
        "att_path1": str(attestation),
        "att_sha1": hashlib.sha256(attestation.read_bytes()).hexdigest(),
    }


_DRY_BASE = {
    "mode": "dry_run",
    "corpora": "synth",
    "attackers": "replay",
    "judges": "rules",
    "out": "runs/dry",
    "seeds": "0",
}


# -- P1-02: --group ----------------------------------------------------------


def test_group_key_mirror_matches_run_matrix_and_runbook_default() -> None:
    # The console's group-key mirror is one-to-one with the CLI's allowed set;
    # Build's default grouping is the run_matrix parser default written out
    # explicitly, which is exactly the eight keys level2_report requires (a
    # narrower grouping is rejected at Level-2 export, so the documented
    # measured lanes and the console lane both pass this value); the help
    # says so; and no narrower grouping is offered as a suggestion.
    assert set(_GROUP_KEYS) == run_matrix._ALLOWED_GROUP_KEYS  # noqa: SLF001
    assert len(_GROUP_KEYS) == len(set(_GROUP_KEYS))
    assert set(_RUNBOOK_GROUP.split(",")) <= set(_GROUP_KEYS)
    assert _RUNBOOK_GROUP == _CLI_DEFAULT_GROUP == (
        "model,source,risk,effective_modality,expected_behavior,attacker,"
        "source_policy_id,source_policy_version"
    )
    assert set(_RUNBOOK_GROUP.split(",")) == set(_REQUIRED_GROUP_KEYS)
    parser = run_matrix.build_parser()
    default = next(
        action.default for action in parser._actions  # noqa: SLF001
        if "--group" in action.option_strings
    )
    assert default == _CLI_DEFAULT_GROUP
    assert _SUGGEST_STATIC["group"] == (_RUNBOOK_GROUP,)
    assert "--group" in _PARAM_HELP and _RUNBOOK_GROUP in _PARAM_HELP["--group"]
    assert "Level-2 export requires at least these eight keys" in _PARAM_HELP["--group"]
    assert "narrower groupings are rejected at export" in _PARAM_HELP["--group"]
    assert "blank inherits the CLI default" in _PARAM_HELP["--group"]
    assert "model,risk,effective_modality,source_policy_id" not in _PARAM_HELP["--group"]


def test_build_page_exposes_group_exclusion_and_resume_controls(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()
    execution_at = page.index("data-page-panel='build-execution'")
    modal_at = page.index("id='model-picker'")
    execution = page[execution_at:modal_at]
    # --group: the eight-key CLI default preselected; the datalist offers
    # only that full default (a narrower grouping is rejected at Level-2
    # export) and the hint says so.
    group_tag = _opening_tag(execution, "name='group'")
    assert "list='dl-build-group'" in group_tag
    assert f"value='{_RUNBOOK_GROUP}'" in group_tag
    datalist_at = execution.index("id='dl-build-group'")
    datalist = execution[datalist_at:execution.index("</datalist>", datalist_at)]
    assert datalist.count("<option ") == 1
    assert f"<option value='{_CLI_DEFAULT_GROUP}'>" in datalist
    assert "model,risk,effective_modality,source_policy_id,source_policy_version'" not in datalist
    group_at = execution.index("name='group'")
    group_hint = execution[execution.rfind("<label", 0, group_at):group_at]
    assert "Level-2 export requires at least these eight keys" in group_hint
    assert "blank inherits the CLI default" in group_hint
    # --exclude-tool-conditioned: on by default for the (default) dry lane.
    exclude_tag = _opening_tag(execution, "name='exclude_tool_conditioned'")
    assert " checked" in exclude_tag
    # --reset-open-circuits: never a default; --lock-stale-seconds optional.
    reset_tag = _opening_tag(execution, "name='reset_open_circuits'")
    assert " checked" not in reset_tag
    assert "name='lock_stale_seconds'" in execution
    # Sampling is one synchronized per-arm control. The numeric field keeps the
    # CLI's blank/default behavior while the range exposes 0 as explicit full mode.
    assert "id='sample-size-control'" in execution
    assert "id='sample-limit-range' type='range' min='0'" in execution
    assert "0 = full selected release" in execution
    assert "maximum source-cluster count per selected arm" in execution
    assert "id='sample-seed-input'" in execution
    policy_select = _opening_tag(execution, "id='sampling-policy-select'")
    assert "name='sampling_policy'" in policy_select
    assert execution.count("name='sampling_policy'") == 1
    assert f"value='{DEFAULT_SAMPLING_POLICY}' selected" in execution
    assert f"value='{SOURCE_ORDER_CLUSTER_PREFIX}'" in execution
    # The live preview mirrors the new controls.
    for field in ("group", "exclude_tool_conditioned", "reset_open_circuits", "lock_stale_seconds"):
        assert f"'{field}'" in _BUILDER_SCRIPT
    assert "--limit 0" in _BUILDER_SCRIPT and "applyExclusionDefault" in _BUILDER_SCRIPT


def test_exclusion_default_follows_the_mode_on_rerender(tmp_path: Path) -> None:
    # A fresh page defaults the exclusion on (dry lane); every measured render
    # forces it disabled/off even if a stale submission carried the field; a
    # re-rendered dry form keeps whatever the operator submitted.
    app = _app(tmp_path)
    try:
        measured = app._build_page(
            prefill={"mode": "measured", "corpora": "strongreject_official"},
            errors={"models": "fixture"},
        ).decode("utf-8")
        stale_measured = app._build_page(
            prefill={
                "mode": "measured",
                "corpora": "strongreject_official",
                "exclude_tool_conditioned": "on",
            },
            errors={"exclude_tool_conditioned": "fixture"},
        ).decode("utf-8")
        dry_off = app._build_page(prefill={"mode": "dry_run"}).decode("utf-8")
        dry_on = app._build_page(
            prefill={"mode": "dry_run", "exclude_tool_conditioned": "on"}
        ).decode("utf-8")
    finally:
        app.close()
    assert " checked" not in _opening_tag(measured, "name='exclude_tool_conditioned'")
    assert " disabled" in _opening_tag(measured, "name='exclude_tool_conditioned'")
    assert " checked" not in _opening_tag(
        stale_measured, "name='exclude_tool_conditioned'"
    )
    assert " disabled" in _opening_tag(
        stale_measured, "name='exclude_tool_conditioned'"
    )
    assert " checked" not in _opening_tag(dry_off, "name='exclude_tool_conditioned'")
    assert " disabled" not in _opening_tag(dry_off, "name='exclude_tool_conditioned'")
    assert " checked" in _opening_tag(dry_on, "name='exclude_tool_conditioned'")
    assert " disabled" not in _opening_tag(dry_on, "name='exclude_tool_conditioned'")


def test_builder_forbids_tool_row_exclusion_outside_standalone_dry_run(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        assert "exclude_tool_conditioned" not in app._validate_builder({
            **_DRY_BASE,
            "exclude_tool_conditioned": "on",
        })
        for mode in ("measured", "attestation_probe", "diagnostic_canary"):
            errors = app._validate_builder({
                **_DRY_BASE,
                "mode": mode,
                "exclude_tool_conditioned": "on",
            })
            assert "standalone dry run" in errors["exclude_tool_conditioned"]
            assert "retain every selected cluster row" in errors[
                "exclude_tool_conditioned"
            ]
    finally:
        app.close()

    assert "box.disabled=m!=='dry_run';box.checked=m==='dry_run'" in (
        _BUILDER_SCRIPT
    )


def test_group_is_validated_against_the_cli_and_composed(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        assert "group" not in app._validate_builder({**_DRY_BASE, "group": _RUNBOOK_GROUP})
        assert "group" not in app._validate_builder({**_DRY_BASE, "group": _CLI_DEFAULT_GROUP})
        unknown = app._validate_builder({**_DRY_BASE, "group": "model,bogus_key"})
        assert "bogus_key" in unknown["group"] and "allowed:" in unknown["group"]
        duplicate = app._validate_builder({**_DRY_BASE, "group": "model,model"})
        assert "unique" in duplicate["group"]
        empty = app._validate_builder({**_DRY_BASE, "group": ","})
        assert "at least one" in empty["group"]
        command, values, _params = app._compose_from_builder({
            **_DRY_BASE, "group": _RUNBOOK_GROUP,
        })
        assert values["--group"] == _RUNBOOK_GROUP
        parsed = run_matrix.build_parser().parse_args(build_argv(command, values)[3:])
        assert parsed.group == _RUNBOOK_GROUP
        # Blank group means the CLI default (no flag is composed).
        _command, values, _params = app._compose_from_builder(dict(_DRY_BASE))
        assert "--group" not in values
    finally:
        app.close()


# -- P1-01: explicit --limit on every non-dry lane -----------------------------


def test_non_dry_lane_always_carries_an_explicit_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _bind_campaign_env(tmp_path, monkeypatch)
    app = _operator_registry_app(tmp_path)
    measured = {
        "mode": "measured", "corpora": "strongreject_official",
        "attackers": "replay", "judges": "rules", "out": "runs/m",
        "seeds": "0", "sample_seed": "0", "scope": "sc", "max_age": "24",
        **attestation, "cap_target": "4",
        "cap_judge": "4", "cap_http": "12", "deadline": "600",
    }
    try:
        # A hosted paid lane must type a limit (blank is NOT admitted).
        hosted_blank = app._validate_builder({**measured, "api": "anthropic:claude-opus-5"})
        assert "limit" in hosted_blank and "explicit" in hosted_blank["limit"]
        hosted_full = app._validate_builder({
            **measured,
            "api": "anthropic:claude-opus-5",
            "limit": "0",
            "sample_seed": "",
        })
        assert "limit" not in hosted_full and "sample_seed" not in hosted_full
        # A local-only measured lane may leave it blank: the documented policy
        # is the complete release, which the builder composes as --limit 0.
        local_blank = app._validate_builder({**measured, "local": "vllm:local/model"})
        assert "limit" not in local_blank
        # Probes and canaries never accept a blank limit either.
        probe_blank = app._validate_builder({
            "mode": "attestation_probe", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "seeds": "0", "scope": "s", "out": "runs/p",
        })
        assert "limit" in probe_blank
        canary_blank = app._validate_builder({
            "mode": "diagnostic_canary", "canary_dry": "on", "attackers": "replay",
            "judges": "rules", "seeds": "0", "out": "runs/c",
        })
        assert "limit" in canary_blank
        # Composition: a non-dry lane with a blank limit emits --limit 0 and
        # retains the same value in the reviewed params; an explicit value is
        # passed through unchanged; a dry lane leaves the CLI default alone.
        _cmd, values, params = app._compose_from_builder({
            **measured, "api": "anthropic:claude-opus-5", "limit": "",
        })
        assert values["--limit"] == "0" and params["limit"] == "0"
        _cmd, values, params = app._compose_from_builder({
            **measured, "api": "anthropic:claude-opus-5", "limit": "5",
        })
        assert values["--limit"] == "5" and params["limit"] == "5"
        _cmd, values, params = app._compose_from_builder({
            **measured, "api": "anthropic:claude-opus-5", "limit": "0",
        })
        assert values["--limit"] == "0" and params["limit"] == "0"
        _cmd, values, params = app._compose_from_builder({
            "mode": "attestation_probe", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "limit": "1", "seeds": "0", "scope": "s",
            "out": "runs/p",
        })
        assert values["--limit"] == "1"
        _cmd, values, params = app._compose_from_builder(dict(_DRY_BASE))
        assert "--limit" not in values and "limit" not in params
        assert "--sampling-policy" not in values
        assert "sampling_policy" not in params
    finally:
        app.close()
    assert "50" in _PARAM_HELP["--limit"] and "0 means the complete" in _PARAM_HELP["--limit"]
    assert "Omit only" not in _PARAM_HELP["--limit"]


def test_builder_sampling_control_and_local_wall_time_keep_cli_semantics(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        fresh = app.handle("GET", "/build")[2].decode("utf-8")
        assert "name='target_answer_retries' value='1'" in fresh
        assert "syncHostedRetryPolicy" in _BUILDER_SCRIPT
        assert "input.value='0';input.readOnly=true" in _BUILDER_SCRIPT
        selected = app._build_page(
            prefill={
                **_DRY_BASE,
                "limit": "0",
                "sample_seed": "17",
                "sampling_policy": SOURCE_ORDER_CLUSTER_PREFIX,
            }
        ).decode("utf-8")
        fresh_panel = _opening_tag(fresh, "id='sample-size-control'")
        selected_panel = _opening_tag(selected, "id='sample-size-control'")
        assert " hidden" in fresh_panel and "aria-hidden='true'" in fresh_panel
        assert " hidden" not in selected_panel and "aria-hidden='false'" in selected_panel
        assert "name='limit' value='0'" in selected
        assert "name='sample_seed' value='17'" in selected
        assert f"value='{SOURCE_ORDER_CLUSTER_PREFIX}' selected" in selected
        assert "syncSampleSizeControl" in _BUILDER_SCRIPT
        assert "matching no-call preflight" in _BUILDER_SCRIPT
        assert "Effective selection: " in _BUILDER_SCRIPT
        assert "Math.min(value,exactMax)" in _BUILDER_SCRIPT
        assert "data-base-max='1000'" not in selected
        unknown_range = _opening_tag(selected, "id='sample-limit-range'")
        assert " hidden" not in unknown_range and " disabled" in unknown_range
        unknown_number = _opening_tag(selected, "id='sample-limit-number'")
        assert " disabled" not in unknown_number

        dry_canary_page = app._build_page(prefill={
            "mode": "diagnostic_canary",
            "canary_dry": "on",
            "attackers": "replay",
            "judges": "rules",
            "seeds": "0",
        }).decode("utf-8")
        dry_canary_panel = _opening_tag(
            dry_canary_page, "id='sample-size-control'"
        )
        assert " hidden" not in dry_canary_panel
        assert "aria-hidden='false'" in dry_canary_panel
        assert "name='limit' value='1'" in dry_canary_page
        assert "Synthetic arm selected automatically" in dry_canary_page
        assert "mode==='diagnostic_canary'&&checkedName('canary_dry')" in (
            _BUILDER_SCRIPT
        )
        assert "parts.push('--corpora synth')" in _BUILDER_SCRIPT
        assert "parts.push('--dry-run')" in _BUILDER_SCRIPT

        normalized = app._builder_params({
            **_DRY_BASE,
            "mode": "measured",
            "local": "vllm:fixture/model",
            "local_budget_hours": "3",
            "deadline": "7200",
        })
        assert normalized["local_budget_hours"] == "3"
        assert normalized["deadline"] == "7200"

        measured_local = {
            **normalized,
            "limit": "5",
            "sample_seed": "17",
            "cap_target": "1",
            "cap_judge": "1",
            "cap_http": "1",
        }
        errors = app._validate_builder(measured_local)
        assert "local_budget_hours" not in errors
        assert "deadline" not in errors
        independent = app._validate_builder({**measured_local, "deadline": "10800"})
        assert "local_budget_hours" not in independent
        assert "deadline" not in independent
        wrong_route = app._validate_builder({
            **_DRY_BASE,
            "local_budget_hours": "3",
            "deadline": "7200",
        })
        assert "measured all-local lane" in wrong_route["local_budget_hours"]
        no_seed = app._validate_builder({
            **measured_local,
            "sample_seed": "",
        })
        assert "within each selected arm" in no_seed["sample_seed"]
        invalid_policy = app._validate_builder({
            **measured_local,
            "sampling_policy": "ignore-the-policy-mutant",
        })
        assert "supported sampling policies" in invalid_policy["sampling_policy"]
        _command, values, params = app._compose_from_builder({
            **_DRY_BASE,
            "limit": "2",
            "sample_seed": "17",
            "sampling_policy": SOURCE_ORDER_CLUSTER_PREFIX,
        })
        assert values["--sampling-policy"] == SOURCE_ORDER_CLUSTER_PREFIX
        assert params["sampling_policy"] == SOURCE_ORDER_CLUSTER_PREFIX
        _command, retry_values, retry_params = app._compose_from_builder({
            **_DRY_BASE,
            "target_answer_retries": "1",
        })
        assert retry_values["--target-answer-retries"] == "1"
        assert retry_params["target_answer_retries"] == "1"
        for allowed in ("0", "10"):
            assert "target_answer_retries" not in app._validate_builder({
                **_DRY_BASE,
                "target_answer_retries": allowed,
            })
        hosted_retry = app._validate_builder({
            **_DRY_BASE,
            "api": "anthropic:claude-opus-5",
            "target_answer_retries": "1",
        })
        assert "no answer-quality retries" in hosted_retry[
            "target_answer_retries"
        ]
        assert "target_answer_retries" not in app._validate_builder({
            **_DRY_BASE,
            "api": "anthropic:claude-opus-5",
            "target_answer_retries": "0",
        })
        assert "integer in [0, 10]" in app._validate_builder({
            **_DRY_BASE,
            "target_answer_retries": "11",
        })["target_answer_retries"]
        assert app._projection_params({
            **_DRY_BASE,
            "sampling_policy": DEFAULT_SAMPLING_POLICY,
        }) != app._projection_params({
            **_DRY_BASE,
            "sampling_policy": SOURCE_ORDER_CLUSTER_PREFIX,
        })
    finally:
        app.close()

    assert "call-start admission window" in _PARAM_HELP["--deadline-seconds"]
    assert "process wall-time cap" in _LOCAL_BUDGET_HELP
    assert "complete process tree" in _LOCAL_BUDGET_HELP
    assert "Set --deadline-seconds independently" in _LOCAL_BUDGET_HELP


def test_builder_sampling_slider_uses_exact_per_arm_projection_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    arms = [
        {
            "logical_source_arm": "airbench_full",
            "total_records": 30,
            "selected_records": 30,
            "total_clusters": 3,
            "selected_clusters": 3,
            "limit": 4,
            "sample_seed": 7,
        },
        {
            "logical_source_arm": "strongreject_official",
            "total_records": 100,
            "selected_records": 40,
            "total_clusters": 10,
            "selected_clusters": 4,
            "limit": 4,
            "sample_seed": 7,
        },
    ]
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: ({
            "projection_id": "lane-projection-" + "1" * 24,
            "call_projection": {
                "target_calls": 70,
                "judge_calls": 0,
                "http_attempts": 0,
            },
            "arms": arms,
        }, ""),
    )
    try:
        params = {
            **_DRY_BASE,
            "corpora": "airbench_full,strongreject_official",
            "limit": "4",
            "sample_seed": "7",
        }
        page = app._build_page(prefill=params).decode("utf-8")
        exact_range = _opening_tag(page, "id='sample-limit-range'")
        assert "max='10'" in exact_range and "value='4'" in exact_range
        assert " disabled" not in exact_range
        assert "Available clusters" in page and "Available converted rows" in page
        assert "airbench_full" in page and "strongreject_official" in page
        assert "Exact projection: 7 clusters" in page

        changed_arms = app._build_page(
            prefill={**params, "corpora": "airbench_full"}
        ).decode("utf-8")
        changed_range = _opening_tag(changed_arms, "id='sample-limit-range'")
        assert " disabled" in changed_range
        assert "matching no-call preflight" in changed_arms
        assert "Exact projection:" not in changed_arms

        full = app._build_page(prefill={**params, "limit": "0"}).decode("utf-8")
        assert "Exact projection: 13 clusters" in full
        above = app._build_page(prefill={**params, "limit": "12"}).decode("utf-8")
        assert "name='limit' value='12'" in above
        above_range = _opening_tag(above, "id='sample-limit-range'")
        assert "max='10'" in above_range and "value='10'" in above_range
    finally:
        app.close()


def test_local_wall_time_wraps_only_final_measured_all_local_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    try:
        monkeypatch.setattr(
            app, "_coreutils_timeout_executable", lambda: "/usr/bin/timeout"
        )
        inner = [sys.executable, "-m", "experiments.run_matrix", "--deadline-seconds", "7200"]
        params = {
            "mode": "measured",
            "local": "vllm:fixture/model",
            "judges": "rules,guardrail",
            "local_budget_hours": "3",
            "deadline": "7200",
        }
        wrapped, seconds = app._wrap_local_measured_wall_time(
            "run_matrix", {}, params, inner
        )
        assert seconds == 10800
        assert wrapped == [
            "/usr/bin/timeout",
            "--verbose",
            "--signal=TERM",
            "--kill-after=10s",
            "10800s",
            *inner,
        ]
        assert inner[-1] == "7200"

        for values in (
            {"--dry-run": "on"},
            {"--preflight-only": "on"},
            {"--model-acquisition-plan-only": "on"},
        ):
            assert app._wrap_local_measured_wall_time(
                "run_matrix", values, params, inner
            ) == (inner, None)
        assert app._wrap_local_measured_wall_time(
            "model_acquire", {}, params, inner
        ) == (inner, None)

        with pytest.raises(ValueError, match="all-local"):
            app._wrap_local_measured_wall_time(
                "run_matrix",
                {},
                {**params, "judges": "rules,llm", "judge_model": "openai:gpt"},
                inner,
            )
        monkeypatch.setattr(app, "_coreutils_timeout_executable", lambda: None)
        with pytest.raises(ValueError, match="GNU coreutils timeout"):
            app._wrap_local_measured_wall_time("run_matrix", {}, params, inner)
    finally:
        app.close()


def test_start_job_launches_but_does_not_retain_wall_time_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import experiments.rig_web_app.lifecycle as lifecycle_module

    app = _app(tmp_path)
    inner = [sys.executable, "-m", "experiments.run_matrix", "--deadline-seconds", "7200"]
    retained = [
        sys.executable,
        "-m",
        "experiments.run_matrix",
        "--deadline-seconds",
        "7200",
    ]
    launched: list[list[str]] = []

    class FakeProcess:
        pid = 5252

        @staticmethod
        def poll() -> None:
            return None

    def fake_popen(argv, **_kwargs):  # noqa: ANN001
        launched.append(list(argv))
        return FakeProcess()

    params = {
        "mode": "measured",
        "local": "vllm:fixture/model",
        "judges": "rules,guardrail",
        "local_budget_hours": "3",
        "deadline": "7200",
    }
    monkeypatch.setattr(lifecycle_module, "build_argv", lambda *_args, **_kwargs: inner)
    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    monkeypatch.setattr(
        app, "_bind_selected_execution_config_identity", lambda value: dict(value)
    )
    monkeypatch.setattr(
        app, "_bind_execution_config_bundle_identity", lambda value: dict(value)
    )
    monkeypatch.setattr(
        app,
        "_durable_launch_state",
        lambda *_args, **_kwargs: (
            retained,
            dict(params),
            None,
            None,
            None,
            None,
            None,
            (),
        ),
    )
    monkeypatch.setattr(app, "_run_matrix_child_environment", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(app, "_durable_log_redactions", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(app, "_start_log_capture", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        app, "_coreutils_timeout_executable", lambda: "/usr/bin/timeout"
    )
    try:
        job = app.start_job("run_matrix", {}, builder_params=params)
        if os.name == "posix":
            assert Path(launched[0][1]).name == 'job_runtime.py'
            launched[0] = launched[0][launched[0].index('--') + 1:]
        assert launched == [[
            "/usr/bin/timeout",
            "--verbose",
            "--signal=TERM",
            "--kill-after=10s",
            "10800s",
            *inner,
        ]]
        command_document = json.loads(
            (job.directory / "command.json").read_text(encoding="utf-8")
        )
        assert command_document == {
            "job_id": job.job_id,
            "command": "run_matrix",
            "argv": retained,
            "supervised": os.name == "posix",
            "controller_wall_time_seconds": 10800,
        }
        assert job.argv == retained
    finally:
        app.close()


@pytest.mark.skipif(os.name == "nt", reason="GNU timeout process-group semantics")
def test_local_wall_time_kills_sigterm_ignoring_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    heartbeat = tmp_path / "heartbeat"
    grandchild = (
        "import pathlib,signal,sys,time;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        "p=pathlib.Path(sys.argv[1]);"
        "exec('while True:\\n p.open(\\\"ab\\\").write(b\\\"x\\\")\\n time.sleep(0.05)')"
    )
    child = (
        "import signal,subprocess,sys,time;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]);"
        "exec('while True:\\n time.sleep(1)')"
    )
    try:
        timeout_executable = app._coreutils_timeout_executable()
        assert timeout_executable is not None
        monkeypatch.setattr(
            app, "_coreutils_timeout_executable", lambda: timeout_executable
        )
        wrapped, _seconds = app._wrap_local_measured_wall_time(
            "run_matrix",
            {},
            {
                "mode": "measured",
                "local": "vllm:fixture/model",
                "judges": "rules",
                "local_budget_hours": "1",
            },
            [sys.executable, "-c", child, grandchild, str(heartbeat)],
        )
        wrapped[3] = "--kill-after=1s"
        wrapped[4] = "1s"
        completed = subprocess.run(wrapped, check=False, timeout=10)
        # A command that exits on TERM gives GNU timeout's ordinary 124. When
        # the command ignores TERM, --kill-after sends KILL to the managed
        # process group; Python may observe the supervisor itself as -SIGKILL,
        # while a shell intermediary reports the conventional 128 + SIGKILL.
        assert completed.returncode in {
            124,
            -signal.SIGKILL,
            128 + signal.SIGKILL,
        }
        before = heartbeat.stat().st_size
        time.sleep(0.3)
        assert heartbeat.stat().st_size == before
    finally:
        app.close()


# -- P1-MISSED-1: the Build synth dry lane runs with the CLI default limit -------


def test_build_default_synth_dry_lane_runs_to_completion(tmp_path: Path) -> None:
    # The Build page's REAL rendered defaults (parsed from the page, not
    # hard-coded: dry run, replay, judges rules,llm with the offline mock
    # forced by compose, blank limit = CLI default 50 clusters, exclusion ON,
    # the eight-key CLI group) plus the one operator choice the README
    # describes (tick the synth arm) and an output directory compose an argv
    # that the real run_matrix executes offline to completion.  A rules-only
    # cascade would fail closed on the first non-confident row, so the page
    # must not default to it.
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        form = _builder_form_defaults(page)
        assert form["mode"] == "dry_run"
        assert form["judges"] == "rules,llm" and form["judge_model"] == ""
        assert form["attackers"] == "replay"
        assert form["corpora"] == "" and form["api"] == "" and form["local"] == ""
        assert form["limit"] == "" and form["group"] == _RUNBOOK_GROUP
        assert form["exclude_tool_conditioned"] == "on"
        assert "reset_open_circuits" not in form
        form["corpora"] = "synth"
        form["out"] = str(app.results_root / "dry")
        assert app._validate_builder(form) == {}
        command, values, _params = app._compose_from_builder(form)
        assert values["--judges"] == "rules,llm" and values["--judge-model"] == "mock"
        assert values["--exclude-tool-conditioned"] == "on"
        assert values["--group"] == _RUNBOOK_GROUP
        assert "--limit" not in values
        argv = build_argv(command, values)[3:]
        parsed = run_matrix.build_parser().parse_args(argv)
        assert parsed.exclude_tool_conditioned is True and parsed.limit == 50
        assert run_matrix.main(argv) == 0
    finally:
        app.close()


def test_judges_default_to_rules_llm_on_dry_lanes_only(tmp_path: Path) -> None:
    # A fresh page (dry lane) renders rules and llm checked (the documented
    # section 8 dry cascade; compose forces the mock judge); a page rendered
    # for a non-dry mode without a judges submission defaults to rules only;
    # a re-rendered submission keeps exactly the operator's boxes.
    app = _app(tmp_path)
    try:
        fresh = app.handle("GET", "/build")[2].decode("utf-8")
        measured = app._build_page(prefill={"mode": "measured"}).decode("utf-8")
        resubmitted = app._build_page(
            prefill={"mode": "dry_run", "judges": "rules"}
        ).decode("utf-8")
    finally:
        app.close()
    for document, expected in (
        (fresh, {"rules", "llm"}),
        (measured, {"rules"}),
        (resubmitted, {"rules"}),
    ):
        checked = {
            judge
            for judge in ("rules", "llm", "guardrail")
            if " checked" in _opening_tag(document, f"data-judge='{judge}'")
        }
        assert checked == expected


# -- P1-06: measured resume controls ------------------------------------------


def test_resume_and_lock_controls_compose_only_for_measured_lanes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation = _bind_campaign_env(tmp_path, monkeypatch)
    app = _operator_registry_app(tmp_path)
    measured = {
        "mode": "measured", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "out": "runs/m", "seeds": "0", "sample_seed": "0",
        "scope": "sc", "max_age": "24", **attestation,
        "cap_target": "4", "cap_judge": "4",
        "cap_http": "12", "deadline": "600", "limit": "5",
    }
    try:
        accepted = app._validate_builder({
            **measured, "reset_open_circuits": "on", "lock_stale_seconds": "3600",
        })
        assert "reset_open_circuits" not in accepted
        assert "lock_stale_seconds" not in accepted
        for mode_form in (
            _DRY_BASE,
            {**_DRY_BASE, "mode": "attestation_probe"},
            {**_DRY_BASE, "mode": "diagnostic_canary", "canary_dry": "on"},
        ):
            rejected = app._validate_builder({**mode_form, "reset_open_circuits": "on"})
            assert "measured-lane resume" in rejected["reset_open_circuits"]
        assert "positive" in app._validate_builder({
            **_DRY_BASE, "lock_stale_seconds": "0",
        })["lock_stale_seconds"]
        assert "checkbox" in app._validate_builder({
            **_DRY_BASE, "reset_open_circuits": "yes",
        })["reset_open_circuits"]
        assert "checkbox" in app._validate_builder({
            **_DRY_BASE, "exclude_tool_conditioned": "1",
        })["exclude_tool_conditioned"]
        command, values, params = app._compose_from_builder({
            **measured, "reset_open_circuits": "on", "lock_stale_seconds": "3600",
            "group": _RUNBOOK_GROUP,
        })
        assert values["--reset-open-circuits"] == "on"
        assert values["--lock-stale-seconds"] == "3600"
        argv = build_argv(command, values)[3:]
        parsed = run_matrix.build_parser().parse_args(argv)
        assert parsed.reset_open_circuits is True and parsed.lock_stale_seconds == 3600
        # The no-call preflight projection of the same lane never clears
        # durable circuit state, but keeps the grid-shaping flags.
        # Even a stale retained workflow cannot carry the standalone-dry-only
        # exclusion into the purpose-changed --preflight-only child.
        projected = app._builder_preflight_values(
            {**values, "--exclude-tool-conditioned": "on"},
            output=tmp_path / "pre",
        )
        assert "--reset-open-circuits" not in projected
        assert projected["--preflight-only"] == "on"
        assert projected["--group"] == _RUNBOOK_GROUP
        assert "--exclude-tool-conditioned" not in projected
        assert projected["--lock-stale-seconds"] == "3600"
        # The resume/diagnostic controls never change the grid identity the
        # preflight reuse check compares.
        assert app._projection_params(params) == app._projection_params({
            key: value
            for key, value in params.items()
            if key not in {"reset_open_circuits", "lock_stale_seconds"}
        })
        # A dry lane never composes the reset even if a stale form sends it.
        _cmd, values, _params = app._compose_from_builder({
            **_DRY_BASE, "reset_open_circuits": "on",
        })
        assert "--reset-open-circuits" not in values
    finally:
        app.close()


# -- P1-03: dashboard playbook -----------------------------------------------


def test_playbook_run_matrix_steps_open_build(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/")[2].decode("utf-8")
    finally:
        app.close()
    playbook_at = page.index("Campaign playbook")
    playbook = page[playbook_at:page.index("</ol>", playbook_at)]
    assert "cmd=run_matrix" not in playbook
    assert "$FABLE" not in playbook and "$SOL" not in playbook
    assert "set from canary" not in playbook
    assert playbook.count("href='/build'>open Build") == 3
    # The no-call preflight still prefills the generic rig_check form with a
    # complete, valid argument set (no shell placeholders). rig_check always
    # adds --preflight-only, so its form cannot carry the dry-run-only row
    # exclusion; limit 1 avoids the tool-conditioned synth fixture rows.
    assert "cmd=rig_check" in playbook
    assert "--exclude-tool-conditioned" not in playbook
    assert "--limit=1" in playbook
    assert "prefill" in playbook


def test_run_page_rig_check_omits_and_rejects_row_exclusion(
    tmp_path: Path,
) -> None:
    assert "--exclude-tool-conditioned" not in {
        param.flag for param in COMMANDS["rig_check"].params
    }
    with pytest.raises(ValueError, match="unknown parameter"):
        build_argv("rig_check", {"--exclude-tool-conditioned": "on"})

    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/commands")[2].decode("utf-8")
        marker = "<input type='hidden' name='command' value='rig_check'>"
        marker_at = page.index(marker)
        card = page[page.rfind("<details", 0, marker_at):page.index(
            "</details>", marker_at
        )]
        assert "name='--exclude-tool-conditioned'" not in card

        status, _content_type, body = app.handle("POST", "/jobs", {
            "command": "rig_check",
            "--dry-run": "on",
            "--corpora": "synth",
            "--limit": "1",
            "--exclude-tool-conditioned": "on",
            "--out": str(app.results_root / "forbidden-preflight"),
        })
        assert status == 400
        assert b"unknown parameter" in body
        assert app.jobs == {}
    finally:
        app.close()


# -- P1-04: receipt locators reach a non-dry matrix child -----------------------


def test_receipt_env_reaches_non_dry_matrix_children_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "r.json"
    receipt.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(receipt))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", "a" * 64)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "s.json"))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "b" * 64)
    app = _app(tmp_path)
    names = (
        "URA_PROJECT_REVISION_MANIFEST",
        "URA_PROJECT_REVISION_SHA256",
        "URA_SOURCE_CONFORMANCE_MANIFEST",
        "URA_SOURCE_CONFORMANCE_SHA256",
    )
    try:
        live = app._run_matrix_child_environment({}, scrub_receipt_env=False)
        assert all(live[name] == __import__("os").environ[name] for name in names)
        dry = app._run_matrix_child_environment({}, scrub_receipt_env=True)
        assert not any(name in dry for name in names)
        # Non-matrix commands keep the least-privilege base environment.
        generic = app._generic_child_environment("figures", {})
        assert not any(name in generic for name in names)
        # A Run-page rig_check with blank receipt fields launches with the
        # exported locators, exactly like the documented campaign shell, and
        # its dry-run form launches with them scrubbed like a Build dry lane.
        captured: list[dict[str, str]] = []
        real_popen = subprocess.Popen

        def spy(argv, **kwargs):  # noqa: ANN001
            # Only the matrix child matters (stop_job may spawn helpers).
            if isinstance(argv, (list, tuple)) and "experiments.rig_check" in argv:
                captured.append(dict(kwargs.get("env") or {}))
            return real_popen(argv, **kwargs)

        monkeypatch.setattr(subprocess, "Popen", spy)
        status, location, _body = app.handle("POST", "/jobs", {
            "command": "rig_check", "--corpora": "synth", "--limit": "1",
            "--out": str(app.results_root / "preflight"),
        })
        assert status == 303
        app.stop_job(location.rsplit("/", 1)[1])
        status, location, _body = app.handle("POST", "/jobs", {
            "command": "rig_check", "--dry-run": "on", "--corpora": "synth",
            "--limit": "1",
            "--out": str(app.results_root / "dry-preflight"),
        })
        assert status == 303
        app.stop_job(location.rsplit("/", 1)[1])
        assert len(captured) == 2
        assert all(captured[0][name] == __import__("os").environ[name] for name in names)
        assert not any(name in captured[1] for name in names)
        deadline = time.time() + 20
        while any(job.state() == "running" for job in app.jobs.values()) and time.time() < deadline:
            time.sleep(0.05)
    finally:
        app.close()
    for flag in ("--project-revision", "--source-conformance"):
        assert "forwards" in _PARAM_HELP[flag] and "Build folds" in _PARAM_HELP[flag]
        assert "forwards" in _PARAM_HELP[flag + "-sha256"]


# -- P1-05: reviewed precomputed attacker inputs ---------------------------------


def test_ideator_builder_replay_is_digest_bound_and_snapshot_materialized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _CLI_ONLY_ATTACKERS == {}
    assert "ideator" in _SUGGEST_STATIC["attackers"]
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        ideator_tag = _opening_tag(page, "data-fw='ideator'")
        assert "disabled" not in ideator_tag
        row = page[page.index("data-fw='ideator'"):]
        row = row[:row.index("</label>")]
        assert "verified seed-pair replay" in row
        assert "id='prepared-ideator'" in page
        assert "name='ideator_manifest'" in page
        assert "name='ideator_manifest_sha'" in page
        assert "name='ideator_pair_limit'" in page
        assert "ura-ideator-seed-pairs/2" in page
        assert "v1 is legacy" in page
        assert "binds every pair to one admitted source row" in page
        assert "syncIdeatorPairLimit" in _BUILDER_SCRIPT

        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
            "+A8AAQUBAScY42YAAAAASUVORK5CYII="
        )
        image = app.results_root / "ideator-pair.png"
        image.write_bytes(png)
        manifest = app.results_root / "ideator-seed-pairs.json"
        manifest.write_text(
            json.dumps({
                "format_version": "ura-ideator-seed-pairs/1",
                "seed_pairs": [{
                    "text": "reviewed text",
                    "image_path": str(image),
                    "image_sha256": hashlib.sha256(png).hexdigest(),
                }],
            }),
            encoding="utf-8",
        )
        params = {
            **_DRY_BASE,
            "attackers": "ideator",
            "ideator_manifest": str(manifest),
            "ideator_manifest_sha": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "ideator_pair_limit": "1",
        }
        assert app._validate_builder(params) == {}
        reviewed, snapshot, _snapshot_sha256 = (
            app._capture_execution_config_snapshot(params)
        )
        assert {
            "attacker_config",
            "attacker_artifact_ideator",
            "attacker_artifact_ideator_image_0000",
        } <= set(snapshot)

        oversized_manifest = app.results_root / "ideator-oversized-text.json"
        oversized_manifest.write_text(
            json.dumps({
                "format_version": "ura-ideator-seed-pairs/1",
                "seed_pairs": [{
                    "text": '"' * 300_000,
                    "image_path": str(image),
                    "image_sha256": hashlib.sha256(png).hexdigest(),
                }],
            }),
            encoding="utf-8",
        )
        oversized_params = {
            **params,
            "ideator_manifest": str(oversized_manifest),
            "ideator_manifest_sha": hashlib.sha256(
                oversized_manifest.read_bytes()
            ).hexdigest(),
        }
        assert "serialized seed text exceeds" in app._validate_builder(
            oversized_params
        )["ideator"]

        # Mutation regression: changing the operator file after review cannot
        # change the launched bytes. A mutation inside the held snapshot is
        # independently rejected by the execution-ticket digest.
        image.write_bytes(png + b"mutated after review")
        selected = app._materialize_prepared_attacker_config(
            reviewed,
            snapshot_payload=snapshot["attacker_config"],
            artifact_snapshots=snapshot,
        )
        assert selected is not None
        emitted = json.loads(selected.read_text(encoding="utf-8"))["ideator"]
        assert set(emitted) == {
            "seed_pairs",
            "seed_pair_image_sha256",
            "pair_limit",
        }
        assert emitted["pair_limit"] == 1
        assert emitted["seed_pair_image_sha256"] == [
            hashlib.sha256(png).hexdigest()
        ]
        held_image = Path(emitted["seed_pairs"][0][1])
        assert held_image.read_bytes() == png
        assert held_image != image.resolve()
        selected_digest = hashlib.sha256(selected.read_bytes()).hexdigest()
        private_paths = app._private_attacker_artifact_paths({
            "--attacker-config": str(selected),
            "--attacker-config-sha256": selected_digest,
        })
        assert held_image in private_paths
        cleanup_registrations: list[tuple[object, tuple[object, ...]]] = []
        monkeypatch.setattr(
            run_matrix.atexit,
            "register",
            lambda callback, *args: cleanup_registrations.append((callback, args)),
        )
        monkeypatch.setenv(
            "URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG", str(selected.resolve())
        )
        operational, artifact_identity = run_matrix._load_attacker_config(
            str(selected),
            ["ideator"],
            selected_digest,
        )
        assert operational["ideator"]["seed_pairs"] == [
            ["reviewed text", str(held_image)]
        ]
        assert operational["ideator"]["pair_limit"] == 1
        assert "seed_pair_image_sha256" not in operational["ideator"]
        assert artifact_identity is not None
        portable_ideator = run_matrix._portable_attacker_configs(operational)[
            "ideator"
        ]
        assert portable_ideator["seed_pairs_identity"][0]["image"][
            "sha256"
        ] == hashlib.sha256(png).hexdigest()
        assert portable_ideator["pair_limit"] == 1
        assert app._projection_params(params)["ideator_pair_limit"] == "1"
        assert app._projection_params(params) != app._projection_params(
            {**params, "ideator_pair_limit": "0"}
        )

        # The reviewed digest remains authoritative across the private
        # Builder-to-Runner handoff, not merely across the operator snapshot.
        mutated_selected = app._materialize_prepared_attacker_config(
            reviewed,
            snapshot_payload=snapshot["attacker_config"],
            artifact_snapshots=snapshot,
        )
        assert mutated_selected is not None
        mutated_emitted = json.loads(
            mutated_selected.read_text(encoding="utf-8")
        )["ideator"]
        mutated_image = Path(mutated_emitted["seed_pairs"][0][1])
        mutated_image.write_bytes(png + b"mutated private handoff")
        mutated_digest = hashlib.sha256(mutated_selected.read_bytes()).hexdigest()
        monkeypatch.setenv(
            "URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG",
            str(mutated_selected.resolve()),
        )
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            run_matrix._load_attacker_config(
                str(mutated_selected),
                ["ideator"],
                mutated_digest,
            )
        assert len(cleanup_registrations) == 2
        assert mutated_image.exists()
        cleanup_callback, cleanup_args = cleanup_registrations[-1]
        cleanup_callback(*cleanup_args)
        assert not mutated_image.exists()
        tampered = dict(snapshot)
        tampered["attacker_artifact_ideator_image_0000"] = png + b"ticket mutation"
        with pytest.raises(ValueError, match="snapshot bytes do not match"):
            app._validate_execution_snapshot(reviewed, tampered)

        assert "ideator" in app._validate_builder(params)
        manifest_bad = {**params, "ideator_manifest_sha": "0" * 64}
        assert "does not match" in app._validate_builder(manifest_bad)["ideator"]
        excessive_pairs = {**params, "ideator_pair_limit": "2"}
        assert "exceeds the verified manifest inventory" in app._validate_builder(
            excessive_pairs
        )["ideator"]
        outside_image = tmp_path / "outside-results.png"
        outside_image.write_bytes(png)
        outside_manifest = app.results_root / "outside-seed-pairs.json"
        outside_manifest.write_text(
            json.dumps({
                "format_version": "ura-ideator-seed-pairs/1",
                "seed_pairs": [{
                    "text": "must not escape",
                    "image_path": str(outside_image),
                    "image_sha256": hashlib.sha256(png).hexdigest(),
                }],
            }),
            encoding="utf-8",
        )
        outside_params = {
            **params,
            "ideator_manifest": str(outside_manifest),
            "ideator_manifest_sha": hashlib.sha256(
                outside_manifest.read_bytes()
            ).hexdigest(),
        }
        assert "under the results root" in app._validate_builder(outside_params)[
            "ideator"
        ]

        # purplellama replays only CyberSecEval rows: any other arm (including
        # synth) is rejected with the adapter's reason; cyberseceval arms pass.
        assert "purplellama" in _SOURCE_RESTRICTED_ATTACKERS
        errors = app._validate_builder({**_DRY_BASE, "attackers": "purplellama"})
        assert "CyberSecEval" in errors["attackers"]
        errors = app._validate_builder({
            **_DRY_BASE, "attackers": "purplellama",
            "corpora": "cyberseceval_mitre,strongreject_official",
        })
        assert "CyberSecEval" in errors["attackers"]
        errors = app._validate_builder({
            **_DRY_BASE, "attackers": "purplellama", "corpora": "cyberseceval_mitre",
        })
        assert "attackers" not in errors
        # A dry canary is composed as --corpora synth whatever the arm boxes
        # say (and needs none), so purplellama is rejected on it too - with or
        # without a cyberseceval arm ticked - before any subprocess exists.
        dry_canary = {
            "mode": "diagnostic_canary", "canary_dry": "on",
            "attackers": "purplellama", "judges": "rules", "seeds": "0",
            "limit": "1", "out": "runs/c",
        }
        for canary_form in (dry_canary, {**dry_canary, "corpora": "cyberseceval_mitre"}):
            errors = app._validate_builder(canary_form)
            assert "CyberSecEval" in errors["attackers"]
            started = len(app.jobs)
            status, _ctype, body = app.handle("POST", "/build", canary_form)
            assert status == 200 and len(app.jobs) == started
            assert "The lane was not started" in body.decode("utf-8")
        # A live canary over a cyberseceval arm keeps purplellama admissible.
        errors = app._validate_builder({
            **dry_canary, "canary_dry": "", "corpora": "cyberseceval_mitre",
        })
        assert "CyberSecEval" not in errors.get("attackers", "")
    finally:
        app.close()


# -- P1-07: export_aggregators on the Run page ----------------------------------


def test_export_aggregators_is_an_allowlisted_acquisition_export(tmp_path: Path) -> None:
    entry = COMMANDS["export_aggregators"]
    assert entry.module == "experiments.export_aggregators"
    groups = {name: title for title, _icon, _ref, names in COMMAND_GROUPS for name in names}
    assert groups["export_aggregators"] == "Acquisition exports"
    source = next(param for param in entry.params if param.flag == "--source")
    assert source.required and "all" in source.choices and "holisafe" in source.choices
    out_root = next(param for param in entry.params if param.flag == "--out-root")
    assert out_root.required and out_root.kind == "path"
    argv = build_argv("export_aggregators", {"--source": "airbench", "--out-root": "runs/corpora"})
    assert argv[2:] == ["experiments.export_aggregators", "--source", "airbench", "--out-root", "runs/corpora"]
    with pytest.raises(ValueError, match="requires --out-root"):
        build_argv("export_aggregators", {"--source": "airbench"})
    with pytest.raises(ValueError, match="must be one of"):
        build_argv("export_aggregators", {"--source": "bogus", "--out-root": "runs/corpora"})
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/commands")[2].decode("utf-8")
        assert "name='command' value='export_aggregators'" in page
        # Missing required fields are rejected before a subprocess exists.
        started = len(app.jobs)
        status, _ctype, body = app.handle("POST", "/jobs", {
            "command": "export_aggregators", "--source": "xstest",
        })
        assert status == 400 and b"requires --out-root" in body
        assert len(app.jobs) == started
    finally:
        app.close()


# -- P1-08: Run-page required markers derive from each module's parser -----------


def _captured_parser(module, probe_argv: list[str]) -> argparse.ArgumentParser:
    holder: dict[str, argparse.ArgumentParser] = {}

    class _Captured(Exception):
        pass

    original = argparse.ArgumentParser.parse_args

    def capture(self, args=None, namespace=None):  # noqa: ANN001
        holder["parser"] = self
        raise _Captured

    argparse.ArgumentParser.parse_args = capture
    try:
        try:
            module.main(probe_argv)
        except _Captured:
            pass
    finally:
        argparse.ArgumentParser.parse_args = original
    assert "parser" in holder, f"{module.__name__} built no parser"
    return holder["parser"]


def test_run_page_required_markers_match_argparse_required_flags(tmp_path: Path) -> None:
    # Every Run-page command marks exactly the flags its module's argparse
    # declares required (mutually exclusive groups are not required flags).
    # The typed controllers add console-side requirements on top of argparse:
    # webui_selftest (never a bare console invocation) and model_acquire (its
    # Build workflow always binds the plan/store/receipt inputs).
    console_required_extra = {"webui_selftest", "model_acquire"}
    for name, entry in COMMANDS.items():
        if name == "rig_check":
            continue  # forwards the run_matrix surface
        if entry.module == "experiments.run_matrix":
            parser = run_matrix.build_parser()
        else:
            module = importlib.import_module(entry.module)
            parser = _captured_parser(module, ["--nonexistent-probe"])
        real_required = {
            option
            for action in parser._actions  # noqa: SLF001
            for option in action.option_strings
            if option.startswith("--") and action.required
        }
        ui_required = {param.flag for param in entry.params if param.required}
        if name in console_required_extra:
            assert real_required <= ui_required, name
        else:
            assert ui_required == real_required, (name, ui_required ^ real_required)
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/commands")[2].decode("utf-8")
    finally:
        app.close()
    # The marker is rendered for each required field of each generic form.
    expected = sum(
        sum(1 for param in entry.params if param.required)
        for name, entry in COMMANDS.items()
        if name not in {"run_matrix", "model_acquire", "ollama_pull", "capture_t3mp3st", "harmbench_capture"}
    )
    assert page.count("class='req' title='required'") == expected
    assert expected > 20


# -- R1-console 1 (D4): HF_TOKEN reaches the export_aggregators child only --------


def test_export_aggregators_child_inherits_hf_token_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The gated DecodingTrust/HoliSafe sources read HF_TOKEN from the child's
    # own environment, so the console forwards the process-memory token to the
    # export_aggregators child exactly as it does for the sealed model_acquire
    # controller - and to no other generic command.  Blank/unset is never
    # forwarded; HUGGING_FACE_HUB_TOKEN is never forwarded.
    monkeypatch.setenv("HF_TOKEN", "hf-fixture-token")
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "must-not-pass")
    app = _app(tmp_path)
    try:
        child = app._generic_child_environment("export_aggregators", {})
        assert child["HF_TOKEN"] == "hf-fixture-token"
        assert "HUGGING_FACE_HUB_TOKEN" not in child
        for other in ("figures", "export_jalmbench", "export_vlsbench", "native_import"):
            assert "HF_TOKEN" not in app._generic_child_environment(other, {}), other
        assert "HF_TOKEN" not in app._run_matrix_child_environment({}, scrub_receipt_env=True)
        monkeypatch.setenv("HF_TOKEN", "   ")
        assert "HF_TOKEN" not in app._generic_child_environment("export_aggregators", {})
        monkeypatch.delenv("HF_TOKEN")
        assert "HF_TOKEN" not in app._generic_child_environment("export_aggregators", {})
        # The Run-page launch path hands that environment to the child.
        monkeypatch.setenv("HF_TOKEN", "hf-fixture-token")
        captured: list[dict[str, str]] = []
        real_popen = subprocess.Popen

        def spy(argv, **kwargs):  # noqa: ANN001
            if isinstance(argv, (list, tuple)) and "experiments.export_aggregators" in argv:
                captured.append(dict(kwargs.get("env") or {}))
                # Never contact a dataset host from a test: run a no-op child
                # with the same environment the console composed.
                argv = [sys.executable, "-c", "pass"]
            return real_popen(argv, **kwargs)

        monkeypatch.setattr(subprocess, "Popen", spy)
        status, location, _body = app.handle("POST", "/jobs", {
            "command": "export_aggregators", "--source": "decodingtrust",
            "--out-root": str(app.results_root / "corpora"),
        })
        assert status == 303
        job = app.jobs[location.rsplit("/", 1)[1]]
        deadline = time.time() + 20
        while job.state() == "running" and time.time() < deadline:
            time.sleep(0.05)
        assert len(captured) == 1
        assert captured[0]["HF_TOKEN"] == "hf-fixture-token"
        assert "HUGGING_FACE_HUB_TOKEN" not in captured[0]
        assert not any(name.endswith("_API_KEY") for name in captured[0])
    finally:
        app.close()


# -- R1-console 4: a required choice has no selectable blank default --------------


def test_required_choice_select_has_no_selectable_blank(tmp_path: Path) -> None:
    # export_aggregators --source is argparse-required with no default and
    # build_argv rejects a blank submission; the Run-page select must agree:
    # a required select carries the required attribute and only a disabled
    # "(select)" prompt, while an optional choices flag keeps "(default)".
    app = _app(tmp_path)
    try:
        source = next(
            param for param in COMMANDS["export_aggregators"].params if param.flag == "--source"
        )
        rendered = app._param_input(source)
        assert rendered.startswith("<select name='--source' required>")
        assert "<option value='' disabled selected>(select)</option>" in rendered
        assert "(default)" not in rendered
        defense = next(param for param in COMMANDS["run_matrix"].params if param.flag == "--defense")
        optional = app._param_input(defense)
        assert optional.startswith("<select name='--defense'>")
        assert "<option value=''>(default)</option>" in optional and "required" not in optional
        page = app.handle("GET", "/commands")[2].decode("utf-8")
        assert "<select name='--source' required>" in page
        assert "<select name='--defense'><option value=''>(default)</option>" in page
        # The fail-closed server contract is unchanged.
        started = len(app.jobs)
        status, _ctype, body = app.handle("POST", "/jobs", {
            "command": "export_aggregators", "--source": "",
            "--out-root": str(app.results_root / "corpora"),
        })
        assert status == 400 and b"requires --source" in body
        assert len(app.jobs) == started
    finally:
        app.close()


# -- R1-console 3: the live preview composes --limit 0 only where admitted ----------


def test_preview_limit_zero_only_for_local_only_measured_lanes() -> None:
    # The JS preview mirrors the server: a blank limit composes --limit 0 only
    # for a measured lane with no hosted target and no hosted LLM judge (the
    # only shape validation admits); hosted paid lanes, probes, and canaries
    # show no fallback, and the summary line prints the same value.
    assert "var localOnlyMeasured=mode==='measured'&&!api.length&&!hostedJudge;" in _BUILDER_SCRIPT
    assert "else if(localOnlyMeasured){parts.push('--limit 0');}" in _BUILDER_SCRIPT
    assert "localOnlyMeasured?'0 (complete release)':'not set'" in _BUILDER_SCRIPT
    assert "mode!=='dry_run'&&!(mode==='diagnostic_canary'" not in _BUILDER_SCRIPT
    # The synchronized sampling control computes the same predicate earlier;
    # inspect the later command-preview instance exercised by this contract.
    hosted_judge_at = _BUILDER_SCRIPT.rindex("var hostedJudge=")
    hosted_judge = _BUILDER_SCRIPT[hosted_judge_at:_BUILDER_SCRIPT.index(";", hosted_judge_at)]
    assert "jg.indexOf('llm')>=0" in hosted_judge
    assert ".modelbox[data-kind='api']" in hosted_judge and "judgeModelValue" in hosted_judge



def test_console_forwards_the_only_bound_on_isolated_engine_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine timeout must reach a console lane as it reaches a CLI lane.

    run_matrix exposes no flag for it: every isolated-runtime bridge and both
    engine seals resolve the bound from the environment. Dropping it pinned
    every console bridge lane to the 300 s default while the identical lane
    honoured the operator's bound from the CLI, so one named lane meant two
    different runs.
    """

    monkeypatch.setenv("URA_ENGINE_TIMEOUT_SECONDS", "1800")
    app = _app(tmp_path)

    live = app._run_matrix_child_environment({}, scrub_receipt_env=False)
    assert live["URA_ENGINE_TIMEOUT_SECONDS"] == "1800"
    # A dry lane scrubs receipts but is still the same execution bound.
    dry = app._run_matrix_child_environment({}, scrub_receipt_env=True)
    assert dry["URA_ENGINE_TIMEOUT_SECONDS"] == "1800"
    # The HarmBench capture drives the same isolated runtime.
    capture = app._generic_child_environment("harmbench_capture", {})
    assert capture["URA_ENGINE_TIMEOUT_SECONDS"] == "1800"
    # It stays a least-privilege environment for unrelated commands.
    assert "URA_ENGINE_TIMEOUT_SECONDS" not in app._generic_child_environment("figures", {})

    # The value the child receives is exactly what the CLI would resolve.
    from ura.adapters._engine_common import _resolve_timeout

    monkeypatch.setenv("URA_ENGINE_TIMEOUT_SECONDS", live["URA_ENGINE_TIMEOUT_SECONDS"])
    assert _resolve_timeout(None) == 1800.0


def test_console_receipt_validation_sees_every_arm_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A console receipt validation must be able to reach every admitted arm.

    ``verify_manifest_components`` with no selected arms checks EVERY admitted
    arm and requires each one's locator to be set, but a validation names no
    --arm, so forwarding only the arms named on the command line left the child
    able to see none of them. The console could then only ever refuse a receipt
    the CLI validates, naming a variable its own parent process holds.
    """

    import json as _json

    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True, exist_ok=True)
    source_config = repo / "experiments" / "source-instances.json"
    source_config.write_text(
        _json.dumps(
            {
                "arm_one": {"path_env": "URA_ARM_ONE_PATH"},
                "arm_two": {"path_env": "URA_ARM_TWO_PATH"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("URA_ARM_ONE_PATH", str(tmp_path / "one.csv"))
    monkeypatch.setenv("URA_ARM_TWO_PATH", str(tmp_path / "two.csv"))

    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    app = RigWebApp(results_root=results, state_dir=tmp_path / "state")
    app.repo_root = repo

    validation = app._generic_child_environment(
        "source_conformance",
        {"--source-config": str(source_config), "--manifest": str(tmp_path / "r.json"),
         "--sha256": "c" * 64},
    )
    assert validation["URA_ARM_ONE_PATH"] == str(tmp_path / "one.csv")
    assert validation["URA_ARM_TWO_PATH"] == str(tmp_path / "two.csv")

    # A scaffold still gets only the arms it names: it hashes those arms alone.
    scaffold = app._generic_child_environment(
        "source_conformance",
        {"--source-config": str(source_config), "--scaffold": "on", "--arm": "arm_one",
         "--out": str(tmp_path / "out.json")},
    )
    assert scaffold["URA_ARM_ONE_PATH"] == str(tmp_path / "one.csv")
    assert "URA_ARM_TWO_PATH" not in scaffold
