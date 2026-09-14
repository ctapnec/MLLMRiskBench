"""Focused model-picker, judge-routing, and truthful Jobs UI regressions."""
from __future__ import annotations

import io
import json
import hashlib
import os
import re
import sqlite3
import time
from pathlib import Path

import pytest

from experiments.local_targets import (
    known_vllm_quantization_issue,
    model_hardware_profile,
)
from experiments.rig_web import RigWebApp
from experiments.rig_web_app.campaigns import _load_campaign
from experiments.rig_web_app.catalog import Command, CommandParam
from ura.targets.api import api_target_requires_config, build_api_target


_HOSTED_A = "openai:judge-cheap"
_HOSTED_B = "openai:judge-expensive"
_LOCAL = "vllm:org/Judge-7B"
_LOCAL_OTHER = "vllm:org/Other-7B"
_PROVIDER_ALIAS_PAIRS = (
    ("anthropic", "claude"),
    ("openai", "gpt"),
    ("google", "gemini"),
    ("glm", "zhipu"),
    ("kimi", "moonshot"),
    ("qwen", "dashscope"),
    ("qwen", "alibaba"),
    ("doubao", "bytedance"),
)
_HOSTED_ROUTE_IDENTITY_PAIRS = (
    (
        "claude-haiku-4-5-20251001",
        "anthropic:claude-haiku-4-5-20251001",
        True,
    ),
    ("gpt-5.1-2025-11-13", "openai:gpt-5.1-2025-11-13", True),
    ("gemini-3.6-flash", "google:gemini-3.6-flash", True),
    ("deepseek-v4-pro", "deepseek:deepseek-v4-pro", True),
    (
        "claude-fable-5",
        "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000",
        True,
    ),
    (
        "openai:gpt-5.6-sol",
        "openai-responses:gpt-5.6-sol;reasoning_mode=pro;"
        "reasoning_effort=medium;reasoning_context=all_turns",
        False,
    ),
)


def _gpu(vram_gib: float = 24.0) -> dict[str, object]:
    return {
        "available": True,
        "source": "fixture",
        "gpu_count": 1,
        "aggregate_vram_gib": vram_gib,
        "max_gpu_vram_gib": vram_gib,
        "gpus": [{
            "index": 0,
            "name": "fixture GPU",
            "memory_total_mib": int(vram_gib * 1024),
            "vram_gib": vram_gib,
            "compute_capability": "8.9",
        }],
    }


def _repo_app(
    tmp_path: Path,
    *,
    api: dict[str, object] | None = None,
    local: dict[str, object] | None = None,
    roster: dict[str, object] | None = None,
    pricing: dict[str, object] | None = None,
) -> RigWebApp:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "api-targets.example.json").write_text(
        json.dumps(api or {
            _HOSTED_A: {
                "modalities": ["text"], "max_tokens": 1024, "temperature": 0.0,
            },
            _HOSTED_B: {
                "modalities": ["text", "image"],
                "max_tokens": 2048,
                "temperature": 0.0,
            },
        }),
        encoding="utf-8",
    )
    local_entries = local or {
            _LOCAL: {
                "revision": "a" * 40,
                "modalities": ["text"],
                "parameter_count_b": 7,
                "tensor_parallel_size": 1,
            },
        }
    (rig / "local-targets.example.json").write_text(
        json.dumps(local_entries),
        encoding="utf-8",
    )
    evidence = repo / "profile-readiness.json"
    evidence.write_text("{}\n", encoding="utf-8")
    profiles: dict[str, object] = {}
    for spec, value in local_entries.items():
        if not isinstance(value, dict):
            continue
        identity_key = "revision" if "revision" in value else "digest"
        identity = value.get(identity_key)
        modalities = value.get("modalities")
        if (
            not isinstance(identity, str)
            or not isinstance(modalities, list)
            or "text" not in modalities
        ):
            continue
        profiles[spec] = {
            "generation_tokens": 4096,
            "identity": {identity_key: identity.lower()},
            "local_execution": (
                {
                    "gpu_memory_utilization": value.get(
                        "gpu_memory_utilization", 0.9
                    ),
                    "max_model_len": -1,
                    "tensor_parallel_size": (
                        value.get("tensor_parallel_size")
                        if value.get("tensor_parallel_size") in {1, 2}
                        else 1
                    ),
                }
                if spec.startswith("vllm:")
                else {"num_ctx": "fit", "think": value.get("think", False)}
            ),
            "modalities": list(modalities),
            "readiness": {
                "path": str(evidence.resolve()),
                "sha256": "c" * 64,
                "readiness_id": "d" * 64,
            },
            "request_timeout_seconds": 120.0,
        }
    (repo / "experiments" / "local-model-profiles.json").write_text(
        json.dumps({
            "schema": "ura-local-model-execution-profiles/3",
            "models": profiles,
        }),
        encoding="utf-8",
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps(roster or {"vllm_version": "0.27.1", "models": {}}),
        encoding="utf-8",
    )
    if pricing is not None:
        (repo / "experiments" / "pricing.json").write_text(
            json.dumps(pricing), encoding="utf-8"
        )
    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_gpu(),
    )
    # This test module exercises picker/judge contracts, not daemon discovery.
    app._ollama_roster_snapshot = lambda **_kwargs: {  # type: ignore[method-assign]
        "models": [], "excluded": [],
    }
    return app


def _model_selection_tags(document: str) -> list[str]:
    return re.findall(
        r"<input\b[^>]*class='modelbox'[^>]*>", document
    )


def _paid_probe_form(*, out: str) -> dict[str, str]:
    return {
        "mode": "attestation_probe",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
        "seeds": "0",
        "sample_seed": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
        "cap_target": "1",
        "cap_judge": "1",
        "cap_http": "3",
        "deadline": "600",
        "scope": "ticket-config-scope",
        "out": out,
    }


def _write_source_registry(app: RigWebApp) -> Path:
    path = app.repo_root / "experiments" / "source-instances.json"
    path.write_text(json.dumps({
        "harmbench_text": {
            "converter": "harmbench",
            "path_env": "URA_HARMBENCH_TEXT_PATH",
            "source_label": "HarmBench text fixture",
            "split": "official-text",
        },
    }), encoding="utf-8")
    return path


def _bind_fixture_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    project = tmp_path / "project-revision.json"
    project.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    source = tmp_path / "source-conformance.json"
    source.write_text('{"schema":"fixture-source"}\n', encoding="utf-8")
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project))
    monkeypatch.setenv(
        "URA_PROJECT_REVISION_SHA256",
        hashlib.sha256(project.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(source))
    monkeypatch.setenv(
        "URA_SOURCE_CONFORMANCE_SHA256",
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    return project, source


def _api_registry_entry(spec: str) -> dict[str, object]:
    """Return an executable registry fixture for one hosted route."""

    if not api_target_requires_config(spec):
        return {"modalities": list(build_api_target(spec).modality_support)}
    return {
        "modalities": ["text"],
        "max_tokens": 1024,
        "temperature": 0.0,
    }


def test_shared_picker_is_accessible_and_keeps_target_and_judge_state_isolated(
    tmp_path: Path,
) -> None:
    app = _repo_app(tmp_path)
    text = app._build_page(prefill={"judge_model": _HOSTED_B}).decode("utf-8")

    assert "data-open-model-picker='target'" in text
    assert "data-open-model-picker='judge'" in text
    assert "role='dialog'" in text and "aria-modal='true'" in text
    assert "aria-hidden='true' hidden" in text
    assert "data-picker-kind='api'" in text and "data-picker-kind='local'" in text
    assert "id='api-provider-filter'" in text
    for control in (
        "local-name-filter", "local-param-range", "local-param-number",
        "local-compatible-filter", "local-unknown-filter",
    ):
        assert f"id='{control}'" in text

    # Each card owns exactly one native selection input. The same input is a
    # target checkbox/radio or a judge radio depending on the caller; rendering
    # separate hidden role controls caused two visible selectors under author CSS.
    model_tags = _model_selection_tags(text)
    assert len(model_tags) == text.count("<div class='modelrow'") == 3
    assert text.count("class='modelbox'") == 3
    assert "judge-modelbox" not in text
    assert "data-judge-for" not in text and "data-target-for" not in text
    assert all("data-target-selected='false'" in tag for tag in model_tags)
    assert sum("type='checkbox'" in tag for tag in model_tags) == 2
    assert sum("type='radio'" in tag for tag in model_tags) == 1
    for tag in model_tags:
        control_id = re.search(r"\bid='([^']+)'", tag)
        assert control_id is not None
        assert f"for='{control_id.group(1)}'" in text
    assert "id='judge-model-input' name='judge_model'" in text
    assert f"value='{_HOSTED_B}'" in text
    assert "hosted Haiku judge" not in text

    # Step one itself is the back-navigation control; no redundant button is
    # rendered inside step two. The second step becomes revisit-able only after
    # a runtime has been chosen.
    assert "data-picker-step='runtime'" in text
    assert "aria-controls='model-picker-runtime'" in text
    assert "data-picker-step='models'" in text
    assert "Back to runtime" not in text and "model-picker-back" not in text

    # The dialog restores/traps focus and synchronizes its exposed state.
    for contract in (
        "event.key==='Escape'", "event.target===picker", "pickerLastFocus.focus()",
        "event.key!=='Tab'", "setAttribute('aria-hidden','false')",
        "setAttribute('aria-hidden','true')", "setAttribute('aria-expanded','false')",
    ):
        assert contract in text
    # Role-specific semantics are switched on that single input while target
    # state and the hidden submitted judge value remain independent.
    assert "input.type='radio';input.name='_judge_model_ui'" in text
    assert "input.type=input.getAttribute('data-target-type')||'checkbox'" in text
    assert "data-target-selected" in text
    assert "rememberPickerSelection();" in text
    assert "var llmStage=form.querySelector(\".judgebox[data-judge='llm']\");" in text
    assert "if(llmStage){llmStage.checked=true;}" in text
    assert "setPickerRole('target')" in text
    app.close()


def test_picker_has_one_selector_per_hosted_vllm_and_ollama_row_and_safe_layout(
    tmp_path: Path,
) -> None:
    ollama = "ollama:fixture-unique:latest"
    app = _repo_app(tmp_path, local={
        _LOCAL: {
            "revision": "a" * 40,
            "modalities": ["text"],
            "parameter_count_b": 7,
            "tensor_parallel_size": 1,
        },
        ollama: {"digest": "b" * 64, "modalities": ["text"]},
    })
    page = app._build_page().decode("utf-8")
    style = app.handle("GET", "/static/style.css")[2].decode("utf-8")

    tags = _model_selection_tags(page)
    assert len(tags) == page.count("<div class='modelrow'") == 4
    assert page.count("data-backend='vllm'") == 1
    assert page.count("data-backend='ollama'") == 1
    assert page.count("class='modelbox'") == 4
    assert "judge-modelbox" not in page

    # The local filter UI belongs only to the vLLM list. Ollama is a separate
    # daemon inventory and therefore follows modality scope without inheriting
    # the vLLM name, size, fit, count, or empty-state semantics.
    local_count_at = page.index("id='local-filter-count'")
    vllm_list_at = page.index("id='vllm-target-list'")
    ollama_list_at = page.index("id='ollama-target-list'")
    assert local_count_at < vllm_list_at < ollama_list_at
    assert "else if(kind==='local'&&backend==='ollama')" not in page
    assert (
        "if(visible&&kind==='local'&&backend==='vllm'){counts.local++;}"
        in page
    )

    # Grid tracks can shrink to the containing modal/card instead of imposing
    # a wider intrinsic minimum; the vLLM range/number pair stacks on phones.
    for contract in (
        "minmax(min(14rem,100%),1fr)",
        "minmax(min(290px,100%),1fr)",
        "grid-template-columns:minmax(0,1fr) minmax(5.5rem,7rem)",
        ".paramfilter > * { min-width:0; max-width:100%; }",
        ".paramfilter { grid-template-columns:1fr; }",
        ".modelquant select { width:min(100%,24rem); min-width:0; max-width:100%; }",
    ):
        assert contract in style
    app.close()


def test_profiled_vllm_topology_reaches_materialized_ui_config(
    tmp_path: Path,
) -> None:
    app = _repo_app(
        tmp_path,
        local={
            _LOCAL: {
                "revision": "a" * 40,
                "modalities": ["text"],
                "parameter_count_b": 7,
                "tensor_parallel_size": 2,
                "gpu_memory_utilization": 0.85,
            }
        },
    )
    try:
        path = app._materialize_selected_local_config([_LOCAL])
        selected = json.loads(path.read_text(encoding="utf-8"))[_LOCAL]
        assert selected["tensor_parallel_size"] == 2
        assert selected["gpu_memory_utilization"] == 0.85
        assert "TP2" in app._build_page().decode("utf-8")
    finally:
        app.close()


def test_expensive_warning_comes_from_comparable_pricing_and_is_judge_only(
    tmp_path: Path,
) -> None:
    pricing = {
        "providers": {"openai": {"models": {
            "judge-cheap": {"rates": [{
                "effective_date": "2026-01-01", "currency": "USD",
                "per_million_tokens": {"input": 1.0, "output": 2.0},
            }]},
            "judge-expensive": {"rates": [{
                "effective_date": "2026-01-01", "currency": "USD",
                "per_million_tokens": {"input": 10.0, "output": 30.0},
            }]},
        }}},
    }
    app = _repo_app(tmp_path, pricing=pricing)
    text = app.handle("GET", "/build")[2].decode("utf-8")
    style = app.handle("GET", "/static/style.css")[2].decode("utf-8")

    assert text.count("<span class='badge amber tip judge-cost-warning'") == 1
    assert "Highest configured current input + output judging rate" in text
    assert "40 USD per one million input + output tokens" in text
    assert ".model-picker[data-role=target] .judge-cost-warning" in style
    assert "display:none;" in style
    assert "aria-label='Warning: expensive judge model'" in text
    app.close()


def test_hosted_provider_filter_uses_canonical_execution_families(
    tmp_path: Path,
) -> None:
    fable = (
        "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000"
    )
    sol = (
        "openai-responses:gpt-5.6-sol;reasoning_mode=pro;"
        "reasoning_effort=medium;reasoning_context=all_turns"
    )
    app = _repo_app(tmp_path, api={
        fable: _api_registry_entry(fable),
        sol: _api_registry_entry(sol),
        "claude:alias-model": _api_registry_entry("claude:alias-model"),
        "zhipu:alias-model": _api_registry_entry("zhipu:alias-model"),
    })
    page = app._build_page().decode("utf-8")

    assert page.count("<option value='anthropic'>anthropic</option>") == 1
    assert page.count("<option value='openai'>openai</option>") == 1
    assert page.count("<option value='glm'>glm</option>") == 1
    assert "<option value='anthropic-fable'>" not in page
    assert "<option value='openai-responses'>" not in page
    assert "<option value='claude'>" not in page
    assert "<option value='zhipu'>" not in page
    for spec, provider in (
        (fable, "anthropic"),
        (sol, "openai"),
        ("claude:alias-model", "anthropic"),
        ("zhipu:alias-model", "glm"),
    ):
        at = page.index(f"data-model='{spec}'")
        row = page[page.rfind("<div class='modelrow'", 0, at):at]
        assert f"data-provider='{provider}'" in row
    app.close()


def test_server_validates_explicit_judge_and_local_engine_conflicts(
    tmp_path: Path,
) -> None:
    local = {
        spec: {
            "revision": revision * 40,
            "modalities": ["text"],
            "parameter_count_b": 7,
            "tensor_parallel_size": 1,
        }
        for spec, revision in ((_LOCAL, "a"), (_LOCAL_OTHER, "b"))
    }
    app = _repo_app(tmp_path, local=local)
    base = {
        "mode": "measured",
        "api": _HOSTED_A,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules,llm",
        "seeds": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
    }

    assert "choose an explicit" in app._validate_builder(base)["judge_model"]
    assert "unknown" in app._validate_builder({
        **base, "judge_model": "openai:crafted-not-in-roster",
    })["judge_model"]
    assert "differ" in app._validate_builder({
        **base, "judge_model": _HOSTED_A,
    })["judge_model"]
    assert "judge_model" not in app._validate_builder({
        **base, "judge_model": _LOCAL,
    })
    stale_selection = {
        **base,
        "judges": "rules",
        "judge_model": _LOCAL,
    }
    assert "requires enabling the llm judge stage" in app._validate_builder(
        stale_selection
    )["judge_model"]
    status, _headers, body = app.handle("POST", "/build", stale_selection)
    assert status == 200
    assert b"requires enabling the llm judge stage" in body
    assert app.jobs == {}
    local_pair = {
        **base, "api": "", "local": _LOCAL,
        "judge_model": _LOCAL_OTHER,
    }
    assert "judge_model" not in app._validate_builder(local_pair)
    for mode in ("attestation_probe", "diagnostic_canary", "measured"):
        assert "judge_model" not in app._validate_builder({
            **local_pair,
            "mode": mode,
        })
    assert "response-independent" in app._validate_builder({
        **local_pair,
        "attackers": "crescendo",
    })["judge_model"]
    app.close()


@pytest.mark.parametrize(("canonical", "alias"), _PROVIDER_ALIAS_PAIRS)
def test_builder_rejects_provider_alias_duplicate_targets_and_self_judge_before_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    canonical: str,
    alias: str,
) -> None:
    model = "shared-account-model"
    target_spec = f"{alias}:{model}"
    equivalent_spec = f"{canonical}:{model}"
    app = _repo_app(tmp_path, api={
        target_spec: _api_registry_entry(target_spec),
        equivalent_spec: _api_registry_entry(equivalent_spec),
    })
    starts: list[object] = []
    monkeypatch.setattr(
        app,
        "start_job",
        lambda *_args, **_kwargs: starts.append(object()),
    )
    common = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "seeds": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
        "out": "runs/alias-rejection",
    }
    try:
        self_judge = {
            **common,
            "api": target_spec,
            "judges": "rules,llm",
            "judge_model": equivalent_spec,
        }
        errors = app._validate_builder(self_judge)
        assert "provider-alias resolution" in errors["judge_model"]
        status, _, body = app.handle("POST", "/build", self_judge)
        assert status == 200
        assert b"provider-alias resolution" in body

        duplicate_targets = {
            **common,
            "api": f"{target_spec},{equivalent_spec}",
            "judges": "rules",
        }
        errors = app._validate_builder(duplicate_targets)
        assert "provider-alias resolution" in errors["models"]
        status, _, body = app.handle("POST", "/build", duplicate_targets)
        assert status == 200
        assert b"provider-alias resolution" in body
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


@pytest.mark.parametrize(
    ("first", "second", "same_condition"),
    _HOSTED_ROUTE_IDENTITY_PAIRS,
)
def test_builder_rejects_bare_and_inherent_route_identity_collisions_before_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    first: str,
    second: str,
    same_condition: bool,
) -> None:
    app = _repo_app(tmp_path, api={
        first: _api_registry_entry(first),
        second: _api_registry_entry(second),
    })
    starts: list[object] = []
    monkeypatch.setattr(
        app,
        "start_job",
        lambda *_args, **_kwargs: starts.append(object()),
    )
    common = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "seeds": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
        "out": "runs/route-identity-rejection",
    }
    try:
        self_judge = {
            **common,
            "api": first,
            "judges": "rules,llm",
            "judge_model": second,
        }
        errors = app._validate_builder(self_judge)
        assert "hosted-route identity resolution" in errors["judge_model"]
        status, _, body = app.handle("POST", "/build", self_judge)
        assert status == 200
        assert b"hosted-route identity resolution" in body

        duplicate_targets = {
            **common,
            "api": f"{first},{second}",
            "judges": "rules",
        }
        errors = app._validate_builder(duplicate_targets)
        if same_condition:
            assert "hosted-route identity resolution" in errors["models"]
            status, _, body = app.handle("POST", "/build", duplicate_targets)
            assert status == 200
            assert b"hosted-route identity resolution" in body
        else:
            assert "models" not in errors
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_builder_rejects_duplicate_local_digests_and_self_judge_before_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    first = "ollama:alias-a"
    second = "ollama:alias-b"
    entry = {"digest": digest, "modalities": ["text"]}
    app = _repo_app(tmp_path, local={first: entry, second: entry})
    starts: list[object] = []
    monkeypatch.setattr(
        app,
        "start_job",
        lambda *_args, **_kwargs: starts.append(object()),
    )
    common = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "seeds": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
        "out": "runs/local-identity-rejection",
    }
    try:
        self_judge = {
            **common,
            "local": first,
            "judges": "rules,llm",
            "judge_model": second,
        }
        errors = app._validate_builder(self_judge)
        assert "immutable content-identity" in errors["judge_model"]
        status, _, body = app.handle("POST", "/build", self_judge)
        assert status == 200
        assert b"immutable content-identity" in body

        duplicate_targets = {
            **common,
            "local": f"{first},{second}",
            "judges": "rules",
        }
        errors = app._validate_builder(duplicate_targets)
        assert "immutable content-identity" in errors["models"]
        status, _, body = app.handle("POST", "/build", duplicate_targets)
        assert status == 200
        assert b"immutable content-identity" in body
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_builder_rejects_cross_provider_same_custom_endpoint_before_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://same.example/v1"
    target = "glm:same-model"
    judge = "kimi:same-model"
    config = {
        "modalities": ["text"],
        "max_tokens": 64,
        "temperature": 0.0,
        "base_url": endpoint,
    }
    app = _repo_app(tmp_path, api={target: config, judge: config})
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("start")
    )
    params = {
        "mode": "measured",
        "api": target,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules,llm",
        "judge_model": judge,
        "ack_hosted_judge_data_transfer": "on",
        "seeds": "0",
        "sample_seed": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
        "out": "runs/same-endpoint",
    }
    try:
        errors = app._validate_builder(params)
        assert "endpoint identity resolution" in errors["judge_model"]
        status, _headers, body = app.handle("POST", "/build", params)
        assert status == 200
        assert b"endpoint identity resolution" in body
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_builder_rejects_compatible_route_impersonating_native_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = "gpt-5.6-sol"
    native = f"openai:{model}"
    compatible = f"deepseek:{model}"
    base = {"modalities": ["text"], "max_tokens": 64, "temperature": 0.0}
    app = _repo_app(tmp_path, api={
        native: base,
        compatible: {**base, "base_url": "https://api.openai.com/v1"},
    })
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("start")
    )
    common = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "seeds": "0",
        "sample_seed": "0",
        "limit": "1",
        "max_queries": "1",
        "max_turns": "1",
        "out": "runs/native-endpoint-alias",
    }
    try:
        self_judge = {
            **common,
            "api": native,
            "judges": "rules,llm",
            "judge_model": compatible,
            "ack_hosted_judge_data_transfer": "on",
        }
        assert "endpoint identity" in app._validate_builder(self_judge)[
            "judge_model"
        ]

        duplicate = {
            **common,
            "api": f"{native},{compatible}",
            "judges": "rules",
        }
        assert "endpoint identity" in app._validate_builder(duplicate)["models"]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_paid_ticket_burns_when_selected_api_registry_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "glm:ticket-model"
    first = {
        "modalities": ["text"], "max_tokens": 64, "temperature": 0.0,
        "base_url": "https://first.example/v1",
    }
    second = {
        **first,
        "max_tokens": 128,
        "base_url": "https://second.example/v1",
    }
    app = _repo_app(tmp_path, api={spec: first})
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 3}, ""
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("start")
    )
    form = {**_paid_probe_form(out="runs/api-ticket"), "api": spec}
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None, body.decode("utf-8", errors="replace")
        ticket = match.group(1).decode("ascii")

        registry = app.repo_root / "experiments" / "rig" / "api-targets.example.json"
        registry.write_text(json.dumps({spec: second}), encoding="utf-8")
        rejected = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        replayed = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        assert rejected[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in rejected[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_paid_ticket_burns_when_selected_local_registry_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "vllm:org/Ticket-7B"
    first = {
        "revision": "a" * 40,
        "modalities": ["text"],
        "parameter_count_b": 7,
        "tensor_parallel_size": 1,
        "max_model_len": 4096,
    }
    second = {**first, "revision": "b" * 40, "max_model_len": 8192}
    app = _repo_app(tmp_path, local={spec: first})
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 0}, ""
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("start")
    )
    form = {**_paid_probe_form(out="runs/local-ticket"), "local": spec}
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None
        ticket = match.group(1).decode("ascii")

        registry = app.repo_root / "experiments" / "rig" / "local-targets.example.json"
        registry.write_text(json.dumps({spec: second}), encoding="utf-8")
        rejected = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        replayed = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        assert rejected[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in rejected[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_real_source_without_executable_registry_never_reaches_job_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("started")
    )
    form = {
        **_paid_probe_form(out="runs/missing-source-registry"),
        "api": _HOSTED_A,
        "corpora": "harmbench_text",
    }
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        assert b"require the executable operator registry" in body
        assert b"name='launch_ticket'" not in body
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


@pytest.mark.parametrize("mutation", ["source_registry", "source_receipt"])
def test_paid_ticket_burns_on_selected_source_snapshot_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    app = _repo_app(tmp_path)
    registry = _write_source_registry(app)
    _project, source_receipt = _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 1},
            "",
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("started")
    )
    form = {
        **_paid_probe_form(out=f"runs/source-ticket-{mutation}"),
        "api": _HOSTED_A,
        "corpora": "harmbench_text",
    }
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None
        ticket = match.group(1).decode("ascii")

        if mutation == "source_registry":
            registry.write_text(json.dumps({
                "harmbench_text": {"converter": "synth", "synth": True},
            }), encoding="utf-8")
        else:
            source_receipt.write_text(
                '{"schema":"changed-source"}\n', encoding="utf-8"
            )

        rejected = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        replayed = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        assert rejected[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in rejected[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_private_source_snapshot_survives_registry_change_at_popen_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    registry = _write_source_registry(app)
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 1},
            "",
        ),
    )
    observed: dict[str, object] = {}

    class FakeProcess:
        pid = 9292

        @staticmethod
        def poll() -> int:
            return 0

    def fake_popen(argv, **kwargs):
        registry.write_text(json.dumps({
            "harmbench_text": {"converter": "synth", "synth": True},
        }), encoding="utf-8")
        launch = list(argv)
        source_path = Path(launch[launch.index("--source-config") + 1])
        expected = launch[launch.index("--source-config-sha256") + 1]
        raw = source_path.read_bytes()
        observed.update({
            "path": str(source_path),
            "config": json.loads(raw.decode("utf-8")),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "expected": expected,
            "marker": (kwargs.get("env") or {}).get(
                "URA_PRIVATE_TRANSIENT_SOURCE_CONFIG"
            ),
        })
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    form = {
        **_paid_probe_form(out="runs/source-barrier"),
        "api": _HOSTED_A,
        "corpora": "harmbench_text",
    }
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None
        confirmed = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": match.group(1).decode("ascii"),
        })
        assert confirmed[0] == 303
        assert observed["sha256"] == observed["expected"]
        assert observed["marker"] == observed["path"]
        assert observed["config"] == {
            "harmbench_text": {
                "converter": "harmbench",
                "path_env": "URA_HARMBENCH_TEXT_PATH",
                "source_label": "HarmBench text fixture",
                "split": "official-text",
                "synth": False,
            },
        }
        job = next(iter(app.jobs.values()))
        durable = json.dumps({
            "argv": job.argv,
            "params": job.builder_params,
            "command": (job.directory / "command.json").read_text(
                encoding="utf-8"
            ),
        }, sort_keys=True)
        assert str(observed["path"]) not in durable
        assert "private-source-config@sha256:" in durable
    finally:
        app.close()


@pytest.mark.parametrize("evidence", ["project_revision", "live_attestation"])
def test_paid_ticket_burns_on_project_or_attestation_byte_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    evidence: str,
) -> None:
    app = _repo_app(tmp_path)
    project, _source = _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 1},
            "",
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("started")
    )
    form = {
        **_paid_probe_form(out=f"runs/{evidence}-ticket"),
        "api": _HOSTED_A,
    }
    changed = project
    if evidence == "live_attestation":
        changed = tmp_path / "live-attestation.json"
        changed.write_text('{"schema":"attestation-a"}\n', encoding="utf-8")
        form.update({
            "mode": "measured",
            "max_age": "24",
            "att_path1": str(changed),
            "att_sha1": hashlib.sha256(changed.read_bytes()).hexdigest(),
        })
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None, body.decode("utf-8", errors="replace")
        ticket = match.group(1).decode("ascii")
        changed.write_text(
            f'{{"schema":"changed-{evidence}"}}\n', encoding="utf-8"
        )

        rejected = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        replayed = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        assert rejected[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in rejected[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_paid_ticket_burns_when_t3mp3st_prepared_artifact_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 1},
            "",
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("started")
    )
    artifact = app.results_root / "t3mp3st-plan.json"

    def write_artifact(provider: str) -> None:
        artifact.write_text(json.dumps({
            "format_version": "ura-t3mp3st-plan-bundle/1",
            "upstream_revision": "a" * 40,
            "source_provider": provider,
            "source_model": "fixture-model",
        }), encoding="utf-8")

    write_artifact("provider-a")
    attestation = tmp_path / "t3mp3st-attestation.json"
    attestation.write_text('{"schema":"fixture-attestation"}\n', encoding="utf-8")
    form = {
        **_paid_probe_form(out="runs/t3mp3st-ticket"),
        "mode": "diagnostic_canary",
        "max_age": "24",
        "att_path1": str(attestation),
        "att_sha1": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "api": _HOSTED_A,
        "attackers": "t3mp3st",
        "t3_artifact": str(artifact),
        "t3_artifact_sha": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None, body.decode("utf-8", errors="replace")
        ticket = match.group(1).decode("ascii")
        write_artifact("provider-b")

        rejected = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        replayed = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        assert rejected[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in rejected[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_paid_ticket_burns_when_harmbench_prepared_config_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    _write_source_registry(app)
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 1},
            "",
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("started")
    )

    def replay_bundle(name: str, revision: str) -> tuple[Path, str]:
        path = app.results_root / name
        path.write_text(json.dumps({
            "format_version": "ura-harmbench-transfer-replay/1",
            "upstream_revision": revision,
            "experiment": "fixture-model",
            "methods": ["PEZ"],
            "cases_per_method": 1,
            "selection": {
                "corpus_name": "harmbench_text",
                "limit": 1,
                "sample_seed": 0,
            },
            "source_artifact": {},
            "source_requests": [],
            "cases": [],
            "content_sha256": "d" * 64,
        }), encoding="utf-8")
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    first, first_sha = replay_bundle("harm-a.json", "a" * 40)
    second, second_sha = replay_bundle("harm-b.json", "b" * 40)
    config = app.results_root / "harm-config.json"

    def write_config(path: Path, digest: str, revision: str) -> None:
        config.write_text(json.dumps({"harmbench": {
            "methods": ["PEZ"],
            "experiment": "fixture-model",
            "upstream_revision": revision,
            "replay_artifact": str(path),
            "replay_artifact_sha256": digest,
        }}), encoding="utf-8")

    write_config(first, first_sha, "a" * 40)
    attestation = tmp_path / "attestation.json"
    attestation.write_text('{"schema":"fixture-attestation"}\n', encoding="utf-8")
    form = {
        **_paid_probe_form(out="runs/harm-ticket"),
        "mode": "diagnostic_canary",
        "max_age": "24",
        "att_path1": str(attestation),
        "att_sha1": hashlib.sha256(attestation.read_bytes()).hexdigest(),
        "api": _HOSTED_A,
        "corpora": "harmbench_text",
        "attackers": "harmbench",
        "harm_config": str(config),
    }
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None, body.decode("utf-8", errors="replace")
        ticket = match.group(1).decode("ascii")
        write_config(second, second_sha, "b" * 40)

        rejected = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        replayed = app.handle(
            "POST", "/build", {"confirm": "yes", "launch_ticket": ticket}
        )
        assert rejected[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in rejected[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert starts == [] and app.jobs == {}
    finally:
        app.close()


def test_private_harmbench_snapshot_survives_config_change_at_popen_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    _write_source_registry(app)

    def replay_bundle(name: str, revision: str) -> tuple[Path, str]:
        path = app.results_root / name
        path.write_text(json.dumps({
            "format_version": "ura-harmbench-transfer-replay/1",
            "upstream_revision": revision,
            "experiment": "fixture-model",
            "methods": ["PEZ"],
            "cases_per_method": 1,
            "selection": {
                "corpus_name": "harmbench_text",
                "limit": 1,
                "sample_seed": 0,
            },
            "source_artifact": {},
            "source_requests": [],
            "cases": [],
            "content_sha256": "c" * 64,
        }), encoding="utf-8")
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    first, first_sha = replay_bundle("barrier-a.json", "a" * 40)
    second, second_sha = replay_bundle("barrier-b.json", "b" * 40)
    config = app.results_root / "barrier-harm-config.json"

    def write_config(path: Path, digest: str, revision: str) -> None:
        config.write_text(json.dumps({"harmbench": {
            "methods": ["PEZ"],
            "experiment": "fixture-model",
            "upstream_revision": revision,
            "replay_artifact": str(path),
            "replay_artifact_sha256": digest,
        }}), encoding="utf-8")

    write_config(first, first_sha, "a" * 40)
    params = app._bind_selected_execution_config_identity({
        "mode": "dry_run",
        "corpora": "harmbench_text",
        "attackers": "harmbench",
        "judges": "rules",
        "harm_config": str(config),
        "out": "runs/harm-barrier",
    })
    params = app._bind_execution_config_bundle_identity(params)
    source_path, source_sha = app._materialize_selected_source_config(params)
    attacker_path = app._materialize_prepared_attacker_config(params)
    assert source_path is not None and source_sha is not None
    assert attacker_path is not None
    attacker_sha = hashlib.sha256(attacker_path.read_bytes()).hexdigest()
    observed: dict[str, object] = {}

    class FakeProcess:
        pid = 9494

        @staticmethod
        def poll() -> int:
            return 0

    def fake_popen(argv, **kwargs):
        write_config(second, second_sha, "b" * 40)
        launch = list(argv)
        selected_path = Path(launch[launch.index("--attacker-config") + 1])
        expected = launch[launch.index("--attacker-config-sha256") + 1]
        raw = selected_path.read_bytes()
        observed.update({
            "path": str(selected_path),
            "entry": json.loads(raw.decode("utf-8"))["harmbench"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "expected": expected,
            "marker": (kwargs.get("env") or {}).get(
                "URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG"
            ),
        })
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    try:
        job = app.start_job("run_matrix", {
            "--dry-run": "on",
            "--corpora": "harmbench_text",
            "--source-config": str(source_path),
            "--source-config-sha256": source_sha,
            "--attackers": "harmbench",
            "--attacker-config": str(attacker_path),
            "--attacker-config-sha256": attacker_sha,
            "--judges": "rules",
            "--out": "runs/harm-barrier",
        }, builder_params=params, scrub_receipt_env=True)
        assert observed["sha256"] == observed["expected"] == attacker_sha
        assert observed["marker"] == observed["path"]
        assert observed["entry"] == {
            "experiment": "fixture-model",
            "methods": ["PEZ"],
            "replay_artifact": str(first.resolve()),
            "replay_artifact_sha256": first_sha,
            "upstream_revision": "a" * 40,
        }
        durable = json.dumps({
            "argv": job.argv,
            "params": job.builder_params,
            "command": (job.directory / "command.json").read_text(
                encoding="utf-8"
            ),
        }, sort_keys=True)
        assert str(attacker_path) not in durable
        assert "private-attacker-config@sha256:" in durable
    finally:
        app.close()


def test_private_api_snapshot_survives_registry_change_at_popen_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "glm:barrier-model"
    first = {
        "modalities": ["text"], "max_tokens": 64, "temperature": 0.0,
        "base_url": "https://first.example/v1",
    }
    second = {
        **first,
        "max_tokens": 128,
        "base_url": "https://second.example/v1",
    }
    app = _repo_app(tmp_path, api={spec: first})
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 0, "http_attempts": 3}, ""
        ),
    )
    observed: dict[str, object] = {}
    registry = app.repo_root / "experiments" / "rig" / "api-targets.example.json"

    class FakeProcess:
        pid = 9191
        returncode = 0

        def poll(self) -> int:
            return 0

    def fake_popen(argv, **_kwargs):
        registry.write_text(json.dumps({spec: second}), encoding="utf-8")
        launch = list(argv)
        path = Path(launch[launch.index("--api-config") + 1])
        expected = launch[launch.index("--api-config-sha256") + 1]
        raw = path.read_bytes()
        observed["config"] = json.loads(raw.decode("utf-8"))
        observed["sha256"] = hashlib.sha256(raw).hexdigest()
        observed["expected"] = expected
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    form = {**_paid_probe_form(out="runs/api-barrier"), "api": spec}
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None
        confirmed = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": match.group(1).decode("ascii"),
        })
        assert confirmed[0] == 303
        assert observed["sha256"] == observed["expected"]
        assert observed["config"] == {spec: first}
        assert "second.example" not in json.dumps(observed)
    finally:
        app.close()


def test_run_matrix_child_receives_only_selected_credentials_and_source_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    source_config = _write_source_registry(app)
    api_config = app.repo_root / "experiments" / "rig" / "api-targets.example.json"
    attacker_config = app.results_root / "attacker-config.json"
    attacker_config.write_text(json.dumps({
        "replay": {"credential_env": "ATTACKER_ONLY_TOKEN"},
    }), encoding="utf-8")
    selected = {
        "OPENAI_API_KEY": "selected-openai-secret",
        "URA_HARMBENCH_TEXT_PATH": str(tmp_path / "private-dataset.jsonl"),
        "ATTACKER_ONLY_TOKEN": "selected-attacker-secret",
    }
    excluded = {
        "ANTHROPIC_API_KEY": "unrelated-anthropic",
        "GEMINI_API_KEY": "unrelated-google",
        "HF_TOKEN": "unrelated-hf",
        "AWS_SECRET_ACCESS_KEY": "unrelated-aws",
        "OPENAI_LOG": "debug",
        "ANTHROPIC_LOG": "debug",
        "HTTPS_PROXY": "http://unrelated-proxy.invalid:8080",
        "SSL_CERT_FILE": str(tmp_path / "unrelated-ca.pem"),
        "URA_OPENAI_BASE_URL": "https://hostile-openai.invalid/v1",
        "URA_ANTHROPIC_BASE_URL": "https://hostile-anthropic.invalid/v1",
        "URA_GLM_BASE_URL": "https://hostile-glm.invalid/v1",
    }
    # The non-secret receipt locators the CLI reads as argparse defaults are
    # forwarded to a NON-dry matrix child (audit P1-04: a Run-page rig_check
    # with blank receipt fields admits like the exported campaign shell); the
    # allowlist still excludes every unrelated secret/base-URL above.
    forwarded_receipts = {
        "URA_PROJECT_REVISION_MANIFEST": str(tmp_path / "campaign-project.json"),
        "URA_PROJECT_REVISION_SHA256": "a" * 64,
        "URA_SOURCE_CONFORMANCE_MANIFEST": str(tmp_path / "campaign-source.json"),
        "URA_SOURCE_CONFORMANCE_SHA256": "b" * 64,
    }
    for name, value in {**selected, **excluded, **forwarded_receipts}.items():
        monkeypatch.setenv(name, value)
    captured: dict[str, str] = {}

    class FakeProcess:
        pid = 9393

        @staticmethod
        def poll() -> int:
            return 0

    def fake_popen(_argv, **kwargs):
        captured.update(kwargs.get("env") or {})
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    try:
        app.start_job("run_matrix", {
            "--api": _HOSTED_A,
            "--api-config": str(api_config),
            "--corpora": "harmbench_text",
            "--source-config": str(source_config),
            "--attackers": "replay",
            "--attacker-config": str(attacker_config),
            "--judges": "rules",
            "--out": "runs/env-contract",
        })
        for name, value in selected.items():
            assert captured.get(name) == value
        for name in excluded:
            assert name not in captured
        for name, value in forwarded_receipts.items():
            assert captured.get(name) == value
        # A dry lane never inherits them (offline lanes are neither admitted
        # nor failed by an inherited receipt).
        captured.clear()
        app.start_job(
            "run_matrix",
            {
                "--dry-run": "on",
                "--corpora": "synth",
                "--attackers": "replay",
                "--judges": "rules",
                "--out": "runs/env-contract-dry",
            },
            scrub_receipt_env=True,
        )
        for name in forwarded_receipts:
            assert name not in captured
    finally:
        app.close()


def test_private_evidence_receives_exact_one_shot_child_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    revision_raw = b'{"schema":"private-project-fixture"}\n'
    conformance_raw = b'{"schema":"private-source-fixture"}\n'
    attestation_raw = b'{"schema":"private-attestation-fixture"}\n'
    revision_sha = hashlib.sha256(revision_raw).hexdigest()
    conformance_sha = hashlib.sha256(conformance_raw).hexdigest()
    attestation_sha = hashlib.sha256(attestation_raw).hexdigest()
    revision_path, _ = app._materialize_selected_project_revision(
        {"project_revision_sha": revision_sha},
        snapshot_payload=revision_raw,
    )
    conformance_path, _ = app._materialize_selected_source_conformance(
        {"source_conformance_sha": conformance_sha},
        snapshot_payload=conformance_raw,
    )
    attestations = app._materialize_selected_live_attestations(
        {"att_path1": "held", "att_sha1": attestation_sha},
        execution_snapshot={"live_attestation_01": attestation_raw},
    )
    attestation_path, _ = attestations[0]
    captured: dict[str, str] = {}

    class FakeProcess:
        pid = 5454
        _handle = 0

        @staticmethod
        def poll() -> int:
            return 0

    def fake_popen(_argv, **kwargs):
        captured.update(kwargs.get("env") or {})
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    try:
        app.start_job("run_matrix", {
            "--dry-run": "on",
            "--corpora": "synth",
            "--attackers": "replay",
            "--judges": "rules",
            "--out": "runs/private-evidence-markers",
            "--project-revision": str(revision_path),
            "--project-revision-sha256": revision_sha,
            "--source-conformance": str(conformance_path),
            "--source-conformance-sha256": conformance_sha,
            "--live-attestation#1": str(attestation_path),
            "--live-attestation-sha256#1": attestation_sha,
        })
        assert captured["URA_PRIVATE_TRANSIENT_PROJECT_REVISION"] == str(
            revision_path
        )
        assert captured["URA_PRIVATE_TRANSIENT_SOURCE_CONFORMANCE"] == str(
            conformance_path
        )
        assert captured["URA_PRIVATE_TRANSIENT_LIVE_ATTESTATION_01"] == str(
            attestation_path
        )
        assert "URA_PRIVATE_TRANSIENT_LIVE_ATTESTATION_02" not in captured
    finally:
        app.close()
    assert not revision_path.exists()
    assert not conformance_path.exists()
    assert not attestation_path.exists()


def test_run_matrix_consumes_each_private_evidence_inode_from_held_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments import run_matrix

    app = _repo_app(tmp_path)
    fixtures: list[tuple[bytes, Path, str, str, str]] = []
    try:
        revision_raw = b'{"fixture":"project-revision"}\n'
        revision_sha = hashlib.sha256(revision_raw).hexdigest()
        revision_path, _ = app._materialize_selected_project_revision(
            {"project_revision_sha": revision_sha},
            snapshot_payload=revision_raw,
        )
        fixtures.append((
            revision_raw,
            revision_path,
            "URA_PRIVATE_TRANSIENT_PROJECT_REVISION",
            ".private-project-revision",
            "project-revision",
        ))

        conformance_raw = b'{"fixture":"source-conformance"}\n'
        conformance_sha = hashlib.sha256(conformance_raw).hexdigest()
        conformance_path, _ = app._materialize_selected_source_conformance(
            {"source_conformance_sha": conformance_sha},
            snapshot_payload=conformance_raw,
        )
        fixtures.append((
            conformance_raw,
            conformance_path,
            "URA_PRIVATE_TRANSIENT_SOURCE_CONFORMANCE",
            ".private-source-conformance",
            "source-conformance",
        ))

        attestation_raw = b'{"fixture":"live-attestation"}\n'
        attestation_sha = hashlib.sha256(attestation_raw).hexdigest()
        attestation_path, _ = app._materialize_selected_live_attestations(
            {"att_path1": "held", "att_sha1": attestation_sha},
            execution_snapshot={"live_attestation_01": attestation_raw},
        )[0]
        fixtures.append((
            attestation_raw,
            attestation_path,
            "URA_PRIVATE_TRANSIENT_LIVE_ATTESTATION_01",
            ".private-live-attestations",
            "live-attestation-01",
        ))

        for raw, path, marker, directory, prefix in fixtures:
            digest = hashlib.sha256(raw).hexdigest()
            monkeypatch.setenv(marker, str(path))
            loaded = run_matrix._read_optional_bound_config(
                str(path),
                digest,
                flag_name="--private-evidence-fixture",
                transient_environment=marker,
                transient_directory=directory,
                transient_prefix=prefix,
                max_bytes=4 * 1024 * 1024,
            )
            assert loaded is not None
            held, loaded_path, size, observed, transient = loaded
            assert (held, loaded_path, size, observed, transient) == (
                raw,
                path.resolve(),
                len(raw),
                digest,
                True,
            )
            assert marker not in os.environ
            assert not path.exists()
    finally:
        app.close()


def test_supervised_job_logs_redact_private_locators_across_os_writers(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "leak_runner.py"
    script.write_text(
        "import logging, os, subprocess, sys\n"
        "value=sys.argv[sys.argv.index('--model-acquisition-store')+1]\n"
        "logger=logging.getLogger('prebound')\n"
        "logger.addHandler(logging.StreamHandler(sys.stderr))\n"
        "logger.setLevel(logging.ERROR)\n"
        "logger.error('logging:'+value)\n"
        "os.write(1, ('native:'+value+'\\n').encode())\n"
        "subprocess.run([sys.executable,'-c',"
        "'import os,sys;os.write(2,(\"grandchild:\"+sys.argv[1]).encode())',"
        "value], check=True)\n"
        "print('slash:'+value.replace('\\\\','/'))\n",
        encoding="utf-8",
    )
    private_store = tmp_path / "operator private" / "model-store"
    private_store.mkdir(parents=True)
    results = tmp_path / "runs"
    results.mkdir()
    command = Command(
        "run_matrix",
        "leak_runner",
        "redaction fixture",
        (CommandParam("--model-acquisition-store", "path", required=True),),
    )
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=repo,
        commands={"run_matrix": command},
    )
    try:
        job = app.start_job(
            "run_matrix", {"--model-acquisition-store": str(private_store)}
        )
        deadline = time.time() + 30
        while job.state() == "running" and time.time() < deadline:
            time.sleep(0.05)
        assert job.state() == "complete"
        app._reconcile()
        stdout = (job.directory / "stdout.log").read_text(
            encoding="utf-8", errors="replace"
        )
        stderr = (job.directory / "stderr.log").read_text(
            encoding="utf-8", errors="replace"
        )
        retained = json.dumps({
            "argv": job.argv,
            "command": (job.directory / "command.json").read_text(
                encoding="utf-8"
            ),
        })
        for raw in {
            str(private_store),
            str(private_store).replace("\\", "/"),
        }:
            assert raw not in stdout
            assert raw not in stderr
            assert raw not in retained
        assert "native:<redacted-private>" in stdout
        assert "slash:<redacted-private>" in stdout
        assert "logging:<redacted-private>" in stderr
        assert "grandchild:<redacted-private>" in stderr
        assert "private-model-acquisition-store" in retained
    finally:
        app.close()


def test_streaming_redaction_covers_chunk_boundaries_and_bounds_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import experiments.rig_web_app.lifecycle as lifecycle_module

    pattern = b"PRIVATE-LOCATOR-ACROSS-CHUNKS"
    raw = b"x" * (lifecycle_module._LOG_PIPE_READ_BYTES - 7) + pattern + b"tail"
    source = io.BytesIO(raw)
    sink = io.BytesIO()
    lifecycle_module.LifecycleMixin._capture_redacted_pipe(
        source, sink, (pattern,)
    )
    output = sink.getvalue()
    assert pattern not in output
    assert b"<redacted-private>tail" in output

    mixed_case = io.BytesIO()
    lifecycle_module.LifecycleMixin._capture_redacted_pipe(
        io.BytesIO(pattern.swapcase()), mixed_case, (pattern,)
    )
    assert pattern.swapcase() not in mixed_case.getvalue()
    assert mixed_case.getvalue() == b"<redacted-private>"

    monkeypatch.setattr(lifecycle_module, "_MAX_DURABLE_JOB_LOG_BYTES", 512)
    bounded = io.BytesIO()
    lifecycle_module.LifecycleMixin._capture_redacted_pipe(
        io.BytesIO(b"z" * 100_000), bounded, ()
    )
    retained = bounded.getvalue()
    assert len(retained) <= 512
    assert lifecycle_module._LOG_TRUNCATED_MARKER in retained


def test_detached_log_sink_rejects_links_and_open_time_inode_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import experiments.rig_web_app.log_supervisor as supervisor

    job_dir = (tmp_path / "job").resolve()
    job_dir.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_bytes(b"same")

    hardlink = job_dir / "stdout.log"
    hardlink.hardlink_to(outside)
    with pytest.raises(ValueError, match="direct regular file"):
        supervisor._open_safe_sink(str(hardlink))
    hardlink.unlink()

    symlink = job_dir / "stderr.log"
    try:
        symlink.symlink_to(outside)
    except OSError:
        symlink = None
    if symlink is not None:
        with pytest.raises(ValueError, match="direct regular file"):
            supervisor._open_safe_sink(str(symlink))
        symlink.unlink()

    sink = job_dir / "stdout.log"
    replacement = job_dir / "replacement.log"
    sink.write_bytes(b"aaaa")
    replacement.write_bytes(b"bbbb")
    real_open = supervisor.os.open

    def swap_then_open(path, flags, *args, **kwargs):
        if Path(path) == sink:
            replacement.replace(sink)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(supervisor.os, "open", swap_then_open)
    with pytest.raises(ValueError, match="changed while being opened"):
        supervisor._open_safe_sink(str(sink))


def test_builder_snapshot_rejects_same_size_open_time_inode_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import experiments.rig_web_app.builder_validation as validation

    reviewed = tmp_path / "reviewed.json"
    replacement = tmp_path / "replacement.json"
    reviewed.write_bytes(b'{"value":"A"}\n')
    replacement.write_bytes(b'{"value":"B"}\n')
    expected = hashlib.sha256(reviewed.read_bytes()).hexdigest()
    real_open = validation.os.open

    def swap_then_open(path, flags, *args, **kwargs):
        if Path(path) == reviewed:
            replacement.replace(reviewed)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(validation.os, "open", swap_then_open)
    with pytest.raises(ValueError, match="changed while being opened"):
        validation.BuilderValidationMixin._bounded_content_snapshot(
            str(reviewed),
            expected,
            label="reviewed evidence",
            max_bytes=1024,
        )


def test_detached_redactor_keeps_logging_across_console_close_and_restart(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "restart_runner.py"
    script.write_text(
        "import sys,time\n"
        "value=sys.argv[sys.argv.index('--model-acquisition-store')+1]\n"
        "print('before:'+value, flush=True)\n"
        "time.sleep(3)\n"
        "print('after:'+value, flush=True)\n",
        encoding="utf-8",
    )
    private_store = tmp_path / "operator private" / "detached-store"
    private_store.mkdir(parents=True)
    state = tmp_path / "state"
    results = tmp_path / "runs"
    command = Command(
        "run_matrix",
        "restart_runner",
        "restart log fixture",
        (CommandParam("--model-acquisition-store", "path", required=True),),
    )

    def new_app() -> RigWebApp:
        return RigWebApp(
            results_root=results,
            state_dir=state,
            repo_root=repo,
            commands={"run_matrix": command},
        )

    first = new_app()
    job = first.start_job(
        "run_matrix", {"--model-acquisition-store": str(private_store)}
    )
    time.sleep(0.2)
    started = time.monotonic()
    first.close()
    assert time.monotonic() - started < 1.5
    assert first._log_capture_workers == {}

    restarted = new_app()
    try:
        restored = restarted.jobs[job.job_id]
        assert restored.state() == "running"
        log_path = restored.directory / "stdout.log"
        deadline = time.time() + 10
        while time.time() < deadline:
            text = log_path.read_text(encoding="utf-8", errors="replace")
            if "after:<redacted-private>" in text:
                break
            time.sleep(0.05)
        else:
            pytest.fail("detached redactor did not retain the child's final line")
        assert "before:<redacted-private>" in text
        assert str(private_store) not in text
        assert str(private_store).replace("\\", "/") not in text
    finally:
        restarted.close()


def test_hosted_judge_sampling_and_data_transfer_are_fail_closed_in_builder(
    tmp_path: Path,
) -> None:
    app = _repo_app(tmp_path)
    base = {
        "mode": "measured",
        "local": _LOCAL,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules,llm",
        "judge_model": _HOSTED_A,
        "seeds": "0",
        "max_queries": "1",
        "max_turns": "1",
        "out": "runs/hosted-judge-policy",
    }
    try:
        missing_ack = app._validate_builder({
            **base, "limit": "1", "sample_seed": "0",
        })
        assert "may be sent" in missing_ack["ack_hosted_judge_data_transfer"]

        full = app._validate_builder({
            **base,
            "ack_hosted_judge_data_transfer": "on",
            "limit": "0",
        })
        assert "limit" not in full and "sample_seed" not in full

        unseeded = app._validate_builder({
            **base,
            "ack_hosted_judge_data_transfer": "on",
            "limit": "1",
        })
        assert (
            "same logical arm, converted corpus digest, limit and sample seed"
            in unseeded["sample_seed"]
        )

        local_rules = app._validate_builder({
            **base,
            "judges": "rules",
            "judge_model": "",
            "limit": "0",
        })
        assert "limit" not in local_rules and "sample_seed" not in local_rules
        assert "ack_hosted_judge_data_transfer" not in local_rules

        misplaced_ack = app._validate_builder({
            **base,
            "judges": "rules",
            "judge_model": "",
            "ack_hosted_judge_data_transfer": "on",
            "limit": "0",
        })
        assert "only to a live hosted" in (
            misplaced_ack["ack_hosted_judge_data_transfer"]
        )

        page = app._build_page().decode("utf-8")
        checkbox = re.search(
            r"<input type='checkbox' name='ack_hosted_judge_data_transfer'[^>]*>",
            page,
        )
        assert checkbox is not None and "checked" not in checkbox.group(0)
        assert "source/reference grading context may be sent" in page
        assert "provider's retention" in page
        assert "live condition" in page
    finally:
        app.close()


def test_hosted_judge_ack_is_bound_only_inside_opaque_paid_ticket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _repo_app(tmp_path)
    _bind_fixture_receipts(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 1, "judge_calls": 1, "http_attempts": 3}, ""
        ),
    )
    starts: list[str] = []
    monkeypatch.setattr(
        app, "start_job", lambda *_args, **_kwargs: starts.append("start")
    )
    form = {
        **_paid_probe_form(out="runs/ack-ticket"),
        "api": _HOSTED_B,
        "judges": "rules,llm",
        "judge_model": _HOSTED_A,
        "ack_hosted_judge_data_transfer": "on",
    }
    try:
        status, _headers, body = app.handle("POST", "/build", form)
        assert status == 200
        match = re.search(rb"name='launch_ticket' value='([^']+)'", body)
        assert match is not None
        ticket = match.group(1).decode("ascii")
        assert app._launch_tickets[ticket][2][
            "ack_hosted_judge_data_transfer"
        ] == "on"
        assert b"ack_hosted_judge_data_transfer" not in body

        tampered = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": ticket,
            "ack_hosted_judge_data_transfer": "",
        })
        replay = app.handle("POST", "/build", {
            "confirm": "yes", "launch_ticket": ticket,
        })
        assert tampered[0] == replay[0] == 200
        assert b"confirmation expired or was changed" in tampered[2]
        assert b"confirmation expired or was changed" in replay[2]
        assert starts == []
    finally:
        app.close()


def test_web_compose_materializes_local_judge_but_dry_mode_stays_mock(
    tmp_path: Path,
) -> None:
    app = _repo_app(tmp_path)
    _command, values, _params = app._compose_from_builder({
        "mode": "measured",
        "api": _HOSTED_A,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules,llm",
        "judge_model": _LOCAL,
        "approximate_common_metrics": "on",
        "out": "runs/judge",
    })
    assert values["--judges"] == "rules,llm"
    assert values["--judge-model"] == _LOCAL
    assert values["--approximate-common-metrics"] == "on"
    assert "--local" not in values
    local_config = Path(values["--local-config"])
    assert set(json.loads(local_config.read_text(encoding="utf-8"))) == {_LOCAL}

    _command, dry, _params = app._compose_from_builder({
        "mode": "dry_run",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules,llm",
        "judge_model": _HOSTED_B,
        "out": "runs/dry",
    })
    assert dry["--judge-model"] == "mock"
    assert "--local-config" not in dry
    app.close()


def test_all_explicit_builder_paths_are_projected_or_rejected_before_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = (tmp_path / "operator-private" / "inactive-judge").resolve()
    spec = f"vllm:{checkpoint}"
    digest = "d" * 64
    app = _repo_app(tmp_path, local={
        spec: {
            "digest": digest,
            "modalities": ["text"],
            "parameter_count_b": 7,
            "tensor_parallel_size": 1,
        },
    })
    values = {
        "--dry-run": "on",
        "--corpora": "synth",
        "--attackers": "replay",
        "--judges": "rules",
        "--out": "runs/path-free",
    }
    builder_params = {
        "mode": "dry_run",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
        "judge_model": spec,
        f"quantization::{spec}": "none",
        "out": "runs/path-free",
    }
    popen_calls: list[list[str]] = []

    class FakeProcess:
        pid = 4242
        _handle = 0

        @staticmethod
        def poll() -> int:
            return 0

    def fake_popen(argv, **_kwargs):
        popen_calls.append(list(argv))
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    try:
        job = app.start_job(
            "run_matrix",
            values,
            builder_params=builder_params,
        )
        identity = f"vllm:local-checkpoint@sha256:{digest}"
        retained = json.dumps({
            "argv": job.argv,
            "builder_params": job.builder_params,
        }, sort_keys=True)
        assert str(checkpoint) not in retained and spec not in retained
        assert identity in retained
        assert f"quantization::{identity}" in (job.builder_params or {})
        assert spec not in "\n".join(popen_calls[0])  # it was inactive

        command = (job.directory / "command.json").read_text(encoding="utf-8")
        page = app.handle("GET", f"/jobs/{job.job_id}")[2].decode("utf-8")
        with sqlite3.connect(app.state_dir / "console.db") as connection:
            rows = connection.execute(
                "SELECT argv, builder_params FROM jobs"
            ).fetchall()
        durable_surfaces = "\n".join(
            [retained, command, page]
            + [f"{argv}\n{params}" for argv, params in rows]
        )
        assert str(checkpoint) not in durable_surfaces and spec not in durable_surfaces

        # An unconfigured/tampered path has no content identity. It is rejected
        # before Popen, in-memory Job insertion, command.json, or SQLite.
        unknown = (tmp_path / "operator-private" / "tampered").resolve()
        unknown_spec = f"vllm:{unknown}"
        before_jobs = set(app.jobs)
        before_directories = set(app.state_dir.glob("job-*"))
        before_popen = len(popen_calls)
        with pytest.raises(ValueError) as exc_info:
            app.start_job(
                "run_matrix",
                values,
                builder_params={
                    **builder_params,
                    "judge_model": unknown_spec,
                    f"quantization::{unknown_spec}": "none",
                },
            )
        assert str(unknown) not in str(exc_info.value)
        assert set(app.jobs) == before_jobs
        assert set(app.state_dir.glob("job-*")) == before_directories
        assert len(popen_calls) == before_popen
        with sqlite3.connect(app.state_dir / "console.db") as connection:
            assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    finally:
        app.close()


def test_explicit_checkpoint_paths_never_render_in_picker_or_error_state(
    tmp_path: Path,
) -> None:
    checkpoint = (tmp_path / "operator-private" / "picker checkpoint").resolve()
    spec = f"vllm:{checkpoint}"
    digest = "e" * 64
    identity = f"vllm:local-checkpoint@sha256:{digest}"
    app = _repo_app(tmp_path, local={
        spec: {
            "digest": digest,
            "modalities": ["text"],
            "parameter_count_b": 7,
            "tensor_parallel_size": 1,
        },
    })
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        assert spec not in page and str(checkpoint) not in page
        assert identity in page
        assert f"name='quantization::{identity}'" in page

        rendered_error = app._build_page(
            prefill={
                "local": spec,
                "judge_model": spec,
                f"quantization::{spec}": "none",
            },
            errors={
                "models": f"invalid local target {spec}",
                "judge_model": f"invalid local judge {checkpoint}",
            },
        ).decode("utf-8")
        assert spec not in rendered_error and str(checkpoint) not in rendered_error
        assert identity in rendered_error

        runtime = app._runtime_builder_params({
            "local": identity,
            "judge_model": identity,
            f"quantization::{identity}": "none",
        })
        assert runtime["local"] == runtime["judge_model"] == spec
        assert runtime[f"quantization::{spec}"] == "none"

        status, _, validation_body = app.handle("POST", "/build", {
            "mode": "measured",
            "local": identity,
            "corpora": "synth",
            "attackers": "replay",
            "judges": "rules",
            "seeds": "0",
            "out": "runs/private-path-validation",
            f"quantization::{identity}": "none",
        })
        assert status == 200 and app.jobs == {}
        validation_page = validation_body.decode("utf-8")
        assert spec not in validation_page and str(checkpoint) not in validation_page

        unknown = (tmp_path / "operator-private" / "tampered picker").resolve()
        unknown_spec = f"vllm:{unknown}"
        tampered_page = app._build_page(
            prefill={
                "local": unknown_spec,
                f"quantization::{unknown_spec}": "none",
            },
            errors={"models": f"unknown local target {unknown_spec}"},
        ).decode("utf-8")
        assert unknown_spec not in tampered_page and str(unknown) not in tampered_page
        assert "private explicit-local value omitted" in tampered_page

        status, _, rejected_body = app.handle("POST", "/build", {
            "mode": "measured",
            "local": unknown_spec,
            "corpora": "synth",
            "attackers": "replay",
            "judges": "rules",
            "seeds": "0",
            "out": "runs/tampered-private-path",
            f"quantization::{unknown_spec}": "none",
        })
        assert status == 200 and app.jobs == {}
        rejected_page = rejected_body.decode("utf-8")
        assert unknown_spec not in rejected_page and str(unknown) not in rejected_page
    finally:
        app.close()


@pytest.mark.parametrize(
    ("spec", "revision", "bad_quantization"),
    [
        (
            "vllm:llava-hf/llava-v1.6-mistral-7b-hf",
            "2424fdd47412fccc66d91719126b420e9fbd7065",
            "fp8",
        ),
        (
            "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR",
            "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e",
            "bitsandbytes",
        ),
    ],
)
def test_known_failed_precision_is_exact_and_bf16_remains_admitted(
    spec: str,
    revision: str,
    bad_quantization: str,
) -> None:
    entry = {
        "revision": revision,
        "modalities": ["text", "image"],
        "parameter_count_b": 7,
        "quantization": bad_quantization,
    }
    assert known_vllm_quantization_issue(
        spec, revision, bad_quantization, "v0.27.1"
    )
    bad = model_hardware_profile(spec, entry, _gpu(), runtime_version="0.27.1")
    assert bad["fits"] is False and bad["quantization_available"] is False

    bf16 = model_hardware_profile(
        spec,
        {**entry, "quantization": "none"},
        _gpu(),
        runtime_version="0.27.1",
    )
    assert bf16["fits"] is True
    assert bf16["recommended_quantization"] == "none"
    assert not known_vllm_quantization_issue(
        spec, revision, bad_quantization, "0.27.2"
    )


def test_picker_disables_only_exact_failed_precision_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments import local_targets

    monkeypatch.setattr(local_targets, "installed_vllm_version", lambda: "0.27.1")
    llava = "vllm:llava-hf/llava-v1.6-mistral-7b-hf"
    gray = "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR"
    roster = {
        "vllm_version": "0.27.1",
        "models": {
            llava: {
                "revision": "2424fdd47412fccc66d91719126b420e9fbd7065",
                "modalities": ["text", "image"], "parameter_count_b": 7,
            },
            gray: {
                "revision": "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e",
                "modalities": ["text", "image"], "parameter_count_b": 7,
            },
        },
    }
    app = _repo_app(tmp_path, local={}, roster=roster)
    text = app.handle("GET", "/build")[2].decode("utf-8")

    assert text.count("known unsupported precision") >= 2
    assert "<option value='fp8' disabled" in text
    assert "<option value='bitsandbytes' disabled" in text
    assert "<option value='none' disabled" not in text
    assert "BF16 remains available" in text
    assert "non-contiguous tensor" in text
    assert "not a VRAM shortage" in text
    assert "packed_modules_mapping" in text
    app.close()


def _campaign_dir(tmp_path: Path, event: dict[str, object]) -> Path:
    directory = tmp_path / "campaign"
    directory.mkdir(parents=True)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (directory / "ENGINEERING_ONLY.json").write_text(json.dumps({
        "schema": "ura-engineering-campaign/1",
        "campaign_id": "campaign",
        "release_commit": "a" * 40,
        "evidence_class": "engineering_stress",
        "thesis_empirical_evidence": False,
        "hosted_calls_allowed": False,
        "target_call_cap": 1,
        "hard_stop_hours": 23,
        "started_at": started,
    }), encoding="utf-8")
    (directory / "task-log.jsonl").write_text("\n".join((
        json.dumps({
            "at": "2026-08-17T00:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
            "detail": "active",
        }),
        json.dumps(event),
    )) + "\n", encoding="utf-8")
    return directory


def test_download_indicator_requires_explicit_active_activity_event(
    tmp_path: Path,
) -> None:
    event = {
        "at": "2026-08-17T00:00:00Z",
        "event": "task_start",
        "task": "download-model",
        "status": "running",
        "detail": "name alone is not evidence",
    }
    directory = _campaign_dir(tmp_path, event)
    campaign = _load_campaign(directory)
    assert campaign is not None
    assert campaign.status_tag == "unknown"
    assert "running state cannot be verified" in campaign.state_detail
    assert campaign.download_tasks == ()

    event["task_kind"] = "model_download"
    lines = (directory / "task-log.jsonl").read_text(encoding="utf-8").splitlines()
    (directory / "task-log.jsonl").write_text(
        lines[0] + "\n" + json.dumps(event) + "\n", encoding="utf-8"
    )
    campaign = _load_campaign(directory)
    assert campaign is not None and campaign.download_tasks == ("download-model",)

    with (directory / "task-log.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "at": "2026-08-17T00:01:00Z",
            "event": "task_end",
            "task": "download-model",
            "status": "passed",
            "detail": "complete",
        }) + "\n")
    campaign = _load_campaign(directory)
    assert campaign is not None and campaign.download_tasks == ()


def test_jobs_date_controls_and_external_indeterminate_presentation_match_ui(
    tmp_path: Path,
) -> None:
    app = _repo_app(tmp_path)
    directory = app.results_root / "engineering" / "campaign"
    directory.parent.mkdir()
    source = _campaign_dir(tmp_path / "external", {
        "at": "2026-08-17T00:00:00Z",
        "event": "task_start",
        "task": "probe",
        "status": "running",
        "detail": "active",
    })
    source.rename(directory)

    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    dashboard = app.handle("GET", "/")[2].decode("utf-8")
    style = app.handle("GET", "/static/style.css")[2].decode("utf-8")
    assert "targetfilters job-date-filters" in jobs
    assert jobs.count("type='datetime-local'") == 2
    assert ".job-date-filters input[type=datetime-local]" in style
    assert "<span class='badge amber'>external, unknown</span>" in dashboard
    assert "running state cannot be verified" in dashboard
    assert "External running state is a task-log report" not in dashboard
    assert "reported running" not in (jobs + dashboard).lower()
    app.close()


def _write_roster(repo_root: Path, specs: dict[str, list[str]]) -> None:
    (repo_root / "experiments").mkdir(parents=True, exist_ok=True)
    (repo_root / "experiments" / "vllm-roster.json").write_text(
        json.dumps(
            {
                "vllm_version": "0.27.1",
                "models": {
                    spec: {"modalities": mods} for spec, mods in specs.items()
                },
            }
        ),
        encoding="utf-8",
    )


def test_cli_local_target_listing_matches_what_the_console_offers(
    tmp_path: Path,
) -> None:
    """The CLI listing and the Build picker must name the same local targets.

    vLLM's supported-models documentation lists one example model per
    architecture, so the roster legitimately misses a sibling size or a
    fine-tune of a listed base. Those are configured in the operator registry,
    which the console has always merged in; the CLI listed only the roster, so
    the same rig reported different local targets depending on which surface
    was asked, and a campaign target configured with its pinned revision was
    invisible from the command line.
    """

    from experiments import local_targets

    repo_root = tmp_path
    base = "vllm:llava-hf/llava-v1.6-mistral-7b-hf"
    finetune = "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR"
    sibling = "vllm:Qwen/Qwen3-VL-8B-Instruct"
    # The documentation lists the base and a different size of the Qwen family.
    _write_roster(
        repo_root,
        {base: ["text", "image"], "vllm:Qwen/Qwen3-VL-4B-Instruct": ["text", "image"]},
    )
    registry = {
        sibling: {
            "revision": "60595ebc30ec8e3b1d3b9e65d4943ca011c0006a",
            "modalities": ["text", "image"],
            "tensor_parallel_size": 1,
        },
        finetune: {
            "revision": "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e",
            "modalities": ["text", "image"],
            "tensor_parallel_size": 1,
        },
        base: {
            "revision": "2424fdd47412fccc66d91719126b420e9fbd7065",
            "modalities": ["text", "image"],
            "tensor_parallel_size": 1,
        },
    }
    (repo_root / "experiments" / "local-targets.json").write_text(
        json.dumps(registry), encoding="utf-8"
    )
    hardware = {
        "available": True,
        "gpu_count": 2,
        "aggregate_vram_gib": 47.98,
        "max_gpu_vram_gib": 23.99,
        "gpus": [{"index": 0, "vram_gib": 23.99}, {"index": 1, "vram_gib": 23.99}],
    }

    # The roster alone, which is what the CLI used to print, cannot name them:
    # neither the fine-tune nor the 8B sibling is a documented example model.
    roster_only = {
        str(model["spec"])
        for model in local_targets.roster_models(repo_root, hardware, include_unfit=True)
    }
    assert finetune not in roster_only and sibling not in roster_only

    listed = local_targets.local_target_models(repo_root, hardware, include_unfit=True)
    by_spec = {str(model["spec"]): model for model in listed}

    # Every configured campaign target is listed, each with its pinned revision.
    for spec in (sibling, finetune, base):
        assert spec in by_spec, f"{spec} is configured but the CLI does not list it"
        assert by_spec[spec]["source"] == "registry"
        assert by_spec[spec]["revision"] == registry[spec]["revision"]

    # The roster still contributes what the registry does not configure, and
    # says so, so an operator can tell a pinned target from a documented example.
    assert by_spec["vllm:Qwen/Qwen3-VL-4B-Instruct"]["source"] == "vllm_docs"
    assert "revision" not in by_spec["vllm:Qwen/Qwen3-VL-4B-Instruct"]

    # A registry entry wins over the roster row of the same spec: only the
    # registry carries the revision the campaign must pin.
    assert sum(1 for model in listed if str(model["spec"]) == base) == 1

    # And the console's picker offers exactly the same vLLM specs.
    from experiments.rig_web_app.builder_models import BuilderModelsMixin

    class _NoOllama:
        @staticmethod
        def roster(_vllm: dict, *, force: bool = False) -> dict[str, object]:
            # No Ollama daemon in this check; the comparison is vLLM specs only.
            return {"models": []}

    class _Probe(BuilderModelsMixin):
        def __init__(self, root: Path) -> None:
            self.repo_root = root
            self.gpu_hardware = hardware
            self.ollama = _NoOllama()

    probe = _Probe(repo_root)
    offered = {
        spec
        for spec, _label, _mods, kind in probe._model_options()
        if kind == "local" and spec.startswith("vllm:")
    }
    assert offered == set(by_spec)
