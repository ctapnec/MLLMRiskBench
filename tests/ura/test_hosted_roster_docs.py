"""Advertised hosted-roster, pricing, and operator-document parity."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.reports import rate_for
from ura.targets.api import (
    api_target_requires_config,
    build_api_target,
    canonical_api_target_identity,
    normalize_api_target_config,
)


_ROOT = Path(__file__).resolve().parents[2]
_ROSTER = _ROOT / "experiments" / "rig" / "api-targets.example.json"
_PRICING = _ROOT / "experiments" / "rig" / "pricing.example.json"
_FABLE = "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000"
_SOL = (
    "openai-responses:gpt-5.6-sol;reasoning_mode=pro;"
    "reasoning_effort=medium;reasoning_context=all_turns"
)
_COMPAT_ENDPOINT_ENVS = (
    "URA_DEEPSEEK_BASE_URL",
    "URA_GLM_BASE_URL",
    "URA_KIMI_BASE_URL",
    "URA_QWEN_BASE_URL",
    "URA_DOUBAO_BASE_URL",
)


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_advertised_hosted_roster_builds_offline_and_exactly_matches_pricing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every advertised row must be executable without constructing an SDK client."""

    for name in _COMPAT_ENDPOINT_ENVS:
        monkeypatch.delenv(name, raising=False)
    roster = _json(_ROSTER)
    pricing = _json(_PRICING)

    assert _FABLE in roster
    assert _SOL in roster
    assert "anthropic:claude-fable-5" not in roster
    assert "claude-fable-5" not in roster
    assert "openai:gpt-5.6-sol" not in roster
    assert "openai:gpt-5.6-terra" in roster
    assert "openai:gpt-5.6-tera" not in roster
    assert roster["glm:glm-5.2"] == {
        "modalities": ["text"],
        "max_tokens": 4096,
        "temperature": None,
    }
    assert not any("mythos" in spec.casefold() for spec in roster)

    advertised_price_keys: set[tuple[str, str]] = set()
    for spec, raw_config in roster.items():
        assert isinstance(raw_config, dict)
        provider, model = canonical_api_target_identity(spec)
        advertised_price_keys.add((provider, model))
        if api_target_requires_config(spec):
            normalized = normalize_api_target_config(spec, raw_config)
            target = build_api_target(spec, config=normalized)
        else:
            assert spec in {_FABLE, _SOL}
            assert set(raw_config) == {"modalities"}
            target = build_api_target(spec)
        assert tuple(raw_config["modalities"]) == tuple(target.modality_support)

    providers = pricing.get("providers")
    assert isinstance(providers, dict)
    pricing_keys = {
        (provider, model)
        for provider, entry in providers.items()
        if isinstance(entry, dict)
        for model in entry.get("models", {})
    }
    assert pricing_keys == advertised_price_keys

    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=_ROOT,
        gpu_hardware=_gpu(),
    )
    try:
        snapshot, digest, relative, runtime_configs = (
            app._selected_api_config_snapshot(
                {
                    "api": ",".join(roster),
                    "judges": "rules",
                    "mode": "measured",
                }
            )
        )
        assert snapshot["schema"] == "ura-builder-selected-api-config/1"
        assert relative == "experiments/rig/api-targets.example.json"
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert len(snapshot["routes"]) == len(roster)
        assert set(runtime_configs) == {
            spec for spec in roster if api_target_requires_config(spec)
        }
        serialized_snapshot = json.dumps(snapshot, sort_keys=True)
        assert "https://" not in serialized_snapshot
        for route in snapshot["routes"]:
            assert re.fullmatch(
                r"https-base-url-sha256:[0-9a-f]{64}",
                route["endpoint_identity"],
            )
            assert "base_url" not in route["config"]
    finally:
        app.close()


def _gpu() -> dict[str, object]:
    return {
        "available": False,
        "source": "fixture",
        "gpu_count": 0,
        "aggregate_vram_gib": 0.0,
        "max_gpu_vram_gib": 0.0,
        "gpus": [],
    }


def _row(document: str, spec: str) -> str:
    marker = f"data-model='{html.escape(spec, quote=True)}'"
    position = document.index(marker)
    start = document.rfind("<div class='modelrow'", 0, position)
    end = document.find("<div class='modelrow'", position + len(marker))
    return document[start : len(document) if end < 0 else end]


def test_fixed_fable_sol_share_canonical_pricing_and_filter_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FABLE", raising=False)
    monkeypatch.delenv("SOL", raising=False)
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "api-targets.example.json").write_text(
        json.dumps(
            {
                _FABLE: {"modalities": ["text", "image"]},
                _SOL: {"modalities": ["text", "image"]},
            }
        ),
        encoding="utf-8",
    )
    (rig / "local-targets.example.json").write_text("{}\n", encoding="utf-8")
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"vllm_version": "0.27.1", "models": {}}),
        encoding="utf-8",
    )
    pricing = {
        "schema": "ura-console-pricing/1",
        "providers": {
            "anthropic": {
                "models": {
                    "claude-fable-5": {
                        "rates": [
                            {
                                "effective_date": "2026-01-01",
                                "currency": "USD",
                                "per_million_tokens": {
                                    "input": 10.0,
                                    "output": 50.0,
                                },
                            }
                        ]
                    }
                }
            },
            "openai": {
                "models": {
                    "gpt-5.6-sol": {
                        "rates": [
                            {
                                "effective_date": "2026-01-01",
                                "currency": "USD",
                                "per_million_tokens": {
                                    "input": 5.0,
                                    "output": 20.0,
                                },
                            }
                        ]
                    }
                }
            },
        },
    }
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
    app._ollama_roster_snapshot = lambda **_kwargs: {  # type: ignore[method-assign]
        "models": [],
        "excluded": [],
    }
    try:
        document = app.handle("GET", "/build")[2].decode("utf-8")
        fable_row = _row(document, _FABLE)
        sol_row = _row(document, _SOL)

        assert canonical_api_target_identity(_FABLE) == (
            "anthropic",
            "claude-fable-5",
        )
        assert canonical_api_target_identity(_SOL) == ("openai", "gpt-5.6-sol")
        assert "data-provider='anthropic'" in fable_row
        assert "data-provider='openai'" in sol_row
        assert "judge-cost-warning" in fable_row
        assert "60 USD per one million input + output tokens" in fable_row
        assert "judge-cost-warning" not in sol_row
        assert document.count("<span class='badge amber tip judge-cost-warning'") == 1
        for spec in (_FABLE, _SOL):
            rate, why = rate_for(pricing, *canonical_api_target_identity(spec))
            assert rate is not None, why
    finally:
        app.close()


def _documented_commands(document: str) -> list[str]:
    commands: list[str] = []
    lines = document.splitlines()
    for index, line in enumerate(lines):
        if re.search(
            r"\bpython(?:\s+-m)?\s+experiments(?:\.|/)"
            r"(?:run_matrix|rig_check)(?:\.py)?\b",
            line,
        ) is None:
            continue
        command = [line.strip()]
        cursor = index
        while command[-1].rstrip().endswith("\\") and cursor + 1 < len(lines):
            cursor += 1
            command.append(lines[cursor].strip())
        commands.append(" ".join(command))
    return commands


def test_documented_hosted_judge_commands_ack_only_live_transfer() -> None:
    runbook = (_ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    documents = [
        (_ROOT / "README.md").read_text(encoding="utf-8"),
        runbook,
        *(
            path.read_text(encoding="utf-8")
            for path in sorted((_ROOT / "docs").glob("*.md"))
        ),
        *(
            path.read_text(encoding="utf-8")
            for path in sorted((_ROOT / "experiments").glob("*.md"))
            if path.name != "RUN_AND_RETURN.md"
        ),
        *(
            path.read_text(encoding="utf-8")
            for path in sorted((_ROOT / "experiments" / "rig").glob("*.md"))
        ),
    ]
    commands = [command for document in documents for command in _documented_commands(document)]
    hosted_judge_commands = [
        command for command in commands if '--judge-model "$JUDGE"' in command
    ]
    live_commands = [
        command
        for command in hosted_judge_commands
        if "experiments.run_matrix" in command and "--dry-run" not in command
    ]
    preflight_commands = [
        command for command in hosted_judge_commands if "experiments.rig_check" in command
    ]

    assert len(live_commands) >= 2
    assert all("--ack-hosted-judge-data-transfer" in command for command in live_commands)
    assert len(preflight_commands) >= 8
    assert all("--ack-hosted-judge-data-transfer" not in command for command in preflight_commands)
    assert all(
        "ack-hosted-judge-data-transfer" not in command
        for command in commands
        if "experiments.rig_check" in command or "--dry-run" in command
    )
    assert "retention, training/data-use, regional" in runbook
    for measured_destination in (
        "runs/thesis/runner/static-image",
        "runs/thesis/runner/static-audio",
        "runs/thesis/runner/static-video",
        "runs/thesis/runner/crescendo-text",
        'runs/thesis/runner/transfer-$ATTACKER',
        "runs/thesis/runner/local-qwen3-vl-text",
        "runs/thesis/runner/defense-text",
    ):
        position = runbook.index(measured_destination)
        assert "--ack-hosted-judge-data-transfer" in runbook[
            max(0, position - 600) : position
        ]


def test_core_docs_describe_request_endpoint_and_execution_config_contracts() -> None:
    paths = (
        _ROOT / "README.md",
        _ROOT / "docs" / "SCHEMA.md",
        _ROOT / "docs" / "ARCHITECTURE.md",
        _ROOT / "experiments" / "RUN_AND_RETURN.md",
    )
    for path in paths:
        document = path.read_text(encoding="utf-8")
        assert "ura-request-envelope/2" in document, path
        assert "hosted_judge_data_transfer_acknowledged" in document, path
        assert "ura-builder-selected-api-config/1" in document, path
        assert "endpoint_identity" in document, path
        assert "https-base-url-sha256" in document, path
        assert "raw URL" in document, path


def test_advertised_names_are_canonical_across_maintained_docs_and_registries() -> None:
    maintained = (
        _ROOT / "README.md",
        _ROOT / "SECURITY.md",
        *sorted((_ROOT / "docs").glob("*.md")),
        *sorted((_ROOT / "experiments").glob("*.md")),
        *sorted((_ROOT / "experiments" / "rig").glob("*.md")),
        _ROSTER,
        _PRICING,
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in maintained)
    assert "claude-mythos-5" not in combined.casefold()
    assert "gpt-5.6-tera" not in combined.casefold()
    assert "gpt-5.6-terra" in combined.casefold()
