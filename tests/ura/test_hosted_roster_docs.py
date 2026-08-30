"""Advertised hosted-roster, pricing, and operator-document parity."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.catalog import _ARM_CATALOG
from experiments.rig_web_app.reports import rate_for
from ura.converters import _CONVERTERS
from ura.data_models import RiskCategory
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
    fixture_root = tmp_path / "repo"
    fixture_registry = fixture_root / "experiments" / "rig" / _ROSTER.name
    fixture_registry.parent.mkdir(parents=True)
    fixture_registry.write_bytes(_ROSTER.read_bytes())
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=fixture_root,
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
        "runs/thesis/runner/defense-text",
    ):
        position = runbook.index(measured_destination)
        assert "--ack-hosted-judge-data-transfer" in runbook[
            max(0, position - 600) : position
        ]
    local_destination = "runs/thesis/runner/local-qwen3-vl-text-core100"
    local_position = runbook.index(local_destination)
    local_context = runbook[max(0, local_position - 800) : local_position]
    assert "--ack-hosted-judge-data-transfer" not in local_context
    assert "--judges rules,guardrail" in local_context
    assert '--limit "$URA_LOCAL_CORE_CLUSTER_LIMIT"' in local_context


def test_core_docs_describe_request_endpoint_and_execution_config_contracts() -> None:
    paths = (
        _ROOT / "README.md",
        _ROOT / "docs" / "SCHEMA.md",
        _ROOT / "docs" / "ARCHITECTURE.md",
        _ROOT / "experiments" / "RUN_AND_RETURN.md",
    )
    for path in paths:
        document = path.read_text(encoding="utf-8")
        assert "ura-request-envelope/3" in document, path
        assert "hosted_judge_data_transfer_acknowledged" in document, path
        assert "ura-builder-selected-api-config/1" in document, path
        assert "endpoint_identity" in document, path
        assert "https-base-url-sha256" in document, path
        assert "raw URL" in document, path


# Display names the maintained prose uses for each converter family; the
# count-propagation test below asserts every family is enumerated by name.
_CONVERTER_DISPLAY_NAMES = {
    "advbench": "AdvBench",
    "agentharm": "AgentHarm",
    "airbench": "AIR-Bench",
    "bipia": "BIPIA",
    "cyberseceval": "CyberSecEval",
    "decodingtrust": "DecodingTrust",
    "figstep": "FigStep",
    "gptgeochat": "GPTGeoChat",
    "harmbench": "HarmBench",
    "holisafe": "HoliSafe",
    "injecagent": "InjecAgent",
    "jailbreakbench": "JailbreakBench",
    "jailbreakv": "JailBreakV",
    "jalmbench": "JALMBench",
    "mllmguard": "MLLMGuard",
    "mmsafety": "MM-SafetyBench",
    "mossbench": "MOSSBench",
    "rjudge": "R-Judge",
    "saladbench": "SALAD-Bench",
    "simplesafetytests": "SimpleSafetyTests",
    "siuo": "SIUO",
    "strongreject": "StrongREJECT",
    "videosafetybench": "Video-SafetyBench",
    "vlsbench": "VLSBench",
    "xstest": "XSTest",
}
_AGGREGATOR_TEXT_ARMS = (
    "saladbench_base",
    "airbench_full",
    "xstest_full",
    "simplesafetytests_full",
    "decodingtrust_stereotype",
)


def test_maintained_docs_enumerate_every_converter_family_and_arm() -> None:
    """Count propagation (P2-03/P2-04/P2-05): the 25-family/45-arm prose lists,
    the runbook locator block and lanes, and the rig README registry table must
    enumerate what the code registers, not a stale 20-family/39-arm subset."""

    assert set(_CONVERTER_DISPLAY_NAMES) == set(_CONVERTERS)
    registry = _json(_ROOT / "experiments" / "rig" / "source-instances.example.json")
    assert len(registry) == len(_ARM_CATALOG)
    assert {entry["converter"] for entry in registry.values()} == set(_CONVERTERS)

    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    protocol = (_ROOT / "experiments" / "PROTOCOL.md").read_text(encoding="utf-8")
    experiments_readme = (_ROOT / "experiments" / "README.md").read_text(encoding="utf-8")
    rig_readme = (_ROOT / "experiments" / "rig" / "README.md").read_text(encoding="utf-8")
    runbook = (_ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(encoding="utf-8")

    assert f"{len(_CONVERTERS)} converter families" in readme
    assert f"{len(_CONVERTERS)} converter families" in protocol
    assert f"{len(_CONVERTERS)} converter families" in experiments_readme
    assert f"builder covers all {len(_ARM_CATALOG)} maintained source arms" in readme
    assert f"all {len(_CONVERTERS)} converters" in rig_readme
    assert f"Its {len(_ARM_CATALOG)} logical arms" in rig_readme
    for name, display in _CONVERTER_DISPLAY_NAMES.items():
        assert display in readme, display
        assert display in protocol, display
        assert display in rig_readme, display
        assert name in experiments_readme, name
        assert f"| `{name}` |" in runbook, name
    for arm, entry in registry.items():
        assert f"export {entry['path_env']}=" in runbook, arm
        assert f"`{entry['path_env']}`" in rig_readme or f"`{arm}`" in rig_readme, arm
    text_arms = re.search(r"export TEXT_ARMS='([^']+)'", runbook)
    image_arms = re.search(r"export IMAGE_ARMS='([^']+)'", runbook)
    assert text_arms is not None and image_arms is not None
    assert set(_AGGREGATOR_TEXT_ARMS) <= set(text_arms.group(1).split(","))
    assert "holisafe_full" in image_arms.group(1).split(",")
    media_roots = re.search(r'export URA_MEDIA_ROOTS="([^"]+)"', runbook)
    assert media_roots is not None
    assert "$URA_CORPORA/HoliSafe" in media_roots.group(1).split(":")
    assert "### 3.4 Aggregator corpora" in runbook
    assert "-m experiments.export_aggregators --source all" in runbook


def test_rig_readme_describes_the_shipped_hosted_registry_and_credentials() -> None:
    """The rig README must describe the example registry that actually ships
    (P2-07/P2-MISSED-1) and name every credential/base-URL variable the code
    reads (P2-10)."""

    rig_readme = (_ROOT / "experiments" / "rig" / "README.md").read_text(encoding="utf-8")
    runbook = (_ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(encoding="utf-8")
    roster = _json(_ROSTER)
    for spec in roster:
        assert f"| `{spec}` |" in rig_readme, spec
    assert f"exactly these {_number_word(len(roster))} keys" in rig_readme
    assert "intentionally absent" not in rig_readme
    for env_name in ("ARK_API_KEY", "ZHIPU_API_KEY", *_COMPAT_ENDPOINT_ENVS):
        assert env_name in rig_readme, env_name
        assert env_name in runbook, env_name
    for env_name in (
        "URA_MODEL_ACQUISITION_PLAN_DIR",
        "URA_MODEL_ACQUISITION_PLAN",
        "URA_MODEL_ACQUISITION_PLAN_SHA256",
        "URA_MODEL_ACQUISITION_RECEIPT",
        "URA_MODEL_ACQUISITION_RECEIPT_SHA256",
        "URA_MODEL_ACQUISITION_STORE",
    ):
        assert env_name in runbook, env_name


def _number_word(value: int) -> str:
    words = {20: "twenty", 21: "twenty-one", 22: "twenty-two", 19: "nineteen", 18: "eighteen"}
    return words.get(value, str(value))


def test_attack_tags_crosswalk_lists_every_risk_category() -> None:
    document = (_ROOT / "docs" / "ATTACK_TAGS.md").read_text(encoding="utf-8")
    for category in RiskCategory:
        assert f"| `{category.value}` |" in document, category.value


def test_local_example_same_base_pair_shares_memory_utilization() -> None:
    """The LLaVA base and GraySwan RR rows are the one planned same-base defense
    contrast; the example must not silently give them different engine memory
    settings (P2-08)."""

    registry = _json(_ROOT / "experiments" / "rig" / "local-targets.example.json")
    base = registry["vllm:llava-hf/llava-v1.6-mistral-7b-hf"]
    guarded = registry["vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR"]
    assert isinstance(base, dict) and isinstance(guarded, dict)
    assert base["gpu_memory_utilization"] == guarded["gpu_memory_utilization"] == 0.85
    assert base["tensor_parallel_size"] == guarded["tensor_parallel_size"]
    assert base["max_tokens"] == guarded["max_tokens"]


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


_CLI_DEFAULT_GROUP_KEYS = (
    "model,source,risk,effective_modality,expected_behavior,attacker,"
    "source_policy_id,source_policy_version"
)


def test_runbook_lanes_use_the_level2_grouping_and_bounded_population_tiers() -> None:
    """Every documented measured/preflight lane passes the CLI-default eight-key
    grouping (the only grouping the Level-2 export admits), hosted-target or
    hosted-judge lanes carry a positive-limit binding, and the core/extended
    local tiers remain explicit and separate (R4-1/2/3)."""
    runbook = (_ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(encoding="utf-8")
    protocol = (_ROOT / "experiments" / "PROTOCOL.md").read_text(encoding="utf-8")
    local_plan = (_ROOT / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
        encoding="utf-8"
    )
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    lanes = runbook[runbook.index("## 9. Plan lanes"):runbook.index("## 14. Tier 5")]
    group_values = re.findall(r"--group (\S+)", lanes)
    assert group_values and set(group_values) == {_CLI_DEFAULT_GROUP_KEYS}
    assert "--limit 0 --sample-seed" not in lanes
    limit_placeholder = "--limit '<pre-registered-cluster-limit (section 5.2)>'"
    commands = [
        command
        for command in _documented_commands(lanes)
        if '--judge-model "$JUDGE"' in command or "--api " in command
    ]
    # Canaries keep --limit 1 and the audio lane its bounded variable; no
    # hosted-route lane may run the complete corpus.
    assert not any("--limit 0" in command for command in commands)
    assert sum(limit_placeholder in command for command in commands) >= 9
    flattened = {
        "runbook": " ".join(runbook.split()),
        "protocol": " ".join(protocol.split()),
        "local plan": " ".join(local_plan.split()),
        "README": " ".join(readme.split()),
    }
    runbook_flat = flattened["runbook"]
    protocol_flat = flattened["protocol"]
    for flat in (runbook_flat, protocol_flat):
        assert "--limit 100" in flat
        assert "--limit 50" in flat
        assert "24-hour" in flat and "86400" in flat
        assert "ura-corpus-cluster-order-v1\\0<logical-arm>\\0<sample_seed>" in flat
        assert "first eight bytes" in flat and "big-endian" in flat
        assert "without replacement" in flat and "nested" in flat
    local_plan_flat = flattened["local plan"]
    assert "ura-corpus-cluster-order-v1\\0<logical-arm>\\0<sample_seed>" in (
        local_plan_flat
    )
    assert "nested, overlapping prefixes, not disjoint partitions" in local_plan_flat
    assert "not a proportional or risk-stratified sample" in protocol_flat
    assert "local scoring stages" in runbook_flat
    assert "scores through local stages only" in protocol_flat
    assert "rules-only cascade is not a general scoring mode" in protocol_flat
    readme_flat = flattened["README"]
    assert (
        "100 clusters per source arm for core lanes and 50 for extended" in readme_flat
    )

    sampling_contract = (
        "equal per-arm cap",
        "Cluster-key fallback precedence is nonblank "
        "`meta[\"source_cluster_id\"]`, then nonblank `DataPoint.id`, then the "
        "converted row index",
        "Python's `random.Random(scoped_seed).shuffle(...)`",
        "without replacement",
        "nested",
        "uses `--sample-seed 0` only",
        "`--sample-seed 1` is a separately projected future cohort",
        "The framework supports full-set execution for local and hosted targets",
        "Current-campaign policy authorizes full mode only for all-local replication",
    )

    def assert_sampling_contract(document: str) -> None:
        for required in sampling_contract:
            assert required in document

    for document in flattened.values():
        assert_sampling_contract(document)

    # Mutation probes prove that the test fails if exact RNG, fallback, cohort,
    # or current-campaign full-mode semantics are weakened independently.
    for required in sampling_contract:
        mutated = runbook_flat.replace(required, "MUTATED_CONTRACT_TOKEN")
        assert mutated != runbook_flat
        with pytest.raises(AssertionError):
            assert_sampling_contract(mutated)


def test_follow_on_runbook_keeps_purpose_and_media_contracts() -> None:
    runbook = (_ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    local_plan = (_ROOT / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
        encoding="utf-8"
    )
    controller_readme = (
        _ROOT / "experiments" / "local_campaign" / "README.md"
    ).read_text(encoding="utf-8")
    section = " ".join(
        runbook[
            runbook.index("#### NanoGCG: sealed suffix capture, then replay"):
            runbook.index("#### HarmBench: capture, then replay")
        ].split()
    )
    required = (
        "not a claim of one surrogate forward pass",
        "URA_IDEATOR_MEDIA_ROOT",
        "same ordered `URA_MEDIA_ROOTS` value",
        "`--timeout-seconds 600` applies to each planning HTTP request",
        "set -o pipefail",
        'URA_T3_CAPTURE_SESSION="ura-t3mp3st-capture-',
        "separate exact preflight, diagnostic-canary and measured argument vectors",
        "`--attacker-config-sha256 <matching-digest>`",
        "path is operational, not part of model-acquisition identity",
        "Do not append to or rewrite the sealed core cohort's `runs/thesis/RUNNOTE.md`",
        "`ura-external-measured-job/2` start/terminal records",
    )

    def assert_contract(value: str) -> None:
        for token in required:
            assert token in value
        assert (
            "must be reused verbatim across plan, acquisition, projection, canary "
            "and measured execution"
        ) not in value

    assert_contract(section)
    assert "retained immutable argument array" not in runbook
    for token in required:
        mutated = section.replace(token, "MUTATED_FOLLOW_ON_CONTRACT")
        assert mutated != section
        with pytest.raises(AssertionError):
            assert_contract(mutated)

    for document in (local_plan, controller_readme):
        normalized_document = " ".join(document.split())
        assert "common scientific base" in normalized_document
        assert (
            "separate exact preflight, canary and measured argument arrays"
            in normalized_document
        )
        assert "Each purpose keeps its own plan and receipt" in normalized_document
        assert "retained immutable argument array" not in normalized_document


def test_runbook_section_18_documents_the_build_surface_and_hf_token_children() -> None:
    """Section 18 states the Build-vs-CLI surface the console parity tests
    enforce and the HF_TOKEN child policy (R4-5, R5-2, D4)."""
    runbook = (_ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(encoding="utf-8")
    section = " ".join(
        runbook[runbook.index("## 18. Rig-local console and campaign builder"):].split()
    )
    for token in (
        "`--models`",
        "`ideator`",
        "`ura-ideator-seed-pairs/1`",
        "`purplellama`",
        "`cyberseceval_*`",
        "`--group`",
        _CLI_DEFAULT_GROUP_KEYS,
        "`--exclude-tool-conditioned`",
        "`--reset-open-circuits`",
        "`--lock-stale-seconds`",
        "`URA_PROJECT_REVISION_*`",
        "`URA_SOURCE_CONFORMANCE_*`",
        "`export_aggregators`",
        "acquisition children (`model_acquire` and `export_aggregators`)",
    ):
        assert token in section, token
    assert "CLI-only" not in section
    assert "per selected arm" in section
    assert "detached process wall-time ceiling" in section
    assert "Set `--deadline-seconds` independently" in section
    assert "durable call-start window" in section
    assert "converts exactly to `--deadline-seconds`" not in section
    assert "dedicated sealed-acquisition child" not in runbook
    architecture = " ".join(
        (_ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8").split()
    )
    assert "`--models` shorthand" in architecture
    assert "`ura-ideator-seed-pairs/1`" in architecture
    assert "`ideator` is CLI-only" not in architecture
    assert _CLI_DEFAULT_GROUP_KEYS in architecture
    assert "dedicated acquisition child" not in architecture
