"""Command allowlist, builder catalogs, and shared presentation metadata."""

from __future__ import annotations

import html
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MAX_RENDER_BYTES = 4 * 1024 * 1024
_LOG_TAIL_BYTES = 64 * 1024
_CSV_PREVIEW_ROWS = 200
_INVENTORY_MAX_ENTRIES = 8000
_INVENTORY_MAX_DEPTH = 4
_WARNINGS_FILE = "console-warnings.json"
_WARNINGS_MAX = 40
_WARNING_TONES = {"error": "red", "warning": "amber", "info": "blue"}

#: Recorded campaign sampling policy (thesis ledger 11.22/11.27, runbook 5.2).
#: Presentation of an operator-recorded decision; the actual enforcement is
#: the recorded --limit/--sample-seed on each hosted run_matrix invocation.
_CAMPAIGN_POLICY = (
    ("Full converted corpora", "run on local lanes only - never a hosted paid-API model"),
    (
        "Paid-API lanes",
        "run a pre-registered cluster subsample (recorded "
        "--limit and --sample-seed); the identical subset is used across every "
        "hosted condition and comparisons restrict to that intersection",
    ),
    (
        "No cross-tier pooling",
        "local full-corpus and hosted-subsample rates "
        "are distinct populations and are never pooled",
    ),
    (
        "Judge budget",
        "the selected model judge consumes the judge-call ceiling on every "
        "judged response; hosted judges additionally incur provider spend",
    ),
    (
        "Prepaid budgets",
        "Anthropic $100, OpenAI $50, Google $25, "
        "Moonshot $15, DeepSeek $10; canaries record observed tokens/spend, "
        "while per-lane caps use prepaid funds and prospective call upper bounds",
    ),
)


@dataclass(frozen=True)
class CommandParam:
    flag: str
    kind: str  # str | int | float | path | flag
    required: bool = False
    help: str = ""
    #: Strict value enumeration mirroring the CLI's argparse choices; renders
    #: as a select. Empty means free-form.
    choices: tuple[str, ...] = ()
    #: Name of a suggestion list (rendered as a datalist; free text stays
    #: allowed). Presentation only - build_argv validation is unchanged.
    suggest: str = ""
    #: Mirrors ``action="append"`` CLI flags: the form may send ``flag`` plus
    #: ``flag#1``, ``flag#2``, ... rows, emitted as one repeated flag per
    #: value, in index order.  Non-repeatable flags reject ``#`` suffixes.
    repeat: bool = False


#: Per-flag help text shown as field tooltips and inline hints on the Run
#: page.  Presentation only; the CLI's own --help remains authoritative.
_PARAM_HELP: dict[str, str] = {
    "--dry-run": "Use MockTarget and the offline mock LLM only - no provider "
    "calls, no spend. Produces a diagnostic dry-run artifact.",
    "--diagnostic-canary": "Run a small real slice under real attack and judge "
    "conditions to project per-cluster cost. Diagnostic "
    "only; never enters a measured tree.",
    "--attestation-probe": "One bounded real call per model to confirm the "
    "served identity and read token usage. First paid "
    "step; the per-model cost anchor comes from here.",
    "--api": "Comma list of hosted target ids from api-targets.json (e.g. the "
    "Fable/Sol focal pair). Hosted lanes must carry --limit and "
    "--sample-seed.",
    "--local": "Comma list of backend:model specs for local GPU lanes. Local "
    "lanes run the full corpus. A selected hosted judge remains metered; a "
    "local judge avoids hosted API spend but cannot share one process with a "
    "local target.",
    "--corpora": "Comma list of source arm ids (from source-instances.json) or "
    "'synth'. Every selected real arm must be admitted in the "
    "source-conformance receipt.",
    "--attackers": "Comma list of attack engines. 'replay' sends the corpus "
    "prompt as-is; 'crescendo' escalates over turns; the rest "
    "are external adapters.",
    "--judges": "Judge stages: 'rules' is the deterministic rule scorer "
    "(free), 'llm' adds an explicitly selected hosted or local model judge.",
    "--judge-model": "Configured hosted or local target id used by the LLM "
    "judge; 'mock' is reserved for offline dry runs.",
    "--ack-hosted-judge-data-transfer": "Explicit acknowledgement that a hosted "
    "judge receives target output plus source/reference grading context under "
    "the selected provider's retention and usage terms.",
    "--approximate-common-metrics": "Explicit opt-in for separate supplementary "
    "common-security response proxies on common-metric-ineligible source rows. "
    "These are non-authoritative, never replace source-native metrics, and carry "
    "an uncalibrated reliability indicator that is not probability or accuracy.",
    "--limit": "Cluster subsample size. REQUIRED on every hosted paid lane - "
    "it bounds spend. Omit only for local full-corpus lanes.",
    "--sample-seed": "Deterministic seed for the cluster subsample. Fix it and "
    "record it so every hosted condition sees the identical "
    "subset (comparable, never pooled across tiers).",
    "--seeds": "Comma list of trajectory seeds (attack stochasticity), distinct "
    "from --sample-seed.",
    "--max-queries": "Max target queries per trajectory (turn budget upper bound).",
    "--max-turns": "Max conversation turns per trajectory.",
    "--max-total-target-calls": "Hard circuit-breaker: abort the lane after "
    "this many target calls. A budget guard.",
    "--max-total-judge-calls": "Hard circuit-breaker on model-backed judge "
    "calls, hosted or local. A budget guard.",
    "--max-total-http-attempts": "Hard cap on total HTTP attempts across the "
    "lane (retries included).",
    "--deadline-seconds": "Wall-clock deadline for the lane; a runaway guard.",
    "--source-config": "Path to the source registry (experiments/"
    "source-instances.json). Bound automatically when the "
    "campaign env is exported.",
    "--api-config": "Path to the hosted-target registry (experiments/api-targets.json).",
    "--api-config-sha256": "Exact byte SHA-256 for a read-once selected hosted config.",
    "--local-config-sha256": "Exact byte SHA-256 for a read-once selected local config.",
    "--out": "Output directory under the rig results root for this run's artifacts.",
    "--expected-revision": "The exact 40-hex project commit this checkout must "
    "match for the revision receipt.",
    "--validate": "Path to an existing artifact to re-validate (with --sha256) "
    "instead of creating a new one.",
    "--scaffold": "Pre-fill the mechanical receipt fields from bounded "
    "observations, leaving operator judgments as OPERATOR_TODO "
    "placeholders.",
    "--selftest-sleep": "UI diagnostic only: sleep this many seconds and exit.",
    "--models": "Comma list of model names resolved through the hosted and "
    "local target registries (api-targets.json / "
    "local-targets.json). Mutually exclusive with explicit "
    "--api/--local; unknown or ambiguous names are rejected.",
    "--preflight-only": "Validate and project the complete grid without any "
    "model or judge call (what rig_check runs).",
    "--project-revision": "Path to the validated ura-project-revision/1 "
    "receipt. Defaults from URA_PROJECT_REVISION_"
    "MANIFEST; required for every non-dry invocation.",
    "--project-revision-sha256": "Exact byte SHA-256 paired with "
    "--project-revision (defaults from the "
    "campaign environment).",
    "--source-conformance": "Path to the validated ura-source-conformance/1 "
    "receipt; required when any real source arm is "
    "selected. Defaults from URA_SOURCE_CONFORMANCE_"
    "MANIFEST.",
    "--source-conformance-sha256": "Exact byte SHA-256 paired with --source-conformance.",
    "--quantization": "Default vLLM override (bitsandbytes, awq, gptq, fp8, "
    "none); per-model config wins; empty chooses the highest "
    "fitting 16-, 8-, or 4-bit precision.",
    "--dtype": "vLLM dtype for local models (auto, bfloat16, float16).",
    "--lock-stale-seconds": "Diagnostic stale-age metadata for cell locks; "
    "locks are never removed automatically.",
    "--live-attestation": "Repeatable: one content-addressed "
    "ura-live-attestation/2 receipt per row, paired "
    "positionally with a --live-attestation-sha256 row.",
    "--live-attestation-sha256": "Repeatable: the exact byte digest for the "
    "same-numbered --live-attestation row.",
    "--live-attestation-max-age-hours": "Maximum receipt age at measured-grid "
    "admission; must be in (0, 8760].",
    "--right-attacker": "Enables the replay-vs-adaptive comparison: "
    "--attacker is the left arm, this is the right arm "
    "(same model and defense on both sides).",
    "--minimum-unique-clusters": "Minimum source prompt/intent clusters per "
    "estimable transfer cell (>= 2).",
    "--bootstrap": "Cluster bootstrap resamples for the analysis CLIs.",
    "--bootstrap-resamples": "Bootstrap resamples for the human-audit "
    "analysis (this CLI's spelling of --bootstrap).",
    "--allow-single-rater": "Exploratory only: accept a labels file with one "
    "rater (agreement statistics need two or more).",
    "--alpha": "Two-sided significance level in (0, 1).",
    "--seed": "Deterministic analysis resampling seed.",
}


#: Prepaid provider budgets (thesis ledger Section 11.22).  Presentation of a
#: recorded operator decision; the console never spends anything.
_PROVIDER_BUDGETS: tuple[tuple[str, str, str], ...] = (
    (
        "Anthropic",
        "$100",
        "focal Fable target + the Haiku judge (the volume "
        "driver, metered on every judged response) + one breadth row",
    ),
    ("OpenAI", "$50", "focal GPT-5.6 Sol + at most one extra breadth row"),
    ("Google AI", "$25", "Gemini Flash-class row"),
    ("Moonshot", "$15", "one to two Kimi snapshots"),
    ("DeepSeek", "$10", "one row"),
)


#: The physical modalities a scored campaign arm carries. Multimodal arms
#: pair a text channel with an image/audio/video channel, so they belong to
#: BOTH modalities - a text+image arm is selected by the text chip and the
#: image chip alike (no arm is forced into a single bucket).
_MODALITIES = ("text", "image", "audio", "video", "tool")


#: The complete maintained source-arm catalogue: (arm id, physical modalities,
#: disabled reason).  All 39 registry arms are listed.  There are THREE kinds,
#: mirroring ``ura.eligibility`` and ``ura.source_metrics`` exactly:
#:   * empty reason, NOT in _SOURCE_METRIC_ARMS - a common-runner SCORED lane
#:     (``common_metrics_eligible: True``), scored by common harmful-ASR/FRR.
#:   * empty reason, IN _SOURCE_METRIC_ARMS - ``common_metrics_eligible: False``
#:     but its exact (source, required_metric) evaluator IS implemented in
#:     ``ura.source_metrics``, so run_matrix scores it as a source-metric lane
#:     (restricted to the attacker(s) its converter declares).  RUNNABLE.
#:   * non-empty reason - ``common_metrics_eligible: False`` and NO implemented
#:     source evaluator. Default admission fails before any target call; an
#:     explicit approximate-common-metrics opt-in permits only separately
#:     labelled, non-authoritative response proxies. This is NOT a native_import
#:     target: native_import canonicalises the upstream end-to-end engines.
def _ineligible(metric: str) -> str:
    return (
        f"This source requires the source-specific '{metric}' metric (not common "
        "harmful-ASR), but that evaluator is not integrated. Default scored "
        "admission therefore remains closed. The explicit approximate-common-"
        "metrics opt-in can add separate supplementary, non-authoritative "
        "response-proxy metrics; it does not implement or replace this source "
        "evaluator."
    )


def _tool_ineligible(metric: str) -> str:
    return (
        f"This source requires the source-specific {metric!r} metric and an "
        "executable tool environment. No maintained Runner target currently "
        "declares that capability, so both default scoring and the approximate "
        "response-proxy route remain fail-closed. Use a validated native tool "
        "runtime/import instead."
    )


_ARM_CATALOG: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("strongreject_official", ("text",), ""),
    ("advbench_harmful", ("text",), ""),
    ("jailbreakbench_harmful", ("text",), ""),
    ("jailbreakbench_benign", ("text",), ""),
    ("harmbench_text", ("text",), ""),
    ("cyberseceval_mitre", ("text",), ""),
    ("cyberseceval_interpreter", ("text",), ""),
    ("cyberseceval_insecure_coding", ("text",), ""),
    (
        "cyberseceval_prompt_injection",
        ("text",),
        _ineligible("cyberseceval_prompt_injection_judge_question"),
    ),
    ("mmsafety_official", ("text", "image"), ""),
    ("jailbreakv_full", ("text", "image"), ""),
    ("harmbench_multimodal", ("text", "image"), ""),
    ("vlsbench_release", ("text", "image"), ""),
    ("mossbench_official", ("text", "image"), ""),
    ("siuo_release", ("text", "image"), ""),
    ("figstep_full", ("text", "image"), ""),
    ("mllmguard_privacy", ("text", "image"), ""),
    ("mllmguard_bias", ("text", "image"), ""),
    ("mllmguard_toxicity", ("text", "image"), ""),
    ("mllmguard_legality", ("text", "image"), ""),
    (
        "mllmguard_position_swapping",
        ("text", "image"),
        _ineligible("mllmguard_position_swapping_truthfulness"),
    ),
    (
        "mllmguard_noise_injection",
        ("text", "image"),
        _ineligible("mllmguard_noise_injection_truthfulness"),
    ),
    (
        "mllmguard_hallucination",
        ("text", "image"),
        _ineligible("mllmguard_hallucination_truthfulness"),
    ),
    ("gptgeochat_release", ("text", "image"), ""),
    ("jalmbench_audio", ("text", "audio"), ""),
    ("videosafetybench_benign_query", ("text", "video"), ""),
    ("videosafetybench_harmful_query", ("text", "video"), ""),
    ("agentharm_benign", ("text", "tool"), _tool_ineligible("official_agentharm_tool_grading")),
    ("agentharm_harmful", ("text", "tool"), _tool_ineligible("official_agentharm_tool_grading")),
    ("bipia_test_abstract", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_code", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_email", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_qa", ("text",), _ineligible("indirect_injection_task_success")),
    ("bipia_test_table", ("text",), _ineligible("indirect_injection_task_success")),
    (
        "injecagent_direct_harm_base",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    (
        "injecagent_direct_harm_enhanced",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    (
        "injecagent_data_stealing_base",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    (
        "injecagent_data_stealing_enhanced",
        ("text", "tool"),
        _tool_ineligible("official_injecagent_tool_call_scoring"),
    ),
    ("rjudge_release", ("text",), ""),
)
#: Common-metric-ineligible arms whose exact (source, required_metric) evaluator
#: IS implemented in ``ura.source_metrics._IMPLEMENTED_SOURCE_EVALUATORS``, so
#: run_matrix scores them as source-metric lanes.  Each maps to (required_metric,
#: allowed attackers), mirroring the converter's ``source_metric_attackers``.
#: These are RUNNABLE, not disabled; a parity test asserts this set matches the
#: implemented-evaluator registry so the console can never drift from execution.
_SOURCE_METRIC_ARMS: dict[str, tuple[str, tuple[str, ...]]] = {
    "rjudge_release": ("rjudge_safety_judgment", ("replay",)),
    "gptgeochat_release": ("gptgeochat_binary_moderation", ("replay",)),
}
#: Scored arms for modality checks - common lanes AND source-metric lanes both
#: run in run_matrix and carry real modality requirements (empty reason).
_ARM_MODALITIES: tuple[tuple[str, tuple[str, ...]], ...] = tuple(
    (arm, mods) for arm, mods, reason in _ARM_CATALOG if not reason
)
#: Common-metric-ineligible arms with NO implemented source evaluator: shown
#: disabled and rejected before a scored lane.  Excludes the source-metric arms.
_INELIGIBLE_ARMS: frozenset[str] = frozenset(arm for arm, _mods, reason in _ARM_CATALOG if reason)
_INELIGIBLE_REASONS: dict[str, str] = {arm: reason for arm, _mods, reason in _ARM_CATALOG if reason}

#: Attack frameworks (engines) offered in the builder, mirroring the harness
#: registry in src/ura/adapters/engines.py, with the modalities each can drive.
#: replay/crescendo are modality-agnostic (they carry whatever the corpus
#: datapoint holds); the external text-jailbreak adapters are text-first.
_ALL_MODALITIES = ("text", "image", "audio", "video")
#: The 20 registered attacker names.  This mirrors the single source of truth
#: ``ura.adapters.engines.ATTACKER_NAMES``; importing that module eagerly would
#: pull in every heavy engine dependency just to list names, so the console
#: keeps a light mirror and a parity test asserts the two never drift.
_ATTACKER_NAMES: tuple[str, ...] = (
    "replay",
    "crescendo",
    "pyrit",
    "garak",
    "deepteam",
    "promptfoo",
    "t3mp3st",
    "petri",
    "fuzzyai",
    "nanogcg",
    "autodan",
    "agentdojo",
    "giskard",
    "easyjailbreak",
    "h4rm3l",
    "spikee",
    "ideator",
    "purplellama",
    "asb",
    "harmbench",
)
#: Attackers whose ``runner_replay_eligible`` is False - native-artifact
#: integrations (own their target/trajectory or evaluator) that run_matrix
#: REJECTS in the common runner ("cannot be replayed through Runner").  They are
#: shown disabled with their real action (the native-import path), never as
#: selectable common-runner frameworks.  A parity test asserts this matches the
#: harness registry.
_NATIVE_ONLY_ATTACKERS: frozenset[str] = frozenset(
    {
        "garak",
        "promptfoo",
        "petri",
        "fuzzyai",
        "autodan",
        "agentdojo",
        "giskard",
        "easyjailbreak",
        "asb",
    }
)
#: Every registered adapter is visible in Build. T3MP3ST and HarmBench use the
#: explicit prepare/capture controls rendered beside the normal lane builder.
_BUILDER_OMITTED_ATTACKERS: frozenset[str] = frozenset()
#: Every registered attacker (mirrors ura.adapters.engines.ATTACKER_NAMES, the
#: shared registry - a parity test asserts the two match). replay/crescendo are
#: modality-agnostic (they carry whatever the corpus datapoint holds); the
#: prepared external adapters below are text-first.
_FRAMEWORK_DESCRIPTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "replay": ("send the corpus prompt as-is (single turn)", _ALL_MODALITIES),
    "crescendo": ("escalate the request over multiple turns", _ALL_MODALITIES),
    "pyrit": ("Microsoft PyRIT adapter", ("text",)),
    "garak": ("NVIDIA garak probes", ("text",)),
    "deepteam": ("DeepTeam red-team adapter", ("text",)),
    "promptfoo": ("Promptfoo adapter", ("text",)),
    "t3mp3st": ("prepared T3MP3ST safe-probe replay", ("text",)),
    "petri": ("Petri adapter", ("text",)),
    "fuzzyai": ("FuzzyAI adapter", ("text",)),
    "nanogcg": ("nanoGCG gradient adapter", ("text",)),
    "autodan": ("AutoDAN-Turbo adapter", ("text",)),
    "agentdojo": ("AgentDojo adapter", ("text",)),
    "giskard": ("Giskard scan adapter", ("text",)),
    "easyjailbreak": ("EasyJailbreak adapter", ("text",)),
    "h4rm3l": ("h4rm3l program-synthesis adapter", ("text",)),
    "spikee": ("Spikee adapter", ("text",)),
    "ideator": ("IDEATOR adapter", ("text",)),
    "purplellama": ("PurpleLlama adapter", ("text",)),
    "asb": ("Agent Security Bench adapter", ("text",)),
    "harmbench": ("prepared HarmBench case-transfer replay", ("text",)),
}
_FRAMEWORKS: tuple[tuple[str, str, tuple[str, ...]], ...] = tuple(
    (
        name,
        _FRAMEWORK_DESCRIPTIONS.get(name, ("adapter", ("text",)))[0],
        _FRAMEWORK_DESCRIPTIONS.get(name, ("adapter", ("text",)))[1],
    )
    for name in _ATTACKER_NAMES
)

#: Builder execution modes -> the run_matrix flag they set (empty = measured).
_BUILD_MODES: tuple[tuple[str, str, str], ...] = (
    ("dry_run", "--dry-run", "Offline dry-run (MockTarget, no calls, no spend)"),
    (
        "attestation_probe",
        "--attestation-probe",
        "Attestation probe (one paid call per model; cost anchor)",
    ),
    (
        "diagnostic_canary",
        "--diagnostic-canary",
        "Diagnostic canary (small paid slice; observed tokens/spend only)",
    ),
    ("measured", "", "Measured lane (paid; produces campaign evidence)"),
)


#: Files the console may edit in place.  Strict allowlist keyed by a short
#: token; each is an operator-local registry read fresh by run_matrix, so an
#: edit here takes effect on the next job.  Value is
#: (relative_target, relative_example, description).  No path outside this map
#: is ever writable, and only JSON content that parses is accepted.
_EDITABLE_CONFIGS: dict[str, tuple[str, str, str]] = {
    "api-targets": (
        "experiments/api-targets.json",
        "experiments/rig/api-targets.example.json",
        "Hosted target roster: exact provider:model ids with modalities, "
        "max_tokens, temperature. Read fresh by run_matrix each invocation.",
    ),
    "source-instances": (
        "experiments/source-instances.json",
        "experiments/rig/source-instances.example.json",
        "Source arm registry: logical arm id -> converter, path_env, split. "
        "Add a reviewed release under a new arm id; never repoint an existing "
        "arm at different data.",
    ),
    "local-targets": (
        "experiments/local-targets.json",
        "experiments/rig/local-targets.example.json",
        "Local vLLM target registry: vllm:org/model -> pinned revision, "
        "modalities, tensor-parallel size, GPU memory, optional max_model_len "
        "context cap, and generation max_tokens. Consumed via "
        "--local / --local-config; runs on the rig's own GPUs (no API spend).",
    ),
    "budgets": (
        "experiments/budgets.json",
        "experiments/rig/budgets.example.json",
        "Prepaid provider budgets shown on the dashboard and Stats: a "
        "list of {name, prepaid, match, funds}. 'match' is a lowercase "
        "prefix used to attribute observed usage to the provider. "
        "Presentation only - the console spends nothing.",
    ),
    "pricing": (
        "experiments/pricing.json",
        "experiments/rig/pricing.example.json",
        "Effective-dated per-model price table used to calculate monetary "
        "cost from recorded token usage: providers -> models -> rates "
        "[{effective_date, currency, per_million_tokens{input, output, "
        "cache_read, cache_write, reasoning, batch_input, batch_output}}]. "
        "Rates ship null - fill them from the provider's current price "
        "sheet; the console never invents a price.",
    ),
}


#: Static suggestion lists.  The attacker suggestions are derived from the
#: shared registry mirror ``_ATTACKER_NAMES`` (all 20), so a new engine appears
#: automatically and none is silently omitted.
_SUGGEST_STATIC: dict[str, tuple[str, ...]] = {
    # Only campaign-usable common-runner attackers are suggested. Native-only
    # integrations use native_import; explicit non-campaign adapters stay CLI-only.
    "attackers": (
        "replay,crescendo",
        *(
            attacker
            for attacker in _ATTACKER_NAMES
            if attacker not in _NATIVE_ONLY_ATTACKERS and attacker not in _BUILDER_OMITTED_ATTACKERS
        ),
    ),
    "judges": ("rules,llm", "rules", "llm", "rules,guardrail", "guardrail"),
    "group": ("model", "source", "model,source"),
    "seeds": ("0", "0,1", "0,1,2"),
}


@dataclass(frozen=True)
class Command:
    name: str
    module: str
    description: str
    params: tuple[CommandParam, ...]


#: Shared surface for the matrix driver and its argv-forwarding preflight.
#: One entry per real ``run_matrix`` argparse option (asserted by the
#: interface-parity tests against ``run_matrix.build_parser()``).
_MATRIX_PARAMS = (
    CommandParam("--dry-run", "flag"),
    CommandParam("--preflight-only", "flag"),
    CommandParam("--diagnostic-canary", "flag"),
    CommandParam("--attestation-probe", "flag"),
    CommandParam("--models", "str", suggest="api"),
    CommandParam("--api", "str", suggest="api"),
    CommandParam("--local", "str"),
    CommandParam("--corpora", "str", suggest="arms"),
    CommandParam("--attackers", "str", suggest="attackers"),
    CommandParam("--judges", "str", suggest="judges"),
    CommandParam("--judge-model", "str", suggest="api"),
    CommandParam("--ack-hosted-judge-data-transfer", "flag"),
    CommandParam("--approximate-common-metrics", "flag"),
    CommandParam("--defense", "str", choices=("none", "input", "output", "both")),
    CommandParam("--defense-guard", "str", choices=("rules", "guardrail")),
    CommandParam("--guardrail-model", "str"),
    CommandParam("--guardrail-revision", "str"),
    CommandParam("--guardrail-device", "str"),
    CommandParam("--defense-guardrail-model", "str"),
    CommandParam("--defense-guardrail-revision", "str"),
    CommandParam("--defense-guardrail-device", "str"),
    CommandParam("--group", "str", suggest="group"),
    CommandParam("--attacker-config", "path"),
    CommandParam("--attacker-config-sha256", "str"),
    CommandParam("--reset-open-circuits", "flag"),
    CommandParam("--model-acquisition-plan-only", "flag"),
    CommandParam("--model-acquisition-plan-dir", "path"),
    CommandParam("--model-acquisition-plan", "path"),
    CommandParam("--model-acquisition-plan-sha256", "str"),
    CommandParam("--model-acquisition-receipt", "path"),
    CommandParam("--model-acquisition-receipt-sha256", "str"),
    CommandParam("--model-acquisition-store", "path"),
    CommandParam("--source-config", "path"),
    CommandParam("--source-config-sha256", "str"),
    CommandParam("--api-config", "path"),
    CommandParam("--api-config-sha256", "str"),
    CommandParam("--local-config", "path"),
    CommandParam("--local-config-sha256", "str"),
    CommandParam("--project-revision", "path"),
    CommandParam("--project-revision-sha256", "str"),
    CommandParam("--source-conformance", "path"),
    CommandParam("--source-conformance-sha256", "str"),
    CommandParam("--quantization", "str"),
    CommandParam("--dtype", "str"),
    CommandParam("--limit", "int"),
    CommandParam("--sample-seed", "int"),
    CommandParam("--seeds", "str", suggest="seeds"),
    CommandParam("--max-queries", "int"),
    CommandParam("--max-turns", "int"),
    CommandParam("--max-total-target-calls", "int"),
    CommandParam("--max-total-judge-calls", "int"),
    CommandParam("--max-total-http-attempts", "int"),
    CommandParam("--deadline-seconds", "int"),
    CommandParam("--lock-stale-seconds", "int"),
    CommandParam("--execution-scope-id", "str"),
    CommandParam("--live-attestation", "path", repeat=True),
    CommandParam("--live-attestation-sha256", "str", repeat=True),
    CommandParam("--live-attestation-max-age-hours", "float"),
    CommandParam("--out", "path"),
)


def _commands() -> dict[str, Command]:
    common_out = (CommandParam("--out", "path", help="output directory under the rig root"),)
    entries = [
        Command(
            "project_revision",
            "experiments.project_revision",
            "Create or validate the ura-project-revision/1 receipt",
            (
                CommandParam("--expected-revision", "str"),
                CommandParam("--out", "path"),
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
            ),
        ),
        Command(
            "source_conformance",
            "experiments.source_conformance",
            "Scaffold or validate the compact source acquisition receipt",
            (
                CommandParam("--scaffold", "flag"),
                CommandParam("--arm", "str", repeat=True),
                CommandParam("--observation", "str", repeat=True),
                CommandParam("--out", "path"),
                CommandParam("--manifest", "path"),
                CommandParam("--sha256", "str"),
                CommandParam("--source-config", "path"),
            ),
        ),
        Command(
            "capture_t3mp3st",
            "experiments.capture_t3mp3st",
            "Capture a validated T3MP3ST planning bundle for measured replay",
            (
                CommandParam("--corpus", "str"),
                CommandParam("--input", "path"),
                CommandParam("--source-config", "path"),
                CommandParam("--limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--endpoint", "str"),
                CommandParam("--upstream-revision", "str"),
                CommandParam("--source-provider", "str"),
                CommandParam("--source-model", "str"),
                CommandParam("--timeout-seconds", "float"),
                CommandParam("--out", "path"),
            ),
        ),
        Command(
            "harmbench_capture",
            "experiments.harmbench_capture",
            "Prepare a content-addressed HarmBench case bundle for measured replay",
            (
                CommandParam("--repo", "path"),
                CommandParam("--revision", "str"),
                CommandParam("--source", "path"),
                CommandParam("--corpus-name", "str"),
                CommandParam("--method", "str", repeat=True),
                CommandParam("--experiment", "str"),
                CommandParam("--limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--cases-per-method", "int"),
                CommandParam("--artifact-out", "path"),
                CommandParam("--attacker-config-out", "path"),
                CommandParam("--python", "path"),
                CommandParam("--credential-env", "str", repeat=True),
                CommandParam("--timeout-seconds", "float"),
            ),
        ),
        Command(
            "rig_check",
            "experiments.rig_check",
            "No-call preflight for a planned grid (same surface as run_matrix)",
            _MATRIX_PARAMS,
        ),
        Command(
            "run_matrix",
            "experiments.run_matrix",
            "Execute or dry-run one experiment matrix lane",
            _MATRIX_PARAMS,
        ),
        Command(
            "live_attestation",
            "experiments.live_attestation",
            "Derive a typed transport receipt from a completed probe",
            (
                CommandParam("--probe-root", "path"),
                CommandParam("--execution-scope-id", "str"),
                *common_out,
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
            ),
        ),
        Command(
            "lane_canary",
            "experiments.lane_canary",
            "Summarize one typed diagnostic canary completion",
            (
                CommandParam("--results", "path"),
                CommandParam("--eligibility", "path"),
                CommandParam("--out-dir", "path"),
            ),
        ),
        Command(
            "level1_evidence",
            "experiments.level1_evidence",
            "Build the Level-1 lifecycle JSON/CSV for one cohort",
            (
                CommandParam("--eligibility", "path", repeat=True),
                CommandParam("--results", "path", repeat=True),
                CommandParam("--live-attestation", "path", repeat=True),
                CommandParam("--live-attestation-sha256", "str", repeat=True),
                CommandParam("--out-json", "path"),
                CommandParam("--out-csv", "path"),
            ),
        ),
        Command(
            "suite_summary",
            "experiments.suite_summary",
            "Build the no-pooling suite evidence inventory",
            (
                CommandParam("--results", "path", repeat=True),
                CommandParam("--native", "path", repeat=True),
                CommandParam("--eligibility", "path", repeat=True),
                CommandParam("--source-config", "path"),
                *common_out,
            ),
        ),
        Command(
            "level2_report",
            "experiments.level2_report",
            "Export deterministic Level-2 JSON/CSV/Markdown broad tables",
            (
                CommandParam("--results", "path", repeat=True),
                CommandParam("--native", "path", repeat=True),
                CommandParam("--out-json", "path"),
                CommandParam("--out-csv", "path"),
                CommandParam("--out-md", "path"),
            ),
        ),
        Command(
            "human_audit",
            "experiments.human_audit",
            "Prepare or analyse the human-audit frames",
            (
                CommandParam("--results", "path"),
                CommandParam("--prepare", "int"),
                CommandParam("--prepare-source-task", "int"),
                CommandParam("--labels", "path"),
                CommandParam("--source-task-labels", "path"),
                CommandParam("--output", "path"),
                CommandParam("--acknowledge-sensitive-content", "flag"),
                CommandParam("--allow-single-rater", "flag"),
                CommandParam("--bootstrap-resamples", "int"),
                CommandParam("--alpha", "float"),
                CommandParam("--seed", "int"),
            ),
        ),
        Command(
            "figures",
            "experiments.figures",
            "Render figure previews or measured focal figures",
            (
                CommandParam("--synth", "flag"),
                CommandParam("--results", "path"),
                CommandParam("--left-model", "str"),
                CommandParam("--right-model", "str"),
                CommandParam("--human-audit", "path"),
                CommandParam("--human-audit-sha256", "str"),
                CommandParam("--strongreject-corpus", "str"),
                CommandParam("--mmsafety-corpus", "str"),
                CommandParam("--mossbench-corpus", "str"),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                *common_out,
            ),
        ),
        Command(
            "paired_compare",
            "experiments.paired_compare",
            "Paired cluster comparison between two exact conditions",
            (
                CommandParam("--results", "path"),
                CommandParam("--left-model", "str"),
                CommandParam("--right-model", "str"),
                CommandParam("--left-defense", "str"),
                CommandParam("--right-defense", "str"),
                CommandParam("--attacker", "str"),
                CommandParam("--right-attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--mode", "str", choices=("auto", "static", "live")),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                CommandParam("--permutations", "int"),
                CommandParam("--alpha", "float"),
                CommandParam("--assume-exchangeable", "flag"),
                CommandParam("--output", "path"),
            ),
        ),
        Command(
            "judge_sensitivity",
            "experiments.judge_sensitivity",
            "Same-response judge-stage sensitivity analysis",
            (
                CommandParam("--results", "path"),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--output", "path"),
            ),
        ),
        Command(
            "kappa",
            "experiments.kappa",
            "Pairwise judge-agreement diagnostics",
            (
                CommandParam("--results", "path"),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
            ),
        ),
        Command(
            "transfer_matrix",
            "experiments.transfer_matrix",
            "Support-qualified descriptive transfer analysis",
            (
                CommandParam("--results", "path"),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--minimum-unique-clusters", "int"),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                CommandParam("--alpha", "float"),
            ),
        ),
        Command(
            "export_jalmbench",
            "experiments.export_jalmbench",
            "Export the official JALMBench Parquet release for the converter",
            (
                CommandParam("--source", "path"),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *common_out,
            ),
        ),
        Command(
            "export_vlsbench",
            "experiments.export_vlsbench",
            "Export the official VLSBench Parquet release for the converter",
            (
                CommandParam("--source", "path"),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *common_out,
            ),
        ),
        Command(
            "native_import",
            "experiments.native_import",
            "Validate and canonicalize a native artifact family",
            (
                CommandParam("--config", "path"),
                CommandParam("--validate", "path"),
                *common_out,
            ),
        ),
        Command(
            "syn_compat",
            "experiments.syn_compat",
            "Synthetic compatibility corpus: generate/check/evaluate (rule-fidelity only)",
            (
                CommandParam("--generate", "flag"),
                CommandParam("--check", "flag"),
                CommandParam("--evaluate", "flag"),
                CommandParam("--cases", "path"),
                CommandParam("--metadata", "path"),
                CommandParam("--out", "path"),
                CommandParam("--seed", "int"),
                CommandParam("--perturbations-per-template", "int"),
            ),
        ),
        Command(
            "local_targets",
            "experiments.local_targets",
            "List or refresh the vLLM local-target roster (version-matched)",
            (
                CommandParam("--refresh", "flag"),
                CommandParam("--vllm-version", "str"),
                CommandParam("--repo-root", "str"),
            ),
        ),
        Command(
            "ollama_pull",
            "experiments.ollama_pull",
            "Pull one model through the fixed loopback Ollama daemon",
            (
                CommandParam("--model", "str", required=True),
                CommandParam("--base-url", "str"),
                CommandParam("--models-path", "path", required=True),
                CommandParam("--owned-pid", "int", required=True),
                CommandParam("--owned-process-identity", "str", required=True),
                CommandParam("--timeout-seconds", "float"),
            ),
        ),
        Command(
            "model_acquire",
            "experiments.model_acquire",
            "Acquire one reviewed immutable Hugging Face model plan",
            (
                CommandParam("--plan", "path", required=True),
                CommandParam("--plan-sha256", "str", required=True),
                CommandParam("--store", "path", required=True),
                CommandParam("--receipts-dir", "path", required=True),
                CommandParam("--transport-cache", "path"),
                CommandParam("--max-download-bytes", "int", required=True),
                CommandParam("--min-free-bytes", "int", required=True),
                CommandParam("--deadline-seconds", "float", required=True),
                CommandParam("--activity-event", "path"),
                CommandParam("--activity-job-id", "str"),
            ),
        ),
        Command(
            "webui_selftest",
            "experiments.rig_web",
            "UI diagnostic only: sleep briefly and exit",
            (CommandParam("--selftest-sleep", "float", required=True),),
        ),
    ]
    return {entry.name: entry for entry in entries}


COMMANDS = _commands()


#: Presentation-only grouping of the allowlisted commands by runbook stage.
#: Every generic-Run command appears in exactly one group (asserted by tests).
#: Controller-only commands such as run_matrix, model_acquire, and ollama_pull are intentionally
#: omitted because their validated Build workflows own launch authorization.
COMMAND_GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        "Receipts and conformance",
        "receipt",
        "runbook sections 2, 4.1, 17",
        ("project_revision", "source_conformance"),
    ),
    (
        "Prepared attack capture",
        "flask",
        "capture first, replay in Build",
        ("capture_t3mp3st", "harmbench_capture"),
    ),
    ("Acquisition exports", "box", "runbook section 3.2", ("export_jalmbench", "export_vlsbench")),
    (
        "Preflight, probes and lanes",
        "play",
        "runbook sections 8-13",
        ("rig_check", "live_attestation", "lane_canary"),
    ),
    ("Native and synthetic", "flask", "runbook sections 14, 16", ("native_import", "syn_compat")),
    (
        "Targets and rosters",
        "coins",
        "runbook sections 5, 13",
        ("local_targets",),
    ),
    (
        "Analysis and reporting",
        "chart",
        "runbook section 16",
        (
            "level1_evidence",
            "suite_summary",
            "level2_report",
            "figures",
            "paired_compare",
            "judge_sensitivity",
            "kappa",
            "transfer_matrix",
        ),
    ),
    ("Human audit", "users", "runbook sections 15, 15.1", ("human_audit",)),
    ("Console diagnostics", "pulse", "runbook section 18", ("webui_selftest",)),
)


def _param_values(
    param: CommandParam,
    values: Mapping[str, str],
) -> list[str]:
    """Collect one parameter's non-empty form values, repeat rows included.

    A repeatable parameter accepts the bare ``flag`` field plus any number of
    ``flag#N`` rows (N a positive integer), returned in index order with the
    bare field first.  Non-repeatable parameters accept the bare field only;
    their ``#`` variants stay unknown parameters.
    """

    collected: list[tuple[int, str]] = []
    base = values.get(param.flag, "")
    base = base.strip() if isinstance(base, str) else ""
    if base:
        collected.append((0, base))
    if param.repeat:
        prefix = param.flag + "#"
        for key, raw in values.items():
            if not key.startswith(prefix):
                continue
            suffix = key[len(prefix) :]
            if not suffix.isdigit() or int(suffix) <= 0:
                raise ValueError(f"invalid repeat row {key!r}")
            raw = raw.strip() if isinstance(raw, str) else ""
            if raw:
                collected.append((int(suffix), raw))
    collected.sort(key=lambda item: item[0])
    return [raw for _index, raw in collected]


def build_argv(
    command: str,
    values: Mapping[str, str],
    *,
    commands: Mapping[str, Command] | None = None,
) -> list[str]:
    """Build an exact argument vector from a typed allowlisted form."""

    registry = COMMANDS if commands is None else commands
    entry = registry.get(command)
    if entry is None:
        raise ValueError(f"unknown command {command!r}")
    known = {param.flag: param for param in entry.params}
    allowed = set(known)
    for param in entry.params:
        if param.repeat:
            allowed.update(key for key in values if key.startswith(param.flag + "#"))
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(f"unknown parameter(s) for {command!r}: {unknown}")
    argv = [sys.executable, "-m", entry.module]
    for param in entry.params:
        raws = _param_values(param, values)
        if not raws:
            if param.required:
                raise ValueError(f"{command!r} requires {param.flag}")
            continue
        if param.kind == "flag":
            if len(raws) != 1 or raws[0] not in {"on", "true", "1", "yes"}:
                raise ValueError(f"{param.flag} is a checkbox flag")
            argv.append(param.flag)
            continue
        for raw in raws:
            if param.kind == "int":
                int(raw)
            elif param.kind == "float":
                float(raw)
            elif param.kind == "path":
                if "\x00" in raw:
                    raise ValueError(f"invalid path for {param.flag}")
            if param.choices and raw not in param.choices:
                raise ValueError(f"{param.flag} must be one of {', '.join(param.choices)}")
            argv.extend([param.flag, raw])
    return argv


def _contained(root: Path, relative: str) -> Path:
    """Resolve a browser path strictly inside the configured root."""

    candidate = (relative or "").replace("\\", "/").strip()
    if candidate.startswith("/") or ":" in candidate.split("/", 1)[0]:
        raise ValueError("artifact paths must be relative to the rig root")
    resolved = (root / candidate).resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError("artifact path escapes the rig root")
    return resolved


_BADGE_FIELDS = (
    (
        "evidence_kind",
        {
            "diagnostic_dry_run": ("diagnostic dry-run", "amber"),
            "measured_run": ("measured run", "blue"),
        },
    ),
    (
        "execution_purpose",
        {
            "diagnostic_canary": ("diagnostic canary", "amber"),
            "attestation_probe": ("attestation probe", "amber"),
            "measured_run": ("measured run", "blue"),
        },
    ),
    (
        "evidence_class",
        {
            "synthetic_offline": ("synthetic offline", "amber"),
            "live_diagnostic": ("live diagnostic", "amber"),
        },
    ),
    (
        "status",
        {
            "complete": ("complete", "green"),
            "error": ("error", "red"),
            "running": ("running", "blue"),
        },
    ),
)


def evidence_badges(document: Any) -> list[tuple[str, str]]:
    """Derive explicit diagnostic/measured and status badges from a JSON body."""

    badges: list[tuple[str, str]] = []
    if not isinstance(document, dict):
        return badges
    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    merged: dict[str, Any] = {**scope, **document}
    for name, mapping in _BADGE_FIELDS:
        value = merged.get(name)
        if isinstance(value, str) and value in mapping:
            badges.append(mapping[value])
    if merged.get("dry_run") is True:
        badges.append(("dry-run", "amber"))
    if merged.get("campaign_authorized") is False:
        badges.append(("campaign not authorized", "gray"))
    if merged.get("empirical_validity_established") is False:
        badges.append(("no empirical validity", "gray"))
    counts = document.get("counts")
    if isinstance(counts, dict):
        strata = counts.get("planning_strata")
        if isinstance(strata, dict):
            for key, label in (
                ("structural_not_applicable", "structural N/A"),
                ("missing", "missing"),
                ("error", "error"),
            ):
                value = strata.get(key)
                if isinstance(value, int) and value > 0:
                    badges.append((f"{label}: {value}", "gray" if key != "error" else "red"))
    return badges


#: Inline stroke icons (24x24 viewBox); presentation only, no external assets.
_ICONS: dict[str, str] = {
    "logo": (
        "<path d='M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z'/>"
        "<path d='M8.5 12.5l2.5 2.5 4.5-5'/>"
    ),
    "grid": (
        "<rect x='3' y='3' width='7' height='7' rx='1.5'/>"
        "<rect x='14' y='3' width='7' height='7' rx='1.5'/>"
        "<rect x='3' y='14' width='7' height='7' rx='1.5'/>"
        "<rect x='14' y='14' width='7' height='7' rx='1.5'/>"
    ),
    "terminal": "<path d='M4 17l6-5-6-5'/><path d='M12 19h8'/>",
    "pulse": "<path d='M22 12h-4l-3 9L9 3l-3 9H2'/>",
    "folder": (
        "<path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z'/>"
    ),
    "file": (
        "<path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 "
        "2-2V8z'/><path d='M14 2v6h6'/>"
    ),
    "receipt": (
        "<path d='M9 11l3 3L22 4'/>"
        "<path d='M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 "
        "2-2h11'/>"
    ),
    "box": (
        "<path d='M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 "
        "8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z'/>"
        "<path d='M3.3 7L12 12l8.7-5'/><path d='M12 22V12'/>"
    ),
    "play": "<path d='M6 3l14 9-14 9V3z'/>",
    "flask": (
        "<path d='M10 2v6.3L4.2 19a2 2 0 0 0 1.8 3h12a2 2 0 0 0 1.8-3L14 "
        "8.3V2'/><path d='M8 2h8'/><path d='M7.5 14h9'/>"
    ),
    "chart": "<path d='M18 20V10'/><path d='M12 20V4'/><path d='M6 20v-6'/>",
    "users": (
        "<path d='M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2'/>"
        "<circle cx='9' cy='7' r='4'/>"
        "<path d='M23 21v-2a4 4 0 0 0-3-3.87'/>"
        "<path d='M16 3.13a4 4 0 0 1 0 7.75'/>"
    ),
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "disk": ("<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='2.5'/>"),
    "sliders": (
        "<path d='M4 21v-7'/><path d='M4 10V3'/><path d='M12 21v-9'/>"
        "<path d='M12 8V3'/><path d='M20 21v-5'/><path d='M20 12V3'/>"
        "<path d='M1 14h6'/><path d='M9 8h6'/><path d='M17 16h6'/>"
    ),
    "coins": (
        "<circle cx='8' cy='8' r='6'/>"
        "<path d='M18.09 10.37A6 6 0 1 1 10.34 18'/>"
        "<path d='M7 6h1v4'/><path d='M16.71 13.88l.7.71-2.82 2.82'/>"
    ),
    "save": (
        "<path d='M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1"
        "-2 2z'/><path d='M17 21v-8H7v8'/><path d='M7 3v5h8'/>"
    ),
    "book": (
        "<path d='M4 19.5A2.5 2.5 0 0 1 6.5 17H20'/>"
        "<path d='M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 "
        "6.5 2z'/>"
    ),
    # Modality glyphs (shown instead of TEXT/IMAGE/AUDIO/VIDEO word tags).
    "mod_text": "<path d='M4 6h16'/><path d='M4 12h12'/><path d='M4 18h8'/>",
    "mod_image": (
        "<rect x='3' y='3' width='18' height='18' rx='2'/>"
        "<circle cx='8.5' cy='8.5' r='1.5'/><path d='M21 15l-5-5L5 21'/>"
    ),
    "mod_audio": ("<path d='M4 9v6h4l5 4V5L8 9H4z'/><path d='M16 8.5a4 4 0 0 1 0 7'/>"),
    "mod_video": (
        "<rect x='2' y='6' width='13' height='12' rx='2'/><path d='M15 10l7-4v12l-7-4z'/>"
    ),
}


def _icon(name: str, *, size: int = 18) -> str:
    body = _ICONS.get(name, _ICONS["file"])
    return (
        f"<svg class='ic' width='{size}' height='{size}' viewBox='0 0 24 24' "
        "fill='none' stroke='currentColor' stroke-width='1.8' "
        f"stroke-linecap='round' stroke-linejoin='round' "
        f"aria-hidden='true'>{body}</svg>"
    )


_MOD_ICON_NAME = {
    "text": "mod_text",
    "image": "mod_image",
    "audio": "mod_audio",
    "video": "mod_video",
}


def _mod_icon(modality: str) -> str:
    """A colored modality chip with an accessible label, instead of a word tag
    (keeps dense arm/target grids from being overwhelmed by TEXT/IMAGE/... text).
    """
    name = _MOD_ICON_NAME.get(modality, "file")
    return (
        f"<span class='modicon m-{html.escape(modality)}' "
        f"title='{html.escape(modality)}' "
        f"aria-label='{html.escape(modality)}'>{_icon(name, size=12)}</span>"
    )


def _mod_set(mods: tuple[str, ...]) -> str:
    """The right-aligned cluster of modality chips for a checkbox row header."""
    return "<span class='modset'>" + "".join(_mod_icon(m) for m in mods) + "</span>"


def _arm_head(name_html: str, mods: tuple[str, ...]) -> str:
    """One checkbox-row header line: name on the left, modality chips on the
    right - a consistent, uncluttered placement instead of icons trailing the
    name."""
    return f"<span class='armhead'><span class='armname'>{name_html}</span>{_mod_set(mods)}</span>"
