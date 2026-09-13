"""Command allowlist, builder catalogs, and shared presentation metadata."""

from __future__ import annotations

import html
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ura.sampling import SAMPLING_POLICIES

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MAX_RENDER_BYTES = 4 * 1024 * 1024
_LOG_TAIL_BYTES = 64 * 1024
_CSV_PREVIEW_ROWS = 200
_INVENTORY_MAX_ENTRIES = 8000
_INVENTORY_MAX_DEPTH = 4
_WARNINGS_FILE = "console-warnings.json"
_WARNINGS_MAX = 40
_WARNING_TONES = {"error": "red", "warning": "amber", "info": "blue"}


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
    "--exclude-tool-conditioned": "Drop tool-conditioned source rows (no Runner "
    "attacker can execute them yet) with a recorded exclusion count instead of "
    "failing the whole request. Valid only for a standalone offline dry run; "
    "preflight and evidence-bearing routes reject it.",
    "--api": "Comma list of hosted target ids from api-targets.json (e.g. the "
    "Fable/Sol focal pair). Hosted lanes must carry an explicit --limit; "
    "--sample-seed is required only for a positive bounded selection.",
    "--local": "Comma list of backend:model specs for local GPU lanes. Local "
    "lanes may use an approved bounded per-arm sample or an explicitly "
    "projected full-corpus cohort. A selected hosted judge remains metered; "
    "a local judge avoids hosted API spend but cannot share one process with "
    "a local target.",
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
    "--limit": "Maximum unique source clusters applied independently to each "
    "selected corpus arm. Omitting it means the CLI default of 50 clusters per "
    "arm; 0 means the complete selected release for every arm. "
    "Hosted paid lanes must enter the value explicitly: use a positive bound, "
    "or 0 only with a separate full-grid projection, covering call/HTTP/judge "
    "caps, deadline and approval.",
    "--sample-seed": "Seed for each arm-scoped pseudorandom cluster shuffle "
    "without replacement. Fix and record it so limits are nested and conditions "
    "with the same logical arm, converted corpus digest, limit and seed see "
    "the identical subset (comparable, never pooled across arms or tiers).",
    "--seeds": "Comma list of trajectory seeds (attack stochasticity), distinct "
    "from --sample-seed.",
    "--sampling-policy": "Whole-cluster prefix policy. The seeded pseudorandom "
    "policy is the unchanged CLI default; source order takes the first source "
    "clusters. An explicit value is retained in request and projection identity.",
    "--max-queries": "Max target queries per trajectory (turn budget upper bound).",
    "--max-turns": "Max conversation turns per trajectory.",
    "--target-answer-retries": "Additional attempts after an empty, malformed, "
    "binary/control-like, or symbol-only model answer. Local default is one. "
    "Paid hosted targets require zero; their bounded transport retries are "
    "separate and apply only to retryable HTTP status errors.",
    "--recovery-completed-prefix": "Validated create-only recovery selection "
    "that removes only exact already-completed input identities from the "
    "unchanged requested population.",
    "--recovery-completed-prefix-sha256": "Exact byte SHA-256 paired with the "
    "recovery completed-prefix artifact.",
    "--max-total-target-calls": "Hard circuit-breaker: abort the lane after "
    "this many target calls. A budget guard.",
    "--max-total-judge-calls": "Hard circuit-breaker on model-backed judge "
    "calls, hosted or local. A budget guard.",
    "--max-total-http-attempts": "Hard cap on total HTTP attempts across the "
    "lane (retries included).",
    "--deadline-seconds": "Durable call-start admission window measured from "
    "the matrix's first invocation. It prevents new model acquisitions and "
    "new calls after expiry; it does not interrupt an already admitted call "
    "or guarantee that the process finishes within this many seconds.",
    "--source-config": "Path to the source registry (experiments/"
    "source-instances.json). Bound automatically when the "
    "campaign env is exported.",
    "--api-config": "Path to the hosted-target registry (experiments/api-targets.json).",
    "--api-config-sha256": "Exact byte SHA-256 for a read-once selected hosted config.",
    "--local-config-sha256": "Exact byte SHA-256 for a read-once selected local config.",
    "--profile-registry": "Machine-local registry that retains identity-bound local-model "
    "readiness recommendations for both CLI and Build. Hosted targets never use it.",
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
    "receipt; required for every non-dry invocation. The CLI defaults it from "
    "URA_PROJECT_REVISION_MANIFEST; the console forwards that exported "
    "variable (and URA_PROJECT_REVISION_SHA256) to a non-dry child when it is "
    "set in the console process, and Build folds the value into the argv.",
    "--project-revision-sha256": "Exact byte SHA-256 paired with "
    "--project-revision. The CLI defaults it from URA_PROJECT_REVISION_SHA256, "
    "which the console forwards to a non-dry child when set.",
    "--source-conformance": "Path to the validated ura-source-conformance/1 "
    "receipt; required when any real source arm is selected. The CLI defaults "
    "it from URA_SOURCE_CONFORMANCE_MANIFEST; the console forwards that "
    "exported variable (and URA_SOURCE_CONFORMANCE_SHA256) to a non-dry child "
    "when it is set in the console process, and Build folds the value into "
    "the argv.",
    "--source-conformance-sha256": "Exact byte SHA-256 paired with "
    "--source-conformance. The CLI defaults it from "
    "URA_SOURCE_CONFORMANCE_SHA256, which the console forwards to a non-dry "
    "child when set.",
    "--quantization": "Default vLLM override (bitsandbytes, awq, gptq, fp8, "
    "none); per-model config wins; empty chooses the highest "
    "fitting 16-, 8-, or 4-bit precision.",
    "--dtype": "vLLM dtype for local models (auto, bfloat16, float16).",
    "--lock-stale-seconds": "Diagnostic stale-age metadata for cell locks; "
    "locks are never removed automatically. Optional positive integer "
    "(CLI default 86400).",
    "--reset-open-circuits": "Operator acknowledgement: clear the durable "
    "provider/judge circuit after correcting its root cause, then rerun the "
    "identical measured lane to resume (runbook section 17). Never a "
    "default.",
    "--group": "Comma list of aggregation group keys from the CLI's allowed "
    "set (model, target, attacker, strategy, source, risk, risk_category, "
    "risk_subtype, modality, effective_modality, is_multimodal, "
    "expected_behavior, attack_family, seed, source_policy_id, "
    "source_policy_version). The CLI default (and the runbook's measured "
    "lanes, Build's default) is model,source,risk,effective_modality,"
    "expected_behavior,attacker,source_policy_id,source_policy_version. "
    "Level-2 export requires at least these eight keys; narrower groupings "
    "are rejected at export; blank inherits the CLI default.",
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
    "--bootstrap-resamples": "Labels-analysis-only bootstrap resamples for "
    "the human audit (this CLI's spelling of --bootstrap); invalid during "
    "preparation.",
    "--prepared-rating-form": "Exact controller-prepared blank two-rater form "
    "that the completed labels must match without dropped or substituted rows.",
    "--prepared-rating-form-sha256": "Authorized lowercase SHA-256 of the exact "
    "prepared rating form.",
    "--alpha": "Labels-analysis-only two-sided significance level in (0, 1).",
    "--seed": "Labels-analysis-only deterministic resampling seed; preparation "
    "uses a versioned seedless selector.",
    "--allow-single-rater": "Exploratory labels analysis only. The resulting "
    "report remains ineligible for evidence-ready human-audit claims.",
}

#: Builder-owned process wall-time ceiling for long local measured lanes. It is
#: deliberately separate from Runner's ``--deadline-seconds`` call-start gate.
_LOCAL_BUDGET_HELP = (
    "Final measured all-local process only. Whole hours become a detached process "
    "wall-time cap that terminates and then kills the complete process tree after "
    "expiry. Set --deadline-seconds independently for Runner's call-start window."
)


#: The physical modalities a scored campaign arm carries. Multimodal arms
#: pair a text channel with an image/audio/video channel, so they belong to
#: BOTH modalities - a text+image arm is selected by the text chip and the
#: image chip alike (no arm is forced into a single bucket).
_MODALITIES = ("text", "image", "audio", "video", "tool")


#: The complete maintained source-arm catalogue: (arm id, physical modalities,
#: disabled reason).  All 45 registry arms are listed.  There are THREE kinds,
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
    ("saladbench_base", ("text",), ""),
    ("decodingtrust_stereotype", ("text",), ""),
    ("airbench_full", ("text",), ""),
    ("xstest_full", ("text",), ""),
    ("simplesafetytests_full", ("text",), ""),
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
    ("holisafe_full", ("text", "image"), ""),
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

#: Arms drawn from unified / multi-benchmark AGGREGATOR sources (each itself
#: pools or spans many upstream safety corpora). Tagged with an "aggregator"
#: badge in the builder so the operator can see the aggregator-class sources at a
#: glance; this is display metadata only and does not change admission.
_AGGREGATOR_ARMS: frozenset[str] = frozenset({
    "saladbench_base",
    "airbench_full",
    "xstest_full",
    "simplesafetytests_full",
    "holisafe_full",
    "decodingtrust_stereotype",
})

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
#: Precomputed-only adapters whose required prepared input still has no Builder
#: control. IDEATOR is intentionally absent: Build accepts its exact
#: content-addressed seed-pair manifest and snapshots every selected PNG.
_CLI_ONLY_ATTACKERS: dict[str, str] = {}
#: Adapters that replay only rows of one upstream source family (the adapter
#: raises for any other DataPoint.source).  Maps attacker -> (arm id prefix,
#: reason); mirrored in builder validation so the lane is rejected before a
#: subprocess exists.
_SOURCE_RESTRICTED_ATTACKERS: dict[str, tuple[str, str]] = {
    "purplellama": (
        "cyberseceval_",
        "purplellama replays only source-authentic CyberSecEval rows "
        "(DataPoint.source == 'cyberseceval'); select only cyberseceval_* "
        "arms with it (no synth)",
    ),
}
#: Mirror of ``experiments.run_matrix._ALLOWED_GROUP_KEYS`` (a parity test
#: asserts the two never drift); importing run_matrix at page-render time
#: would pull in the whole harness just to list keys.
_GROUP_KEYS: tuple[str, ...] = (
    "model",
    "target",
    "attacker",
    "strategy",
    "source",
    "risk",
    "risk_category",
    "risk_subtype",
    "modality",
    "effective_modality",
    "is_multimodal",
    "expected_behavior",
    "attack_family",
    "seed",
    "source_policy_id",
    "source_policy_version",
)
#: The run_matrix argparse default for --group.  experiments.level2_report
#: refuses any aggregate whose group_by lacks these eight keys, so every
#: documented measured/preflight lane (RUN_AND_RETURN sections 9-13) passes
#: exactly this value and Build defaults to it; a parity test pins both the
#: parser default and the level-2 requirement to this string.
_CLI_DEFAULT_GROUP = (
    "model,source,risk,effective_modality,expected_behavior,attacker,"
    "source_policy_id,source_policy_version"
)
#: The runbook's measured/preflight --group value: the CLI default, written
#: out explicitly so a console lane aggregates exactly like the documented
#: CLI lane and its cells reach the Level-2 export.
_RUNBOOK_GROUP = _CLI_DEFAULT_GROUP
#: Every registered attacker (mirrors ura.adapters.engines.ATTACKER_NAMES, the
#: shared registry - a parity test asserts the two match). replay/crescendo are
#: modality-agnostic (they carry whatever the corpus datapoint holds); the
#: prepared external adapters below are text-first.
_FRAMEWORK_DESCRIPTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "replay": ("send the corpus prompt as-is (single turn)", _ALL_MODALITIES),
    "crescendo": ("escalate the request over multiple turns", _ALL_MODALITIES),
    "pyrit": ("Microsoft PyRIT 0.14.0 in its own explicit venv", ("text",)),
    "garak": ("NVIDIA garak probes", ("text",)),
    "deepteam": ("DeepTeam 1.0.7 in its own explicit venv", ("text",)),
    "promptfoo": ("Promptfoo adapter", ("text",)),
    "t3mp3st": ("prepared T3MP3ST safe-probe replay", ("text",)),
    "petri": ("Petri adapter", ("text",)),
    "fuzzyai": ("FuzzyAI adapter", ("text",)),
    "nanogcg": ("precomputed nanoGCG suffix replay; live generation disabled", ("text",)),
    "autodan": ("AutoDAN-Turbo adapter", ("text",)),
    "agentdojo": ("AgentDojo adapter", ("text",)),
    "giskard": ("Giskard scan adapter", ("text",)),
    "easyjailbreak": ("EasyJailbreak adapter", ("text",)),
    "h4rm3l": ("h4rm3l 0.2.4 in its own explicit venv", ("text",)),
    "spikee": ("Spikee 0.9.1 in its own explicit venv", ("text",)),
    "ideator": ("IDEATOR verified precomputed text-image seed-pair replay", ("text",)),
    "purplellama": ("PurpleLlama source-identity replay (CyberSecEval arms only)", ("text",)),
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
            if attacker not in _NATIVE_ONLY_ATTACKERS
            and attacker not in _BUILDER_OMITTED_ATTACKERS
            and attacker not in _CLI_ONLY_ATTACKERS
        ),
    ),
    "judges": ("rules,llm", "rules", "llm", "rules,guardrail", "guardrail"),
    # Only the full default grouping is offered: Level-2 export rejects any
    # narrower grouping, and a blank field inherits the same CLI default.
    "group": (_RUNBOOK_GROUP,),
    "seeds": ("0", "0,1", "0,1,2"),
}


@dataclass(frozen=True)
class Command:
    name: str
    module: str
    description: str
    params: tuple[CommandParam, ...]


#: Complete matrix-driver surface. One entry per real ``run_matrix`` argparse
#: option (asserted by interface-parity tests). The argv-forwarding preflight
#: derives its subset below because it always adds ``--preflight-only``.
_MATRIX_PARAMS = (
    CommandParam("--dry-run", "flag"),
    CommandParam("--preflight-only", "flag"),
    CommandParam("--diagnostic-canary", "flag"),
    CommandParam("--attestation-probe", "flag"),
    CommandParam("--exclude-tool-conditioned", "flag"),
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
    CommandParam("--engine-runtime-config", "path"),
    CommandParam("--engine-runtime-config-sha256", "str"),
    CommandParam("--reset-open-circuits", "flag"),
    CommandParam("--verify-model-sha256", "flag"),
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
    CommandParam(
        "--sampling-policy", "str", choices=tuple(sorted(SAMPLING_POLICIES))
    ),
    CommandParam("--seeds", "str", suggest="seeds"),
    CommandParam("--max-queries", "int"),
    CommandParam("--max-turns", "int"),
    CommandParam("--target-answer-retries", "int"),
    CommandParam("--recovery-completed-prefix", "path"),
    CommandParam("--recovery-completed-prefix-sha256", "str"),
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

# rig_check always appends --preflight-only. The standalone-dry-only exclusion
# can therefore never be valid on that forwarding surface, even when the form
# also supplies --dry-run.
_RIG_CHECK_PARAMS = tuple(
    param
    for param in _MATRIX_PARAMS
    if param.flag != "--exclude-tool-conditioned"
)


def _commands() -> dict[str, Command]:
    common_out = (CommandParam("--out", "path", help="output directory under the rig root"),)
    # Same field where the module's argparse marks --out required; the Run
    # page renders the required marker from this (a parity test derives the
    # set from each module's real parser).
    required_out = (
        CommandParam(
            "--out", "path", required=True, help="output directory under the rig root"
        ),
    )
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
                CommandParam("--source-config", "path", required=True),
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
                CommandParam("--upstream-revision", "str", required=True),
                CommandParam("--framework-lock", "path"),
                CommandParam("--framework-env-root", "path"),
                CommandParam("--framework-state-root", "path"),
                CommandParam("--source-provider", "str", required=True),
                CommandParam("--source-model", "str", required=True),
                CommandParam("--timeout-seconds", "float"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "harmbench_capture",
            "experiments.harmbench_capture",
            "Prepare a content-addressed HarmBench case bundle for measured replay",
            (
                CommandParam("--repo", "path", required=True),
                CommandParam("--revision", "str", required=True),
                CommandParam("--source", "path", required=True),
                CommandParam("--corpus-name", "str"),
                CommandParam("--method", "str", repeat=True, required=True),
                CommandParam("--experiment", "str"),
                CommandParam("--limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--cases-per-method", "int"),
                CommandParam("--artifact-out", "path", required=True),
                CommandParam("--attacker-config-out", "path", required=True),
                CommandParam("--python", "path"),
                CommandParam("--credential-env", "str", repeat=True),
                CommandParam("--timeout-seconds", "float"),
            ),
        ),
        Command(
            "rig_check",
            "experiments.rig_check",
            "No-call preflight for a planned grid",
            _RIG_CHECK_PARAMS,
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
                CommandParam("--results", "path", required=True),
                CommandParam("--eligibility", "path", required=True),
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
                CommandParam("--out-json", "path", required=True),
                CommandParam("--out-csv", "path", required=True),
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
                *required_out,
            ),
        ),
        Command(
            "level2_report",
            "experiments.level2_report",
            "Export deterministic Level-2 JSON/CSV/Markdown broad tables",
            (
                CommandParam("--results", "path", repeat=True),
                CommandParam("--native", "path", repeat=True),
                CommandParam("--out-json", "path", required=True),
                CommandParam("--out-csv", "path", required=True),
                CommandParam("--out-md", "path", required=True),
            ),
        ),
        Command(
            "human_audit",
            "experiments.human_audit",
            "Prepare or analyse the human-audit frames",
            (
                CommandParam("--results", "path", required=True),
                CommandParam("--historical-code-repository", "path"),
                CommandParam("--judge-configuration-sha256", "str"),
                CommandParam("--prepare", "int"),
                CommandParam("--prepare-source-task", "int"),
                CommandParam("--labels", "path"),
                CommandParam("--source-task-labels", "path"),
                CommandParam("--prepared-rating-form", "path"),
                CommandParam("--prepared-rating-form-sha256", "str"),
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
                CommandParam("--verify-artifact-sha256", "flag"),
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
                CommandParam("--results", "path", required=True),
                CommandParam("--historical-code-repository", "path",
                    help="Repository containing the original source revisions for retained runs."),
                CommandParam("--left-model", "str", required=True),
                CommandParam("--right-model", "str", required=True),
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
                CommandParam("--results", "path", required=True),
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
                CommandParam("--results", "path", required=True),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
            ),
        ),
        Command(
            "transfer_matrix",
            "experiments.transfer_matrix",
            "Support-qualified descriptive transfer analysis",
            (
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--results", "path", required=True),
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
                CommandParam("--source", "path", required=True),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *required_out,
            ),
        ),
        Command(
            "export_vlsbench",
            "experiments.export_vlsbench",
            "Export the official VLSBench Parquet release for the converter",
            (
                CommandParam("--source", "path", required=True),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *required_out,
            ),
        ),
        Command(
            "export_aggregators",
            "experiments.export_aggregators",
            "Acquire one (or all) aggregator corpora into the converter layout",
            (
                CommandParam(
                    "--source",
                    "str",
                    required=True,
                    choices=(
                        "saladbench",
                        "airbench",
                        "xstest",
                        "simplesafetytests",
                        "decodingtrust",
                        "holisafe",
                        "all",
                    ),
                    help="which aggregator corpus to prepare (or all six)",
                ),
                CommandParam(
                    "--out-root",
                    "path",
                    required=True,
                    help="corpora root (the exported URA_CORPORA); each source "
                    "writes under its own subdir",
                ),
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
            "response_svm",
            "experiments.response_svm",
            "Retained response classifiers: harmful compliance, over-refusal and judge disagreement (no calls)",
            (
                CommandParam("--export", "flag"),
                CommandParam("--evaluate", "flag"),
                CommandParam("--package", "flag"),
                CommandParam("--predict", "flag"),
                CommandParam("--database", "path"),
                CommandParam("--candidates", "path"),
                CommandParam("--campaign", "str", repeat=True),
                CommandParam("--matched-campaign", "str"),
                CommandParam("--judge-condition", "str"),
                CommandParam("--exclude-model", "str", repeat=True),
                CommandParam("--dataset", "path"),
                CommandParam("--study-result", "path"),
                CommandParam("--study-predictions", "path"),
                CommandParam("--models", "path", help="Trusted fitted models.joblib from this tool only"),
                CommandParam("--features", "str", choices=("prompt", "response", "prompt_response")),
                CommandParam("--out", "path", required=True),
                CommandParam("--seed", "int"),
                CommandParam("--max-feature-characters", "int"),
                CommandParam("--bootstrap", "int"),
                CommandParam("--holdout-model", "str", repeat=True),
                CommandParam("--holdout-corpus", "str", repeat=True),
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
            "local_model_readiness",
            "experiments.local_model_readiness",
            "Profile one vLLM or Ollama target with the seeded 10-text/5-image gate",
            (
                CommandParam("--local", "str"),
                CommandParam("--context-ceiling", "int", help="Optional context ceiling tested by readiness; "
                    "leave empty for hardware fit. Minimum 25001 tokens. Ollama still requires full GPU residency."),
                CommandParam("--local-config", "path"),
                CommandParam("--local-config-sha256", "str"),
                CommandParam("--model-acquisition-plan-only", "flag"),
                CommandParam("--model-acquisition-plan-dir", "path"),
                CommandParam("--model-acquisition-plan", "path"),
                CommandParam("--model-acquisition-plan-sha256", "str"),
                CommandParam("--model-acquisition-receipt", "path"),
                CommandParam("--model-acquisition-receipt-sha256", "str"),
                CommandParam("--model-acquisition-store", "path"),
                CommandParam("--out", "path"),
                CommandParam("--profile-registry", "path"),
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
                CommandParam("--expected-spec", "str"),
            ),
        ),
        Command(
            "retained_local_sources",
            "experiments.retained_local_sources",
            "Select saved local runs for input-matched follow-on preparation, without model calls",
            (
                CommandParam("--source-root", "path", required=True, repeat=True,
                    help="Completed Runner results directories. Select narrow job directories, not the entire results store."),
                CommandParam("--run-id", "str", repeat=True,
                    help="Optional exact run IDs; blank selects all completed local runs in the named directories."),
                CommandParam("--out", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_retained_inputs",
            "experiments.hosted_retained_inputs",
            "Prepare an input-matched hosted subset from saved local runs, without paid calls",
            (
                CommandParam("--local-inventory", "path", required=True,
                    help="Inventory produced by Select saved local runs; historical inventories also need runner-view."),
                CommandParam("--local-inventory-sha256", "str", required=True),
                CommandParam("--runner-view", "path", help="Historical inventories only; omit for selected local source directories."),
                CommandParam("--budget", "path", required=True),
                CommandParam("--budget-sha256", "str", required=True),
                CommandParam("--api-config", "path", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--target", "str", required=True),
                CommandParam("--global-input-cap", "int"),
                CommandParam("--media-index", "path",
                    help="Optional for selected local sources: original converted inputs and configured media roots provide their locations."),
                CommandParam("--media-index-sha256", "str"),
                CommandParam("--materialize-corpus", "str"),
                CommandParam("--source-corpora", "path",
                    help="Optional for selected local sources: reconstructs the recorded original corpus subset, without resampling."),
                CommandParam("--source-corpora-sha256", "str"),
                CommandParam("--out", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_campaign_prepare",
            "experiments.hosted_campaign_prepare",
            "Count selected requests and prepare shared target and judging allowances; no generation",
            (
                CommandParam("--request", "path", required=True),
                CommandParam("--request-sha256", "str", required=True),
                CommandParam("--out-root", "path", required=True),
                CommandParam("--count-cache", "path", help="Reuse exact token-count receipts after interruption."),
                CommandParam("--shared-budget-root", "path"),
                CommandParam("--shared-budget-sha256", "str"),
                CommandParam("--allow-network-counts", "flag",
                    help="Allow provider token-count endpoints only; this does not enable answer generation."),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_selected_replays",
            "experiments.hosted_selected_replays",
            "Prepare all selected models' matched replay inputs from saved sources and a forecast, without calls",
            (
                CommandParam("--local-inventory", "path", required=True),
                CommandParam("--local-inventory-sha256", "str", required=True),
                CommandParam("--budget", "path", required=True),
                CommandParam("--budget-sha256", "str", required=True),
                CommandParam("--api-config", "path", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--out-root", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_program_runtime",
            "experiments.hosted_program_runtime",
            "Bind an untouched hosted program to installed models without calls; transport observation still required",
            (
                CommandParam("--program", "path", required=True),
                CommandParam("--program-sha256", "str", required=True),
                CommandParam("--budget-root", "path", required=True),
                CommandParam("--budget-plan-sha256", "str", required=True),
                CommandParam("--project-root", "path", required=True),
                CommandParam("--expected-commit", "str", required=True),
                CommandParam("--store", "path", help="Existing managed-model store; no downloads are performed."),
                CommandParam("--out", "path", required=True,
                    help="New or matching interrupted runtime preparation directory."),
                CommandParam("--max-age-hours", "float"),
                CommandParam("--verify-model-sha256", "flag"),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_campaign_execute",
            "experiments.hosted_campaign_execute",
            "Collect prepared hosted programs in parallel; judge retained answers afterward",
            (
                CommandParam("--program", "path", required=True, repeat=True,
                    help="Exact prepared/attested program files, one per selected model condition"),
                CommandParam("--program-sha256", "str", required=True, repeat=True,
                    help="Matching program digests, in the same order as the program files"),
                CommandParam("--budget-root", "path", required=True),
                CommandParam("--budget-plan-sha256", "str", required=True),
                CommandParam("--project-root", "path", required=True),
                CommandParam("--expected-commit", "str", required=True),
                CommandParam("--out", "path", required=True),
                CommandParam("--prepare-runtime", "flag", help="Bind installed models and complete the selected funded transport probes before collection"),
                CommandParam("--model-store", "path", help="Existing resolved managed-model store; defaults to URA_MODEL_STORE"),
                CommandParam("--workers-per-provider", "int",
                    help="Independent target workers per provider (default 2, maximum 8); providers run concurrently"),
                CommandParam("--resume-from", "path", help="Previous collection control directory. "
                    "Keep its programs and budget; choose a fresh output directory for this continuation. "
                    "Completed jobs are restored, not regenerated."),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "hosted_campaign_budget",
            "experiments.hosted_campaign_budget",
            "Project the sealed hosted target and Haiku judge budget without calls",
            (
                CommandParam("--api-config", "path", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--pricing-config", "path", required=True),
                CommandParam("--pricing-config-sha256", "str", required=True),
                CommandParam("--budgets", "path", required=True),
                CommandParam("--budgets-sha256", "str", required=True),
                CommandParam("--pricing-as-of", "str", required=True),
                CommandParam("--route-configuration", "path",
                    help="Selected models with their own request and output-token caps; omit only for the legacy default cohort."),
                CommandParam("--route-configuration-sha256", "str"),
                CommandParam("--reservation-policy", "str", choices=("first_attempts_upfront", "per_attempt"),
                    help="Per-attempt checks queue the full selected inventory under shared spending ceilings."),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_native_judge_prepare",
            "experiments.retained_native_judge_prepare",
            "Prepare local judging of saved API answers without generating or judging",
            (
                CommandParam("--program", "path", required=True, repeat=True),
                CommandParam("--program-sha256", "str", required=True, repeat=True),
                CommandParam("--job", "str", repeat=True, help="Optional exact job names; blank selects all supplied jobs."),
                CommandParam("--include-incomplete", "flag",
                    help="Include saved outputs from interrupted jobs; unsaved inputs remain pending, not judged."),
                CommandParam("--out", "path", required=True),
                CommandParam("--verify-artifact-sha256", "flag"),
            ),
        ),
        Command(
            "retained_native_judge_execute",
            "experiments.retained_native_judge_execute",
            "Judge saved API answers locally, resuming verdicts without target calls",
            (
                CommandParam("--preparation", "path", required=True),
                CommandParam("--preparation-sha256", "str", required=True),
                CommandParam("--out", "path", required=True, help="Reuse the same directory to resume saved judgments."),
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--verify-model-sha256", "flag"),
            ),
        ),
        Command(
            "retained_response_judge_pair",
            "experiments.retained_response_judge_pair",
            "Select matched retained local and hosted outputs for bounded Haiku judging",
            (
                CommandParam("--api-config", "path", help="Needed with an existing campaign judging budget."),
                CommandParam("--shared-budget-root", "path"),
                CommandParam("--shared-budget-sha256", "str"),
                CommandParam("--program", "path", repeat=True),
                CommandParam("--program-sha256", "str", repeat=True),
                CommandParam("--local-runner-view", "path", required=True),
                CommandParam("--hosted-runner-view", "path", required=True),
                CommandParam("--source-receipt", "path", required=True),
                CommandParam("--source-receipt-sha256", "str", required=True),
                CommandParam("--judge-model", "str", required=True),
                CommandParam("--api-config-sha256", "str", required=True),
                CommandParam("--pricing-config", "path", required=True),
                CommandParam("--pricing-config-sha256", "str", required=True),
                CommandParam("--pricing-as-of", "str", required=True),
                CommandParam("--pair-limit", "int"),
                CommandParam("--sample-seed", "int"),
                CommandParam("--max-cost-microusd", "int"),
                CommandParam(
                    "--ack-hosted-judge-data-transfer", "flag", required=True
                ),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_judge_inventory",
            "experiments.retained_judge_inventory",
            "Inventory every local and hosted answer on the same inputs, without judging or spending",
            (
                CommandParam("--local-view", "path", required=True, repeat=True),
                CommandParam("--hosted-view", "path", required=True, repeat=True),
                CommandParam("--input-limit", "int", help="Zero keeps every hosted input, including missing answers."),
                CommandParam("--sample-seed", "int"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_inventory_judge_items",
            "experiments.retained_inventory_judge_items",
            "Prepare all matching saved answers under existing judging funding, without calls",
            (
                CommandParam("--inventory", "path", required=True),
                CommandParam("--local-view", "path", required=True, repeat=True),
                CommandParam("--hosted-view", "path", required=True, repeat=True),
                CommandParam("--budget-root", "path", required=True, repeat=True),
                CommandParam("--budget-plan-sha256", "str", required=True, repeat=True),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_inventory_judging",
            "experiments.retained_inventory_judging",
            "Prepare or resume all funded saved-output Haiku judgments under existing campaign budgets",
            (
                CommandParam("--items-root", "path"),
                CommandParam("--judge-model", "str"),
                CommandParam("--api-config", "path"),
                CommandParam("--pricing-config", "path"),
                CommandParam("--pricing-as-of", "str"),
                CommandParam("--allow-token-counts", "flag"),
                CommandParam("--preparation", "path"),
                CommandParam("--execute", "flag"),
                CommandParam("--ack-paid-execution", "flag"),
                CommandParam("--workers", "int"),
                CommandParam("--matching-workspace-id", "str"),
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_hosted_judge_items",
            "experiments.retained_hosted_judge_items",
            "Prepare saved hosted answers for their existing Haiku funding, without paid calls",
            (
                CommandParam("--preparation", "path", required=True),
                CommandParam("--budget-root", "path", required=True),
                CommandParam("--budget-plan-sha256", "str", required=True),
                CommandParam("--out", "path", required=True),
            ),
        ),
        Command(
            "retained_response_judge_pair_execute",
            "experiments.retained_response_judge_pair_execute",
            "Execute one sealed matched local and hosted Haiku judging plan",
            (
                CommandParam("--shared-budget-root", "path", help="Existing campaign judging allocation."),
                CommandParam("--shared-budget-sha256", "str"),
                CommandParam("--shared-requests", "path", help="Saved output-specific funded Haiku requests."),
                CommandParam("--shared-requests-sha256", "str"),
                CommandParam("--matching-workspace-id", "str", help="The other campaign ID owning matched outputs. "
                    "The selected campaign is included automatically; each verdict and cost belongs to its exact answer."),
                CommandParam("--retain-invalid-verdicts", "flag"),
                CommandParam("--verify-artifact-sha256", "flag"),
                CommandParam("--plan", "path", required=True),
                CommandParam("--local-runner-view", "path", required=True),
                CommandParam("--hosted-runner-view", "path", required=True),
                CommandParam("--source-receipt", "path", required=True),
                CommandParam("--api-config", "path", required=True),
                CommandParam("--pricing-config", "path", required=True),
                CommandParam("--out", "path", required=True),
                CommandParam("--ack-paid-execution", "flag", required=True),
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
                CommandParam("--verify-model-sha256", "flag"),
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
    (
        "Acquisition exports",
        "box",
        "runbook section 3",
        ("export_jalmbench", "export_vlsbench", "export_aggregators"),
    ),
    (
        "Preflight, probes and lanes",
        "play",
        "runbook sections 8-13",
        ("rig_check", "live_attestation", "lane_canary"),
    ),
    ("Analysis and native imports", "flask", "runbook sections 14, 16", ("native_import", "syn_compat", "response_svm")),
    (
        "Targets and rosters",
        "coins",
        "runbook sections 5, 13",
        ("local_targets", "local_model_readiness"),
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
    (
        "Hosted budget and retained judging",
        "coins",
        "runbook sections 19-20",
        (
            "retained_local_sources",
            "hosted_campaign_budget",
            "hosted_retained_inputs",
            "hosted_selected_replays",
            "hosted_campaign_prepare",
            "hosted_program_runtime",
            "hosted_campaign_execute",
            "retained_native_judge_prepare",
            "retained_native_judge_execute",
            "retained_response_judge_pair",
            "retained_judge_inventory",
            "retained_inventory_judge_items",
            "retained_hosted_judge_items",
            "retained_inventory_judging",
            "retained_response_judge_pair_execute",
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
    if command == "human_audit":
        populated = {
            flag
            for flag in (
                "--prepare",
                "--prepare-source-task",
                "--labels",
                "--source-task-labels",
            )
            if isinstance(values.get(flag), str) and values[flag].strip()
        }
        if len(populated) != 1:
            raise ValueError("human_audit requires exactly one preparation or labels mode")
        judge_configuration = values.get("--judge-configuration-sha256", "").strip()
        historical_repository = values.get("--historical-code-repository", "").strip()
        if judge_configuration:
            if not historical_repository or populated & {"--prepare-source-task", "--source-task-labels"}:
                raise ValueError("judge configuration selection requires a historical common frame")
            if (len(judge_configuration) != 64
                or any(c not in "0123456789abcdef" for c in judge_configuration)):
                raise ValueError("judge configuration SHA-256 must be 64 lowercase hex digits")
        output = values.get("--output", "")
        output = output.strip() if isinstance(output, str) else ""
        prepared_path = values.get("--prepared-rating-form", "")
        prepared_sha = values.get("--prepared-rating-form-sha256", "")
        prepared_path = prepared_path.strip() if isinstance(prepared_path, str) else ""
        prepared_sha = prepared_sha.strip() if isinstance(prepared_sha, str) else ""
        labels_mode = bool(populated & {"--labels", "--source-task-labels"})
        analysis_only = {
            flag
            for flag in (
                "--allow-single-rater",
                "--bootstrap-resamples",
                "--alpha",
                "--seed",
            )
            if isinstance(values.get(flag), str) and values[flag].strip()
        }
        if not labels_mode and analysis_only:
            raise ValueError(
                "human_audit preparation is deterministic and seedless; "
                "analysis-only option(s) are invalid: "
                + ", ".join(sorted(analysis_only))
            )
        if labels_mode and not output:
            raise ValueError(
                "human_audit labels modes require an explicit external --output"
            )
        if bool(prepared_path) != bool(prepared_sha):
            raise ValueError(
                "--prepared-rating-form and --prepared-rating-form-sha256 must "
                "be provided together"
            )
        if not labels_mode and (prepared_path or prepared_sha):
            raise ValueError(
                "human_audit preparation modes cannot consume a prepared rating form"
            )
        if prepared_sha and (
            len(prepared_sha) != 64
            or any(character not in "0123456789abcdef" for character in prepared_sha)
        ):
            raise ValueError(
                "--prepared-rating-form-sha256 must be 64 lowercase hex digits"
            )
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
