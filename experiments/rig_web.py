"""Rig-local campaign builder and console over the maintained experiment CLIs.

A single-operator, localhost-only application (WEB-001 basic console, promoted
to the WEB-002 campaign builder): it starts allowlisted ``python -m
experiments.*`` commands from typed forms, composes campaign lanes through a
mode-aware builder (dry run, attestation probe, diagnostic canary, measured
execution) with mode-specific validation and an exact-argv confirmation step,
monitors and stops those jobs (whole process tree), streams their logs,
edits the operator-local registries through an allowlisted JSON editor,
renders retained Level-1/Level-2 artifacts with explicit diagnostic/measured
and pending/N/A/error distinctions, and accounts observed token usage and
its calculated monetary cost from recorded artifacts and an operator-edited
effective-dated pricing table.

State is kept in a stdlib-sqlite database under the console state directory
(jobs, campaign runs, recorded usage, calculated cost, artifact index).  The
database is operational state only - the validated filesystem artifacts
remain the scientific authority, and nothing rendered here is a measurement
surface.  Every experiment the console launches runs the same maintained
``experiments.*`` module the CLI runs, through an argument vector built from a
typed allowlist (parity is tested against the real module parsers); the
console's own bookkeeping - reindexing the usage/report indexes and printing
the recorded-usage cost report - is additionally reachable headlessly via
``rig_web --reindex`` / ``--usage-report``.  No arbitrary shell input is ever
executed (``shell=False``), the server binds 127.0.0.1 only, POST bodies are
size-capped, and no dependency outside the standard library is added.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import html
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


_REPO_ROOT = Path(__file__).resolve().parents[1]
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
    ("Full converted corpora", "run on local lanes only - never a hosted "
     "paid-API model"),
    ("Paid-API lanes", "run a pre-registered cluster subsample (recorded "
     "--limit and --sample-seed); the identical subset is used across every "
     "hosted condition and comparisons restrict to that intersection"),
    ("No cross-tier pooling", "local full-corpus and hosted-subsample rates "
     "are distinct populations and are never pooled"),
    ("Judge budget", "the hosted judge is metered on every judged response "
     "regardless of target locality, so local full-corpus lanes score "
     "rules-only with hosted LLM judging on the common subset only"),
    ("Prepaid budgets", "Anthropic $100, OpenAI $50, Google $25, "
     "Moonshot $15, DeepSeek $10; per-lane limits are derived from the "
     "diagnostic-canary cost projections and recorded before any measured "
     "lane"),
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
               "lanes run the full corpus; only the judge is metered.",
    "--corpora": "Comma list of source arm ids (from source-instances.json) or "
                 "'synth'. Every selected real arm must be admitted in the "
                 "source-conformance receipt.",
    "--attackers": "Comma list of attack engines. 'replay' sends the corpus "
                   "prompt as-is; 'crescendo' escalates over turns; the rest "
                   "are external adapters.",
    "--judges": "Judge stages: 'rules' is the deterministic rule scorer "
                "(free), 'llm' adds the hosted judge (metered per response).",
    "--judge-model": "Target id used by the LLM judge. The campaign judge is "
                     "anthropic:claude-haiku-4-5-20251001; 'mock' for offline.",
    "--limit": "Cluster subsample size. REQUIRED on every hosted paid lane - "
               "it bounds spend. Omit only for local full-corpus lanes.",
    "--sample-seed": "Deterministic seed for the cluster subsample. Fix it and "
                     "record it so every hosted condition sees the identical "
                     "subset (comparable, never pooled across tiers).",
    "--seeds": "Comma list of trajectory seeds (attack stochasticity), distinct "
               "from --sample-seed.",
    "--max-queries": "Max target queries per trajectory (turn budget upper "
                     "bound).",
    "--max-turns": "Max conversation turns per trajectory.",
    "--max-total-target-calls": "Hard circuit-breaker: abort the lane after "
                                "this many target calls. A budget guard.",
    "--max-total-judge-calls": "Hard circuit-breaker on hosted judge calls - "
                               "the dominant Anthropic cost. A budget guard.",
    "--max-total-http-attempts": "Hard cap on total HTTP attempts across the "
                                 "lane (retries included).",
    "--deadline-seconds": "Wall-clock deadline for the lane; a runaway guard.",
    "--source-config": "Path to the source registry (experiments/"
                       "source-instances.json). Bound automatically when the "
                       "campaign env is exported.",
    "--api-config": "Path to the hosted-target registry (experiments/"
                    "api-targets.json).",
    "--out": "Output directory under the rig results root for this run's "
             "artifacts.",
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
    "--source-conformance-sha256": "Exact byte SHA-256 paired with "
                                   "--source-conformance.",
    "--quantization": "vLLM quantization for local models (awq, gptq, fp8); "
                      "empty auto-detects from a pre-quantized checkpoint.",
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
    ("Anthropic", "$100", "focal Fable target + the Haiku judge (the volume "
     "driver, metered on every judged response) + one breadth row"),
    ("OpenAI", "$50", "focal GPT-5.6 Sol + at most one extra breadth row"),
    ("Google AI", "$25", "Gemini Flash-class row"),
    ("Moonshot", "$15", "one to two Kimi snapshots"),
    ("DeepSeek", "$10", "one row"),
)


#: The physical modalities a scored campaign arm carries. Multimodal arms
#: pair a text channel with an image/audio/video channel, so they belong to
#: BOTH modalities - a text+image arm is selected by the text chip and the
#: image chip alike (no arm is forced into a single bucket).
_MODALITIES = ("text", "image", "audio", "video")
_ARM_MODALITIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("strongreject_official", ("text",)),
    ("advbench_harmful", ("text",)),
    ("jailbreakbench_harmful", ("text",)),
    ("jailbreakbench_benign", ("text",)),
    ("harmbench_text", ("text",)),
    ("cyberseceval_mitre", ("text",)),
    ("cyberseceval_interpreter", ("text",)),
    ("cyberseceval_insecure_coding", ("text",)),
    ("rjudge_release", ("text",)),
    ("mmsafety_official", ("text", "image")),
    ("jailbreakv_full", ("text", "image")),
    ("harmbench_multimodal", ("text", "image")),
    ("vlsbench_release", ("text", "image")),
    ("mossbench_official", ("text", "image")),
    ("siuo_release", ("text", "image")),
    ("figstep_full", ("text", "image")),
    ("mllmguard_privacy", ("text", "image")),
    ("mllmguard_bias", ("text", "image")),
    ("mllmguard_toxicity", ("text", "image")),
    ("mllmguard_legality", ("text", "image")),
    ("mllmguard_position_swapping", ("text", "image")),
    ("mllmguard_noise_injection", ("text", "image")),
    ("gptgeochat_release", ("text", "image")),
    ("jalmbench_audio", ("text", "audio")),
    ("videosafetybench_benign_query", ("text", "video")),
    ("videosafetybench_harmful_query", ("text", "video")),
)

#: Attack frameworks (engines) offered in the builder, mirroring the harness
#: registry in src/ura/adapters/engines.py, with the modalities each can drive.
#: replay/crescendo are modality-agnostic (they carry whatever the corpus
#: datapoint holds); the external text-jailbreak adapters are text-first.
_ALL_MODALITIES = ("text", "image", "audio", "video")
_FRAMEWORKS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("replay", "send the corpus prompt as-is (single turn)", _ALL_MODALITIES),
    ("crescendo", "escalate the request over multiple turns", _ALL_MODALITIES),
    ("pyrit", "Microsoft PyRIT adapter", ("text",)),
    ("garak", "NVIDIA garak probes", ("text",)),
    ("deepteam", "DeepTeam red-team adapter", ("text",)),
    ("promptfoo", "Promptfoo adapter", ("text",)),
    ("petri", "Petri adapter", ("text",)),
    ("fuzzyai", "FuzzyAI adapter", ("text",)),
    ("autodan", "AutoDAN-Turbo adapter", ("text",)),
    ("harmbench", "HarmBench attack adapter", ("text", "image")),
)

#: Builder execution modes -> the run_matrix flag they set (empty = measured).
_BUILD_MODES: tuple[tuple[str, str, str], ...] = (
    ("dry_run", "--dry-run", "Offline dry-run (MockTarget, no calls, no spend)"),
    ("attestation_probe", "--attestation-probe",
     "Attestation probe (one paid call per model; cost anchor)"),
    ("diagnostic_canary", "--diagnostic-canary",
     "Diagnostic canary (small paid slice; cost projection)"),
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
        "modalities, tensor-parallel size, GPU memory. Consumed via "
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


#: Static suggestion lists. The attacker names mirror the harness registry in
#: src/ura/adapters/engines.py (replay/crescendo plus the engine adapters).
_SUGGEST_STATIC: dict[str, tuple[str, ...]] = {
    "attackers": (
        "replay", "crescendo", "replay,crescendo", "pyrit", "garak",
        "deepteam", "promptfoo", "t3mp3st", "petri", "fuzzyai", "nanogcg",
        "autodan", "agentdojo", "giskard", "easyjailbreak", "h4rm3l",
        "spikee", "ideator", "purplellama", "asb", "harmbench",
    ),
    "judges": ("rules,llm", "rules", "llm"),
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
    CommandParam("--defense", "str",
                 choices=("none", "input", "output", "both")),
    CommandParam("--defense-guard", "str", choices=("rules", "guardrail")),
    CommandParam("--guardrail-model", "str"),
    CommandParam("--guardrail-revision", "str"),
    CommandParam("--guardrail-device", "str"),
    CommandParam("--defense-guardrail-model", "str"),
    CommandParam("--defense-guardrail-revision", "str"),
    CommandParam("--defense-guardrail-device", "str"),
    CommandParam("--group", "str", suggest="group"),
    CommandParam("--attacker-config", "path"),
    CommandParam("--reset-open-circuits", "flag"),
    CommandParam("--source-config", "path"),
    CommandParam("--api-config", "path"),
    CommandParam("--local-config", "path"),
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
    common_out = (
        CommandParam("--out", "path", help="output directory under the rig root"),
    )
    entries = [
        Command(
            "project_revision", "experiments.project_revision",
            "Create or validate the ura-project-revision/1 receipt",
            (
                CommandParam("--expected-revision", "str"),
                CommandParam("--out", "path"),
                CommandParam("--validate", "path"),
                CommandParam("--sha256", "str"),
            ),
        ),
        Command(
            "source_conformance", "experiments.source_conformance",
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
            "rig_check", "experiments.rig_check",
            "No-call preflight for a planned grid (same surface as run_matrix)",
            _MATRIX_PARAMS,
        ),
        Command(
            "run_matrix", "experiments.run_matrix",
            "Execute or dry-run one experiment matrix lane",
            _MATRIX_PARAMS,
        ),
        Command(
            "live_attestation", "experiments.live_attestation",
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
            "lane_canary", "experiments.lane_canary",
            "Summarize one typed diagnostic canary completion",
            (
                CommandParam("--results", "path"),
                CommandParam("--eligibility", "path"),
                CommandParam("--out-dir", "path"),
            ),
        ),
        Command(
            "level1_evidence", "experiments.level1_evidence",
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
            "suite_summary", "experiments.suite_summary",
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
            "level2_report", "experiments.level2_report",
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
            "human_audit", "experiments.human_audit",
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
            "figures", "experiments.figures",
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
            "paired_compare", "experiments.paired_compare",
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
                CommandParam("--mode", "str",
                             choices=("auto", "static", "live")),
                CommandParam("--bootstrap", "int"),
                CommandParam("--seed", "int"),
                CommandParam("--permutations", "int"),
                CommandParam("--alpha", "float"),
                CommandParam("--assume-exchangeable", "flag"),
                CommandParam("--output", "path"),
            ),
        ),
        Command(
            "judge_sensitivity", "experiments.judge_sensitivity",
            "Same-response judge-stage sensitivity analysis",
            (
                CommandParam("--results", "path"),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
                CommandParam("--output", "path"),
            ),
        ),
        Command(
            "kappa", "experiments.kappa",
            "Pairwise judge-agreement diagnostics",
            (
                CommandParam("--results", "path"),
                CommandParam("--attacker", "str"),
                CommandParam("--corpus", "str"),
            ),
        ),
        Command(
            "transfer_matrix", "experiments.transfer_matrix",
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
            "export_jalmbench", "experiments.export_jalmbench",
            "Export the official JALMBench Parquet release for the converter",
            (
                CommandParam("--source", "path"),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *common_out,
            ),
        ),
        Command(
            "export_vlsbench", "experiments.export_vlsbench",
            "Export the official VLSBench Parquet release for the converter",
            (
                CommandParam("--source", "path"),
                CommandParam("--max-records", "int"),
                CommandParam("--max-total-bytes", "int"),
                *common_out,
            ),
        ),
        Command(
            "native_import", "experiments.native_import",
            "Validate and canonicalize a native artifact family",
            (
                CommandParam("--config", "path"),
                CommandParam("--validate", "path"),
                *common_out,
            ),
        ),
        Command(
            "syn_compat", "experiments.syn_compat",
            "Synthetic compatibility corpus: generate/check/evaluate "
            "(rule-fidelity only)",
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
            "local_targets", "experiments.local_targets",
            "List or refresh the vLLM local-target roster (version-matched)",
            (
                CommandParam("--refresh", "flag"),
                CommandParam("--vllm-version", "str"),
            ),
        ),
        Command(
            "webui_selftest", "experiments.rig_web",
            "UI diagnostic only: sleep briefly and exit",
            (
                CommandParam("--selftest-sleep", "float", required=True),
            ),
        ),
    ]
    return {entry.name: entry for entry in entries}


COMMANDS = _commands()


#: Presentation-only grouping of the allowlisted commands by runbook stage.
#: Every command appears in exactly one group (asserted by tests); grouping
#: never changes what a command does or which arguments it accepts.
COMMAND_GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("Receipts and conformance", "receipt", "runbook sections 2, 4.1, 17",
     ("project_revision", "source_conformance")),
    ("Acquisition exports", "box", "runbook section 3.2",
     ("export_jalmbench", "export_vlsbench")),
    ("Preflight, probes and lanes", "play", "runbook sections 8-13",
     ("rig_check", "run_matrix", "live_attestation", "lane_canary")),
    ("Native and synthetic", "flask", "runbook sections 14, 16",
     ("native_import", "syn_compat")),
    ("Targets and rosters", "coins", "runbook sections 5, 13",
     ("local_targets",)),
    ("Analysis and reporting", "chart", "runbook section 16",
     ("level1_evidence", "suite_summary", "level2_report", "figures",
      "paired_compare", "judge_sensitivity", "kappa", "transfer_matrix")),
    ("Human audit", "users", "runbook sections 15, 15.1",
     ("human_audit",)),
    ("Console diagnostics", "pulse", "runbook section 18",
     ("webui_selftest",)),
)


def _param_values(
    param: CommandParam, values: Mapping[str, str],
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
            suffix = key[len(prefix):]
            if not suffix.isdigit() or int(suffix) <= 0:
                raise ValueError(f"invalid repeat row {key!r}")
            raw = raw.strip() if isinstance(raw, str) else ""
            if raw:
                collected.append((int(suffix), raw))
    collected.sort(key=lambda item: item[0])
    return [raw for _index, raw in collected]


def build_argv(
    command: str, values: Mapping[str, str], *, commands: Mapping[str, Command] | None = None,
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
            allowed.update(
                key for key in values
                if key.startswith(param.flag + "#")
            )
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
    ("evidence_kind", {
        "diagnostic_dry_run": ("diagnostic dry-run", "amber"),
        "measured_run": ("measured run", "blue"),
    }),
    ("execution_purpose", {
        "diagnostic_canary": ("diagnostic canary", "amber"),
        "attestation_probe": ("attestation probe", "amber"),
        "measured_run": ("measured run", "blue"),
    }),
    ("evidence_class", {
        "synthetic_offline": ("synthetic offline", "amber"),
        "live_diagnostic": ("live diagnostic", "amber"),
    }),
    ("status", {
        "complete": ("complete", "green"),
        "error": ("error", "red"),
        "running": ("running", "blue"),
    }),
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
        "<path d='M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 "
        "3h9a2 2 0 0 1 2 2z'/>"
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
    "disk": (
        "<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='2.5'/>"
    ),
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
}


def _icon(name: str, *, size: int = 18) -> str:
    body = _ICONS.get(name, _ICONS["file"])
    return (
        f"<svg class='ic' width='{size}' height='{size}' viewBox='0 0 24 24' "
        "fill='none' stroke='currentColor' stroke-width='1.8' "
        f"stroke-linecap='round' stroke-linejoin='round' "
        f"aria-hidden='true'>{body}</svg>"
    )


_STYLE = """
:root { color-scheme: light dark;
  --bg:#eef1f5; --card:#ffffff; --ink:#182430; --muted:#5b6b7c;
  --line:#d9e0e8; --accent:#0a5fb4; --accent-ink:#ffffff;
  --soft:#f4f7fa; --shadow:0 1px 2px rgba(16,24,32,.06),
  0 4px 14px rgba(16,24,32,.05); }
@media (prefers-color-scheme: dark) {
  :root { --bg:#10161d; --card:#19212b; --ink:#e7edf3; --muted:#92a3b4;
    --line:#28323e; --accent:#59a3ea; --accent-ink:#0d1621;
    --soft:#141b23; --shadow:0 1px 2px rgba(0,0,0,.35); } }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.55 system-ui, "Segoe UI", sans-serif;
  background:var(--bg); color:var(--ink); }
main { max-width:1160px; margin:0 auto; padding:1.4rem 1.2rem 2rem; }
nav { position:sticky; top:0; z-index:5; background:var(--card);
  border-bottom:1px solid var(--line); padding:.6rem 1.2rem;
  display:flex; gap:.4rem; align-items:center; flex-wrap:wrap; }
nav .brand { display:flex; gap:.55rem; align-items:center; font-weight:700;
  margin-right:1rem; letter-spacing:.01em; }
nav .brand .ic { color:var(--accent); }
nav a { display:flex; gap:.4rem; align-items:center; color:var(--muted);
  text-decoration:none; font-weight:600; font-size:.92rem;
  padding:.35rem .7rem; border-radius:8px; }
nav a:hover { background:var(--soft); color:var(--ink); }
nav a.active { background:var(--soft); color:var(--accent); }
h1 { font-size:1.3rem; margin:.4rem 0 1rem; display:flex; gap:.55rem;
  align-items:center; }
h1 .ic { color:var(--accent); }
h2 { font-size:1rem; margin:0 0 .6rem; display:flex; gap:.45rem;
  align-items:center; color:var(--ink); }
h2 .ic { color:var(--muted); }
.card { background:var(--card); border:1px solid var(--line);
  border-radius:12px; padding:1rem 1.2rem; margin:.9rem 0;
  box-shadow:var(--shadow); }
.cols { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:.9rem; }
.cols .card { margin:0; }
.stat { display:flex; flex-direction:column; gap:.15rem; }
.stat .value { font-size:1.35rem; font-weight:700; }
.stat .label { color:var(--muted); font-size:.82rem; }
table { border-collapse:collapse; width:100%; font-size:.87rem; }
th, td { border-bottom:1px solid var(--line); padding:.42rem .6rem;
  text-align:left; vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.78rem;
  text-transform:uppercase; letter-spacing:.05em;
  border-bottom:2px solid var(--line); }
tr:hover td { background:var(--soft); }
.scroll { overflow-x:auto; }
pre { background:var(--soft); border:1px solid var(--line);
  border-radius:10px; padding:.8rem .95rem; overflow-x:auto;
  font-size:.82rem; white-space:pre-wrap; word-break:break-word; }
code { background:var(--soft); border-radius:5px; padding:.05rem .35rem;
  font-size:.85em; }
.badge { display:inline-flex; align-items:center; border-radius:999px;
  padding:.08rem .62rem; font-size:.74rem; font-weight:600;
  margin:0 .25rem .25rem 0; }
.badge.amber { background:#7a5200; color:#ffe9c2; }
.badge.blue { background:#0b4c8c; color:#dcecfd; }
.badge.green { background:#1d6b35; color:#d9f4e1; }
.badge.red { background:#8c1d24; color:#fde0e2; }
.badge.gray { background:#4a5563; color:#e3e8ee; }
.dot { display:inline-block; width:.55rem; height:.55rem;
  border-radius:50%; margin-right:.4rem; vertical-align:baseline; }
.dot.blue { background:#3f8edb; box-shadow:0 0 0 3px
  color-mix(in srgb, #3f8edb 25%, transparent); }
.dot.green { background:#2e9e57; }
.dot.red { background:#d4525b; }
.dot.gray { background:#8a97a5; }
.crumbs { color:var(--muted); font-size:.86rem; margin:0 0 .8rem; }
.crumbs a { color:var(--accent); text-decoration:none; }
.crumbs span.sep { margin:0 .35rem; }
details.cmd { background:var(--card); border:1px solid var(--line);
  border-radius:12px; margin:.55rem 0; box-shadow:var(--shadow); }
details.cmd > summary { list-style:none; cursor:pointer; display:flex;
  gap:.6rem; align-items:baseline; padding:.75rem 1.1rem; }
details.cmd > summary::-webkit-details-marker { display:none; }
details.cmd > summary .ic { color:var(--accent); align-self:center; }
details.cmd > summary .name { font-weight:700; }
details.cmd > summary .desc { color:var(--muted); font-size:.86rem; }
details.cmd[open] > summary { border-bottom:1px solid var(--line); }
details.cmd .inner { padding:.9rem 1.1rem 1.1rem; }
.group-head { display:flex; gap:.55rem; align-items:center;
  margin:1.6rem 0 .4rem; }
.group-head .ic { color:var(--accent); }
.group-head h2 { margin:0; }
.group-head .ref { color:var(--muted); font-size:.8rem; }
form.cmd { display:grid; grid-template-columns:minmax(200px,260px) 1fr;
  gap:.4rem .8rem; align-items:center; }
form.cmd label { color:var(--muted); font-size:.84rem; }
.req { color:#c0392b; font-weight:700; }
form.cmd label .kind { color:var(--muted); opacity:.7; font-size:.75rem; }
form.cmd input[type=text], form.cmd input[type=number],
form.cmd select { width:100%; padding:.38rem .55rem;
  border:1px solid var(--line); border-radius:8px; background:var(--bg);
  color:var(--ink); font-size:.86rem; }
form.cmd select { cursor:pointer; }
form.cmd input:focus, form.cmd select:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
button { display:inline-flex; gap:.4rem; align-items:center;
  background:var(--accent); border:0; color:var(--accent-ink);
  font-weight:600; border-radius:9px; padding:.48rem 1rem; cursor:pointer;
  font-size:.9rem; }
button:hover { filter:brightness(1.08); }
button.danger { background:#a4262f; color:#fff; }
button.small { padding:.28rem .6rem; font-size:.8rem; border-radius:7px; }
form.inline { display:inline; margin:0; }
.chips { display:flex; flex-wrap:wrap; gap:.4rem; margin:.2rem 0 .6rem; }
.chip { background:var(--card); color:var(--muted); border:1px solid var(--line);
  border-radius:999px; padding:.3rem .8rem; font-size:.82rem; font-weight:600;
  cursor:pointer; }
.chip:hover { color:var(--ink); }
.chip.on { background:var(--accent); color:var(--accent-ink);
  border-color:var(--accent); }
.notice { position:relative; }
.notice-close { position:absolute; top:.35rem; right:.45rem;
  background:transparent; color:var(--muted); border:0; font-size:1.15rem;
  line-height:1; padding:.1rem .35rem; cursor:pointer; border-radius:6px; }
.notice-close:hover { background:var(--card); color:var(--ink); }
#jobfilter { width:100%; max-width:420px; padding:.45rem .7rem;
  border:1px solid var(--line); border-radius:9px; background:var(--card);
  color:var(--ink); font-size:.9rem; }
#jobfilter:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
a { color:var(--accent); }
p.note { color:var(--muted); font-size:.84rem; }
footer.note { color:var(--muted); font-size:.8rem; margin-top:2rem;
  border-top:1px solid var(--line); padding-top:.8rem; }
.pipeline { width:100%; min-width:900px; }
.pipeline .node rect { fill:var(--card); stroke:var(--line);
  stroke-width:1.4; }
.pipeline .node.present rect { stroke:var(--accent); stroke-width:2; }
.pipeline .node text { fill:var(--ink); font:600 12.5px system-ui,
  "Segoe UI", sans-serif; }
.pipeline .node text.count { fill:var(--muted); font-weight:500;
  font-size:11.5px; }
.pipeline .node text.count.sub { font-size:10px; opacity:.85; }
.pipeline .node.present text.count { fill:var(--accent); font-weight:700; }
.pipeline a { cursor:pointer; }
.pipeline a:hover .node rect { stroke:var(--accent); stroke-width:2.4;
  filter:brightness(1.04); }
.pipeline .arrow { stroke:var(--muted); stroke-width:1.4; fill:none;
  marker-end:url(#arrowhead); }
.pipeline #arrowhead path { fill:var(--muted); }
.meter { height:.55rem; border-radius:999px; background:var(--soft);
  border:1px solid var(--line); overflow:hidden; margin:.35rem 0 .15rem; }
.meter > div { height:100%; background:var(--accent); }
.argv { display:flex; flex-wrap:wrap; gap:.3rem; }
.argv code { border:1px solid var(--line); padding:.12rem .45rem; }
.filelist td .ic { color:var(--muted); vertical-align:-3px;
  margin-right:.45rem; }
.notice { border-left:4px solid var(--line); border-radius:8px;
  background:var(--soft); padding:.6rem .8rem; margin:.45rem 0;
  font-size:.9rem; }
.notice.amber { border-left-color:#c9922a; }
.notice.red { border-left-color:#c4515c; }
.notice.blue { border-left-color:#3f8edb; }
.notice p.note { margin:.25rem 0 0; }
details.stagefiles { margin:.35rem 0; font-size:.86rem; }
details.stagefiles > summary { cursor:pointer; color:var(--accent);
  font-weight:600; }
details.stagefiles ul { margin:.3rem 0 .5rem; padding-left:1.2rem; }
details.stagefiles li { margin:.12rem 0; overflow-wrap:anywhere; }
#cmdfilter { width:100%; max-width:420px; padding:.45rem .7rem;
  border:1px solid var(--line); border-radius:9px; background:var(--card);
  color:var(--ink); font-size:.9rem; }
#cmdfilter:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent);
  border-color:var(--accent); }
.fieldwrap { display:flex; flex-direction:column; gap:.15rem; }
.fieldhint { color:var(--muted); font-size:.76rem; line-height:1.35; }
.fieldlabel { display:block; color:var(--muted); font-size:.82rem;
  margin:.6rem 0 .25rem; }
input.wide, textarea.editor, .buildbar select, form select { }
textarea.editor { width:100%; min-height:60vh; font:.82rem/1.5
  ui-monospace, "Cascadia Code", Menlo, monospace; padding:.8rem;
  border:1px solid var(--line); border-radius:10px; background:var(--soft);
  color:var(--ink); resize:vertical; }
textarea.editor:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
.editor-actions { display:flex; gap:.6rem; margin:.7rem 0; }
button.ghost { background:transparent; color:var(--accent);
  border:1px solid var(--line); }
.playbook { margin:.4rem 0 0; padding-left:0; list-style:none; }
.playbook li { display:flex; gap:.5rem; align-items:baseline;
  padding:.35rem 0; border-bottom:1px solid var(--line); flex-wrap:wrap; }
.playbook li:last-child { border-bottom:0; }
.step-n { display:inline-flex; width:1.4rem; height:1.4rem;
  align-items:center; justify-content:center; border-radius:50%;
  background:var(--accent); color:var(--accent-ink); font-size:.75rem;
  font-weight:700; flex:none; }
.radios { display:flex; flex-direction:column; gap:.5rem; }
.radio { display:flex; gap:.5rem; align-items:flex-start; cursor:pointer; }
.check { display:flex; gap:.45rem; align-items:flex-start; cursor:pointer;
  padding:.25rem 0; }
.check span { font-size:.88rem; }
.checkgrid { display:grid; grid-template-columns:repeat(auto-fill,
  minmax(240px,1fr)); gap:.15rem .8rem; }
.modgroup { margin:.6rem 0; }
.modgroup h3 { font-size:.82rem; text-transform:uppercase;
  letter-spacing:.05em; color:var(--muted); margin:.5rem 0 .2rem; }
.modscope { display:flex; flex-wrap:wrap; gap:.5rem; margin:.3rem 0 .2rem; }
.modtoggle { display:inline-flex; align-items:center; gap:.45rem;
  cursor:pointer; user-select:none; padding:.5rem .95rem; border-radius:10px;
  border:1.5px solid var(--line); background:var(--card); font-weight:600;
  font-size:.9rem; text-transform:capitalize; transition:all .12s ease; }
.modtoggle input { position:absolute; opacity:0; width:0; height:0; }
.modtoggle span::before { content:''; display:inline-block; width:.7rem;
  height:.7rem; margin-right:.5rem; border-radius:4px; vertical-align:-1px;
  border:1.5px solid var(--muted); background:transparent; }
.modtoggle:has(input:checked) { background:color-mix(in srgb,
  var(--accent) 14%, var(--card)); border-color:var(--accent);
  color:var(--accent); }
.modtoggle:has(input:checked) span::before { background:var(--accent);
  border-color:var(--accent); box-shadow:inset 0 0 0 2px var(--card); }
.modtoggle:hover { border-color:var(--accent); }
.grouphead { display:flex; align-items:center; justify-content:space-between;
  gap:.5rem; margin:.7rem 0 .1rem; }
.grouphead h3 { margin:0; }
.groupsel { display:flex; gap:.5rem; }
.linkbtn { background:transparent; border:0; color:var(--accent);
  font-size:.8rem; font-weight:600; cursor:pointer; padding:.1rem .3rem; }
.linkbtn:hover { text-decoration:underline; }
.modtag { display:inline-block; font-size:.66rem; font-weight:600;
  text-transform:uppercase; letter-spacing:.04em; color:var(--muted);
  background:var(--soft); border:1px solid var(--line); border-radius:5px;
  padding:0 .3rem; margin-left:.2rem; vertical-align:middle; }
.fwrow.incompatible { opacity:.55; }
.fwrow.incompatible .fwflag { color:#c4515c; font-weight:600; }
.fielderr { display:block; color:#c4515c; font-size:.8rem; font-weight:600;
  margin:.2rem 0 .1rem; }
.attrow { display:grid; grid-template-columns:1fr 1fr; gap:.5rem;
  margin:.35rem 0; }
@media (max-width:640px) { .attrow { grid-template-columns:1fr; } }
.notice ul { margin:.35rem 0 .1rem; padding-left:1.2rem; }
.notice li { font-size:.86rem; margin:.15rem 0; }
input.wide { width:100%; padding:.4rem .55rem; border:1px solid var(--line);
  border-radius:8px; background:var(--bg); color:var(--ink); font-size:.86rem; }
.buildbar { position:sticky; bottom:0; display:flex; gap:.8rem;
  align-items:center; padding:.7rem 0; background:linear-gradient(
  to top, var(--bg), transparent); flex-wrap:wrap; }
#buildpreview { font:.78rem ui-monospace, Menlo, monospace;
  overflow-wrap:anywhere; }
.barchart { width:100%; min-width:640px; }
.barchart .bl, .barchart .bn { fill:var(--ink); font:600 12px system-ui,
  sans-serif; }
.barchart .bn { font-weight:500; fill:var(--muted); }
.barchart .bt { fill:var(--soft); stroke:var(--line); stroke-width:1; }
.barchart .bv { fill:var(--accent); }
#busy-overlay { position:fixed; inset:0; z-index:1000; display:none;
  align-items:center; justify-content:center;
  background:color-mix(in srgb, var(--bg) 78%, transparent);
  backdrop-filter:blur(2px); }
#busy-overlay.on { display:flex; }
#busy-overlay .box { background:var(--card); border:1px solid var(--line);
  border-radius:14px; padding:26px 34px; box-shadow:0 12px 40px rgba(0,0,0,.18);
  display:flex; flex-direction:column; align-items:center; gap:14px;
  max-width:min(90vw,420px); text-align:center; }
#busy-overlay .spin { width:38px; height:38px; border-radius:50%;
  border:4px solid var(--line); border-top-color:var(--accent);
  animation:busy-rot .8s linear infinite; }
#busy-overlay .msg { font-weight:600; color:var(--ink); }
#busy-overlay .sub { font-size:.82rem; color:var(--muted); }
@keyframes busy-rot { to { transform:rotate(360deg); } }
button.is-busy { opacity:.6; pointer-events:none; }
@media (prefers-reduced-motion:reduce){ #busy-overlay .spin{ animation:none; } }
"""


_BUILDER_SCRIPT = """<script>(function(){
var form=document.getElementById('builder');
if(!form){return;}
function checked(sel,attr){var out=[];
form.querySelectorAll(sel).forEach(function(el){
if(el.checked){out.push(el.getAttribute(attr));}});return out;}
function checkedKind(kind,attr){var out=[];
form.querySelectorAll('.modelbox').forEach(function(el){
if(el.checked&&el.getAttribute('data-kind')===kind){
out.push(el.getAttribute(attr));}});return out;}
function scopeSet(){var s={};form.querySelectorAll('.modbox').forEach(
function(m){if(m.checked){s[m.getAttribute('data-mod')]=1;}});return s;}
function intersects(list,set){return list.some(function(x){return set[x];});}
function applyScope(){var sc=scopeSet();
// arms: keep an arm only if it shares a modality with the scope
form.querySelectorAll('.armbox').forEach(function(b){
var mods=(b.getAttribute('data-mods')||'').split(',').filter(Boolean);
var ok=intersects(mods,sc);var lab=b.closest('.check');
if(lab){lab.style.display=ok?'':'none';}if(!ok){b.checked=false;}});
form.querySelectorAll('.modgroup').forEach(function(g){
var any=Array.prototype.some.call(g.querySelectorAll('.check'),
function(l){return l.style.display!=='none';});g.style.display=any?'':'none';});
// target models and frameworks: hide any that cannot serve a scoped modality
[['.modelrow','.modelbox'],['.fwrow','.fwbox']].forEach(function(pair){
form.querySelectorAll(pair[0]).forEach(function(row){
var mods=(row.getAttribute('data-mods')||'').split(',').filter(Boolean);
var ok=intersects(mods,sc);row.style.display=ok?'':'none';
if(!ok){var cb=row.querySelector(pair[1]);if(cb){cb.checked=false;}}});});}
function refresh(){applyScope();
// live preview
var mode=(form.querySelector('input[name=mode]:checked')||{}).value||'measured';
var flagFor={dry_run:'--dry-run',attestation_probe:'--attestation-probe',
diagnostic_canary:'--diagnostic-canary',measured:''};
var parts=['run_matrix'];
if(flagFor[mode]){parts.push(flagFor[mode]);}
var api=checkedKind('api','data-model');if(api.length){parts.push('--api '+api.join(','));}
var loc=checkedKind('local','data-model');if(loc.length){parts.push('--local '+loc.join(','));}
var arms=checked('.armbox','data-arm');if(arms.length){parts.push('--corpora '+arms.join(','));}
var fw=checked('.fwbox','data-fw');if(fw.length){parts.push('--attackers '+fw.join(','));}
var jg=checked('.judgebox','data-judge');if(jg.length){parts.push('--judges '+jg.join(','));}
var lim=form.querySelector('input[name=limit]').value;
if(lim){parts.push('--limit '+lim);}
var prev=document.getElementById('buildpreview');
if(prev){prev.textContent=parts.join(' ');}}
form.addEventListener('change',refresh);
form.addEventListener('input',refresh);
// per-group All / None bulk selection over the group's visible arms
form.querySelectorAll('.linkbtn').forEach(function(btn){
btn.addEventListener('click',function(){
var on=this.getAttribute('data-sel')==='all';
var group=this.closest('.modgroup');
group.querySelectorAll('.armbox').forEach(function(b){
var lab=b.closest('.check');
if(!lab||lab.style.display!=='none'){b.checked=on;}});refresh();});});
// server-side re-render prefill: re-check the composed selections
var preEl=document.getElementById('builder-prefill');
if(preEl){try{var pre=JSON.parse(preEl.textContent);
function apply(list,sel,attr){if(!list||!list.length){return;}
form.querySelectorAll(sel).forEach(function(b){
b.checked=list.indexOf(b.getAttribute(attr))>=0;});}
apply(pre.corpora,'.armbox','data-arm');
apply(pre.attackers,'.fwbox','data-fw');
if((pre.api&&pre.api.length)||(pre.local&&pre.local.length)){
form.querySelectorAll('.modelbox').forEach(function(b){
var kind=b.getAttribute('data-kind');
var list=kind==='api'?(pre.api||[]):(pre.local||[]);
b.checked=list.indexOf(b.getAttribute('data-model'))>=0;});}
}catch(e){}}
// repeatable live-attestation receipt/digest rows (paired in order)
var addBtn=document.getElementById('addatt');
if(addBtn){addBtn.addEventListener('click',function(){
var rows=document.getElementById('attrows');
var n=rows.querySelectorAll('.attrow').length+1;
if(n>12){return;}
var div=document.createElement('div');div.className='attrow';
div.setAttribute('data-row',n);
div.innerHTML="<input class='wide' type='text' name='att_path"+n+
"' placeholder='runs/thesis/attest/receipt.live-attestation.json'>"+
"<input class='wide' type='text' name='att_sha"+n+
"' placeholder='exact 64-hex sha256'>";
rows.appendChild(div);});}
form.addEventListener('submit',function(){
form.querySelector("input[name=corpora]").value=checked('.armbox','data-arm').join(',');
form.querySelector("input[name=api]").value=checkedKind('api','data-model').join(',');
form.querySelector("input[name=local]").value=checkedKind('local','data-model').join(',');
form.querySelector("input[name=attackers]").value=checked('.fwbox','data-fw').join(',');
form.querySelector("input[name=judges]").value=checked('.judgebox','data-judge').join(',');});
refresh();
})();</script>"""


_NAV_LINKS = (
    ("/", "grid", "Dashboard"),
    ("/build", "flask", "Build"),
    ("/commands", "terminal", "Run"),
    ("/jobs", "pulse", "Jobs"),
    ("/stats", "chart", "Stats"),
    ("/config", "sliders", "Config"),
    ("/artifacts", "folder", "Artifacts"),
)

_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'>"
    "<path fill='#0a5fb4' d='M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z'/>"
    "<path fill='none' stroke='#ffffff' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round' "
    "d='M8.5 12.5l2.5 2.5 4.5-5'/></svg>"
).encode("utf-8")


def _page(title: str, body: str, active: str = "") -> bytes:
    links = "".join(
        f"<a href='{href}'"
        + (" class='active'" if label == active else "")
        + f">{_icon(icon, size=16)}{label}</a>"
        for href, icon, label in _NAV_LINKS
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<link rel='icon' type='image/svg+xml' href='/static/favicon.svg'>"
        "<link rel='stylesheet' href='/static/style.css'></head><body>"
        f"<nav><span class='brand'>{_icon('logo', size=21)}URA rig console"
        f"</span>{links}</nav>"
        f"<main>{body}"
        "<footer class='note'>The CLI and filesystem artifacts remain "
        "authoritative. This console never reinterprets experiment "
        "semantics; diagnostic evidence never authorizes a campaign."
        "</footer></main>"
        + _BUSY_OVERLAY
        + "</body></html>"
    ).encode("utf-8")


#: A modal busy overlay shown while a slow POST (a pricing fetch, a reindex) is
#: in flight, so the operator sees progress and cannot double-submit.  A form
#: opts in with ``data-busy="<message>"``; the overlay is dismissed if the page
#: is restored from the back/forward cache.
_BUSY_OVERLAY = (
    "<div id='busy-overlay' role='alert' aria-live='assertive'>"
    "<div class='box'><div class='spin'></div>"
    "<div class='msg' id='busy-msg'>Working...</div>"
    "<div class='sub'>This can take up to a minute. Keep this tab open.</div>"
    "</div></div>"
    "<script>(function(){"
    "var ov=document.getElementById('busy-overlay');"
    "var msg=document.getElementById('busy-msg');"
    "document.addEventListener('submit',function(e){"
    "var f=e.target;"
    "if(!f||!f.hasAttribute('data-busy'))return;"
    "if(f.dataset.busyGo){e.preventDefault();return;}"  # block double-submit
    "f.dataset.busyGo='1';"
    "msg.textContent=f.getAttribute('data-busy')||'Working...';"
    "ov.classList.add('on');"
    "var b=f.querySelector('button[type=submit],button:not([type])');"
    "if(b)b.classList.add('is-busy');"
    "},true);"
    "window.addEventListener('pageshow',function(ev){"
    "if(!ev.persisted)return;"
    "ov.classList.remove('on');"
    "document.querySelectorAll('form[data-busy]').forEach(function(f){"
    "delete f.dataset.busyGo;"
    "var b=f.querySelector('button');if(b)b.classList.remove('is-busy');});"
    "});})();</script>"
)


def _badges_html(badges: list[tuple[str, str]]) -> str:
    return "".join(
        f"<span class='badge {html.escape(tone)}'>{html.escape(label)}</span>"
        for label, tone in badges
    )


def _human_size(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.0f} {unit}" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1024
    return f"{size:,.1f} TB"


def _human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def _crumbs(relative: str) -> str:
    parts = [part for part in relative.replace("\\", "/").split("/") if part]
    links = ["<a href='/artifacts'>runs</a>"]
    so_far: list[str] = []
    for part in parts:
        so_far.append(part)
        target = quote("/".join(so_far))
        links.append(
            f"<a href='/artifacts?path={target}'>{html.escape(part)}</a>"
        )
    return (
        "<p class='crumbs'>"
        + "<span class='sep'>/</span>".join(links)
        + "</p>"
    )


#: Campaign pipeline stages shown on the dashboard.  Each stage counts
#: retained files whose names end with one of the listed suffixes; a count
#: is pure file presence and never asserts validity, authorization, or
#: measurement status.
_PIPELINE_STAGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Revision receipt", (".project-revision.json",)),
    ("Source receipts", ("source-conformance.json",)),
    ("Envelopes", (".request-envelope.json",)),
    ("Attestations", (".live-attestation.json",)),
    ("Canaries", (".lane-canary.json", ".canary.json")),
    ("Grids", (".grid.json",)),
    ("Level-1/2", ()),  # filled from level1/level2/suite counts below
)
_ANALYSIS_MARKERS = ("level1", "level2", "suite-evidence")


_STAGE_PATHS_SHOWN = 20


@dataclass
class StageInventory:
    """Presence-only tally for one pipeline stage."""

    count: int = 0
    superseded: int = 0
    paths: list[str] = field(default_factory=list)


def artifact_inventory(root: Path) -> tuple[dict[str, StageInventory], bool]:
    """Count retained artifact files by kind under the results root.

    Bounded, presence-only walk: at most ``_INVENTORY_MAX_ENTRIES`` directory
    entries and ``_INVENTORY_MAX_DEPTH`` levels are visited, lazily, so one
    pathological flat directory cannot stall the dashboard.  Files below a
    ``superseded`` directory are tallied separately (archived, not current).
    Returns the stages plus a truncation flag (counts are a lower bound when
    True).  Counting a file says nothing about its validity.
    """

    stages: dict[str, StageInventory] = {
        label: StageInventory() for label, _ in _PIPELINE_STAGES
    }
    seen = 0
    root = root.resolve()

    def record(label: str, entry: Path) -> None:
        stage = stages[label]
        try:
            relative = entry.relative_to(root).as_posix()
        except ValueError:
            relative = entry.name
        if "superseded" in relative.split("/"):
            stage.superseded += 1
        else:
            stage.count += 1
        if len(stage.paths) < _STAGE_PATHS_SHOWN:
            stage.paths.append(relative)

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            for entry in directory.iterdir():
                seen += 1
                if seen > _INVENTORY_MAX_ENTRIES:
                    return stages, True
                if entry.is_dir():
                    if depth + 1 <= _INVENTORY_MAX_DEPTH:
                        stack.append((entry, depth + 1))
                    continue
                name = entry.name.lower()
                for label, suffixes in _PIPELINE_STAGES:
                    if any(name.endswith(suffix) for suffix in suffixes):
                        record(label, entry)
                if name.endswith((".json", ".csv")) and any(
                    marker in name for marker in _ANALYSIS_MARKERS
                ):
                    record("Level-1/2", entry)
        except OSError:
            continue
    return stages, False


def _pipeline_svg(stages: Mapping[str, StageInventory]) -> str:
    node_w, node_h, gap, top = 128, 58, 24, 12
    total_w = len(_PIPELINE_STAGES) * node_w + (len(_PIPELINE_STAGES) - 1) * gap
    parts = [
        f"<svg class='pipeline' viewBox='0 0 {total_w} {node_h + 2 * top}' "
        "role='img' aria-label='campaign pipeline'>",
        "<defs><marker id='arrowhead' markerWidth='7' markerHeight='7' "
        "refX='6' refY='3.5' orient='auto'><path d='M0 0L7 3.5L0 7z'/>"
        "</marker></defs>",
    ]
    for index, (label, _suffixes) in enumerate(_PIPELINE_STAGES):
        x = index * (node_w + gap)
        stage = stages.get(label, StageInventory())
        cls = "node present" if stage.count else "node"
        if stage.count:
            count_text = f"{stage.count} file{'s' if stage.count != 1 else ''}"
        else:
            count_text = "none yet"
        extra = (
            f"<text class='count sub' x='{x + node_w / 2}' y='{top + 51}' "
            f"text-anchor='middle'>+{stage.superseded} archived</text>"
            if stage.superseded else ""
        )
        node = (
            f"<g class='{cls}'>"
            f"<rect x='{x}' y='{top}' width='{node_w}' height='{node_h}' "
            "rx='10'/>"
            f"<text x='{x + node_w / 2}' y='{top + 23}' "
            f"text-anchor='middle'>{html.escape(label)}</text>"
            f"<text class='count' x='{x + node_w / 2}' y='{top + 40}' "
            f"text-anchor='middle'>{html.escape(count_text)}</text>"
            + extra
            + "</g>"
        )
        # A stage node links to the directory holding its files, preferring a
        # current (non-archived) path so the click lands on live artifacts;
        # presence there never implies validity.
        if stage.paths:
            current = [
                p for p in stage.paths if "superseded" not in p.split("/")
            ]
            first = (current or stage.paths)[0]
            directory = first.rsplit("/", 1)[0] if "/" in first else ""
            node = (
                f"<a href='/artifacts?path={quote(directory)}' "
                f"aria-label='browse {html.escape(label)} artifacts'>"
                + node + "</a>"
            )
        parts.append(node)
        if index < len(_PIPELINE_STAGES) - 1:
            start = x + node_w
            parts.append(
                f"<path class='arrow' d='M{start + 3} {top + node_h / 2} "
                f"L{start + gap - 4} {top + node_h / 2}'/>"
            )
    parts.append("</svg>")
    return "<div class='scroll'>" + "".join(parts) + "</div>"


@dataclass
class Job:
    job_id: str
    command: str
    argv: list[str]
    directory: Path
    process: subprocess.Popen | None = None
    stdout_handle: Any = None
    stderr_handle: Any = None
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    #: The raw builder/form parameters this job was composed from (persisted
    #: so a restored job still shows how it was built).
    builder_params: dict[str, str] | None = None
    #: The pinned project revision exported when the job started.
    pin: str = ""
    #: Short failure context (stderr tail) persisted for a failed job.
    failure: str | None = None
    #: Last-known state for a job restored from the database whose live
    #: process handle is gone (a prior console session started it).
    restored_state: str | None = None
    restored_exit: int | None = None
    #: Set only AFTER the terminal state committed to the database.
    run_recorded: bool = False

    def state(self) -> str:
        if self.process is None:
            return self.restored_state or "unknown"
        code = self.process.poll()
        if code is None:
            return "running"
        if self.ended_at is None:
            self.ended_at = time.time()
        return "complete" if code == 0 else "failed"

    def exit_code(self) -> int | None:
        if self.process is None:
            return self.restored_exit
        return self.process.poll()

    def runtime_seconds(self) -> float:
        end = self.ended_at if self.ended_at is not None else time.time()
        return max(0.0, end - self.started_at)


#: Map a job's command + argv to a campaign-run kind for the registry.
def run_kind(command: str, argv: list[str]) -> str | None:
    if command not in {"run_matrix", "rig_check"}:
        return None
    if command == "rig_check":
        return "preflight"
    if "--attestation-probe" in argv:
        return "attestation_probe"
    if "--diagnostic-canary" in argv:
        return "diagnostic_canary"
    if "--dry-run" in argv:
        return "dry_run"
    return "measured"


def _argv_out_dir(argv: list[str]) -> str:
    for flag in ("--out", "--output"):
        if flag in argv:
            index = argv.index(flag)
            if index + 1 < len(argv):
                return argv[index + 1]
    return ""


# -- recorded token usage and calculated cost -------------------------------
#
# Never an estimate: every number below is read from retained run artifacts,
# entered through their completion markers so checkpoints, superseded partial
# snapshots, and orphaned cell files are never counted.  Monetary cost is
# calculated only from an operator-edited effective-dated pricing table; a
# missing token count or missing price renders as N/A, never as zero.

#: Billing categories recorded per (provider, model).  Semantics follow each
#: provider's own usage fields verbatim (no overlap adjustment is invented):
#: ``input``/``output`` are the provider-reported token counts
#: (``raw.provider_usage`` detail preferred over the normalized ``tokens``
#: map), ``cache_read``/``cache_write`` and ``reasoning`` appear only when the
#: provider reported them.
_TOKEN_CATEGORIES = ("input", "output", "cache_read", "cache_write", "reasoning")
#: Categories that carry their own price.  ``reasoning`` is deliberately absent:
#: providers bill thinking/reasoning tokens as part of ``output`` (the adapters
#: enforce reasoning <= output), so charging it again would double-bill.  It is
#: displayed for transparency but never priced.
_BILLED_CATEGORIES = ("input", "output", "cache_read", "cache_write")
_UNBILLED_PROVIDERS = {"vllm", "ollama", "mock", "local"}
_MARKER_SUFFIX = ".complete.json"


def _tokens_by_category(tokens: Any, provider_usage: Any) -> dict[str, int]:
    """Normalize one call's recorded token counts into billing categories.

    Categories are made non-overlapping so no token is billed twice:
    ``input`` is the billable-at-input-rate count with any separately-billed
    cache reads removed (Anthropic's ``input_tokens`` already excludes cache;
    Fable exposes the net figure as ``uncached_input``; OpenAI's
    ``input_tokens`` is cache-inclusive, so the reported cache read is
    subtracted). ``cache_read``/``cache_write`` are the separately-priced
    cache components. ``reasoning`` is recorded for transparency only - every
    provider here bills thinking/reasoning tokens *as* output tokens (the
    adapters enforce ``reasoning <= output``), so ``compute_costs`` treats it
    as a subset of ``output`` and never charges it a second time.  Local
    adapters record prompt/completion and are not billed at all.
    """

    out: dict[str, int] = {}
    tk = tokens if isinstance(tokens, Mapping) else {}
    pu = provider_usage if isinstance(provider_usage, Mapping) else {}

    def put(category: str, value: Any) -> None:
        if isinstance(value, int) and value >= 0:
            out[category] = value

    put("output", pu.get("output_tokens"))
    if "output" not in out:
        put("output", tk.get("output", tk.get("completion")))
    put("cache_read", pu.get("cache_read_input_tokens"))
    put("cache_write", pu.get("cache_creation_input_tokens"))
    details_in = pu.get("input_tokens_details")
    if isinstance(details_in, Mapping):
        put("cache_read", details_in.get("cached_tokens"))
        put("cache_write", details_in.get("cache_write_tokens"))
    if "cache_read" not in out:
        put("cache_read", tk.get("cached_input"))
    if "cache_write" not in out:
        put("cache_write", tk.get("cache_write_input"))
    details_out = pu.get("output_tokens_details")
    if isinstance(details_out, Mapping):
        put("reasoning", details_out.get(
            "thinking_tokens", details_out.get("reasoning_tokens")
        ))
    if "reasoning" not in out:
        put("reasoning", tk.get("reasoning"))
    # Input last, so the cache reads it must exclude are already known. Prefer
    # an explicitly net figure (Fable's uncached_input); otherwise a provider
    # input_tokens is only ever written by the cache-inclusive OpenAI adapter
    # here, so net out the reported cache read.
    if isinstance(tk.get("uncached_input"), int):
        put("input", tk["uncached_input"])
    elif isinstance(pu.get("input_tokens"), int):
        put("input", max(0, pu["input_tokens"] - out.get("cache_read", 0)))
    else:
        put("input", tk.get("input", tk.get("prompt")))
    return out


def _response_identity(record: Mapping[str, Any]) -> tuple[str, str]:
    """(provider, model) for one responses.jsonl record."""

    raw = record.get("raw")
    raw = raw if isinstance(raw, Mapping) else {}
    target = str(record.get("target", "") or "")
    provider = raw.get("provider") or raw.get("provider_name")
    if not isinstance(provider, str) or not provider:
        provider = target.split(":", 1)[0] if ":" in target else (target or "unknown")
    model = None
    for key in ("resolved_model", "provider_resolved_model", "provider_model",
                "model"):
        candidate = raw.get(key)
        if isinstance(candidate, str) and candidate:
            model = candidate
            break
    return str(provider), str(model or target or "unknown")


def _marker_artifact_path(
    marker_path: Path, descriptor: Any, *, verify_sha: bool = False,
) -> Path:
    """Resolve and byte-check one completion-marker artifact descriptor."""

    if not isinstance(descriptor, Mapping):
        raise ValueError("completion marker artifact descriptor missing")
    name = str(descriptor.get("file", ""))
    if not name or "/" in name or "\\" in name:
        raise ValueError(f"artifact descriptor names a non-bare file {name!r}")
    path = marker_path.parent / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact {name!r} is missing or not a regular file")
    size = path.stat().st_size
    if size != descriptor.get("bytes"):
        raise ValueError(f"artifact {name!r} byte size changed since completion")
    if verify_sha:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != descriptor.get("sha256"):
            raise ValueError(f"artifact {name!r} digest changed since completion")
    return path


def iter_completed_markers(
    root: Path, *, max_entries: int = _INVENTORY_MAX_ENTRIES,
) -> tuple[list[tuple[Path, dict[str, Any]]], dict[str, int]]:
    """Completion markers under root plus honest skip accounting.

    Only ``*.complete.json`` markers with ``status: complete`` and
    ``format_version: 2`` and no sibling ``<stem>.error.json`` are returned;
    everything else (orphan cell files, checkpoints, errored cells) is
    excluded and counted so truncation is never silent.
    """

    markers: list[tuple[Path, dict[str, Any]]] = []
    stats = {"markers": 0, "skipped_error": 0, "skipped_invalid": 0,
             "orphan_responses": 0, "truncated": 0}
    seen = 0
    completed_stems: set[str] = set()
    response_files: list[tuple[Path, str]] = []
    stack: list[Path] = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                stats["truncated"] = 1
                break
            if entry.is_dir():
                stack.append(entry)
                continue
            name = entry.name
            if name.endswith(".responses.jsonl") and not name.endswith(
                ".responses.checkpoint.jsonl"
            ):
                response_files.append(
                    (entry, name[: -len(".responses.jsonl")])
                )
                continue
            if not name.endswith(_MARKER_SUFFIX):
                continue
            stem = name[: -len(_MARKER_SUFFIX)]
            if (directory / f"{stem}.error.json").exists():
                stats["skipped_error"] += 1
                continue
            try:
                doc = json.loads(entry.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                stats["skipped_invalid"] += 1
                continue
            if (
                not isinstance(doc, dict)
                or doc.get("status") != "complete"
                or doc.get("format_version") != 2
                or not isinstance(doc.get("artifacts"), dict)
            ):
                stats["skipped_invalid"] += 1
                continue
            markers.append((entry, doc))
            completed_stems.add(str(entry.parent / stem))
        if seen > max_entries:
            break
    stats["markers"] = len(markers)
    stats["orphan_responses"] = sum(
        1 for path, stem in response_files
        if str(path.parent / stem) not in completed_stems
    )
    return markers, stats


def usage_rows_from_marker(
    marker_path: Path, doc: Mapping[str, Any], *, verify_sha: bool = False,
) -> list[dict[str, Any]]:
    """Recorded per-(role, provider, model, category) usage for one cell.

    Target usage comes from the completion-bound responses artifact
    (``Response.tokens`` plus ``raw.provider_usage`` detail); judge usage from
    the completion-bound trails artifact (``raw.judge_call.tokens``, every
    cascade stage, provider-refusal rows excluded because no judge call was
    made).  A record whose token block is absent is tallied under the
    ``missing_tokens`` category so it renders as N/A, never as zero.
    """

    marker_sha = hashlib.sha256(marker_path.read_bytes()).hexdigest()
    run_id = str(doc.get("run_id", ""))
    out_dir = str(marker_path.parent)
    artifacts = doc["artifacts"]
    tallies: dict[tuple[str, str, str, str], int] = {}

    def add(role: str, provider: str, model: str, category: str, amount: int) -> None:
        key = (role, provider, model, category)
        tallies[key] = tallies.get(key, 0) + amount

    responses_path = _marker_artifact_path(
        marker_path, artifacts.get("responses"), verify_sha=verify_sha
    )
    n_lines = 0
    with responses_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            n_lines += 1
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, Mapping):
                continue
            provider, model = _response_identity(record)
            raw = record.get("raw")
            raw = raw if isinstance(raw, Mapping) else {}
            categories = _tokens_by_category(
                record.get("tokens"), raw.get("provider_usage")
            )
            add("target", provider, model, "calls", 1)
            if not categories:
                add("target", provider, model, "missing_tokens", 1)
            for category, amount in categories.items():
                add("target", provider, model, category, amount)
    expected = artifacts["responses"].get("records")
    if isinstance(expected, int) and expected != n_lines:
        raise ValueError(
            f"responses artifact record count changed since completion "
            f"({n_lines} != {expected})"
        )
    trails_path = _marker_artifact_path(
        marker_path, artifacts.get("trails"), verify_sha=verify_sha
    )
    with trails_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, Mapping):
                continue
            raw = record.get("raw")
            raw = raw if isinstance(raw, Mapping) else {}
            judge_call = raw.get("judge_call")
            if not isinstance(judge_call, Mapping):
                continue  # stage made no judge call
            if judge_call.get("sampling_control") == "not_queried_provider_refusal":
                continue  # provider refused; no call was made or billed
            provider = str(judge_call.get("provider") or "unknown")
            model = str(
                judge_call.get("provider_resolved_model")
                or raw.get("judge_model") or "unknown"
            )
            categories = _tokens_by_category(judge_call.get("tokens"), None)
            add("judge", provider, model, "calls", 1)
            if not categories:
                add("judge", provider, model, "missing_tokens", 1)
            for category, amount in categories.items():
                add("judge", provider, model, category, amount)
    now = time.time()
    return [
        {
            "marker_sha": marker_sha, "role": role, "provider": provider,
            "model": model, "category": category, "amount": amount,
            "run_id": run_id, "out_dir": out_dir, "recorded_at": now,
        }
        for (role, provider, model, category), amount in sorted(tallies.items())
    ]


def collect_usage(
    root: Path, *, verify_sha: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """All recorded usage rows under root, with honest skip accounting."""

    markers, stats = iter_completed_markers(root)
    rows: list[dict[str, Any]] = []
    stats["unreadable_artifacts"] = 0
    for marker_path, doc in markers:
        try:
            rows.extend(
                usage_rows_from_marker(marker_path, doc, verify_sha=verify_sha)
            )
        except (OSError, ValueError):
            stats["unreadable_artifacts"] += 1
    return rows, stats


#: Report artifact schemas indexed for the Stats page and dashboard.
_REPORT_SCHEMAS = {
    "ura-level1-evidence/2": "level1",
    "ura-level2-report/1": "level2",
    "ura-suite-evidence/1": "suite",
    "ura-lane-canary/1": "canary",
}


def collect_reports(
    root: Path, *, max_entries: int = _INVENTORY_MAX_ENTRIES,
) -> list[dict[str, Any]]:
    """Index retained report artifacts by their declared schema_version."""

    rows: list[dict[str, Any]] = []
    seen = 0
    stack: list[Path] = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                return rows
            if entry.is_dir():
                stack.append(entry)
                continue
            if not entry.name.endswith(".json"):
                continue
            try:
                size = entry.stat().st_size
                if size > _MAX_RENDER_BYTES:
                    continue
                doc = json.loads(entry.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            schema = doc.get("schema_version") if isinstance(doc, dict) else None
            kind = _REPORT_SCHEMAS.get(schema or "")
            if kind is None:
                continue
            try:
                relative = entry.relative_to(root).as_posix()
            except ValueError:
                relative = entry.name
            rows.append({
                "path": relative, "schema": str(schema), "kind": kind,
                "sha256": hashlib.sha256(entry.read_bytes()).hexdigest(),
                "bytes": size, "mtime": entry.stat().st_mtime,
                "recorded_at": time.time(),
            })
    return rows


def load_pricing(repo_root: Path = _REPO_ROOT) -> dict[str, Any]:
    """The operator-edited pricing table (local file, then the example)."""

    for candidate in ("pricing.json", "rig/pricing.example.json"):
        path = repo_root / "experiments" / candidate
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def rate_for(
    pricing: Mapping[str, Any], provider: str, model: str,
    *, on_date: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """The effective-dated rate row for (provider, model), or (None, why).

    Picks the newest rate whose effective_date is on or before ``on_date``
    (default today).  Missing provider, model, or applicable rate returns the
    exact missing field so the page can display N/A with its reason.
    """

    providers = pricing.get("providers")
    if not isinstance(providers, Mapping):
        return None, "pricing table has no providers section"
    entry = None
    for key, value in providers.items():
        if str(key).lower() == provider.lower():
            entry = value
            break
    if not isinstance(entry, Mapping):
        return None, f"no pricing entry for provider {provider!r}"
    models = entry.get("models")
    if not isinstance(models, Mapping) or model not in models:
        return None, f"no pricing entry for model {model!r}"
    rates = models[model].get("rates") if isinstance(models[model], Mapping) else None
    if not isinstance(rates, list) or not rates:
        return None, f"no rates recorded for model {model!r}"
    today = on_date or time.strftime("%Y-%m-%d")

    def valid_date(value: Any) -> bool:
        # Zero-padded ISO date only, so lexicographic ordering is date order.
        return isinstance(value, str) and bool(
            re.fullmatch(r"\d{4}-\d{2}-\d{2}", value)
        )

    if any(isinstance(r, Mapping) and not valid_date(r.get("effective_date"))
           for r in rates):
        return None, (
            f"model {model!r} has a rate with a non ISO 8601 (YYYY-MM-DD) "
            "effective_date"
        )
    def _is_priced(rate: Mapping[str, Any]) -> bool:
        # An all-null row is a placeholder, not a real price: skip it so an
        # operator's earlier real rate stays the billed figure even when a
        # later-dated null placeholder sits above it in the list.
        per_million = rate.get("per_million_tokens")
        per_million = per_million if isinstance(per_million, Mapping) else {}
        return any(value is not None for value in per_million.values())

    applicable = [
        rate for rate in rates
        if isinstance(rate, Mapping) and rate["effective_date"] <= today
        and _is_priced(rate)
    ]
    if not applicable:
        return None, f"no priced rate effective on or before {today} for {model!r}"
    # On an equal effective_date, an operator-entered rate outranks an
    # auto-fetched one, and a later list position outranks an earlier one, so a
    # same-date operator correction always wins over an auto rate regardless of
    # the order the two entries happen to sit in the rates list.
    chosen = max(
        enumerate(applicable),
        key=lambda item: (
            item[1]["effective_date"],
            0 if item[1].get("auto_fetched") else 1,
            item[0],
        ),
    )[1]
    return dict(chosen), ""


def compute_costs(
    usage_totals: Mapping[tuple[str, str, str], Mapping[str, int]],
    pricing: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Calculated monetary cost per (role, provider, model) from recorded use.

    Cost is the sum over billing categories of recorded tokens times the
    configured per-million rate.  If any category with recorded tokens has no
    numeric rate, the whole row's cost is N/A and the missing fields are
    named - a partial cost would understate real spend.  Local providers are
    marked not billable rather than zero-cost-by-assumption.
    """

    rows: list[dict[str, Any]] = []
    for (role, provider, model), categories in sorted(usage_totals.items()):
        tokens = {
            category: int(categories.get(category, 0))
            for category in _TOKEN_CATEGORIES
        }
        row: dict[str, Any] = {
            "role": role, "provider": provider, "model": model,
            "calls": int(categories.get("calls", 0)),
            "missing_tokens": int(categories.get("missing_tokens", 0)),
            "tokens": tokens,
            "rate": None, "effective_date": "", "currency": "",
            "cost": None, "missing": [], "billable": True,
            "auto_fetched": False, "source_url": "",
        }
        if provider.lower() in _UNBILLED_PROVIDERS:
            row["billable"] = False
            rows.append(row)
            continue
        rate, why = rate_for(pricing, provider, model)
        if rate is None:
            row["missing"].append(why)
            rows.append(row)
            continue
        per_million = rate.get("per_million_tokens")
        per_million = per_million if isinstance(per_million, Mapping) else {}
        row["rate"] = {k: per_million.get(k) for k in _TOKEN_CATEGORIES}
        row["effective_date"] = str(rate.get("effective_date", ""))
        row["currency"] = str(rate.get("currency", ""))
        row["auto_fetched"] = bool(rate.get("auto_fetched"))
        row["source_url"] = str(rate.get("source_url", ""))
        total = 0.0
        missing: list[str] = []
        for category in _BILLED_CATEGORIES:
            amount = tokens.get(category, 0)
            if amount <= 0:
                continue
            unit = per_million.get(category)
            if isinstance(unit, (int, float)):
                total += amount / 1_000_000 * float(unit)
            else:
                missing.append(f"{provider}/{model}: no {category} rate")
        if row["missing_tokens"]:
            missing.append(
                f"{provider}/{model}: {row['missing_tokens']} call(s) "
                "recorded no token usage"
            )
        if missing:
            row["missing"] = missing
        else:
            row["cost"] = total
        rows.append(row)
    return rows


def reconcile_pricing_ownership(
    submitted: Mapping[str, Any], current: Mapping[str, Any],
) -> None:
    """Strip auto-fetch provenance from any pricing rate the operator edited.

    When the operator corrects a fetched rate IN PLACE through the config
    editor, the row still carries ``auto_fetched`` and the fetcher would treat
    it as its own and overwrite the correction on the next run.  Comparing the
    submitted table against the on-disk one, any rate that still claims
    ``auto_fetched`` but whose (provider, model, effective_date, per-million
    figures) no longer matches an on-disk auto rate must have been changed by
    the operator, so its provenance flags are dropped and it becomes an
    operator-owned rate the fetcher will never supersede.  Mutates ``submitted``
    in place.
    """

    def index_auto(data: Mapping[str, Any]) -> dict[tuple[str, str, Any], list[Any]]:
        idx: dict[tuple[str, str, Any], list[Any]] = {}
        providers = data.get("providers")
        if not isinstance(providers, Mapping):
            return idx
        for provider, pentry in providers.items():
            models = pentry.get("models") if isinstance(pentry, Mapping) else None
            if not isinstance(models, Mapping):
                continue
            for model, mentry in models.items():
                rates = mentry.get("rates") if isinstance(mentry, Mapping) else None
                if not isinstance(rates, list):
                    continue
                for rate in rates:
                    if isinstance(rate, Mapping) and rate.get("auto_fetched"):
                        key = (provider, model, rate.get("effective_date"))
                        per_million = rate.get("per_million_tokens")
                        idx.setdefault(key, []).append(
                            dict(per_million) if isinstance(per_million, Mapping) else {}
                        )
        return idx

    on_disk = index_auto(current)
    providers = submitted.get("providers")
    if not isinstance(providers, Mapping):
        return
    for provider, pentry in providers.items():
        models = pentry.get("models") if isinstance(pentry, Mapping) else None
        if not isinstance(models, Mapping):
            continue
        for model, mentry in models.items():
            rates = mentry.get("rates") if isinstance(mentry, Mapping) else None
            if not isinstance(rates, list):
                continue
            for rate in rates:
                if not (isinstance(rate, dict) and rate.get("auto_fetched")):
                    continue
                key = (provider, model, rate.get("effective_date"))
                per_million = rate.get("per_million_tokens")
                per_million = dict(per_million) if isinstance(per_million, Mapping) else {}
                if any(per_million == known for known in on_disk.get(key, [])):
                    continue  # untouched auto rate: keep its provenance
                # The operator changed this fetched rate: it is now theirs.
                rate.pop("auto_fetched", None)
                rate.pop("source_url", None)
                rate.pop("fetched_at", None)


class ConsoleDB:
    """Durable operational database for the console.

    Stdlib sqlite under the state directory: jobs (with their exact argv and
    builder parameters), the campaign-run registry, recorded per-artifact
    token usage, and the report/artifact index.  Operational state only - the
    validated filesystem artifacts remain the scientific authority.

    Every access is serialized by one lock (the HTTP server is
    multi-threaded).  Terminal job state, its run row, and its usage rows
    commit in a single transaction; callers flip their ``run_recorded`` flag
    only after that commit returns success.  A database fault never raises
    into a page, but it is never silent either: ``last_error`` and
    ``healthy`` feed a visible banner, and history readers return None (an
    unknown, shown as such) rather than a fabricated empty history.
    """

    SCHEMA_VERSION = 2

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.healthy = False
        self.last_error = ""
        self._conn: sqlite3.Connection | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            check = self._conn.execute("PRAGMA quick_check").fetchone()
            if check is None or str(check[0]).lower() != "ok":
                raise sqlite3.DatabaseError(
                    f"integrity check failed: {check[0] if check else 'no result'}"
                )
            self._migrate()
            self.healthy = True
        except sqlite3.Error as exc:
            self.last_error = f"database open failed: {exc}"
            try:
                if self._conn is not None:
                    self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # -- schema ------------------------------------------------------------

    def _migrate(self) -> None:
        assert self._conn is not None
        # sqlite3's legacy isolation mode autocommits DDL, so a `with
        # self._conn` block does not make CREATE/ALTER/DROP atomic with the
        # DML.  Recover any table stranded by an interrupted prior migration
        # first (idempotent), then apply the current schema.
        self._recover_stranded_runs()
        with self._conn:  # one transaction
            tables = {
                str(row[0]) for row in self._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
            )
            if "jobs" in tables:
                existing = {
                    str(row[1]) for row in self._conn.execute(
                        "PRAGMA table_info(jobs)"
                    )
                }
                for column, kind in (
                    ("builder_params", "TEXT"), ("run_kind", "TEXT"),
                    ("out_dir", "TEXT"), ("pin", "TEXT"), ("failure", "TEXT"),
                ):
                    if column not in existing:
                        self._conn.execute(
                            f"ALTER TABLE jobs ADD COLUMN {column} {kind}"
                        )
            else:
                self._conn.execute(
                    """
                    CREATE TABLE jobs (
                        job_id TEXT PRIMARY KEY, command TEXT, argv TEXT,
                        directory TEXT, state TEXT, exit_code INTEGER,
                        started_at REAL, ended_at REAL, updated_at REAL,
                        builder_params TEXT, run_kind TEXT, out_dir TEXT,
                        pin TEXT, failure TEXT
                    )
                    """
                )
            if "runs" in tables:
                columns = [
                    str(row[1]) for row in self._conn.execute(
                        "PRAGMA table_info(runs)"
                    )
                ]
                if "run_id" in columns:  # v1 shape with an autoincrement id
                    self._conn.execute("ALTER TABLE runs RENAME TO runs_v1")
                    self._create_runs()
                    self._conn.execute(
                        "INSERT OR IGNORE INTO runs(job_id,kind,command,"
                        "out_dir,pin,state,exit_code,created_at) "
                        "SELECT job_id,kind,command,out_dir,pin,state,"
                        "exit_code,created_at FROM runs_v1"
                    )
                    self._conn.execute("DROP TABLE runs_v1")
            else:
                self._create_runs()
            self._conn.execute("DROP TABLE IF EXISTS spend")  # v1, rebuilt as usage
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage (
                    marker_sha TEXT, role TEXT, provider TEXT, model TEXT,
                    category TEXT, amount INTEGER, run_id TEXT, out_dir TEXT,
                    recorded_at REAL,
                    PRIMARY KEY (marker_sha, role, provider, model, category)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    path TEXT PRIMARY KEY, schema TEXT, kind TEXT,
                    sha256 TEXT, bytes INTEGER, mtime REAL, recorded_at REAL
                )
                """
            )
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(self.SCHEMA_VERSION),),
            )

    def _create_runs(self) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            CREATE TABLE runs (
                job_id TEXT PRIMARY KEY, kind TEXT, command TEXT,
                out_dir TEXT, pin TEXT, state TEXT, exit_code INTEGER,
                created_at REAL
            )
            """
        )

    def _recover_stranded_runs(self) -> None:
        """Complete a v1->v2 runs migration interrupted after the DDL committed.

        Because DDL autocommits under sqlite3's legacy isolation, a crash or
        error between ``ALTER TABLE runs RENAME TO runs_v1`` and the row copy
        can leave a populated ``runs_v1`` beside an empty v2 ``runs``.  On the
        next open the normal migration would see the new-shape ``runs`` and
        never look at ``runs_v1``, silently losing the history.  This finishes
        the copy idempotently before anything else runs.
        """

        assert self._conn is not None
        tables = {
            str(row[0]) for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "runs_v1" not in tables:
            return
        with self._conn:
            if "runs" not in tables:
                self._create_runs()
            else:
                columns = [
                    str(row[1]) for row in self._conn.execute(
                        "PRAGMA table_info(runs)"
                    )
                ]
                if "run_id" in columns:  # v1-shaped; replace with the v2 shape
                    self._conn.execute("DROP TABLE runs")
                    self._create_runs()
            self._conn.execute(
                "INSERT OR IGNORE INTO runs(job_id,kind,command,out_dir,pin,"
                "state,exit_code,created_at) SELECT job_id,kind,command,"
                "out_dir,pin,state,exit_code,created_at FROM runs_v1"
            )
            self._conn.execute("DROP TABLE runs_v1")

    # -- plumbing ----------------------------------------------------------

    def _fail(self, exc: sqlite3.Error) -> None:
        self.last_error = str(exc)
        self.healthy = False

    def _job_row(
        self, job: "Job", state: str | None = None, exit_code: int | None = None,
    ) -> tuple:
        # A caller that already sampled the job's state passes it in, so the
        # persisted row cannot disagree with the branch decision (avoids a
        # terminal row being written by a "running" upsert if the process
        # exits between two polls).
        resolved_state = state if state is not None else job.state()
        resolved_exit = exit_code if state is not None else job.exit_code()
        return (
            job.job_id, job.command, json.dumps(job.argv),
            json.dumps(job.builder_params) if job.builder_params else None,
            str(job.directory), resolved_state, resolved_exit,
            job.started_at, job.ended_at, time.time(),
            run_kind(job.command, job.argv), _argv_out_dir(job.argv),
            job.pin, job.failure,
        )

    _JOB_UPSERT = (
        "INSERT INTO jobs(job_id,command,argv,builder_params,directory,state,"
        "exit_code,started_at,ended_at,updated_at,run_kind,out_dir,pin,failure)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(job_id) DO UPDATE SET state=excluded.state,"
        "exit_code=excluded.exit_code,ended_at=excluded.ended_at,"
        "updated_at=excluded.updated_at,failure=excluded.failure"
    )

    def upsert_job(
        self, job: "Job", *, state: str | None = None, exit_code: int | None = None,
    ) -> bool:
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    self._conn.execute(
                        self._JOB_UPSERT, self._job_row(job, state, exit_code)
                    )
                return True
            except sqlite3.Error as exc:
                self._fail(exc)
                return False

    def record_terminal(
        self, job: "Job", pin: str, usage_rows: list[dict[str, Any]],
        *, state: str | None = None, exit_code: int | None = None,
    ) -> bool:
        """Commit a job's terminal state, run row, and usage in ONE txn."""

        kind = run_kind(job.command, job.argv)
        resolved_state = state if state is not None else job.state()
        resolved_exit = exit_code if state is not None else job.exit_code()
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    self._conn.execute(
                        self._JOB_UPSERT, self._job_row(job, state, exit_code)
                    )
                    if kind is not None:
                        self._conn.execute(
                            "INSERT INTO runs(job_id,kind,command,out_dir,pin,"
                            "state,exit_code,created_at) VALUES(?,?,?,?,?,?,?,?) "
                            "ON CONFLICT(job_id) DO UPDATE SET "
                            "state=excluded.state,exit_code=excluded.exit_code,"
                            "out_dir=excluded.out_dir,pin=excluded.pin",
                            (job.job_id, kind, job.command,
                             _argv_out_dir(job.argv), pin, resolved_state,
                             resolved_exit, time.time()),
                        )
                    self._insert_usage_rows(usage_rows)
                return True
            except sqlite3.Error as exc:
                self._fail(exc)
                return False

    def _insert_usage_rows(self, usage_rows: list[dict[str, Any]]) -> None:
        assert self._conn is not None
        for row in usage_rows:
            self._conn.execute(
                "INSERT INTO usage(marker_sha,role,provider,model,category,"
                "amount,run_id,out_dir,recorded_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(marker_sha,role,provider,model,category) "
                "DO UPDATE SET amount=excluded.amount,"
                "recorded_at=excluded.recorded_at",
                (row["marker_sha"], row["role"], row["provider"], row["model"],
                 row["category"], row["amount"], row["run_id"], row["out_dir"],
                 row["recorded_at"]),
            )

    def reindex(
        self, usage_rows: list[dict[str, Any]], report_rows: list[dict[str, Any]],
    ) -> bool:
        """Rebuild the derived usage and report indexes in one transaction."""

        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    self._conn.execute("DELETE FROM usage")
                    self._conn.execute("DELETE FROM reports")
                    self._insert_usage_rows(usage_rows)
                    for row in report_rows:
                        self._conn.execute(
                            "INSERT INTO reports(path,schema,kind,sha256,bytes,"
                            "mtime,recorded_at) VALUES(?,?,?,?,?,?,?) "
                            "ON CONFLICT(path) DO UPDATE SET "
                            "schema=excluded.schema,kind=excluded.kind,"
                            "sha256=excluded.sha256,bytes=excluded.bytes,"
                            "mtime=excluded.mtime,recorded_at=excluded.recorded_at",
                            (row["path"], row["schema"], row["kind"],
                             row["sha256"], row["bytes"], row["mtime"],
                             row["recorded_at"]),
                        )
                return True
            except sqlite3.Error as exc:
                self._fail(exc)
                return False

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row] | None:
        """None on failure - an unknown history, never a fabricated empty one."""

        with self._lock:
            if self._conn is None:
                return None
            try:
                return list(self._conn.execute(sql, params))
            except sqlite3.Error as exc:
                self._fail(exc)
                return None

    def load_jobs(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM jobs ORDER BY started_at DESC LIMIT 500")

    def list_runs(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM runs ORDER BY created_at DESC LIMIT 500")

    def list_reports(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM reports ORDER BY mtime DESC LIMIT 500")

    def usage_totals(self) -> dict[tuple[str, str, str], dict[str, int]] | None:
        rows = self._query(
            "SELECT role, provider, model, category, SUM(amount) AS total "
            "FROM usage GROUP BY role, provider, model, category"
        )
        if rows is None:
            return None
        totals: dict[tuple[str, str, str], dict[str, int]] = {}
        for row in rows:
            key = (str(row["role"]), str(row["provider"]), str(row["model"]))
            totals.setdefault(key, {})[str(row["category"])] = int(row["total"] or 0)
        return totals

    def health(self) -> dict[str, Any]:
        counts: dict[str, Any] = {}
        if self._conn is not None and self.healthy:
            for table in ("jobs", "runs", "usage", "reports"):
                rows = self._query(f"SELECT COUNT(*) AS n FROM {table}")  # noqa: S608 - fixed table names
                counts[table] = int(rows[0]["n"]) if rows else None
        return {
            "healthy": self.healthy,
            "schema_version": self.SCHEMA_VERSION,
            "path": str(self.path),
            "last_error": self.last_error,
            "counts": counts,
        }

    def close(self) -> None:
        # Detach the connection under the lock so no in-flight accessor (which
        # checks self._conn inside the same lock) can operate on a closed
        # handle, then close outside the lock.
        with self._lock:
            conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                self._fail(exc)


class RigWebApp:
    """Socket-free request core; the HTTP layer only delegates here."""

    def __init__(
        self,
        *,
        results_root: Path,
        state_dir: Path,
        repo_root: Path = _REPO_ROOT,
        commands: Mapping[str, Command] | None = None,
        job_id_factory: Callable[[], str] | None = None,
        env_file: Path | None = None,
    ) -> None:
        self.results_root = results_root
        self.state_dir = state_dir
        self.repo_root = repo_root
        #: The 600-mode operator secrets file (rig ~/.ura_env). Keys are
        #: written here and mirrored into os.environ; their values are never
        #: read back into a page, logged, or stored in the database.
        self.env_file = env_file if env_file is not None else Path.home() / ".ura_env"
        self.commands = dict(COMMANDS if commands is None else commands)
        self.jobs: dict[str, Job] = {}
        #: The one application lock protecting shared job state (the HTTP
        #: server is multi-threaded; every start/stop/reconcile holds it).
        self._app_lock = threading.RLock()
        #: Serializes read-modify-write of experiments/pricing.json across the
        #: multi-threaded server: the pricing config editor (save_config) and
        #: the pricing fetcher (fetch_pricing) both rewrite that file, and the
        #: fetch does seconds of network I/O between its read and its write, so
        #: without this an overlapping operator save would be silently lost.
        self._pricing_lock = threading.Lock()
        #: Serializes read-modify-write of the operator secrets file so two
        #: concurrent set/clear requests cannot each snapshot the prior file and
        #: drop the other's key on the losing os.replace.
        self._secret_lock = threading.Lock()
        self._job_id_factory = job_id_factory or (
            lambda: f"job-{secrets.token_hex(6)}"
        )
        self.db = ConsoleDB(state_dir / "console.db")
        self._restore_jobs()
        self._recover_unrecorded_runs()

    def close(self) -> None:
        """Release the database cleanly; running jobs stay detached."""

        with self._app_lock:
            self._reconcile_locked()
            for job in self.jobs.values():
                self._close_handles(job)
            self.db.close()

    def _restore_jobs(self) -> None:
        """Repopulate the Jobs page from prior sessions (read-only handles).

        A restored job's live process handle is gone, so it shows its stored
        state; a job left 'running' when a prior console exited is surfaced
        as 'orphaned' (its detached process may still be alive, but this
        console cannot poll or stop it) and that orphaned state is persisted
        so it survives further restarts.
        """

        rows = self.db.load_jobs()
        if rows is None:
            return
        for row in rows:
            job_id = str(row["job_id"])
            if job_id in self.jobs:
                continue
            stored = str(row["state"] or "unknown")
            restored = "orphaned" if stored == "running" else stored
            try:
                argv = json.loads(row["argv"]) if row["argv"] else []
            except (ValueError, TypeError):
                argv = []
            try:
                params = (
                    json.loads(row["builder_params"])
                    if row["builder_params"] else None
                )
            except (ValueError, TypeError):
                params = None
            job = Job(
                job_id=job_id, command=str(row["command"] or ""), argv=argv,
                directory=Path(str(row["directory"] or self.state_dir / job_id)),
                process=None, started_at=float(row["started_at"] or 0.0),
                ended_at=(float(row["ended_at"]) if row["ended_at"] else None),
                builder_params=params if isinstance(params, dict) else None,
                pin=str(row["pin"] or ""),
                failure=(str(row["failure"]) if row["failure"] else None),
                restored_state=restored,
                restored_exit=(int(row["exit_code"]) if row["exit_code"]
                               is not None else None),
                run_recorded=True,
            )
            self.jobs[job_id] = job
            if restored == "orphaned" and stored != "orphaned":
                self.db.upsert_job(job)  # persist orphaned across restarts

    def _recover_unrecorded_runs(self) -> None:
        """Record runs whose console died before their terminal commit.

        A run-kind job started in a prior session that finished (or whose
        record_terminal never committed) leaves no runs-registry row.  On the
        next startup its detached process is gone, so ``_reconcile_locked``
        (which skips process-less jobs) can never record it.  Here, for every
        restored run-kind job with no runs row, if its output directory holds
        completed markers or its stored state is terminal, record the run and
        its recorded usage once - so an interrupted run is never permanently
        lost from the registry.
        """

        runs = self.db.list_runs()
        if runs is None:
            return
        recorded = {str(row["job_id"]) for row in runs}
        pin = os.environ.get("REF_URA", "")
        for job in self.jobs.values():
            if job.process is not None:
                continue
            if job.job_id in recorded:
                continue
            if run_kind(job.command, job.argv) is None:
                continue
            out_dir = _argv_out_dir(job.argv)
            usage_rows: list[dict[str, Any]] = []
            markers = 0
            if out_dir:
                try:
                    usage_rows, stats = collect_usage(self.repo_root / out_dir)
                    markers = stats.get("markers", 0)
                except OSError:
                    usage_rows, markers = [], 0
            terminal = (job.restored_state or "") in {"complete", "failed"}
            if markers or terminal:
                self.db.record_terminal(job, job.pin or pin, usage_rows)

    @staticmethod
    def _close_handles(job: Job) -> None:
        for handle in (job.stdout_handle, job.stderr_handle):
            if handle is not None and not getattr(handle, "closed", True):
                try:
                    handle.close()
                except OSError:
                    pass

    def _reconcile(self) -> None:
        with self._app_lock:
            self._reconcile_locked()

    def _reconcile_locked(self) -> None:
        """Persist live-job state; commit terminal state + usage in one txn.

        ``run_recorded`` flips only after the database transaction commits,
        so an interrupted write is retried on the next reconcile instead of
        being lost.
        """

        pin = os.environ.get("REF_URA", "")
        for job in self.jobs.values():
            if job.process is None:
                continue
            # Sample the terminal state once; pass it through so the upsert and
            # the run/usage transaction cannot disagree if the process exits
            # between polls.
            code = job.process.poll()
            if code is None:
                self.db.upsert_job(job, state="running", exit_code=None)
                continue
            state = "complete" if code == 0 else "failed"
            if job.ended_at is None:
                job.ended_at = time.time()
            if job.run_recorded:
                continue
            self._close_handles(job)
            job.pin = job.pin or pin
            if state == "failed" and job.failure is None:
                tail = self._log_tail(job, "stderr").strip()
                job.failure = tail[-500:] if tail else f"exit {code}"
            usage_rows: list[dict[str, Any]] = []
            out_dir = _argv_out_dir(job.argv)
            if out_dir and run_kind(job.command, job.argv) is not None:
                try:
                    usage_rows, _stats = collect_usage(self.repo_root / out_dir)
                except OSError:
                    usage_rows = []
            if self.db.record_terminal(
                job, job.pin, usage_rows, state=state, exit_code=code
            ):
                job.run_recorded = True

    # -- job lifecycle -----------------------------------------------------

    #: Receipt env vars a dry lane must not inherit, so an offline command is
    #: genuinely offline and self-contained (its argv carries no receipts and
    #: the environment cannot re-inject them).
    _DRY_SCRUB_ENV = (
        "URA_PROJECT_REVISION_MANIFEST", "URA_PROJECT_REVISION_SHA256",
        "URA_SOURCE_CONFORMANCE_MANIFEST", "URA_SOURCE_CONFORMANCE_SHA256",
    )

    def start_job(
        self,
        command: str,
        values: Mapping[str, str],
        *,
        builder_params: Mapping[str, str] | None = None,
        scrub_receipt_env: bool = False,
    ) -> Job:
        argv = build_argv(command, values, commands=self.commands)
        with self._app_lock:
            job_id = self._job_id_factory()
            directory = self.state_dir / job_id
            directory.mkdir(parents=True, exist_ok=False)
            (directory / "command.json").write_text(json.dumps({
                "job_id": job_id,
                "command": command,
                "argv": argv,
            }, indent=2, sort_keys=True), encoding="utf-8")
            stdout_handle = (directory / "stdout.log").open("wb")
            stderr_handle = (directory / "stderr.log").open("wb")
            # Each job gets its own process group/session so a stop can
            # terminate the complete child tree, not just the Python driver.
            popen_kwargs: dict[str, Any] = {}
            if os.name == "nt":
                popen_kwargs["creationflags"] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                popen_kwargs["start_new_session"] = True
            if scrub_receipt_env:
                child_env = dict(os.environ)
                for name in self._DRY_SCRUB_ENV:
                    child_env.pop(name, None)
                popen_kwargs["env"] = child_env
            try:
                process = subprocess.Popen(  # noqa: S603 - allowlisted argv, shell=False
                    argv,
                    cwd=self.repo_root,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    shell=False,
                    **popen_kwargs,
                )
            except OSError:
                stdout_handle.close()
                stderr_handle.close()
                raise
            job = Job(
                job_id=job_id,
                command=command,
                argv=argv,
                directory=directory,
                process=process,
                stdout_handle=stdout_handle,
                stderr_handle=stderr_handle,
                builder_params=dict(builder_params) if builder_params else None,
                pin=os.environ.get("REF_URA", ""),
            )
            self.jobs[job_id] = job
            self.db.upsert_job(job)
            return job

    def _terminate_tree(self, job: Job) -> None:
        """Stop the job's complete child-process tree, then the driver.

        Best-effort but never fatal: a failure to launch the killer, or a
        child that ignores the first signal, must not take down the request
        thread or leave the driver alive.  On POSIX the process group receives
        SIGTERM then (on timeout) SIGKILL regardless of whether the driver
        itself has exited, so a group member that ignores SIGTERM is still
        reaped.  On Windows ``taskkill /T`` walks the live child tree; if it
        cannot be launched, the driver is killed directly.
        """

        process = job.process
        if process is None or process.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(  # noqa: S603 - fixed argv, shell=False
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True, shell=False, check=False,
                )
            except OSError:
                # taskkill.exe unavailable: fall back to the direct kill.
                try:
                    process.kill()
                except OSError:
                    pass
        else:
            import signal  # noqa: PLC0415 - POSIX-only path

            self._signal_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                import signal  # noqa: PLC0415 - POSIX-only path

                # Escalate to the whole group even if the driver is still up.
                self._signal_group(process, signal.SIGKILL)
            else:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass

    @staticmethod
    def _signal_group(process: subprocess.Popen, sig: int) -> None:
        """Signal the job's process group, falling back to the driver."""

        try:
            os.killpg(os.getpgid(process.pid), sig)
        except (OSError, ProcessLookupError):
            try:
                process.send_signal(sig)
            except (OSError, ProcessLookupError, ValueError):
                pass

    def stop_job(self, job_id: str) -> Job:
        with self._app_lock:
            job = self.jobs.get(job_id)
            if job is None:
                raise KeyError(f"unknown job {job_id!r}")
            self._terminate_tree(job)
            # Reconcile the terminal state now: close the log handles and
            # commit job + run + usage in one transaction.
            self._reconcile_locked()
            return job

    def reindex_all(self) -> dict[str, Any]:
        """Rebuild the derived usage and report indexes from retained artifacts.

        Serialized with reconcile/start/stop under the application lock so it
        cannot delete a usage row another thread is committing.  It scans the
        results root AND every output directory recorded in the runs registry
        (a lane's --out may legitimately point outside the results root), so a
        rebuild never silently drops usage that reconcile recorded from such a
        directory.
        """

        with self._app_lock:
            roots: dict[str, Path] = {
                str(self.results_root.resolve()): self.results_root
            }
            runs = self.db.list_runs() or []
            for row in runs:
                out = str(row["out_dir"] or "").strip()
                if not out:
                    continue
                candidate = (self.repo_root / out)
                roots.setdefault(str(candidate.resolve()), candidate)
            usage_rows: list[dict[str, Any]] = []
            merged = {"markers": 0, "skipped_error": 0, "skipped_invalid": 0,
                      "orphan_responses": 0, "truncated": 0,
                      "unreadable_artifacts": 0}
            seen: set[tuple[str, str, str, str, str]] = set()
            for root in roots.values():
                if not root.exists():
                    continue
                rows, stats = collect_usage(root, verify_sha=True)
                for key in merged:
                    merged[key] += int(stats.get(key, 0))
                for entry in rows:
                    dedup = (entry["marker_sha"], entry["role"],
                             entry["provider"], entry["model"], entry["category"])
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    usage_rows.append(entry)
            report_rows = collect_reports(self.results_root)
            ok = self.db.reindex(usage_rows, report_rows)
            return {"ok": ok, "roots": len(roots), "usage_rows": len(usage_rows),
                    "reports": len(report_rows), **merged}

    def _log_tail(self, job: Job, stream: str) -> str:
        path = job.directory / f"{stream}.log"
        if not path.exists():
            return ""
        data = path.read_bytes()
        return data[-_LOG_TAIL_BYTES:].decode("utf-8", errors="replace")

    # -- request handling --------------------------------------------------

    def handle(
        self, method: str, target: str, form: Mapping[str, str] | None = None,
    ) -> tuple[int, str, bytes]:
        parsed = urlparse(target)
        path = parsed.path
        query = {
            key: values[0]
            for key, values in parse_qs(parsed.query).items()
            if values
        }
        try:
            if method == "GET" and path == "/":
                return 200, "text/html; charset=utf-8", self._overview(
                    query.get("reindexed", ""),
                )
            if method == "GET" and path == "/static/style.css":
                return 200, "text/css; charset=utf-8", _STYLE.encode("utf-8")
            if method == "GET" and path in {"/static/favicon.svg", "/favicon.ico"}:
                return 200, "image/svg+xml", _FAVICON_SVG
            if method == "GET" and path == "/commands":
                return 200, "text/html; charset=utf-8", self._commands_page()
            if method == "POST" and path == "/jobs":
                data = dict(form or {})
                command = data.pop("command", "")
                job = self.start_job(command, data)
                return 303, f"/jobs/{job.job_id}", b""
            if method == "GET" and path == "/jobs":
                return 200, "text/html; charset=utf-8", self._jobs_page()
            if method == "GET" and path.startswith("/jobs/") and path.endswith("/log"):
                job_id = path.split("/")[2]
                job = self.jobs.get(job_id)
                if job is None:
                    return 404, "text/plain; charset=utf-8", b"unknown job"
                stream = query.get("stream", "stdout")
                if stream not in {"stdout", "stderr"}:
                    return 400, "text/plain; charset=utf-8", b"unknown stream"
                text = self._log_tail(job, stream)
                return 200, "text/plain; charset=utf-8", text.encode("utf-8")
            if method == "GET" and path.startswith("/jobs/"):
                job_id = path.split("/")[2]
                job = self.jobs.get(job_id)
                if job is None:
                    return 404, "text/plain; charset=utf-8", b"unknown job"
                return 200, "text/html; charset=utf-8", self._job_page(job)
            if method == "POST" and path.startswith("/jobs/") and path.endswith("/stop"):
                job_id = path.split("/")[2]
                self.stop_job(job_id)
                return 303, f"/jobs/{job_id}", b""
            if method == "GET" and path == "/stats":
                return 200, "text/html; charset=utf-8", self._stats_page()
            if method == "GET" and path == "/build":
                return 200, "text/html; charset=utf-8", self._build_page()
            if method == "POST" and path == "/build":
                data = dict(form or {})
                confirmed = data.pop("confirm", "") == "yes"
                command, values, params = self._compose_from_builder(data)
                errors = self._validate_builder(params)
                if errors:
                    # Reject before any subprocess exists; re-render with
                    # field-level errors and the operator's selections kept.
                    return 200, "text/html; charset=utf-8", self._build_page(
                        prefill=params, errors=errors,
                    )
                mode = params.get("mode", "measured")
                spends_money = not (
                    mode == "dry_run"
                    or (mode == "diagnostic_canary"
                        and params.get("canary_dry") == "on")
                )
                if spends_money and not confirmed:
                    return 200, "text/html; charset=utf-8", self._preview_page(
                        command, values, params,
                    )
                job = self.start_job(
                    command, values, builder_params=params,
                    scrub_receipt_env=("--dry-run" in values),
                )
                return 303, f"/jobs/{job.job_id}", b""
            if method == "POST" and path == "/db/reindex":
                summary = self.reindex_all()
                return 303, f"/?reindexed={quote(json.dumps(summary, sort_keys=True))}", b""
            if method == "GET" and path == "/config/secrets":
                return 200, "text/html; charset=utf-8", self._secrets_page(
                    saved=query.get("saved", ""),
                )
            if method == "POST" and path == "/config/secrets":
                data = dict(form or {})
                name = data.get("name", "")
                action = data.get("action", "set")
                try:
                    if action == "clear":
                        self.clear_secret(name)
                    else:
                        # The value is consumed here and never returned in any
                        # response, redirect, or log.
                        self.set_secret(name, data.get("value", ""))
                except ValueError as exc:
                    return 200, "text/html; charset=utf-8", self._secrets_page(
                        error=str(exc),
                    )
                return 303, f"/config/secrets?saved={quote(name)}", b""
            if method == "POST" and path == "/pricing/fetch":
                summary = self.fetch_pricing()
                note = quote(json.dumps(summary, sort_keys=True))
                return 303, f"/config?file=pricing&fetched={note}", b""
            if method == "GET" and path == "/config":
                return 200, "text/html; charset=utf-8", self._config_page(
                    query.get("file", ""), query.get("saved", ""),
                    fetched=query.get("fetched", ""),
                )
            if method == "POST" and path == "/config":
                data = dict(form or {})
                key = data.get("file", "")
                content = data.get("content", "")
                try:
                    self.save_config(key, content)
                except ValueError as exc:
                    return 200, "text/html; charset=utf-8", self._config_page(
                        key, "", error=str(exc), draft=content,
                    )
                return 303, f"/config?file={quote(key)}&saved=1", b""
            if method == "GET" and path == "/artifacts":
                return self._artifacts(query.get("path", ""))
            return 404, "text/plain; charset=utf-8", b"not found"
        except (KeyError, ValueError) as exc:
            body = _page(
                "Request rejected",
                "<div class='card'><h1>Request rejected</h1>"
                f"<pre>{html.escape(str(exc))}</pre></div>",
            )
            return 400, "text/html; charset=utf-8", body

    # -- pages -------------------------------------------------------------

    def _load_warnings(self) -> list[dict[str, str]]:
        """Operator-facing notices from ``console-warnings.json``.

        The file is an operator/tooling-authored presentation input under the
        results root: ``{"warnings": [{"level", "title", "detail"}, ...]}``.
        It never changes experiment semantics; unknown levels render as
        ``warning``.  Malformed content is ignored (the console must not 500
        over a notice file).
        """

        path = self.results_root / _WARNINGS_FILE
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        entries = raw.get("warnings") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            return []
        out: list[dict[str, str]] = []
        for entry in entries[:_WARNINGS_MAX]:
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title", "")).strip()
            if not title:
                continue
            out.append({
                "level": str(entry.get("level", "warning")).lower(),
                "title": title,
                "detail": str(entry.get("detail", "")).strip(),
            })
        return out

    def _warnings_html(self) -> str:
        entries = self._load_warnings()
        if not entries:
            return ""
        rows = []
        for entry in entries:
            tone = _WARNING_TONES.get(entry["level"], "amber")
            nid = hashlib.sha1(
                f"{entry['level']}|{entry['title']}".encode("utf-8")
            ).hexdigest()[:12]
            detail = (
                f"<p class='note'>{html.escape(entry['detail'])}</p>"
                if entry["detail"] else ""
            )
            rows.append(
                f"<div class='notice {tone}' data-nid='{nid}'>"
                "<button type='button' class='notice-close' "
                "aria-label='dismiss notice' title='Dismiss (this browser "
                "only)'>&times;</button>"
                f"<span class='badge {tone}'>{html.escape(entry['level'])}"
                f"</span> <strong>{html.escape(entry['title'])}</strong>"
                + detail + "</div>"
            )
        return (
            "<div class='card'><h2>" + _icon("pulse") + "Notices</h2>"
            + "".join(rows) +
            "<p class='note'>Operator-recorded notices from "
            f"<code>{_WARNINGS_FILE}</code>; they annotate, and never "
            "authorize or invalidate, the artifacts themselves. Dismissing "
            "a notice hides it in this browser only - the file is "
            "unchanged. <a href='#' id='notice-restore' "
            "style='display:none'></a></p></div>"
            "<script>(function(){"
            "var KEY='ura-dismissed-notices';"
            "function load(){try{return JSON.parse("
            "localStorage.getItem(KEY))||[]}catch(e){return[]}}"
            "function save(v){localStorage.setItem(KEY,JSON.stringify(v));}"
            "var restore=document.getElementById('notice-restore');"
            "function apply(){var d=load();var hidden=0;"
            "document.querySelectorAll('.notice').forEach(function(n){"
            "var on=d.indexOf(n.getAttribute('data-nid'))>=0;"
            "n.style.display=on?'none':'';if(on){hidden++;}});"
            "if(restore){restore.style.display=hidden?'':'none';"
            "restore.textContent='Show '+hidden+' dismissed notice'+"
            "(hidden===1?'':'s');}}"
            "document.querySelectorAll('.notice-close').forEach(function(b){"
            "b.addEventListener('click',function(){"
            "var id=this.parentElement.getAttribute('data-nid');"
            "var d=load();if(d.indexOf(id)<0){d.push(id);save(d);}"
            "apply();});});"
            "if(restore){restore.addEventListener('click',function(e){"
            "e.preventDefault();save([]);apply();});}"
            "apply();})();</script>"
        )

    @staticmethod
    def _policy_card() -> str:
        rows = "".join(
            f"<tr><td>{html.escape(term)}</td><td>{html.escape(rule)}</td></tr>"
            for term, rule in _CAMPAIGN_POLICY
        )
        return (
            "<div class='card'><h2>" + _icon("receipt")
            + "Campaign sampling policy</h2>"
            "<div class='scroll'><table>" + rows + "</table></div>"
            "<p class='note'>Operator-recorded policy (thesis ledger "
            "Sections 11.22/11.27; runbook section 5.2). Enforcement lives "
            "in each recorded run_matrix invocation, not in this card.</p>"
            "</div>"
        )

    def _campaign_context(self) -> str:
        """Non-secret campaign bindings from the environment, if present."""

        rows = []
        for label, name in (
            ("Pinned revision", "REF_URA"),
            ("Revision receipt", "URA_PROJECT_REVISION_MANIFEST"),
            ("Receipt SHA-256", "URA_PROJECT_REVISION_SHA256"),
            ("Corpora root", "URA_CORPORA"),
        ):
            value = os.environ.get(name, "")
            if not value:
                continue
            shown = value if len(value) <= 64 else value[:30] + "..." + value[-22:]
            rows.append(
                f"<tr><td>{html.escape(label)}</td>"
                f"<td><code>{html.escape(shown)}</code></td></tr>"
            )
        if not rows:
            return (
                "<p class='note'>No campaign bindings exported in this "
                "console's environment.</p>"
            )
        return (
            "<div class='scroll'><table>"
            + "".join(rows)
            + "</table></div>"
            "<p class='note'>Values echoed from this console's environment "
            "for orientation only; nothing here validates them. The receipt "
            "and attestation validators are the only authority.</p>"
        )

    @staticmethod
    def _next_hint(stages: Mapping[str, StageInventory]) -> str:
        order = (
            ("Revision receipt", "project_revision",
             "author the prospective revision receipt (runbook section 2)"),
            ("Source receipts", "source_conformance",
             "run the bounded one-arm observations and author the source "
             "receipt (runbook section 4.1)"),
            ("Attestations", "run_matrix",
             "run the account attestation probes and derive transport "
             "receipts (runbook section 8)"),
            ("Canaries", "run_matrix",
             "run the diagnostic lane canaries and record cost projections "
             "(runbook section 9.1)"),
            ("Grids", "run_matrix",
             "start the measured lanes (runbook sections 10-13)"),
        )
        note = (
            "<p class='note'>This suggestion reads file presence only; the "
            "runbook and its fail-closed gates decide what is actually "
            "admissible.</p>"
        )
        for label, form, description in order:
            stage = stages.get(label)
            if stage is None or stage.count == 0:
                return (
                    "<div class='card'><h2>" + _icon("play")
                    + "Suggested next step</h2><p>Runbook order points to: "
                    f"<strong>{html.escape(description)}</strong> - the "
                    f"<code>{html.escape(form)}</code> form on the "
                    "<a href='/commands'>Run</a> page.</p>" + note + "</div>"
                )
        return (
            "<div class='card'><h2>" + _icon("play") + "Suggested next step"
            "</h2><p>All pipeline stages have files; analysis and reporting "
            "live in runbook section 16.</p>" + note + "</div>"
        )

    # -- stats -------------------------------------------------------------

    @staticmethod
    def _bar_chart(rows: list[tuple[str, float]], *, unit: str = "") -> str:
        """A minimal horizontal bar chart (values in [0,1]); presentation only."""

        if not rows:
            return ""
        bar_h, gap, pad_l, width = 22, 10, 220, 640
        height = len(rows) * (bar_h + gap) + gap
        parts = [
            f"<svg class='barchart' viewBox='0 0 {width} {height}' "
            "role='img' aria-label='result chart'>"
        ]
        for index, (label, value) in enumerate(rows):
            value = 0.0 if value < 0 else (1.0 if value > 1 else value)
            y = gap + index * (bar_h + gap)
            bar_w = (width - pad_l - 60) * value
            shown = f"{value * 100:.0f}%" if not unit else f"{value:g}{unit}"
            parts.append(
                f"<text class='bl' x='{pad_l - 8}' y='{y + bar_h - 6}' "
                f"text-anchor='end'>{html.escape(label[:34])}</text>"
                f"<rect class='bt' x='{pad_l}' y='{y}' "
                f"width='{width - pad_l - 60}' height='{bar_h}' rx='4'/>"
                f"<rect class='bv' x='{pad_l}' y='{y}' width='{bar_w:.1f}' "
                f"height='{bar_h}' rx='4'/>"
                f"<text class='bn' x='{pad_l + bar_w + 6}' y='{y + bar_h - 6}'>"
                f"{html.escape(shown)}</text>"
            )
        parts.append("</svg>")
        return "<div class='scroll'>" + "".join(parts) + "</div>"

    def _health_banner(self) -> str:
        """A visible banner when the database is unhealthy - never silent."""

        health = self.db.health()
        if health["healthy"] and not health["last_error"]:
            return ""
        return (
            "<div class='notice red'><span class='badge red'>database</span> "
            "<strong>Console database "
            + ("error" if health["healthy"] else "unavailable")
            + f"</strong><p class='note'>{html.escape(health['last_error'])} "
            "- job history, run registry, and recorded usage may be "
            "incomplete or unavailable (shown as unknown, never as empty). "
            "Jobs still run; validated artifacts are unaffected. Use "
            "Reindex on the dashboard after repairing the file.</p></div>"
        )

    def _usage_cost_rows(self) -> tuple[list[dict[str, Any]] | None, str]:
        """Cost rows from recorded usage, or (None, why-unavailable)."""

        totals = self.db.usage_totals()
        if totals is None:
            return None, "database unavailable - recorded usage unknown"
        pricing = load_pricing(self.repo_root)
        return compute_costs(totals, pricing), ""

    @staticmethod
    def _fmt_money(value: float | None, currency: str) -> str:
        if value is None:
            return "N/A"
        unit = {"USD": "$"}.get(currency.upper(), currency + " ")
        return f"{unit}{value:,.4f}"

    def _spend_card(self) -> str:
        cost_rows, unavailable = self._usage_cost_rows()
        if cost_rows is None:
            body = (
                f"<p class='note'><strong>N/A</strong> - "
                f"{html.escape(unavailable)}.</p>"
            )
            return (
                "<div class='card'><h2>" + _icon("coins")
                + "Budgets, usage &amp; calculated cost</h2>" + body + "</div>"
            )
        # Per-model usage/cost table (recorded tokens by category, the rate
        # applied, and the calculated cost - or N/A naming what is missing).
        detail = []
        for row in cost_rows:
            cats = row["tokens"]
            token_cells = "".join(
                f"<td>{cats[c]:,}</td>" if cats[c] else "<td>-</td>"
                for c in _TOKEN_CATEGORIES
            )
            if not row["billable"]:
                cost_cell = "<td>local (not billed)</td>"
            elif row["cost"] is not None:
                source = (
                    " - <span class='badge amber'>auto-fetched, verify</span>"
                    if row.get("auto_fetched") else
                    " - <span class='badge gray'>operator-set</span>"
                )
                cost_cell = (
                    f"<td><strong>{self._fmt_money(row['cost'], row['currency'])}"
                    f"</strong><br><span class='fieldhint'>rate of "
                    f"{html.escape(row['effective_date'])}{source}</span></td>"
                )
            else:
                why = "; ".join(row["missing"]) or "price not recorded"
                cost_cell = (
                    "<td>N/A <span class='fieldhint'>"
                    + html.escape(why) + "</span></td>"
                )
            detail.append(
                f"<tr><td>{html.escape(row['role'])}</td>"
                f"<td>{html.escape(row['provider'])}<br><code>"
                f"{html.escape(row['model'][:44])}</code></td>"
                f"<td>{row['calls']:,}"
                + (f"<br><span class='fieldhint'>{row['missing_tokens']} "
                   "without token usage</span>" if row["missing_tokens"] else "")
                + f"</td>{token_cells}{cost_cell}</tr>"
            )
        heads = "".join(
            f"<th>{c.replace('_', ' ')}</th>" for c in _TOKEN_CATEGORIES
        )
        detail_table = (
            "<div class='scroll'><table><tr><th>Role</th><th>Provider / model"
            f"</th><th>Calls</th>{heads}<th>Calculated cost</th></tr>"
            + "".join(detail) + "</table></div>"
            if detail else
            "<p class='note'>No recorded usage yet. Usage appears here once "
            "a completed run's artifacts are recorded (reconcile on job "
            "finish, or Reindex on the dashboard).</p>"
        )
        # Provider budget summary: prepaid minus calculated spend.
        by_provider: dict[str, tuple[float, bool]] = {}
        for row in cost_rows:
            if not row["billable"]:
                continue
            spent, complete = by_provider.get(row["provider"].lower(), (0.0, True))
            if row["cost"] is None:
                by_provider[row["provider"].lower()] = (spent, False)
            else:
                by_provider[row["provider"].lower()] = (spent + row["cost"], complete)
        budget_rows = []
        for name, amount, match, _role in self._budgets():
            spent, complete = next(
                (v for p, v in by_provider.items() if p.startswith(match)),
                (0.0, True),
            )
            prepaid = self._parse_money(amount)
            spent_text = self._fmt_money(spent, "USD") if complete else (
                "N/A <span class='fieldhint'>some models lack a recorded "
                "price</span>"
            )
            if prepaid is None:
                remaining = "N/A <span class='fieldhint'>prepaid not numeric</span>"
            elif not complete:
                remaining = "N/A <span class='fieldhint'>cost incomplete</span>"
            else:
                remaining = self._fmt_money(prepaid - spent, "USD")
            budget_rows.append(
                f"<tr><td>{html.escape(name)}</td>"
                f"<td><strong>{html.escape(amount)}</strong></td>"
                f"<td>{spent_text}</td><td>{remaining}</td></tr>"
            )
        return (
            "<div class='card'><h2>" + _icon("coins")
            + "Budgets, usage &amp; calculated cost</h2>"
            "<div class='scroll'><table><tr><th>Provider</th><th>Prepaid</th>"
            "<th>Calculated spend</th><th>Remaining</th></tr>"
            + "".join(budget_rows) + "</table></div>"
            + detail_table +
            "<p class='note'>Tokens are the recorded usage read from "
            "completion-bound run artifacts (Response tokens and provider "
            "usage detail; judge-call tokens from completed trails) - never "
            "an estimate. Cost multiplies those tokens by the operator-edited "
            "<a href='/config?file=pricing'>pricing</a> table (effective-"
            "dated); a missing token count or price renders as N/A, never as "
            "zero. Prepaid budgets come from the editable "
            "<a href='/config?file=budgets'>budgets</a> config. If a provider "
            "ever reports an actually billed amount in an artifact, that "
            "amount is authoritative over this calculation.</p></div>"
        )

    @staticmethod
    def _parse_money(amount: str) -> float | None:
        match = re.fullmatch(r"\$?\s*([0-9]+(?:\.[0-9]+)?)", amount.strip())
        return float(match.group(1)) if match else None

    def _runs_card(self) -> str:
        runs = self.db.list_runs()
        if runs is None:
            return (
                "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
                "<p class='note'><strong>Unavailable</strong> - the console "
                "database cannot be read, so the run registry is unknown "
                "(not empty).</p></div>"
            )
        if not runs:
            return (
                "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
                "<p class='note'>No lanes recorded yet. Each rig_check and "
                "run_matrix job is registered here (kind, output, pinned "
                "revision) as it finishes - durable across console "
                "restarts.</p></div>"
            )
        tone = {"complete": "green", "failed": "red", "running": "blue"}
        rows = []
        for row in runs:
            state = str(row["state"] or "")
            out = str(row["out_dir"] or "")
            link = (f"<a href='/artifacts?path={quote(out)}'>{html.escape(out)}"
                    "</a>" if out else "-")
            when = time.strftime(
                "%m-%d %H:%M", time.localtime(float(row["created_at"] or 0))
            )
            rows.append(
                f"<tr><td>{when}</td>"
                f"<td><span class='badge {tone.get(state, 'gray')}'>"
                f"{html.escape(str(row['kind'] or ''))}</span></td>"
                f"<td>{html.escape(str(row['command'] or ''))}</td>"
                f"<td>{link}</td>"
                f"<td><code>{html.escape(str(row['pin'] or '')[:10])}</code>"
                "</td></tr>"
            )
        return (
            "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
            "<div class='scroll'><table><tr><th>When</th><th>Kind</th>"
            "<th>Command</th><th>Output</th><th>Pin</th></tr>"
            + "".join(rows) + "</table></div>"
            "<p class='note'>Every rig_check/run_matrix lane, recorded as it "
            "finishes and durable across restarts. This is an operational "
            "index; the validated artifacts it links remain authoritative.</p>"
            "</div>"
        )

    def _report_index(self) -> list[dict[str, Any]]:
        """Indexed report artifacts: the database index, else a live scan."""

        rows = self.db.list_reports()
        if rows:
            return [dict(row) for row in rows]
        return collect_reports(self.results_root)

    def _render_level2(self, rel: str, doc: Mapping[str, Any]) -> str:
        """Render one ura-level2-report/1: real estimate rows, one chart per
        metric, never a cross-metric combination or a universal score."""

        common = doc.get("common")
        estimates = (
            common.get("estimates") if isinstance(common, Mapping) else None
        )
        if not isinstance(estimates, list) or not estimates:
            return (
                "<div class='card'><h2>" + _icon("chart")
                + f"{html.escape(rel)}</h2><p class='note'>Validated Level-2 "
                "report with no common estimate rows (native-only or empty)."
                "</p></div>"
            )
        by_metric: dict[str, list[Mapping[str, Any]]] = {}
        for row in estimates:
            if isinstance(row, Mapping):
                by_metric.setdefault(str(row.get("metric", "?")), []).append(row)
        sections = []
        for metric in sorted(by_metric):
            rows = by_metric[metric]
            family = str(rows[0].get("semantic_family", ""))
            polarity = str(rows[0].get("polarity", ""))
            # A chart is drawn only when every value in this metric is a
            # rate in [0, 1]; other scales stay table-only rather than being
            # squeezed into a misleading axis.
            values = [row.get("value") for row in rows]
            chartable = all(
                isinstance(v, (int, float)) and 0.0 <= float(v) <= 1.0
                for v in values
            )
            chart = ""
            if chartable:
                chart_rows = [
                    (
                        f"{row.get('model_spec', '?')} · "
                        f"{row.get('corpus_arm', '?')} · "
                        f"{row.get('attacker', '?')}",
                        float(row.get("value", 0.0)),
                    )
                    for row in rows[:24]
                ]
                chart = self._bar_chart(chart_rows)
            else:
                chart = (
                    "<p class='note'>Not charted: values are not rates in "
                    "[0, 1]; the table below is the presentation.</p>"
                )
            table_rows = []
            for row in rows[:60]:
                ci_low, ci_high = row.get("ci_low"), row.get("ci_high")
                ci = (
                    f"[{ci_low:.3f}, {ci_high:.3f}]"
                    if isinstance(ci_low, (int, float))
                    and isinstance(ci_high, (int, float))
                    else "N/A (no CI recorded)"
                )
                completed = row.get("judgments_completed")
                decided = row.get("judgments_decided")
                coverage = (
                    f"{decided}/{completed}"
                    if isinstance(decided, int) and isinstance(completed, int)
                    else "N/A"
                )
                n_clusters = row.get("n_clusters")
                value = row.get("value")
                value_text = (
                    f"{float(value):.4f}"
                    if isinstance(value, (int, float)) else "N/A"
                )
                table_rows.append(
                    f"<tr><td><code>{html.escape(str(row.get('model_spec', '')))}"
                    "</code></td>"
                    f"<td>{html.escape(str(row.get('corpus_arm', '')))}</td>"
                    f"<td>{html.escape(str(row.get('attacker', '')))}</td>"
                    f"<td>{html.escape(str(row.get('defense', '')))}</td>"
                    f"<td><strong>{value_text}</strong></td>"
                    f"<td>{ci}</td>"
                    f"<td>{html.escape(str(row.get('n_records', 'N/A')))}</td>"
                    f"<td>{html.escape(str(n_clusters) if n_clusters is not None else 'N/A')}</td>"
                    f"<td>{coverage}</td></tr>"
                )
            sections.append(
                f"<h3>{html.escape(metric)} <span class='modtag'>"
                f"{html.escape(family)}</span><span class='modtag'>"
                f"{html.escape(polarity)}</span></h3>"
                + chart +
                "<div class='scroll'><table><tr><th>model_spec</th>"
                "<th>corpus_arm</th><th>attacker</th><th>defense</th>"
                "<th>value</th><th>ci_low, ci_high</th><th>n_records</th>"
                "<th>n_clusters</th><th>decided/completed</th></tr>"
                + "".join(table_rows) + "</table></div>"
            )
        return (
            "<div class='card'><h2>" + _icon("chart")
            + f"{html.escape(rel)} <span class='badge blue'>measured</span>"
            "</h2>"
            "<p class='note'>Deterministic Level-2 export "
            "(<code>common.estimates</code>). One chart per metric; "
            "unrelated metrics are never combined and no universal safety "
            "score exists. Diagnostic evidence cannot reach this report by "
            "construction.</p>"
            + "".join(sections)
            + f"<p class='note'><a href='/artifacts?path={quote(rel)}'>open "
            "the full validated artifact &rarr;</a></p></div>"
        )

    def _render_level1(self, rel: str, doc: Mapping[str, Any]) -> str:
        """Render one ura-level1-evidence/2: separate unit ledgers with the
        real count fields, diagnostic/measured distinct."""

        scope = doc.get("scope") if isinstance(doc.get("scope"), Mapping) else {}
        counts = doc.get("counts") if isinstance(doc.get("counts"), Mapping) else {}
        kind = str(scope.get("evidence_kind", "unknown"))
        badge = (
            "<span class='badge amber'>diagnostic dry-run</span>"
            if kind == "diagnostic_dry_run"
            else "<span class='badge blue'>measured</span>"
        )
        tables = []
        for title, key in (
            ("Prospective request units", "prospective_request_units"),
            ("Planning strata", "planning_strata"),
            ("Execution units", "execution_units"),
            ("Judgment records", "judgment_records"),
            ("Request-level errors", "request_level_errors"),
        ):
            block = counts.get(key)
            if not isinstance(block, Mapping):
                tables.append(
                    f"<h3>{html.escape(title)}</h3><p class='note'>"
                    "N/A - not supplied in this artifact.</p>"
                )
                continue
            cells = "".join(
                "<tr><td>" + html.escape(str(name).replace("_", " "))
                + "</td><td>"
                + ("null (by design)" if value is None else f"{value:,}")
                + "</td></tr>"
                for name, value in block.items()
                if name != "unit"
            )
            tables.append(
                f"<h3>{html.escape(title)} <span class='modtag'>"
                f"{html.escape(str(block.get('unit', '')))}</span></h3>"
                "<div class='scroll'><table>" + cells + "</table></div>"
            )
        return (
            "<div class='card'><h2>" + _icon("file")
            + f"{html.escape(rel)} {badge}</h2>"
            "<p class='note'>Level-1 lifecycle inventory. Request units, "
            "planning strata, execution units, and judgment records are "
            "separate unit ledgers and are never summed into each other; "
            "structural N/A, missing, and error are distinct states.</p>"
            + "".join(tables)
            + f"<p class='note'><a href='/artifacts?path={quote(rel)}'>open "
            "the full validated artifact &rarr;</a></p></div>"
        )

    def _stats_page(self) -> bytes:
        self._reconcile()
        reports = self._report_index()
        cards = []
        listed = []
        for report in reports:
            rel = str(report["path"])
            listed.append(
                f"<li><a href='/artifacts?path={quote(rel)}'>"
                f"{html.escape(rel)}</a> <span class='modtag'>"
                f"{html.escape(str(report['kind']))}</span></li>"
            )
            if report["kind"] not in {"level1", "level2"} or len(cards) >= 6:
                continue
            try:
                doc = json.loads(
                    (self.results_root / rel).read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            if report["kind"] == "level2":
                cards.append(self._render_level2(rel, doc))
            else:
                cards.append(self._render_level1(rel, doc))
        results = (
            "<div class='card'><h2>" + _icon("file") + "Report artifacts</h2>"
            f"<ul>{''.join(listed)}</ul></div>"
            if listed else
            "<div class='card'><p class='note'>No Level-1/Level-2 report "
            "artifacts retained yet. They appear here once lanes and the "
            "analysis CLIs have run; diagrams render from the real "
            "<code>ura-level2-report/1</code> estimate rows.</p></div>"
        )
        body = (
            "<h1>" + _icon("chart", size=22) + "Campaign stats</h1>"
            + self._health_banner()
            + self._spend_card()
            + self._runs_card()
            + "".join(cards)
            + results
        )
        return _page("Campaign stats", body, active="Stats")

    # -- campaign builder --------------------------------------------------

    def _load_registry(self, name: str, example: str) -> dict[str, Any]:
        """Parse an operator-local registry, falling back to its example."""

        for candidate in (name, example):
            path = self.repo_root / "experiments" / candidate
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                return data
        return {}

    @staticmethod
    def _entry_modalities(entry: Any) -> tuple[str, ...]:
        if isinstance(entry, dict) and isinstance(entry.get("modalities"), list):
            mods = tuple(
                str(m) for m in entry["modalities"] if isinstance(m, str)
            )
            if mods:
                return mods
        return ("text",)

    def _vllm_roster_version(self) -> str | None:
        try:
            from experiments.local_targets import roster_version  # noqa: PLC0415

            return roster_version(self.repo_root)
        except Exception:  # noqa: BLE001 - convenience metadata only
            return None

    def _model_options(self) -> list[tuple[str, str, tuple[str, ...], str]]:
        """Selectable targets as (spec, label, modalities, kind).

        ``kind`` is 'api' for hosted routes (composed into --api) or 'local'
        for on-rig vLLM targets (composed into --local). Modalities come from
        each roster entry so the builder can hide a target that cannot handle a
        selected modality. Local targets are the hand-configured local-targets
        registry plus the vLLM roster (the models the rig's vLLM can serve;
        vLLM downloads a chosen one on first run). The focal Anthropic/OpenAI
        pair are the inherent env adapters if exported.
        """

        from experiments.local_targets import roster_models  # noqa: PLC0415

        options: list[tuple[str, str, tuple[str, ...], str]] = []
        for env_name, label in (("FABLE", "Fable (focal)"), ("SOL", "Sol (focal)")):
            spec = os.environ.get(env_name, "").strip()
            if spec:
                options.append((spec, label, ("text", "image"), "api"))
        for key, entry in self._load_registry(
            "api-targets.json", "rig/api-targets.example.json"
        ).items():
            options.append((key, key, self._entry_modalities(entry), "api"))
        local_seen: set[str] = set()
        for key, entry in self._load_registry(
            "local-targets.json", "rig/local-targets.example.json"
        ).items():
            local_seen.add(key)
            options.append((key, key, self._entry_modalities(entry), "local"))
        try:
            roster = roster_models(self.repo_root)
        except Exception:  # noqa: BLE001 - roster is a convenience, never fatal
            roster = []
        for model in roster:
            spec = str(model["spec"])
            if spec in local_seen:
                continue
            local_seen.add(spec)
            mods = tuple(str(m) for m in model.get("modalities", ["text"]))
            options.append((spec, spec, mods or ("text",), "local"))
        return options

    #: How many repeatable live-attestation rows the builder form accepts.
    _MAX_ATT_ROWS = 12

    def _compose_from_builder(
        self, form: Mapping[str, str],
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        """Turn builder selections into a validated run_matrix value map.

        The individual modality/model/framework checkboxes are collected
        client-side into comma-joined hidden fields, so this only reads the
        composed strings and hands them to the same typed build_argv path.
        Returns ``(command, values, params)`` where ``params`` is the raw
        builder form (persisted with the job and replayed on re-render).
        """

        params = {
            key: str(value).strip() for key, value in form.items()
            if str(value).strip()
        }
        mode = params.get("mode", "measured")
        dry = mode == "dry_run" or (
            mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        values: dict[str, str] = {}
        for source, flag in (
            ("corpora", "--corpora"), ("api", "--api"),
            ("local", "--local"), ("attackers", "--attackers"),
            ("judges", "--judges"), ("limit", "--limit"),
            ("sample_seed", "--sample-seed"), ("seeds", "--seeds"),
            ("max_queries", "--max-queries"), ("max_turns", "--max-turns"),
            ("cap_target", "--max-total-target-calls"),
            ("cap_judge", "--max-total-judge-calls"),
            ("cap_http", "--max-total-http-attempts"),
            ("deadline", "--deadline-seconds"),
            ("scope", "--execution-scope-id"),
            ("max_age", "--live-attestation-max-age-hours"),
            ("project_revision", "--project-revision"),
            ("project_revision_sha", "--project-revision-sha256"),
            ("source_conformance", "--source-conformance"),
            ("source_conformance_sha", "--source-conformance-sha256"),
            ("dtype", "--dtype"), ("quantization", "--quantization"),
            ("out", "--out"),
        ):
            raw = params.get(source, "")
            if raw:
                values[flag] = raw
        for index in range(1, self._MAX_ATT_ROWS + 1):
            path = params.get(f"att_path{index}", "")
            sha = params.get(f"att_sha{index}", "")
            if path:
                values[f"--live-attestation#{index}"] = path
            if sha:
                values[f"--live-attestation-sha256#{index}"] = sha
        defense = params.get("defense", "")
        if defense and defense != "none":
            values["--defense"] = defense
            guard = params.get("defense_guard", "")
            if guard:
                values["--defense-guard"] = guard
        judges = values.get("--judges", "")
        if "llm" in judges.split(","):
            # A dry lane must grade with the offline mock LLM - never a real,
            # metered hosted judge - so a "no calls, no spend" mode cannot
            # silently issue paid Haiku judge calls.
            values["--judge-model"] = "mock" if dry else (
                params.get("judge_model", "")
                or "anthropic:claude-haiku-4-5-20251001"
            )
        for token, mode_flag, _desc in _BUILD_MODES:
            if token == mode and mode_flag:
                values[mode_flag] = "on"
        if mode == "attestation_probe":
            # A probe is one query and one turn by definition; fix them so the
            # composed argv matches the probe shape run_matrix enforces
            # instead of inheriting the driver's default of 4.
            values["--max-queries"] = "1"
            values["--max-turns"] = "1"
        if mode == "diagnostic_canary" and params.get("canary_dry") == "on":
            values["--dry-run"] = "on"
            # The dry canary is offline-synthetic by definition; compose the
            # synthetic corpus (the builder has no synth arm checkbox) and
            # drop any real target selection.
            values["--corpora"] = "synth"
            values.pop("--api", None)
            values.pop("--local", None)
        if dry:
            # A dry lane needs no admission receipts; the env-prefilled
            # receipt fields must not leak into an offline command (the child
            # is also launched with those env vars scrubbed).
            for flag in ("--project-revision", "--project-revision-sha256",
                         "--source-conformance", "--source-conformance-sha256"):
                values.pop(flag, None)
        else:
            # A non-dry lane's argv must be self-contained: if a receipt field
            # was left blank but the campaign environment binds it, fold the
            # env value into the command so the retained "Exact command"
            # reproduces the same admission in a clean shell.
            for flag, env_name in (
                ("--project-revision", "URA_PROJECT_REVISION_MANIFEST"),
                ("--project-revision-sha256", "URA_PROJECT_REVISION_SHA256"),
                ("--source-conformance", "URA_SOURCE_CONFORMANCE_MANIFEST"),
                ("--source-conformance-sha256", "URA_SOURCE_CONFORMANCE_SHA256"),
            ):
                if not values.get(flag) and os.environ.get(env_name):
                    values[flag] = os.environ[env_name]
        # Bind the operator-local registries so a lane resolves its roster,
        # local target config, and source receipt as the runbook expects.
        for relative, flag in (
            ("experiments/api-targets.json", "--api-config"),
            ("experiments/source-instances.json", "--source-config"),
        ):
            if (self.repo_root / relative).is_file():
                values[flag] = relative
        if values.get("--local"):
            local_cfg = "experiments/local-targets.json"
            if (self.repo_root / local_cfg).is_file():
                values["--local-config"] = local_cfg
        return "run_matrix", values, params

    @staticmethod
    def _split_list(raw: str) -> list[str]:
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _validate_builder(self, params: Mapping[str, str]) -> dict[str, str]:
        """Mode-specific builder validation, keyed by form field.

        Mirrors the run_matrix admission gates so an invalid lane is rejected
        with a field-level explanation BEFORE any subprocess exists.  The CLI
        gates remain authoritative; this never weakens them.
        """

        errors: dict[str, str] = {}
        mode = params.get("mode", "measured")
        canary_dry = mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        api = self._split_list(params.get("api", ""))
        local = self._split_list(params.get("local", ""))
        corpora = self._split_list(params.get("corpora", ""))
        attackers = self._split_list(params.get("attackers", ""))
        seeds = self._split_list(params.get("seeds", "") or "0")
        targets = len(api) + len(local)
        real_corpora = [arm for arm in corpora if arm != "synth"]
        att_rows: list[tuple[str, str]] = []
        for index in range(1, self._MAX_ATT_ROWS + 1):
            path = params.get(f"att_path{index}", "")
            sha = params.get(f"att_sha{index}", "")
            if path or sha:
                att_rows.append((path, sha))

        def require_int(field: str, *, positive: bool = False) -> int | None:
            raw = params.get(field, "")
            if not raw:
                return None
            try:
                value = int(raw)
            except ValueError:
                errors[field] = "must be an integer"
                return None
            if positive and value <= 0:
                errors[field] = "must be a positive integer"
                return None
            return value

        limit = require_int("limit")
        if limit is not None and limit < 0:
            errors["limit"] = "must be non-negative"
        require_int("sample_seed")
        require_int("max_queries", positive=True)
        require_int("max_turns", positive=True)

        raw_seeds = params.get("seeds", "")
        if raw_seeds:
            seed_parts = self._split_list(raw_seeds)
            if not all(re.fullmatch(r"-?\d+", part) for part in seed_parts):
                errors["seeds"] = "must be a comma list of integers"
            elif len(set(seed_parts)) != len(seed_parts):
                errors["seeds"] = "seeds must be unique"
        scope_value = params.get("scope", "")
        if scope_value and re.search(r"\s", scope_value):
            errors["scope"] = "must not contain whitespace"

        def require_hex(field: str) -> None:
            raw = params.get(field, "")
            if raw and not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
                errors[field] = "must be an exact 64-hex SHA-256"

        require_hex("project_revision_sha")
        require_hex("source_conformance_sha")

        def env_or(field: str, env_name: str) -> bool:
            return bool(params.get(field, "") or os.environ.get(env_name, ""))

        has_project = (
            env_or("project_revision", "URA_PROJECT_REVISION_MANIFEST")
            and env_or("project_revision_sha", "URA_PROJECT_REVISION_SHA256")
        )
        has_source = (
            env_or("source_conformance", "URA_SOURCE_CONFORMANCE_MANIFEST")
            and env_or("source_conformance_sha", "URA_SOURCE_CONFORMANCE_SHA256")
        )

        def forbid_live_fields(reason: str) -> None:
            if params.get("scope", ""):
                errors["scope"] = reason
            if params.get("max_age", ""):
                errors["max_age"] = reason
            if att_rows:
                errors["att"] = reason

        def require_caps_and_deadline() -> None:
            for cap in ("cap_target", "cap_judge", "cap_http", "deadline"):
                value = require_int(cap, positive=True)
                if value is None and cap not in errors:
                    errors[cap] = (
                        "required: a finite positive ceiling before any "
                        "non-dry run"
                    )

        def require_live_admission() -> None:
            if not params.get("scope", ""):
                errors["scope"] = "required for live execution"
            age = params.get("max_age", "")
            try:
                age_value = float(age) if age else 0.0
            except ValueError:
                age_value = 0.0
            if not 0 < age_value <= 8760:
                errors["max_age"] = (
                    "required: maximum attestation age in hours, in (0, 8760]"
                )
            if not att_rows:
                errors["att"] = (
                    "at least one live-attestation receipt/digest pair is "
                    "required"
                )
            if not has_project:
                errors["project_revision"] = (
                    "required: validated project-revision receipt and digest "
                    "(field or campaign environment)"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = (
                    "required: validated source-conformance receipt and "
                    "digest for real source arms"
                )
            require_caps_and_deadline()

        for path, sha in att_rows:
            if not path or not sha:
                errors["att"] = (
                    "every receipt row needs both the receipt path and its "
                    "exact 64-hex digest"
                )
            elif not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                errors["att"] = "receipt digest must be an exact 64-hex SHA-256"

        if not params.get("out", ""):
            errors["out"] = "required: output directory for this run"
        if not corpora and not canary_dry:
            # A dry canary composes the synthetic corpus itself, so it needs
            # no arm checkbox; every other lane must select at least one arm.
            errors["corpora"] = "select at least one corpus arm"
        if not attackers:
            errors["attackers"] = "select at least one attack framework"
        if len(local) > 1:
            errors["models"] = (
                "one local target per process (vLLM/Ollama engines must not "
                "accumulate on the rig GPUs)"
            )

        if mode == "dry_run":
            forbid_live_fields(
                "a diagnostic dry run cannot consume or produce live "
                "attestation"
            )
        elif mode == "attestation_probe":
            if targets != 1:
                errors["models"] = "an attestation probe takes exactly one target"
            if len(corpora) != 1:
                errors["corpora"] = "an attestation probe takes exactly one corpus"
            if attackers != ["replay"]:
                errors["attackers"] = (
                    "an attestation probe uses exactly the replay attacker"
                )
            if len(seeds) != 1:
                errors["seeds"] = "an attestation probe takes exactly one seed"
            if params.get("defense", "none") != "none":
                errors["defense"] = "an attestation probe requires defense none"
            if limit not in {1, 2}:
                errors["limit"] = "an attestation probe requires --limit 1 or 2"
            if params.get("max_queries", "") not in {"", "1"}:
                errors["max_queries"] = "an attestation probe uses one query"
            if params.get("max_turns", "") not in {"", "1"}:
                errors["max_turns"] = "an attestation probe uses one turn"
            if not params.get("scope", ""):
                errors["scope"] = "required: execution scope id"
            if not has_project:
                errors["project_revision"] = (
                    "required: validated project-revision receipt and digest"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = (
                    "required for a real-source probe corpus"
                )
            if att_rows:
                errors["att"] = (
                    "an attestation probe cannot consume prior attestations"
                )
            if params.get("max_age", ""):
                errors["max_age"] = (
                    "an attestation probe cannot consume prior attestations"
                )
            require_caps_and_deadline()
        elif mode == "diagnostic_canary":
            if limit != 1:
                errors["limit"] = (
                    "a diagnostic canary requires exactly --limit 1 (all rows "
                    "in that source cluster are retained)"
                )
            if len(attackers) != 1:
                errors["attackers"] = (
                    "a diagnostic canary takes exactly one attacker"
                )
            if len(seeds) != 1:
                errors["seeds"] = "a diagnostic canary takes exactly one seed"
            if canary_dry:
                # The dry canary is composed as offline-synthetic (corpora
                # synth, no targets, no receipts): the operator only picks the
                # attacker/seed/limit, so no arm or target selection is
                # required, and live-attestation fields are forbidden.
                forbid_live_fields(
                    "a dry canary cannot consume or produce live attestation"
                )
            else:
                if len(corpora) != 1:
                    errors["corpora"] = (
                        "a live canary takes exactly one corpus"
                    )
                if targets != 1:
                    errors["models"] = (
                        "a live canary takes exactly one target model"
                    )
                require_live_admission()
        else:  # measured execution
            if targets < 1:
                errors["models"] = "select at least one target model"
            require_live_admission()
            if api and (limit is None or (limit is not None and limit <= 0)):
                errors["limit"] = (
                    "hosted paid lanes must carry a positive pre-registered "
                    "--limit that bounds spend (campaign sampling policy); "
                    "--limit 0 would run the full corpus"
                )
            if api and not params.get("sample_seed", ""):
                errors["sample_seed"] = (
                    "hosted paid lanes must record --sample-seed (identical "
                    "subset across conditions)"
                )
        return errors

    def _ceilings_card(self, params: Mapping[str, str]) -> str:
        """The call-ceiling summary shown before a non-dry job starts."""

        api = self._split_list(params.get("api", ""))
        local = self._split_list(params.get("local", ""))
        corpora = self._split_list(params.get("corpora", ""))
        attackers = self._split_list(params.get("attackers", ""))
        seeds = self._split_list(params.get("seeds", "") or "0")
        grid_cells = max(1, len(api) + len(local)) * max(1, len(corpora)) * \
            max(1, len(attackers))
        shape = (
            f"{len(api) + len(local)} target(s) x {len(corpora)} corpus "
            f"arm(s) x {len(attackers)} attacker(s) x {len(seeds)} seed(s) "
            f"= {grid_cells * max(1, len(seeds))} planned cell-seed lanes"
        )
        rows = "".join(
            f"<tr><td><code>{html.escape(flag)}</code></td>"
            f"<td><strong>{html.escape(params.get(field, '') or '(unset)')}"
            "</strong></td><td>" + html.escape(note) + "</td></tr>"
            for field, flag, note in (
                ("cap_target", "--max-total-target-calls",
                 "hard circuit-breaker on model-under-test calls"),
                ("cap_judge", "--max-total-judge-calls",
                 "hard circuit-breaker on hosted judge calls"),
                ("cap_http", "--max-total-http-attempts",
                 "hard cap on transport attempts, retries included"),
                ("deadline", "--deadline-seconds",
                 "wall-clock admission deadline for the lane"),
                ("limit", "--limit",
                 "cluster subsample per corpus (cluster sibling rows are all "
                 "retained, so row counts can exceed this)"),
                ("max_queries", "--max-queries",
                 "target calls per datapoint and seed"),
                ("max_turns", "--max-turns", "conversation turns per "
                 "datapoint and seed"),
            )
        )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Calculated call "
            "ceilings</h2>"
            f"<p><strong>{html.escape(shape)}</strong></p>"
            "<div class='scroll'><table><tr><th>Ceiling</th><th>Value</th>"
            "<th>Meaning</th></tr>" + rows + "</table></div>"
            "<p class='note'>The entered ceilings are the binding budget "
            "guards; run_matrix rejects the lane if they cannot cover its "
            "exact no-call projection. The projection itself is computed by "
            "the CLI preflight from the real corpus, never estimated here."
            "</p></div>"
        )

    def _preview_page(
        self, command: str, values: Mapping[str, str],
        params: Mapping[str, str],
    ) -> bytes:
        """Exact argv + ceilings confirmation before a non-dry job starts."""

        argv = build_argv(command, values, commands=self.commands)
        argv_chips = "<div class='argv'>" + "".join(
            f"<code>{html.escape(part)}</code>" for part in argv
        ) + "</div>"
        hidden = "".join(
            f"<input type='hidden' name='{html.escape(key)}' "
            f"value='{html.escape(value)}'>"
            for key, value in sorted(params.items())
        )
        mode = params.get("mode", "measured")
        body = (
            "<h1>" + _icon("play", size=22) + "Confirm paid execution</h1>"
            "<div class='notice amber'><strong>This mode spends real "
            "money.</strong><p class='note'>Mode: "
            f"<code>{html.escape(mode)}</code>. Review the exact command and "
            "ceilings below; nothing has started yet.</p></div>"
            "<div class='card'><h2>" + _icon("terminal")
            + "Exact command</h2>" + argv_chips + "</div>"
            + self._ceilings_card(params) +
            "<form method='post' action='/build'>"
            + hidden +
            "<input type='hidden' name='confirm' value='yes'>"
            "<div class='buildbar'><button type='submit'>"
            + _icon("play", size=15) + "Start this job</button>"
            "<a href='/build'><button type='button' class='ghost'>Back to "
            "builder</button></a></div></form>"
        )
        return _page("Confirm execution", body, active="Build")

    def _build_page(
        self,
        prefill: Mapping[str, str] | None = None,
        errors: Mapping[str, str] | None = None,
    ) -> bytes:
        prefill = dict(prefill or {})
        errors = dict(errors or {})

        def err(field: str) -> str:
            message = errors.get(field, "")
            return (
                f"<span class='fielderr'>{html.escape(message)}</span>"
                if message else ""
            )

        def val(field: str, default: str = "") -> str:
            return html.escape(prefill.get(field, default))

        selected_mode = prefill.get("mode", "dry_run")
        # Mode radios.
        mode_html = "".join(
            "<label class='radio'>"
            f"<input type='radio' name='mode' value='{token}'"
            + (" checked" if token == selected_mode else "") + ">"
            f"<span><strong>{html.escape(token.replace('_', ' '))}</strong> "
            f"<span class='fieldhint'>{html.escape(desc)}</span></span></label>"
            for token, _flag, desc in _BUILD_MODES
        )
        mode_html += (
            "<label class='check'><input type='checkbox' name='canary_dry'"
            + (" checked" if prefill.get("canary_dry") == "on" else "") + ">"
            "<span><strong>dry (synthetic) canary</strong> "
            "<span class='fieldhint'>with diagnostic canary: run the typed "
            "synthetic canary offline (MockTarget, --corpora synth, no "
            "spend)</span></span></label>"
        ) + err("mode")
        # Modality chips select arms by membership: an arm belongs to every
        # modality it carries, so a text+image arm answers to both chips.
        registry_arms = set(self._registry_keys(
            "source-instances.json", "rig/source-instances.example.json"
        ))

        def _mod_tags(mods: tuple[str, ...]) -> str:
            return "".join(
                f"<span class='modtag'>{html.escape(m)}</span>" for m in mods
            )

        # Group arms by their full modality signature for a readable layout,
        # ordered text-only first then the multimodal signatures.
        signatures: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
        for arm, mods in _ARM_MODALITIES:
            signatures.setdefault(" + ".join(mods), []).append((arm, mods))
        arm_groups = []
        for signature in sorted(signatures, key=lambda s: (len(s), s)):
            boxes = []
            for arm, mods in signatures[signature]:
                known = arm in registry_arms
                note = ("" if known else
                        " <span class='fieldhint'>(not in registry yet)</span>")
                boxes.append(
                    "<label class='check'>"
                    f"<input type='checkbox' class='armbox' "
                    f"data-mods='{html.escape(','.join(mods))}' "
                    f"data-arm='{html.escape(arm)}'>"
                    f"<span>{html.escape(arm)} {_mod_tags(mods)}{note}</span>"
                    "</label>"
                )
            arm_groups.append(
                "<div class='modgroup'><div class='grouphead'>"
                f"<h3>{html.escape(signature)}</h3>"
                "<span class='groupsel'>"
                "<button type='button' class='linkbtn' data-sel='all'>All"
                "</button><button type='button' class='linkbtn' "
                "data-sel='none'>None</button></span></div>"
                "<div class='checkgrid'>" + "".join(boxes) + "</div></div>"
            )
        # Target checkboxes carry supported modalities (so an out-of-scope
        # target is hidden) and a kind (hosted API vs on-rig local vLLM).
        def _target_box(value: str, label: str, mods: tuple[str, ...], kind: str) -> str:
            return (
                "<label class='check modelrow' "
                f"data-mods='{html.escape(','.join(mods))}' "
                f"data-kind='{html.escape(kind)}'>"
                f"<input type='checkbox' class='modelbox' "
                f"data-kind='{html.escape(kind)}' "
                f"data-model='{html.escape(value)}'>"
                f"<span>{html.escape(label)} "
                + "".join(f"<span class='modtag'>{html.escape(m)}</span>"
                          for m in mods)
                + "</span></label>"
            )

        options = self._model_options()
        api_boxes = "".join(
            _target_box(v, lbl, mods, kind)
            for v, lbl, mods, kind in options if kind == "api"
        )
        local_boxes = "".join(
            _target_box(v, lbl, mods, kind)
            for v, lbl, mods, kind in options if kind == "local"
        )
        model_boxes = (
            "<h3>Hosted API</h3><div class='checkgrid'>"
            + (api_boxes or "<p class='note'>No hosted targets configured.</p>")
            + "</div><h3>Local vLLM (on-rig GPUs)</h3><div class='checkgrid'>"
            + (local_boxes or "<p class='note'>No local targets configured.</p>")
            + "</div>"
            + "<p class='note'>Hosted rosters are edited on the "
            "<a href='/config?file=api-targets'>api-targets</a> and "
            "<a href='/config?file=local-targets'>local-targets</a> Config "
            "pages. Local vLLM targets also include the vLLM roster ("
            + (f"synced to vLLM {html.escape(str(self._vllm_roster_version()))}"
               if self._vllm_roster_version()
               else "curated default - run <code>local_targets --refresh</code> "
                    "to sync it to the rig's vLLM version")
            + "); vLLM downloads a chosen model on first run. Hosted targets "
            "spend API budget; local vLLM targets use the rig's GPUs "
            "(no API spend).</p>"
        )
        # (local targets are selected as checkboxes above, not free text)
        # Framework checkboxes (carry supported modalities so the wizard can
        # flag ones that cannot drive a chosen modality).
        framework_boxes = "".join(
            "<label class='check fwrow' "
            f"data-mods='{html.escape(','.join(mods))}'>"
            f"<input type='checkbox' class='fwbox' data-fw='{html.escape(fw)}'"
            + (" checked" if fw == "replay" else "") + ">"
            f"<span><strong>{html.escape(fw)}</strong> "
            f"<span class='fieldhint'>{html.escape(desc)}</span>"
            "<span class='fwflag'></span></span></label>"
            for fw, desc, mods in _FRAMEWORKS
        )
        # Judge checkboxes.
        judges_selected = set(self._split_list(prefill.get("judges", "rules")))
        judge_boxes = (
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='rules'"
            + (" checked" if "rules" in judges_selected else "")
            + "><span><strong>rules</strong> "
            "<span class='fieldhint'>deterministic rule scorer (free)</span>"
            "</span></label>"
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='llm'"
            + (" checked" if "llm" in judges_selected else "")
            + "><span><strong>llm</strong> "
            "<span class='fieldhint'>hosted Haiku judge (metered per response)"
            "</span></span></label>"
        )
        defense_selected = prefill.get("defense", "none")
        defense_opts = "".join(
            f"<option value='{d}'"
            + (" selected" if d == defense_selected else "")
            + f">{d}</option>"
            for d in ("none", "input", "output", "both")
        )
        guard_selected = prefill.get("defense_guard", "rules")
        guard_opts = "".join(
            f"<option value='{d}'"
            + (" selected" if d == guard_selected else "")
            + f">{d}</option>"
            for d in ("rules", "guardrail")
        )
        dtype_selected = prefill.get("dtype", "")
        dtype_opts = "".join(
            f"<option value='{d}'"
            + (" selected" if d == dtype_selected else "")
            + f">{d or '(default: auto)'}</option>"
            for d in ("", "auto", "bfloat16", "float16")
        )

        def text_field(
            field: str, label: str, hint: str, *, default: str = "",
            kind: str = "text", placeholder: str = "",
        ) -> str:
            current = prefill.get(field, default)
            attrs = f" value='{html.escape(current)}'" if current else ""
            ph = f" placeholder='{html.escape(placeholder)}'" if placeholder else ""
            step = " step='any'" if kind == "number" else ""
            return (
                f"<div><label class='fieldlabel'>{html.escape(label)} "
                f"<span class='fieldhint'>{html.escape(hint)}</span></label>"
                f"<input class='wide' type='{kind}'{step} "
                f"name='{html.escape(field)}'{attrs}{ph}>{err(field)}</div>"
            )

        # Repeatable live-attestation receipt/digest rows.
        att_rows_html = []
        prefilled_rows = [
            index for index in range(1, self._MAX_ATT_ROWS + 1)
            if prefill.get(f"att_path{index}") or prefill.get(f"att_sha{index}")
        ]
        visible_rows = max(prefilled_rows or [1])
        for index in range(1, visible_rows + 1):
            att_rows_html.append(
                f"<div class='attrow' data-row='{index}'>"
                f"<input class='wide' type='text' name='att_path{index}' "
                f"placeholder='runs/thesis/attest/receipt.live-attestation.json'"
                f" value='{val(f'att_path{index}')}'>"
                f"<input class='wide' type='text' name='att_sha{index}' "
                f"placeholder='exact 64-hex sha256'"
                f" value='{val(f'att_sha{index}')}'></div>"
            )
        env_project = os.environ.get("URA_PROJECT_REVISION_MANIFEST", "")
        env_project_sha = os.environ.get("URA_PROJECT_REVISION_SHA256", "")
        env_source = os.environ.get("URA_SOURCE_CONFORMANCE_MANIFEST", "")
        env_source_sha = os.environ.get("URA_SOURCE_CONFORMANCE_SHA256", "")
        error_summary = ""
        if errors:
            items = "".join(
                f"<li><strong>{html.escape(field)}</strong>: "
                f"{html.escape(message)}</li>"
                for field, message in sorted(errors.items())
            )
            error_summary = (
                "<div class='notice red'><strong>The lane was not started."
                f"</strong><ul>{items}</ul><p class='note'>Each problem is "
                "also flagged next to its control below. Nothing was "
                "composed or executed.</p></div>"
            )
        body = (
            "<h1>" + _icon("flask", size=22) + "Campaign builder</h1>"
            "<p class='note'>Compose a lane by choosing modalities, target "
            "models, and attack frameworks. On build it opens as a "
            "<code>run_matrix</code> job through the same typed, validated "
            "path - nothing here bypasses the allowlist. Paid modes show the "
            "exact command and its call ceilings for confirmation before "
            "anything starts.</p>"
            + error_summary +
            "<form method='post' action='/build' id='builder'>"
            # hidden composed fields
            "<input type='hidden' name='corpora'><input type='hidden' name='api'>"
            "<input type='hidden' name='local'>"
            "<input type='hidden' name='attackers'>"
            "<input type='hidden' name='judges'>"
            "<div class='card'><h2>" + _icon("play") + "Mode</h2>"
            "<div class='radios'>" + mode_html + "</div></div>"
            "<div class='card'><h2>" + _icon("grid") + "Modality scope</h2>"
            "<p class='note'>The campaign's modalities - all enabled for a "
            "fresh build. Turn one off to hide the arms, target models, and "
            "frameworks that need it.</p>"
            "<div class='modscope'>" + "".join(
                "<label class='modtoggle'><input type='checkbox' class='modbox' "
                f"data-mod='{m}' checked><span>{html.escape(m)}</span></label>"
                for m in _MODALITIES
            ) + "</div></div>"
            "<div class='card'><h2>" + _icon("box") + "Arms &amp; corpora</h2>"
            "<p class='note'>Arms in the current modality scope. Each shows its "
            "modality tags; use All / None per group for bulk selection.</p>"
            + err("corpora") + "".join(arm_groups) + "</div>"
            "<div class='card'><h2>" + _icon("coins") + "Target models</h2>"
            + err("models") + model_boxes + "</div>"
            "<div class='card'><h2>" + _icon("pulse") + "Attack frameworks</h2>"
            + err("attackers") +
            "<div class='checkgrid'>" + framework_boxes + "</div></div>"
            "<div class='card'><h2>" + _icon("receipt") + "Judges &amp; defense"
            "</h2>" + err("judges") + "<div class='checkgrid'>" + judge_boxes
            + "</div><div class='cols'>"
            + text_field("judge_model", "--judge-model",
                         "target id for the LLM judge (default: the Haiku "
                         "campaign judge)",
                         placeholder="anthropic:claude-haiku-4-5-20251001")
            + "<div><label class='fieldlabel'>--defense</label>"
            f"<select name='defense'>{defense_opts}</select>{err('defense')}"
            "</div>"
            "<div><label class='fieldlabel'>--defense-guard "
            "<span class='fieldhint'>guard used when a defense is on</span>"
            f"</label><select name='defense_guard'>{guard_opts}</select></div>"
            "</div></div>"
            "<div class='card'><h2>" + _icon("receipt")
            + "Receipts (fail-closed admission)</h2>"
            "<p class='note'>Every non-dry run requires the validated "
            "project-revision receipt; every real source arm requires the "
            "validated source-conformance receipt. Prefilled from the "
            "exported campaign environment when present.</p><div class='cols'>"
            + text_field("project_revision", "--project-revision",
                         "ura-project-revision/1 receipt path",
                         default=env_project)
            + text_field("project_revision_sha", "--project-revision-sha256",
                         "exact byte digest", default=env_project_sha)
            + text_field("source_conformance", "--source-conformance",
                         "ura-source-conformance/1 receipt path",
                         default=env_source)
            + text_field("source_conformance_sha",
                         "--source-conformance-sha256",
                         "exact byte digest", default=env_source_sha)
            + "</div></div>"
            "<div class='card'><h2>" + _icon("logo")
            + "Execution scope &amp; live attestation</h2>"
            "<p class='note'>Probes create attestations; live canaries and "
            "measured lanes consume them (repeatable receipt/digest rows, "
            "paired in order).</p><div class='cols'>"
            + text_field("scope", "--execution-scope-id",
                         "non-secret account/runtime scope label")
            + text_field("max_age", "--live-attestation-max-age-hours",
                         "maximum receipt age in (0, 8760]", kind="number")
            + "</div><label class='fieldlabel'>Live-attestation receipt / "
            "digest pairs</label>" + err("att")
            + "<div id='attrows'>" + "".join(att_rows_html) + "</div>"
            "<button type='button' class='ghost' id='addatt'>"
            "Add receipt row</button></div>"
            "<div class='card'><h2>" + _icon("sliders")
            + "Sampling &amp; turns</h2><div class='cols'>"
            + text_field("limit", "--limit",
                         "cluster subsample; required on paid hosted lanes; "
                         "probes need 1-2, canaries exactly 1", kind="number")
            + text_field("sample_seed", "--sample-seed",
                         "fix and record for a reproducible subset",
                         default="0", kind="number")
            + text_field("seeds", "--seeds",
                         "comma list of trajectory seeds", default="0")
            + text_field("max_queries", "--max-queries",
                         "max target calls per datapoint and seed",
                         kind="number")
            + text_field("max_turns", "--max-turns",
                         "max conversation turns per datapoint and seed",
                         kind="number")
            + "</div></div>"
            "<div class='card'><h2>" + _icon("coins")
            + "Call ceilings &amp; deadline (budget guards)</h2>"
            "<p class='note'>Required finite positive ceilings on every "
            "non-dry run; run_matrix refuses a lane they cannot cover.</p>"
            "<div class='cols'>"
            + text_field("cap_target", "--max-total-target-calls",
                         "hard cap on target calls", kind="number")
            + text_field("cap_judge", "--max-total-judge-calls",
                         "hard cap on hosted judge calls", kind="number")
            + text_field("cap_http", "--max-total-http-attempts",
                         "hard cap on transport attempts", kind="number")
            + text_field("deadline", "--deadline-seconds",
                         "wall-clock deadline for the lane", kind="number")
            + "</div></div>"
            "<div class='card'><h2>" + _icon("disk")
            + "Local serving (vLLM)</h2><div class='cols'>"
            "<div><label class='fieldlabel'>--dtype</label>"
            f"<select name='dtype'>{dtype_opts}</select></div>"
            + text_field("quantization", "--quantization",
                         "awq, gptq, fp8; empty auto-detects",
                         placeholder="(auto-detect)")
            + "</div></div>"
            "<div class='card'><h2>" + _icon("folder") + "Output</h2>"
            "<div class='cols'>"
            + text_field("out", "--out", "output directory under the rig "
                         "results root", default="runs/thesis/lane")
            + "</div></div>"
            "<div class='buildbar'><button type='submit'>" + _icon("play", size=15)
            + "Compose &amp; review</button>"
            "<span id='buildpreview' class='note'></span></div>"
            "</form>"
            "<script type='application/json' id='builder-prefill'>"
            + json.dumps({
                "corpora": self._split_list(prefill.get("corpora", "")),
                "api": self._split_list(prefill.get("api", "")),
                "local": self._split_list(prefill.get("local", "")),
                "attackers": self._split_list(
                    prefill.get("attackers", "replay")
                ),
            }).replace("</", "<\\/")
            + "</script>"
            + _BUILDER_SCRIPT
        )
        return _page("Campaign builder", body, active="Build")

    def _budgets(self) -> list[tuple[str, str, str, str]]:
        """(name, prepaid, match-prefix, funds) rows from the editable
        budgets config, falling back to the recorded ledger defaults."""

        document = self._load_registry(
            "budgets.json", "rig/budgets.example.json"
        )
        providers = document.get("providers")
        rows: list[tuple[str, str, str, str]] = []
        if isinstance(providers, list):
            for entry in providers:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "")).strip()
                if not name:
                    continue
                rows.append((
                    name,
                    str(entry.get("prepaid", "")).strip() or "-",
                    str(entry.get("match", name.split()[0].lower())).lower(),
                    str(entry.get("funds", "")).strip(),
                ))
        if rows:
            return rows
        return [
            (name, amount, name.split()[0].lower(), role)
            for name, amount, role in _PROVIDER_BUDGETS
        ]

    def _budget_card(self) -> str:
        rows = "".join(
            f"<tr><td>{html.escape(name)}</td>"
            f"<td><strong>{html.escape(amount)}</strong></td>"
            f"<td>{html.escape(role)}</td></tr>"
            for name, amount, _match, role in self._budgets()
        )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Provider budgets</h2>"
            "<div class='scroll'><table><tr><th>Provider</th><th>Prepaid</th>"
            "<th>Funds</th></tr>" + rows + "</table></div>"
            "<p class='note'>Prepaid budgets from the editable "
            "<a href='/config?file=budgets'>budgets</a> config (defaults "
            "recorded in ledger 11.22). The Anthropic balance is the "
            "constraint because the Haiku judge is metered on every judged "
            "response, local lanes included. Exact per-lane "
            "<code>--limit</code> and call caps are set from the "
            "diagnostic-canary cost projections and posted here before any "
            "measured lane. This card spends nothing.</p></div>"
        )

    @staticmethod
    def _pricing_fetch_banner(fetched: str) -> str:
        """Render the outcome of a provider-pricing fetch (escaped)."""

        try:
            summary = json.loads(fetched)
        except ValueError:
            return ""
        if not isinstance(summary, dict) or not summary:
            return ""
        if summary.get("error"):
            return ("<div class='notice red'><strong>Pricing fetch failed."
                    "</strong><p class='note'>"
                    + html.escape(str(summary["error"])) + "</p></div>")
        lines = []
        for provider, report in sorted(
            (summary.get("providers") or {}).items()
        ):
            report = report if isinstance(report, dict) else {}
            matched = report.get("matched") or []
            unmatched = report.get("unmatched") or []
            note = report.get("note") or ""
            if matched:
                lines.append(
                    f"<li><strong>{html.escape(provider)}</strong>: "
                    f"{len(matched)} rate(s) read from "
                    f"<code>{html.escape(str(report.get('url', '')))}</code></li>"
                )
            elif note:
                lines.append(
                    f"<li><strong>{html.escape(provider)}</strong>: "
                    f"{html.escape(str(note))}</li>"
                )
            elif unmatched:
                # Attempted (has url + extractor + models) but the page matched
                # no model rows: say so, so the operator is not left assuming the
                # provider's prices are current when they stay N/A.
                lines.append(
                    f"<li><strong>{html.escape(provider)}</strong>: fetched "
                    f"but matched 0 of {len(unmatched)} model(s) - the page "
                    "layout may have changed; enter these rates by hand</li>"
                )
        return (
            "<div class='notice blue'><strong>Fetched provider pricing ("
            + html.escape(str(summary.get("rates_written", 0)))
            + " rate(s) written).</strong><p class='note'>Auto-fetched rates "
            "are stamped with their source and date; verify each against the "
            "provider's page before relying on the calculated cost. A model you "
            "have priced by hand is left untouched, and editing a fetched rate "
            "in the config editor makes it yours too - once you change its "
            "value the fetcher stops overwriting it.</p>"
            "<ul>" + "".join(lines) + "</ul></div>"
        )

    def fetch_pricing(self) -> dict[str, Any]:
        """Fetch published provider prices into the pricing table.

        Delegates to the same experiments.pricing_fetch module the CLI uses;
        never fabricates a rate (unreadable ones stay manual), stamps each
        fetched rate with its source and date, and never supersedes a rate the
        operator has priced by hand (on any date - the operator's figure is
        billed until they edit it directly).
        """

        from experiments import pricing_fetch  # noqa: PLC0415 - optional, on demand

        today = time.strftime("%Y-%m-%d", time.gmtime())
        try:
            # Hold the pricing lock across the whole read-network-write span so a
            # concurrent pricing edit cannot be lost, and two fetches cannot
            # collide on the temp file.
            with self._pricing_lock:
                return pricing_fetch.fetch_pricing(self.repo_root, today=today)
        except Exception as exc:  # noqa: BLE001 - a fetch fault must not 500
            return {"error": str(exc)}

    # -- provider secrets (presence + write-only; values never rendered) ---

    #: The provider API-key environment variables the console may manage.
    #: (env var, provider label, funded).  Values are never displayed; only
    #: presence and a masked last-4 hint are ever surfaced.
    _SECRET_ENV_VARS: tuple[tuple[str, str, bool], ...] = (
        ("ANTHROPIC_API_KEY", "Anthropic (focal Fable + Haiku judge)", True),
        ("OPENAI_API_KEY", "OpenAI (focal Sol)", True),
        ("GEMINI_API_KEY", "Google Gemini", True),
        ("DEEPSEEK_API_KEY", "DeepSeek", True),
        ("MOONSHOT_API_KEY", "Moonshot (Kimi)", True),
        ("DASHSCOPE_API_KEY", "Alibaba DashScope (Qwen) - unfunded", False),
        ("ZHIPU_API_KEY", "Zhipu (GLM) - unfunded/unpayable", False),
    )
    _SECRET_NAMES = frozenset(name for name, _label, _funded in _SECRET_ENV_VARS)

    @staticmethod
    def _mask(value: str) -> str:
        """A last-4 hint for a present secret; never the value itself."""

        value = value.strip()
        if len(value) <= 4:
            return "set"
        return "set - ...." + value[-4:]

    def secret_status(self) -> list[dict[str, Any]]:
        """Presence (and a masked hint) for each managed provider key.

        Reads only os.environ presence; never the file, never the full value.
        """

        rows = []
        for name, label, funded in self._SECRET_ENV_VARS:
            value = os.environ.get(name, "")
            rows.append({
                "name": name, "label": label, "funded": funded,
                "present": bool(value.strip()),
                "hint": self._mask(value) if value.strip() else "not set",
            })
        return rows

    def set_secret(self, name: str, value: str) -> None:
        """Write/replace an allowlisted provider key in the 600-mode env file.

        Fail-closed: only allowlisted names, only a non-empty single-line
        token.  The value is written to the operator secrets file (created
        0600) and mirrored into os.environ so newly launched jobs pick it up;
        it is never echoed to a page, written to the database, backed up to a
        browsable directory, or logged.
        """

        if name not in self._SECRET_NAMES:
            raise ValueError(f"unknown secret {name!r}")
        value = value.strip()
        if not value:
            raise ValueError("secret value must not be empty")
        # Must be a single line by str.splitlines()'s definition, which is what
        # the env file is later read back with.  That set is broader than just
        # \n/\r: it also includes the Unicode line/paragraph separators
        # (U+0085, U+2028, U+2029) a paste from a PDF or rich-text field can
        # carry.  Reject them here so a stored key can never be split apart on
        # the next read-modify-write and corrupt the sourced file.
        if value.splitlines() != [value]:
            raise ValueError("secret value must be a single line")
        if len(value) > 4096:
            raise ValueError("secret value is implausibly long")
        # The value is written inside single quotes into a file that is sourced
        # by the campaign shell.  A single quote would close the quoting and let
        # the remainder run as shell; control characters would corrupt the line.
        # Real provider keys never contain either, so reject them fail-closed
        # rather than attempting to escape them.
        if "'" in value:
            raise ValueError("secret value must not contain a single quote")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
            raise ValueError("secret value must not contain control characters")
        line = f"export {name}='{value}'"
        pattern = re.compile(rf"^\s*export\s+{re.escape(name)}=")
        # Serialize the read-modify-write so a concurrent set/clear cannot drop
        # a key, and surface any filesystem fault as a ValueError the secrets
        # page renders as "Not saved" (never an unhandled 500; the value never
        # appears in the message).
        with self._secret_lock:
            existing = self._read_env_lines()
            replaced = False
            out_lines = []
            for entry in existing:
                if pattern.match(entry):
                    if not replaced:
                        out_lines.append(line)
                        replaced = True
                    # drop any further duplicate definitions
                else:
                    out_lines.append(entry)
            if not replaced:
                out_lines.append(line)
            text = "\n".join(out_lines) + "\n"
            try:
                self._write_env_file(text)
            except OSError as exc:
                raise ValueError(f"could not write the secrets file: {exc}") from exc
            os.environ[name] = value  # live: new jobs inherit it immediately

    def _read_env_lines(self) -> list[str]:
        """Current lines of the secrets file, fail-closed on a non-absent fault.

        An absent file is empty (nothing stored yet).  A present-but-unreadable
        file (permission denial, transient lock) raises rather than silently
        returning [], because rewriting from [] would drop every other stored
        key.
        """

        try:
            return self.env_file.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ValueError(f"could not read the secrets file: {exc}") from exc

    def _write_env_file(self, text: str) -> None:
        """Write the operator secrets file atomically at mode 0600.

        A 0600 temp file (so the key never briefly lands world-readable) is
        written and os.replace()d into place, so a mid-write fault leaves the
        prior file intact rather than a truncated/empty one - the same
        atomic-write discipline the pricing table uses, but with NO backup copy
        (a browsable .bak of a secret would defeat the point).
        """

        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.env_file.with_name(self.env_file.name + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            # newline="\n": the file is sourced by a POSIX shell, so it must use
            # LF endings on every platform.  Without this, a text-mode write on
            # Windows would emit CRLF and the trailing \r would become part of
            # each key value when the campaign shell sources it (a silent 401).
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            os.replace(tmp, self.env_file)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.chmod(self.env_file, 0o600)
        except OSError:
            pass

    def clear_secret(self, name: str) -> None:
        """Remove an allowlisted provider key from the env file and process."""

        if name not in self._SECRET_NAMES:
            raise ValueError(f"unknown secret {name!r}")
        pattern = re.compile(rf"^\s*export\s+{re.escape(name)}=")
        with self._secret_lock:
            # Fail-closed: if the file is present but unreadable, _read_env_lines
            # raises rather than reporting a false success while the key survives
            # on disk (it would return to life on the next source of the file).
            existing = self._read_env_lines()
            out_lines = [entry for entry in existing if not pattern.match(entry)]
            if existing:
                try:
                    self._write_env_file("\n".join(out_lines) + "\n")
                except OSError as exc:
                    raise ValueError(
                        f"could not write the secrets file: {exc}"
                    ) from exc
            os.environ.pop(name, None)

    def _secrets_page(self, *, error: str = "", saved: str = "") -> bytes:
        rows = []
        for row in self.secret_status():
            tone = "green" if row["present"] else ("gray" if not row["funded"] else "amber")
            state = html.escape(row["hint"])
            clear = (
                "<form class='inline' method='post' action='/config/secrets'>"
                f"<input type='hidden' name='name' value='{html.escape(row['name'])}'>"
                "<input type='hidden' name='action' value='clear'>"
                "<button type='submit' class='danger small'>Clear</button></form>"
                if row["present"] else ""
            )
            rows.append(
                "<tr><td><code>" + html.escape(row["name"]) + "</code></td>"
                f"<td>{html.escape(row['label'])}</td>"
                f"<td><span class='badge {tone}'>{state}</span></td>"
                "<td><input class='wide' type='password' autocomplete='off' "
                f"form='setkey-{html.escape(row['name'])}' name='value' "
                "placeholder='paste key to set/rotate'></td>"
                "<td>"
                f"<form id='setkey-{html.escape(row['name'])}' method='post' "
                "action='/config/secrets'>"
                f"<input type='hidden' name='name' value='{html.escape(row['name'])}'>"
                "<input type='hidden' name='action' value='set'>"
                "<button type='submit' class='small'>Save</button></form> "
                + clear + "</td></tr>"
            )
        banner = ""
        if saved:
            banner = ("<div class='notice blue'><strong>Key " + html.escape(saved)
                      + " updated.</strong><p class='note'>Written to the "
                      "operator secrets file and applied to this console's "
                      "environment; new jobs use it immediately. The value is "
                      "never displayed.</p></div>")
        if error:
            banner = ("<div class='notice red'><strong>Not saved: "
                      + html.escape(error) + "</strong></div>")
        body = (
            "<h1>" + _icon("sliders", size=22) + "Provider API keys</h1>"
            "<p class='crumbs'><a href='/config'>Configuration</a>"
            "<span class='sep'>/</span>secrets</p>"
            + banner +
            "<p class='note'>Set or rotate the hosted-provider API keys the "
            "campaign uses. Keys are written to the operator secrets file "
            "(<code>~/.ura_env</code>, mode 600) and applied to this console's "
            "environment. For your safety the console <strong>never displays a "
            "stored key</strong> - only whether it is set and its last four "
            "characters - and never writes a key to the database, a backup, or "
            "a log. Secrets are still yours to manage; nothing here is shared "
            "off this host.</p>"
            "<div class='card scroll'><table><tr><th>Env var</th>"
            "<th>Provider</th><th>Status</th><th>Set / rotate</th><th></th></tr>"
            + "".join(rows) + "</table></div>"
            "<p class='note'>Unfunded providers (DashScope/Qwen, Zhipu/GLM) are "
            "listed for completeness; their lanes record as structural N/A "
            "unless a key is provided. A key set here takes effect for jobs "
            "launched afterwards.</p>"
        )
        return _page("Provider API keys", body, active="Config")

    # -- config editor -----------------------------------------------------

    def _config_target(self, key: str) -> tuple[Path, str]:
        """Resolve an allowlisted config key to its file path and description.

        Only keys in ``_EDITABLE_CONFIGS`` resolve; anything else is rejected,
        so no path outside the allowlist is ever readable or writable here.
        """

        entry = _EDITABLE_CONFIGS.get(key)
        if entry is None:
            raise ValueError(f"unknown config {key!r}")
        relative, _example, description = entry
        return (self.repo_root / relative), description

    def _config_example_text(self, key: str) -> str:
        """The checked-in example content for an allowlisted config, if any."""

        entry = _EDITABLE_CONFIGS.get(key)
        if entry is None:
            return ""
        example = self.repo_root / entry[1]
        try:
            return example.read_text(encoding="utf-8")
        except OSError:
            return ""

    def save_config(self, key: str, content: str) -> Path:
        """Validate JSON and write an allowlisted config, backing up first.

        Fail-closed: rejects unknown keys and any content that is not a JSON
        object, and preserves the prior bytes under the state dir before
        overwriting so a bad edit is always recoverable.
        """

        path, _description = self._config_target(key)
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise ValueError(f"content is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("config must be a JSON object")
        # The pricing table has a second writer (the fetcher); serialize this
        # write with it so an overlapping fetch cannot lose the operator's edit.
        lock = self._pricing_lock if key == "pricing" else contextlib.nullcontext()
        with lock:
            if key == "pricing":
                # If the operator corrected a fetched rate in place, drop its
                # auto-fetch provenance so the fetcher treats it as operator-
                # owned and never reverts it.  Compare under the lock against the
                # current on-disk table.
                try:
                    on_disk = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    on_disk = {}
                if isinstance(on_disk, dict):
                    reconcile_pricing_ownership(parsed, on_disk)
            normalized = json.dumps(
                parsed, ensure_ascii=False, indent=2, sort_keys=True,
            ) + "\n"
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise ValueError("config target is not a regular file")
                backups = self.state_dir / "config-backups"
                backups.mkdir(parents=True, exist_ok=True)
                stamp = time.strftime("%Y%m%d-%H%M%S")
                (backups / f"{path.name}.{stamp}.bak").write_bytes(path.read_bytes())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(normalized, encoding="utf-8")
        return path

    def _config_page(
        self, key: str, saved: str, *, error: str = "", draft: str = "",
        fetched: str = "",
    ) -> bytes:
        # Index of editable files.
        if key not in _EDITABLE_CONFIGS:
            cards = []
            for token, (relative, _example, description) in _EDITABLE_CONFIGS.items():
                path = self.repo_root / relative
                state = "exists" if path.is_file() else "not created yet"
                cards.append(
                    "<div class='card'><h2>" + _icon("sliders")
                    + f"{html.escape(token)}</h2>"
                    f"<p class='note'><code>{html.escape(relative)}</code> - "
                    f"{html.escape(state)}</p>"
                    f"<p>{html.escape(description)}</p>"
                    f"<p><a href='/config?file={quote(token)}'>"
                    "<button type='button'>Open editor</button></a></p></div>"
                )
            # Provider API keys: presence + set/rotate, values never shown.
            statuses = self.secret_status()
            set_count = sum(1 for s in statuses if s["present"])
            cards.append(
                "<div class='card'><h2>" + _icon("logo") + "Provider API keys"
                "</h2><p class='note'>Set or rotate the hosted-provider keys "
                f"(<code>~/.ura_env</code>, mode 600). {set_count} of "
                f"{len(statuses)} set. The console never displays a stored "
                "key.</p><p><a href='/config/secrets'>"
                "<button type='button'>Manage keys</button></a></p></div>"
            )
            body = (
                "<h1>" + _icon("sliders", size=22) + "Configuration</h1>"
                "<p class='note'>Edit the operator-local registries in place. "
                "Saves are JSON-validated and the prior version is backed up "
                "under the console state directory. These files are read fresh "
                "by each run, so an edit takes effect on the next job. Secret "
                "API keys are managed separately (presence only, never "
                "displayed); nothing here shows a stored key.</p>"
                + "".join(cards)
            )
            return _page("Configuration", body, active="Config")
        # Single-file editor.
        path, description = self._config_target(key)
        relative = _EDITABLE_CONFIGS[key][0]
        example_text = self._config_example_text(key)
        seeded = ""
        if draft:
            content = draft
        else:
            try:
                content = path.read_text(encoding="utf-8")
                if not content.strip():
                    raise OSError  # treat an empty file as unseeded
            except OSError:
                # Seed a fresh editor from the checked-in example so the roster
                # is never a blank page.
                content = example_text
                if example_text:
                    seeded = ("<div class='notice blue'><strong>Prefilled from "
                              "the checked-in example.</strong><p class='note'>"
                              "Review and edit, then save to write the local "
                              "registry.</p></div>")
        banner = seeded
        if saved:
            banner = ("<div class='notice blue'><strong>Saved.</strong>"
                      "<p class='note'>Prior version backed up under the "
                      "console state directory.</p></div>")
        if error:
            banner = ("<div class='notice red'><strong>Not saved: "
                      f"{html.escape(error)}</strong></div>")
        if fetched:
            banner = self._pricing_fetch_banner(fetched) + banner
        # The pricing editor gets a fetch-from-provider-pages action.
        fetch_action = ""
        if key == "pricing":
            fetch_action = (
                "<form class='inline' method='post' action='/pricing/fetch' "
                "data-busy='Fetching provider pricing pages...'>"
                "<button type='submit' class='ghost'>" + _icon("coins", size=15)
                + "Fetch from provider pricing pages</button></form> "
            )
        body = (
            "<h1>" + _icon("sliders", size=22)
            + f"Edit {html.escape(key)}</h1>"
            f"<p class='crumbs'><a href='/config'>Configuration</a>"
            f"<span class='sep'>/</span>{html.escape(relative)}</p>"
            + banner
            + f"<p class='note'>{html.escape(description)}</p>"
            + fetch_action
            + "<form method='post' action='/config'>"
            f"<input type='hidden' name='file' value='{html.escape(key)}'>"
            f"<textarea class='editor' id='cfg-editor' name='content' "
            f"spellcheck='false'>{html.escape(content)}</textarea>"
            + (
                "<textarea id='cfg-example' style='display:none'>"
                f"{html.escape(example_text)}</textarea>"
                if example_text else ""
            )
            + "<div class='editor-actions'>"
            "<button type='submit'>" + _icon("save", size=15)
            + "Validate &amp; save</button>"
            + (
                "<button type='button' class='ghost' id='cfg-prefill'>"
                + _icon("box", size=15) + "Prefill from example</button>"
                if example_text else ""
            )
            + f"<a href='/config?file={quote(key)}'>"
            "<button type='button' class='ghost'>Reload</button></a>"
            "</div></form>"
            "<p class='note'>Save is rejected unless the content parses as a "
            "JSON object; on success it is normalized (sorted keys, 2-space "
            "indent) and the prior bytes are backed up. 'Prefill from example' "
            "loads the checked-in roster into the editor without saving.</p>"
            "<script>(function(){"
            "var btn=document.getElementById('cfg-prefill');"
            "var ex=document.getElementById('cfg-example');"
            "var ed=document.getElementById('cfg-editor');"
            "if(btn&&ex&&ed){btn.addEventListener('click',function(){"
            "if(!ed.value.trim()||confirm('Replace the editor contents with "
            "the example roster?')){ed.value=ex.value;ed.focus();}});}"
            "})();</script>"
        )
        return _page(f"Edit {key}", body, active="Config")

    @staticmethod
    def _playbook_card() -> str:
        steps = (
            ("1", "Author revision receipt", "project_revision",
             {"--expected-revision": "&lt;40-hex pin&gt;",
              "--out": "runs/thesis/project-revision"}),
            ("2", "Preflight (no calls)", "rig_check",
             {"--dry-run": "on", "--api": "$FABLE", "--corpora": "synth"}),
            ("3", "Attestation probe (paid)", "run_matrix",
             {"--attestation-probe": "on", "--api": "$FABLE",
              "--out": "runs/thesis/attest"}),
            ("4", "Diagnostic canary (paid)", "run_matrix",
             {"--diagnostic-canary": "on", "--api": "$FABLE",
              "--corpora": "strongreject_official", "--limit": "8",
              "--sample-seed": "0", "--out": "runs/thesis/canary"}),
            ("5", "Measured lane (paid)", "run_matrix",
             {"--api": "$FABLE,$SOL", "--corpora": "strongreject_official",
              "--attackers": "replay,crescendo", "--judges": "rules,llm",
              "--judge-model": "anthropic:claude-haiku-4-5-20251001",
              "--limit": "&lt;set from canary&gt;", "--sample-seed": "0",
              "--out": "runs/thesis/measured"}),
        )
        rows = []
        for num, title, command, values in steps:
            params = "&".join(
                f"{quote(flag)}={quote(str(val).replace('&lt;', '<').replace('&gt;', '>'))}"
                for flag, val in values.items()
            )
            rows.append(
                "<li><span class='step-n'>" + num + "</span>"
                f"<strong>{html.escape(title)}</strong> "
                f"<code>{html.escape(command)}</code> "
                f"<a href='/commands?cmd={quote(command)}&{params}'>"
                "prefill &rarr;</a></li>"
            )
        return (
            "<div class='card'><h2>" + _icon("book") + "Campaign playbook</h2>"
            "<p class='note'>The runbook sequence in order. 'Prefill' opens the "
            "Run page with that command's form filled - review every value "
            "before starting. Steps 3+ spend real money.</p>"
            "<ol class='playbook'>" + "".join(rows) + "</ol></div>"
        )

    def _db_card(self, reindexed: str) -> str:
        """Database health, schema version, and the one Reindex action."""

        health = self.db.health()
        tone = "green" if health["healthy"] else "red"
        state = "healthy" if health["healthy"] else "UNAVAILABLE"
        counts = health["counts"]
        count_text = (
            ", ".join(
                f"{name}: {value if value is not None else 'unknown'}"
                for name, value in counts.items()
            ) if counts else "counts unknown"
        )
        note = ""
        if reindexed:
            try:
                summary = json.loads(reindexed)
            except ValueError:
                summary = {}
            if isinstance(summary, dict) and summary:
                # Always show the load-bearing counts (even when zero) and
                # escape every key/value - the query string is attacker
                # controlled, so this must never be a raw HTML sink.
                always = ("usage_rows", "markers", "reports", "roots")
                stat_bits = [
                    f"{html.escape(str(name))} "
                    f"{html.escape(str(summary.get(name, 0)))}"
                    for name in always
                ]
                stat_bits += [
                    f"{html.escape(str(key))} {html.escape(str(value))}"
                    for key, value in sorted(summary.items())
                    if key not in {"ok", *always} and value
                ]
                note = (
                    "<div class='notice "
                    + ("blue" if summary.get("ok") else "red")
                    + "'><strong>Reindex "
                    + ("completed" if summary.get("ok") else "FAILED")
                    + ".</strong><p class='note'>Derived usage, cost, and "
                    "report indexes were rebuilt from retained artifacts "
                    "with full digest verification ("
                    + ", ".join(stat_bits)
                    + "). Skip counts are reported, never silent.</p></div>"
                )
        error = (
            f"<p class='note'>Last error: <code>"
            f"{html.escape(health['last_error'])}</code></p>"
            if health["last_error"] else ""
        )
        return (
            "<div class='card'><h2>" + _icon("disk") + "Console database</h2>"
            + note +
            f"<p><span class='badge {tone}'>{state}</span> "
            f"schema v{health['schema_version']} - {html.escape(count_text)}"
            "</p>" + error +
            "<form method='post' action='/db/reindex' "
            "data-busy='Rebuilding the index from retained artifacts...'>"
            "<button type='submit' class='small'>Reindex from artifacts"
            "</button></form>"
            "<p class='note'>Operational state only (jobs, runs, recorded "
            "usage, report index) under the console state directory; the "
            "validated artifacts remain the scientific authority. Reindex "
            "rebuilds every derived row from the retained artifacts.</p>"
            "</div>"
        )

    def _overview(self, reindexed: str = "") -> bytes:
        self._reconcile()
        jobs = list(self.jobs.values())
        running = [job for job in jobs if job.state() == "running"]
        failed = [job for job in jobs if job.state() == "failed"]
        counts, truncated = artifact_inventory(self.results_root)
        disk_html = "<p class='note'>disk usage unavailable</p>"
        try:
            usage = shutil.disk_usage(self.results_root)
        except OSError:
            usage = None
        if usage is not None and usage.total > 0:
            used_pct = 100.0 * (usage.total - usage.free) / usage.total
            disk_html = (
                f"<div class='stat'><span class='value'>"
                f"{_human_size(usage.free)}</span>"
                "<span class='label'>free on results volume</span></div>"
                f"<div class='meter'><div style='width:{used_pct:.1f}%'>"
                "</div></div>"
                f"<p class='note'>{used_pct:.0f}% used of "
                f"{_human_size(usage.total)}</p>"
            )
        pin = os.environ.get("REF_URA", "")
        cost_rows, _cost_unavailable = self._usage_cost_rows()
        if cost_rows is None:
            spend_value, spend_label = "unknown", "calculated spend (db unavailable)"
        else:
            billable = [r for r in cost_rows if r["billable"]]
            if any(r["cost"] is None for r in billable):
                spend_value = "N/A"
                spend_label = "calculated spend (price/tokens missing)"
            else:
                spend_value = self._fmt_money(
                    sum(r["cost"] for r in billable), "USD"
                )
                spend_label = "calculated spend (recorded usage x pricing)"
        stats = (
            "<div class='cols'>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{len(jobs)}</span>"
            "<span class='label'>jobs (persisted)</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot blue'></span>"
            f"{len(running)}</span>"
            "<span class='label'>running now</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot red'></span>"
            f"{len(failed)}</span>"
            "<span class='label'>failed</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><code>{html.escape(pin[:10] or 'unpinned')}"
            "</code></span>"
            "<span class='label'>project revision (REF_URA)</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{spend_value}</span>"
            f"<span class='label'>{html.escape(spend_label)}</span></div></div>"
            f"<div class='card'>{disk_html}</div>"
            "</div>"
        )
        running_rows = "".join(
            f"<tr><td><a href='/jobs/{html.escape(job.job_id)}'>"
            f"{html.escape(job.job_id)}</a></td>"
            f"<td>{html.escape(job.command)}</td>"
            f"<td>{job.runtime_seconds():,.0f}s</td></tr>"
            for job in sorted(running, key=lambda item: item.started_at)
        )
        running_html = (
            "<div class='card'><h2>" + _icon("pulse") + "Running jobs</h2>"
            "<div class='scroll'><table><tr><th>Job</th><th>Command</th>"
            "<th>Runtime</th></tr>" + running_rows + "</table></div></div>"
            if running_rows else ""
        )
        stage_sections = []
        for label, _suffixes in _PIPELINE_STAGES:
            stage = counts.get(label)
            if stage is None or not stage.paths:
                continue
            items = "".join(
                f"<li><a href='/artifacts?path={quote(path)}'>"
                f"{html.escape(path)}</a></li>"
                for path in stage.paths
            )
            total = stage.count + stage.superseded
            if total > len(stage.paths):
                items += (
                    f"<li class='note'>first {len(stage.paths)} of {total} "
                    "shown</li>"
                )
            summary = f"{html.escape(label)}: {stage.count} current"
            if stage.superseded:
                summary += f", {stage.superseded} archived"
            stage_sections.append(
                f"<details class='stagefiles'><summary>{summary}</summary>"
                f"<ul>{items}</ul></details>"
            )
        stage_files = "".join(stage_sections)
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 10000);"
            "</script>" if running else ""
        )
        body = (
            "<h1>" + _icon("grid", size=22) + "Dashboard</h1>"
            + self._health_banner()
            + self._warnings_html()
            + stats
            + self._db_card(reindexed)
            + "<div class='card'><h2>" + _icon("chart") + "Campaign pipeline"
            "</h2>" + _pipeline_svg(counts) +
            "<p class='note'>Click a stage to browse its files. Counts are "
            "retained-file presence under the results root only; presence "
            "never asserts validity, authorization, or measurement status. "
            "“archived” counts files under a "
            "<code>superseded/</code> directory (kept as history, not "
            "current - for example an earlier pin's revision receipt)."
            + (" Inventory scan truncated at its entry cap; counts are a "
               "lower bound." if truncated else "")
            + "</p>" + stage_files + "</div>"
            + self._next_hint(counts)
            + self._playbook_card()
            + running_html
            + self._budget_card()
            + self._policy_card() +
            "<div class='card'><h2>" + _icon("file") + "Campaign bindings"
            "</h2>" + self._campaign_context() + "</div>"
            "<div class='card'><h2>" + _icon("logo") + "Boundaries</h2>"
            "<p class='note'>Allowlisted commands only; no arbitrary shell. "
            "Dry-run/canary/probe artifacts stay diagnostic; measured "
            "claims come only from validated artifacts and the maintained "
            "analysis CLIs.</p></div>"
            + refresh
        )
        return _page("URA rig console", body, active="Dashboard")

    def _param_input(self, param: CommandParam) -> str:
        flag = html.escape(param.flag)
        if param.kind == "flag":
            return f"<input type='checkbox' name='{flag}'>"
        if param.choices:
            options = "".join(
                f"<option value='{html.escape(choice)}'>"
                f"{html.escape(choice)}</option>"
                for choice in param.choices
            )
            return (
                f"<select name='{flag}'>"
                "<option value=''>(default)</option>" + options + "</select>"
            )
        if param.kind == "int":
            return f"<input type='number' step='1' name='{flag}'>"
        if param.kind == "float":
            return f"<input type='number' step='any' name='{flag}'>"
        listattr = (
            f" list='dl-{html.escape(param.suggest)}'" if param.suggest else ""
        )
        return f"<input type='text' name='{flag}'{listattr}>"

    def _command_card(self, name: str) -> str:
        entry = self.commands[name]
        fields = []
        for param in entry.params:
            required = (
                "<span class='req' title='required'>*</span>"
                if param.required else ""
            )
            help_text = param.help or _PARAM_HELP.get(param.flag, "")
            title = f" title='{html.escape(help_text)}'" if help_text else ""
            hint = (
                f"<span class='fieldhint'>{html.escape(help_text)}</span>"
                if help_text else ""
            )
            fields.append(
                f"<label{title}>{html.escape(param.flag)}{required} "
                f"<span class='kind'>{html.escape(param.kind)}</span>"
                "</label>"
                f"<div class='fieldwrap'>{self._param_input(param)}{hint}</div>"
            )
        haystack = html.escape(f"{name} {entry.description}".lower())
        return (
            f"<details class='cmd' data-name='{haystack}'><summary>"
            + _icon("terminal")
            + f"<span class='name'>{html.escape(name)}</span>"
            f"<span class='desc'>{html.escape(entry.description)}</span>"
            "</summary><div class='inner'>"
            f"<p class='note'><code>python -m {html.escape(entry.module)}"
            "</code></p>"
            "<form class='cmd' method='post' action='/jobs'>"
            f"<input type='hidden' name='command' value='{html.escape(name)}'>"
            + "".join(fields)
            + "<span></span><button type='submit'>"
            + _icon("play", size=15) + "Start job</button>"
            "</form></div></details>"
        )

    def _registry_keys(self, name: str, example: str) -> list[str]:
        """Keys of an operator-local registry, falling back to the example.

        Presentation-only suggestions: the local file is authoritative for
        runs; the checked-in example keeps the console useful before the
        operator copies it. Malformed files yield no suggestions.
        """

        for candidate in (name, example):
            path = self.repo_root / "experiments" / candidate
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                return sorted(data)
        return []

    def _datalists(self) -> str:
        lists = dict(_SUGGEST_STATIC)
        lists["arms"] = tuple(
            ["synth"] + self._registry_keys(
                "source-instances.json", "rig/source-instances.example.json"
            )
        )
        lists["api"] = tuple(
            ["mock"] + self._registry_keys(
                "api-targets.json", "rig/api-targets.example.json"
            )
        )
        return "".join(
            f"<datalist id='dl-{html.escape(key)}'>"
            + "".join(
                f"<option value='{html.escape(value)}'></option>"
                for value in values
            )
            + "</datalist>"
            for key, values in lists.items()
        )

    def _commands_page(self) -> bytes:
        grouped: set[str] = set()
        sections = []
        for title, icon, ref, names in COMMAND_GROUPS:
            cards = "".join(
                self._command_card(name)
                for name in names if name in self.commands
            )
            if not cards:
                continue
            grouped.update(names)
            sections.append(
                f"<div class='group-head'>{_icon(icon, size=20)}"
                f"<h2>{html.escape(title)}</h2>"
                f"<span class='ref'>{html.escape(ref)}</span></div>"
                + cards
            )
        leftovers = "".join(
            self._command_card(name)
            for name in sorted(set(self.commands) - grouped)
        )
        if leftovers:
            sections.append(
                f"<div class='group-head'>{_icon('file', size=20)}"
                "<h2>Other</h2></div>" + leftovers
            )
        body = (
            "<h1>" + _icon("terminal", size=22) + "Run a command</h1>"
            "<p class='note'>Typed forms over the allowlisted experiment "
            "CLIs; the argument vector shown on each job page is exactly "
            "what runs. Fields map one-to-one to documented CLI flags; "
            "<span class='req'>*</span> marks a required field.</p>"
            "<p><input id='cmdfilter' type='text' "
            "placeholder='Type to filter commands...' "
            "aria-label='filter commands'></p>"
            + self._datalists()
            + "".join(sections)
            + "<script>(function(){"
            "var box=document.getElementById('cmdfilter');"
            "if(box){box.addEventListener('input',function(){"
            "var q=this.value.toLowerCase();"
            "document.querySelectorAll('details.cmd').forEach(function(d){"
            "var hay=d.getAttribute('data-name')||'';"
            "d.style.display=hay.indexOf(q)>=0?'':'none';});});}"
            # Playbook prefill: ?cmd=<name>&--flag=value opens and fills the
            # matching command form. Values still go through the typed form and
            # build_argv validation on submit; nothing is auto-run.
            "var params=new URLSearchParams(window.location.search);"
            "var cmd=params.get('cmd');"
            "if(cmd){var card=document.querySelector("
            "\"details.cmd input[name=command][value='\"+cmd+\"']\");"
            "if(card){var det=card.closest('details.cmd');det.open=true;"
            "params.forEach(function(val,key){"
            "if(key==='cmd'){return;}"
            "var field=det.querySelector(\"[name='\"+key+\"']\");"
            "if(!field){return;}"
            "if(field.type==='checkbox'){field.checked="
            "(val==='on'||val==='true'||val==='1'||val==='yes');}"
            "else{field.value=val;}});"
            "det.scrollIntoView({behavior:'smooth',block:'center'});}}"
            "})();</script>"
        )
        return _page("Run a command", body, active="Run")

    def _jobs_page(self) -> bytes:
        self._reconcile()
        rows = []
        tallies: dict[str, int] = {"running": 0, "complete": 0, "failed": 0}
        for job_id in sorted(self.jobs, reverse=True):
            job = self.jobs[job_id]
            state = job.state()
            tallies[state] = tallies.get(state, 0) + 1
            tone = {"running": "blue", "complete": "green", "failed": "red",
                    "orphaned": "amber"}.get(state, "gray")
            started = time.strftime(
                "%H:%M:%S", time.localtime(job.started_at)
            )
            stop = (
                "<form class='inline' method='post' "
                f"action='/jobs/{html.escape(job_id)}/stop'>"
                "<button class='danger small' type='submit'>Stop</button>"
                "</form>" if state == "running" else ""
            )
            hay = html.escape(f"{job_id} {job.command}".lower())
            rows.append(
                f"<tr data-state='{html.escape(state)}' data-hay='{hay}'>"
                f"<td><a href='/jobs/{html.escape(job_id)}'>"
                f"{html.escape(job_id)}</a></td>"
                f"<td>{html.escape(job.command)}</td>"
                f"<td><span class='dot {tone}'></span>"
                f"<span class='badge {tone}'>{html.escape(state)}</span></td>"
                f"<td>{started}</td>"
                f"<td>{_human_duration(job.runtime_seconds())}</td>"
                f"<td>{'' if job.exit_code() is None else job.exit_code()}"
                f"</td><td>{stop}</td></tr>"
            )
        chips = (
            "<div class='chips'>"
            f"<button type='button' class='chip on' data-state=''>All "
            f"({len(self.jobs)})</button>"
            + "".join(
                f"<button type='button' class='chip' data-state='{state}'>"
                f"{state.capitalize()} ({count})</button>"
                for state, count in tallies.items()
            )
            + "</div>"
        )
        controls = (
            chips +
            "<p><input id='jobfilter' type='text' "
            "placeholder='Type to filter jobs...' "
            "aria-label='filter jobs'></p>"
        )
        table = (
            "<div class='card scroll'><table id='jobstable'>"
            "<tr><th>Job</th><th>Command</th>"
            "<th>State</th><th>Started</th><th>Runtime</th><th>Exit</th>"
            "<th></th></tr>"
            + "".join(rows) + "</table></div>"
            if rows else
            "<div class='card'><p class='note'>No jobs this session. Start "
            "one from the <a href='/commands'>Run</a> page.</p></div>"
        )
        script = (
            "<script>(function(){"
            "var state='';var box=document.getElementById('jobfilter');"
            "function apply(){var q=box?box.value.toLowerCase():'';"
            "document.querySelectorAll('#jobstable tr[data-state]')"
            ".forEach(function(r){"
            "var okState=!state||r.getAttribute('data-state')===state;"
            "var okText=(r.getAttribute('data-hay')||'').indexOf(q)>=0;"
            "r.style.display=okState&&okText?'':'none';});}"
            "document.querySelectorAll('.chip').forEach(function(c){"
            "c.addEventListener('click',function(){"
            "state=this.getAttribute('data-state')||'';"
            "document.querySelectorAll('.chip').forEach(function(o){"
            "o.classList.remove('on');});this.classList.add('on');"
            "apply();});});"
            "if(box){box.addEventListener('input',apply);}"
            "})();</script>"
            if rows else ""
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 5000);"
            "</script>" if tallies["running"] else ""
        )
        return _page(
            "Jobs",
            "<h1>" + _icon("pulse", size=22) + "Jobs</h1>"
            + self._health_banner()
            + controls + table + script + refresh,
            active="Jobs",
        )

    def _job_page(self, job: Job) -> bytes:
        state = job.state()
        tone = {"running": "blue", "complete": "green", "failed": "red"}.get(
            state, "gray"
        )
        stdout_tail = self._log_tail(job, "stdout") or "(empty)"
        stderr_tail = self._log_tail(job, "stderr") or "(empty)"
        stop_form = (
            f"<form method='post' action='/jobs/{html.escape(job.job_id)}/stop'>"
            "<button class='danger' type='submit'>Stop job</button></form>"
            if state == "running" else ""
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 2000);</script>"
            if state == "running" else ""
        )
        failure = (
            "<div class='card'><h2>" + _icon("pulse") + "Failure</h2>"
            "<p>The command exited with "
            f"code {job.exit_code()}. Standard error is shown below; the "
            "underlying CLI message is authoritative.</p>"
            + (f"<pre>{html.escape(job.failure)}</pre>" if job.failure else "")
            + "</div>"
            if state == "failed" else ""
        )
        builder = ""
        if job.builder_params:
            rows = "".join(
                f"<tr><td>{html.escape(key)}</td>"
                f"<td><code>{html.escape(value)}</code></td></tr>"
                for key, value in sorted(job.builder_params.items())
            )
            builder = (
                "<div class='card'><h2>" + _icon("flask")
                + "Builder parameters</h2><div class='scroll'><table>"
                + rows + "</table></div><p class='note'>The raw campaign-"
                "builder selections this job was composed from (persisted "
                "with the job).</p></div>"
            )
        argv_chips = "<div class='argv'>" + "".join(
            f"<code>{html.escape(part)}</code>" for part in job.argv
        ) + "</div>"
        started = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(job.started_at)
        )
        exit_code = job.exit_code()
        meta = (
            "<div class='cols'>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot {tone}'></span>"
            f"{html.escape(state)}</span>"
            "<span class='label'>state</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{job.runtime_seconds():,.0f}s</span>"
            "<span class='label'>runtime</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{started}</span>"
            "<span class='label'>started</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{'-' if exit_code is None else exit_code}"
            "</span><span class='label'>exit code</span></div></div>"
            "</div>"
        )
        body = (
            f"<h1>{_icon('terminal', size=22)}Job {html.escape(job.job_id)}"
            "</h1>"
            + meta +
            "<div class='card'><h2>" + _icon("file") + "Command</h2>"
            + argv_chips + stop_form + "</div>"
            + builder
            + failure +
            "<div class='card'><h2>" + _icon("chart") + "stdout</h2>"
            f"<pre>{html.escape(stdout_tail)}</pre></div>"
            "<div class='card'><h2>" + _icon("pulse") + "stderr</h2>"
            f"<pre>{html.escape(stderr_tail)}</pre></div>"
            + refresh
        )
        return _page(f"Job {job.job_id}", body, active="Jobs")

    # -- artifact browsing -------------------------------------------------

    def _artifacts(self, relative: str) -> tuple[int, str, bytes]:
        target = _contained(self.results_root, relative)
        if target.is_dir():
            return 200, "text/html; charset=utf-8", self._directory_page(
                target, relative
            )
        if not target.is_file():
            return 404, "text/plain; charset=utf-8", b"no such artifact"
        return self._file_page(target, relative)

    def _directory_page(self, directory: Path, relative: str) -> bytes:
        entries = sorted(
            directory.iterdir(), key=lambda item: (item.is_file(), item.name)
        )
        rows = []
        for entry in entries:
            child = f"{relative}/{entry.name}".lstrip("/")
            is_dir = entry.is_dir()
            icon = _icon("folder", size=15) if is_dir else _icon("file", size=15)
            size = "" if is_dir else _human_size(entry.stat().st_size)
            rows.append(
                f"<tr><td>{icon}<a href='/artifacts?path={quote(child)}'>"
                f"{html.escape(entry.name)}{'/' if is_dir else ''}</a></td>"
                f"<td>{size}</td></tr>"
            )
        listing = (
            "<div class='card scroll'><table class='filelist'>"
            "<tr><th>Name</th><th>Size</th></tr>"
            + "".join(rows) + "</table></div>"
            if rows else
            "<div class='card'><p class='note'>Empty directory.</p></div>"
        )
        body = (
            "<h1>" + _icon("folder", size=22) + "Artifacts</h1>"
            + _crumbs(relative) + listing
        )
        return _page("Artifacts", body, active="Artifacts")

    def _file_page(self, target: Path, relative: str) -> tuple[int, str, bytes]:
        suffix = target.suffix.lower()
        if suffix == ".png":
            return 200, "image/png", target.read_bytes()
        if target.stat().st_size > _MAX_RENDER_BYTES:
            return (
                200, "text/html; charset=utf-8",
                _page(
                    "Artifact",
                    "<h1>" + _icon("file", size=22)
                    + f"{html.escape(relative)}</h1>" + _crumbs(relative)
                    + "<div class='card'><p>"
                    "File exceeds the inline render limit; inspect it on "
                    "disk.</p></div>",
                ),
            )
        text = target.read_text(encoding="utf-8", errors="replace")
        badges_html = ""
        if suffix == ".json":
            try:
                document = json.loads(text)
                badges_html = _badges_html(evidence_badges(document))
                text = json.dumps(document, indent=2, sort_keys=True)
            except ValueError:
                pass
            rendered = f"<pre>{html.escape(text)}</pre>"
        elif suffix == ".csv":
            reader = csv.reader(io.StringIO(text))
            rows = []
            for index, row in enumerate(reader):
                if index > _CSV_PREVIEW_ROWS:
                    rows.append(
                        "<tr><td colspan='99'>(truncated preview)</td></tr>"
                    )
                    break
                tag = "th" if index == 0 else "td"
                rows.append(
                    "<tr>" + "".join(
                        f"<{tag}>{html.escape(cell)}</{tag}>" for cell in row
                    ) + "</tr>"
                )
            rendered = (
                "<div class='card scroll'><table>" + "".join(rows)
                + "</table></div>"
            )
        else:
            rendered = f"<pre>{html.escape(text)}</pre>"
        body = (
            "<h1>" + _icon("file", size=22)
            + f"{html.escape(target.name)}</h1>"
            + _crumbs(relative)
            + (f"<p>{badges_html}</p>" if badges_html else "")
            + rendered
        )
        return (
            200, "text/html; charset=utf-8",
            _page(relative, body, active="Artifacts"),
        )


#: Largest accepted POST body.  The configuration editor is the biggest
#: legitimate payload (a JSON registry); anything larger is rejected before
#: parsing.
_MAX_POST_BYTES = 2 * 1024 * 1024


def _make_server(app: RigWebApp, host: str, port: int):
    """Construct (without serving) the localhost HTTP server for ``app``."""

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            form: dict[str, str] = {}
            if method == "POST":
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length) if raw_length is not None else 0
                except ValueError:
                    length = -1
                # A missing/malformed/negative length, or one over the cap, is
                # rejected outright: never fall through to an unbounded
                # rfile.read(-1).  For an over-cap body the client is still
                # streaming, so drain a bounded amount first (so it can read
                # the 413) then close; a negative/invalid length carries no
                # trustworthy body, so reject immediately.
                if length < 0 or length > _MAX_POST_BYTES:
                    self.close_connection = True
                    if length > _MAX_POST_BYTES:
                        status_code = 413
                        body = b"request body exceeds the console limit"
                        remaining = min(length, 64 * 1024 * 1024)
                        while remaining > 0:
                            chunk = self.rfile.read(min(remaining, 65536))
                            if not chunk:
                                break
                            remaining -= len(chunk)
                    else:
                        status_code = 400
                        body = b"invalid Content-Length"
                    self.send_response(status_code)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                payload = self.rfile.read(length).decode("utf-8")
                form = {
                    key: values[0]
                    for key, values in parse_qs(payload).items()
                    if values
                }
            status, content_type, body = app.handle(method, self.path, form)
            if status == 303:
                self.send_response(303)
                self.send_header("Location", content_type)
                self.end_headers()
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server contract
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802 - http.server contract
            self._dispatch("POST")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            sys.stderr.write("rig-web: " + format % args + "\n")

    return ThreadingHTTPServer((host, port), Handler)


def _serve(app: RigWebApp, host: str, port: int) -> None:
    server = _make_server(app, host, port)
    print(json.dumps({
        "status": "serving",
        "url": f"http://{host}:{server.server_address[1]}/",
        "results_root": str(app.results_root),
        "state_dir": str(app.state_dir),
    }, sort_keys=True))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()  # reconcile terminal jobs and release the database


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rig-local web console over the maintained experiment CLIs "
            "(single operator, localhost only; artifacts stay authoritative)"
        )
    )
    parser.add_argument("--results-root", type=Path, default=Path("runs"))
    parser.add_argument("--state-dir", type=Path, default=Path("runs") / "rig-web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8642)
    parser.add_argument(
        "--reindex", action="store_true",
        help="headless: rebuild the usage/report indexes from retained "
             "artifacts, print the JSON summary, and exit (same operation as "
             "the dashboard Reindex button)",
    )
    parser.add_argument(
        "--usage-report", action="store_true",
        help="headless: print the recorded token usage and calculated cost "
             "(the Stats spend table) as JSON and exit",
    )
    parser.add_argument(
        "--selftest-sleep", type=float, default=None,
        help="UI diagnostic only: sleep this many seconds and exit",
    )
    args = parser.parse_args(argv)
    if args.selftest_sleep is not None:
        time.sleep(args.selftest_sleep)
        print("rig-web selftest complete")
        return 0
    # Headless operations make the console's usage/cost/reindex functions
    # available through the CLI too, without serving the interface.
    if args.reindex or args.usage_report:
        app = RigWebApp(
            results_root=args.results_root.resolve(),
            state_dir=args.state_dir.resolve(),
        )
        app.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            if args.reindex:
                print(json.dumps(app.reindex_all(), sort_keys=True))
            if args.usage_report:
                totals = app.db.usage_totals() or {}
                pricing = load_pricing(app.repo_root)
                rows = compute_costs(totals, pricing)
                print(json.dumps({
                    "schema": "ura-console-usage-report/1",
                    "rows": [
                        {**row, "tokens": dict(row["tokens"])} for row in rows
                    ],
                }, sort_keys=True))
        finally:
            app.close()
        return 0
    if args.host != "127.0.0.1":
        print(
            "rig-web is a single-operator localhost console; refusing to bind "
            f"{args.host!r}",
            file=sys.stderr,
        )
        return 1
    app = RigWebApp(
        results_root=args.results_root.resolve(),
        state_dir=args.state_dir.resolve(),
    )
    app.state_dir.mkdir(parents=True, exist_ok=True)
    _serve(app, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
