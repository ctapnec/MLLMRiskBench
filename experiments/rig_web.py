"""Rig-local web interface over the maintained experiment CLIs.

A thin, single-operator, localhost-only convenience surface (WEB-001, visual
layer WEB-002): it starts allowlisted ``python -m experiments.*`` commands
from typed forms, monitors and stops those jobs, streams their logs, and
browses retained artifacts with explicit diagnostic/measured and
pending/N/A/error badges.  The dashboard additionally shows a campaign
pipeline and artifact inventory derived purely from file presence; presence
of a file never asserts its validity.

The CLI and the filesystem artifacts remain authoritative.  This module never
reimplements experiment semantics, never executes arbitrary shell input
(argument vectors are built from a typed allowlist and run with
``shell=False``), needs no database, and adds no new dependency.  Nothing
rendered here is a measurement surface; measured evidence is only what the
validated artifacts themselves establish.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
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
_MATRIX_PARAMS = (
    CommandParam("--dry-run", "flag"),
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
    CommandParam("--limit", "int"),
    CommandParam("--sample-seed", "int"),
    CommandParam("--seeds", "str", suggest="seeds"),
    CommandParam("--max-queries", "int"),
    CommandParam("--max-turns", "int"),
    CommandParam("--max-total-target-calls", "int"),
    CommandParam("--max-total-judge-calls", "int"),
    CommandParam("--max-total-http-attempts", "int"),
    CommandParam("--deadline-seconds", "int"),
    CommandParam("--execution-scope-id", "str"),
    CommandParam("--live-attestation", "path"),
    CommandParam("--live-attestation-sha256", "str"),
    CommandParam("--live-attestation-max-age-hours", "int"),
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
                CommandParam("--arm", "str"),
                CommandParam("--observation", "str"),
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
                CommandParam("--eligibility", "path"),
                CommandParam("--results", "path"),
                CommandParam("--live-attestation", "path"),
                CommandParam("--live-attestation-sha256", "str"),
                CommandParam("--out-json", "path"),
                CommandParam("--out-csv", "path"),
            ),
        ),
        Command(
            "suite_summary", "experiments.suite_summary",
            "Build the no-pooling suite evidence inventory",
            (
                CommandParam("--results", "path"),
                CommandParam("--native", "path"),
                CommandParam("--eligibility", "path"),
                CommandParam("--source-config", "path"),
                *common_out,
            ),
        ),
        Command(
            "level2_report", "experiments.level2_report",
            "Export deterministic Level-2 JSON/CSV/Markdown broad tables",
            (
                CommandParam("--results", "path"),
                CommandParam("--native", "path"),
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
                CommandParam("--corpus", "str"),
                CommandParam("--mode", "str"),
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
    ("Analysis and reporting", "chart", "runbook section 16",
     ("level1_evidence", "suite_summary", "level2_report", "figures",
      "paired_compare", "judge_sensitivity", "kappa", "transfer_matrix")),
    ("Human audit", "users", "runbook sections 15, 15.1",
     ("human_audit",)),
    ("Console diagnostics", "pulse", "runbook section 18",
     ("webui_selftest",)),
)


def build_argv(
    command: str, values: Mapping[str, str], *, commands: Mapping[str, Command] | None = None,
) -> list[str]:
    """Build an exact argument vector from a typed allowlisted form."""

    registry = COMMANDS if commands is None else commands
    entry = registry.get(command)
    if entry is None:
        raise ValueError(f"unknown command {command!r}")
    known = {param.flag: param for param in entry.params}
    unknown = sorted(set(values) - set(known))
    if unknown:
        raise ValueError(f"unknown parameter(s) for {command!r}: {unknown}")
    argv = [sys.executable, "-m", entry.module]
    for param in entry.params:
        raw = values.get(param.flag, "")
        raw = raw.strip() if isinstance(raw, str) else ""
        if not raw:
            if param.required:
                raise ValueError(f"{command!r} requires {param.flag}")
            continue
        if param.kind == "flag":
            if raw not in {"on", "true", "1", "yes"}:
                raise ValueError(f"{param.flag} is a checkbox flag")
            argv.append(param.flag)
            continue
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
.modchip.on { background:var(--accent); color:var(--accent-ink);
  border-color:var(--accent); }
.modtag { display:inline-block; font-size:.66rem; font-weight:600;
  text-transform:uppercase; letter-spacing:.04em; color:var(--muted);
  background:var(--soft); border:1px solid var(--line); border-radius:5px;
  padding:0 .3rem; margin-left:.2rem; vertical-align:middle; }
.fwrow.incompatible { opacity:.55; }
.fwrow.incompatible .fwflag { color:#c4515c; font-weight:600; }
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
"""


_BUILDER_SCRIPT = """<script>(function(){
var form=document.getElementById('builder');
if(!form){return;}
function checked(sel,attr){var out=[];
form.querySelectorAll(sel).forEach(function(el){
if(el.checked){out.push(el.getAttribute(attr));}});return out;}
function selectedMods(){var s={};
form.querySelectorAll('.armbox').forEach(function(el){
if(el.checked){(el.getAttribute('data-mods')||'').split(',').forEach(
function(m){if(m){s[m]=1;}});}});return Object.keys(s);}
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
var api=checked('.modelbox','data-model');if(api.length){parts.push('--api '+api.join(','));}
var arms=checked('.armbox','data-arm');if(arms.length){parts.push('--corpora '+arms.join(','));}
var fw=checked('.fwbox','data-fw');if(fw.length){parts.push('--attackers '+fw.join(','));}
var jg=checked('.judgebox','data-judge');if(jg.length){parts.push('--judges '+jg.join(','));}
var lim=form.querySelector('input[name=limit]').value;
if(lim){parts.push('--limit '+lim);}
var prev=document.getElementById('buildpreview');
if(prev){prev.textContent=parts.join(' ');}}
form.addEventListener('change',refresh);
form.addEventListener('input',refresh);
form.querySelectorAll('.modchip').forEach(function(chip){
chip.addEventListener('click',function(){
var mod=this.getAttribute('data-mod');
var boxes=Array.prototype.filter.call(form.querySelectorAll('.armbox'),
function(b){return (b.getAttribute('data-mods')||'').split(',').indexOf(mod)>=0;});
var anyOff=boxes.some(function(b){return !b.checked;});
boxes.forEach(function(b){b.checked=anyOff;});
this.classList.toggle('on',anyOff);refresh();});});
form.addEventListener('submit',function(){
form.querySelector("input[name=corpora]").value=checked('.armbox','data-arm').join(',');
form.querySelector("input[name=api]").value=checked('.modelbox','data-model').join(',');
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
        "</footer></main></body></html>"
    ).encode("utf-8")


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

    def state(self) -> str:
        if self.process is None:
            return "unknown"
        code = self.process.poll()
        if code is None:
            return "running"
        if self.ended_at is None:
            self.ended_at = time.time()
        return "complete" if code == 0 else "failed"

    def exit_code(self) -> int | None:
        return None if self.process is None else self.process.poll()

    def runtime_seconds(self) -> float:
        end = self.ended_at if self.ended_at is not None else time.time()
        return max(0.0, end - self.started_at)


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
    ) -> None:
        self.results_root = results_root
        self.state_dir = state_dir
        self.repo_root = repo_root
        self.commands = dict(COMMANDS if commands is None else commands)
        self.jobs: dict[str, Job] = {}
        self._job_id_factory = job_id_factory or (
            lambda: f"job-{secrets.token_hex(6)}"
        )

    # -- job lifecycle -----------------------------------------------------

    def start_job(self, command: str, values: Mapping[str, str]) -> Job:
        argv = build_argv(command, values, commands=self.commands)
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
        process = subprocess.Popen(  # noqa: S603 - allowlisted argv, shell=False
            argv,
            cwd=self.repo_root,
            stdout=stdout_handle,
            stderr=stderr_handle,
            shell=False,
        )
        job = Job(
            job_id=job_id,
            command=command,
            argv=argv,
            directory=directory,
            process=process,
            stdout_handle=stdout_handle,
            stderr_handle=stderr_handle,
        )
        self.jobs[job_id] = job
        return job

    def stop_job(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(f"unknown job {job_id!r}")
        if job.process is not None and job.process.poll() is None:
            job.process.terminate()
            try:
                job.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                job.process.kill()
                job.process.wait(timeout=10)
        return job

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
                return 200, "text/html; charset=utf-8", self._overview()
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
                command, values = self._compose_from_builder(dict(form or {}))
                job = self.start_job(command, values)
                return 303, f"/jobs/{job.job_id}", b""
            if method == "GET" and path == "/config":
                return 200, "text/html; charset=utf-8", self._config_page(
                    query.get("file", ""), query.get("saved", ""),
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

    @staticmethod
    def _extract_rate_rows(document: Any) -> list[tuple[str, float]]:
        """Best-effort (label, rate-in-[0,1]) rows from a Level-2 report body.

        Defensive: unknown shapes yield no rows rather than an error, so the
        page never crashes on an unfamiliar or partial artifact.
        """

        rows: list[tuple[str, float]] = []
        table = None
        if isinstance(document, dict):
            for key in ("rows", "records", "cells", "table"):
                if isinstance(document.get(key), list):
                    table = document[key]
                    break
        if not isinstance(table, list):
            return rows
        for item in table[:40]:
            if not isinstance(item, dict):
                continue
            label = None
            for key in ("model", "target", "condition", "arm", "label", "name"):
                if isinstance(item.get(key), str):
                    label = item[key]
                    break
            rate = None
            for key in ("rate", "asr", "attack_success_rate", "value",
                        "refusal_rate", "estimate"):
                candidate = item.get(key)
                if isinstance(candidate, (int, float)):
                    rate = float(candidate)
                    break
            if label is not None and rate is not None:
                rows.append((label, rate if rate <= 1 else rate / 100.0))
        return rows

    def _campaign_usage(self) -> dict[str, dict[str, int]]:
        """Best-effort provider call/token tallies scanned from run artifacts.

        Presence and magnitude only; never a cost of record. Bounded scan.
        """

        totals: dict[str, dict[str, int]] = {}
        seen = 0
        root = self.results_root.resolve()
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                seen += 1
                if seen > _INVENTORY_MAX_ENTRIES:
                    return totals
                if entry.is_dir():
                    if depth + 1 <= _INVENTORY_MAX_DEPTH:
                        stack.append((entry, depth + 1))
                    continue
                if not entry.name.endswith((".grid.json", ".manifest.json",
                                            ".live-attestation.json")):
                    continue
                try:
                    doc = json.loads(entry.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                usage = doc.get("usage") if isinstance(doc, dict) else None
                if not isinstance(usage, dict):
                    continue
                provider = str(usage.get("provider", "unknown"))
                bucket = totals.setdefault(
                    provider, {"calls": 0, "input_tokens": 0, "output_tokens": 0}
                )
                for key in ("calls", "input_tokens", "output_tokens"):
                    value = usage.get(key)
                    if isinstance(value, int) and value >= 0:
                        bucket[key] += value
        return totals

    def _spend_card(self) -> str:
        usage = self._campaign_usage()
        rows = []
        for name, amount, _role in _PROVIDER_BUDGETS:
            key = name.split()[0].lower()
            observed = next(
                (v for p, v in usage.items() if p.lower().startswith(key)), None
            )
            calls = observed["calls"] if observed else 0
            toks = (observed["input_tokens"] + observed["output_tokens"]
                    ) if observed else 0
            rows.append(
                f"<tr><td>{html.escape(name)}</td>"
                f"<td><strong>{html.escape(amount)}</strong></td>"
                f"<td>{calls:,}</td><td>{toks:,}</td></tr>"
            )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Budgets &amp; spend"
            "</h2><div class='scroll'><table><tr><th>Provider</th>"
            "<th>Prepaid</th><th>Calls</th><th>Tokens</th></tr>"
            + "".join(rows) + "</table></div>"
            "<p class='note'>Prepaid budgets are the recorded ceilings (ledger "
            "11.22). Calls and tokens are scanned from retained run artifacts "
            "(attestation probes, canaries, measured lanes) and are observed "
            "usage, not a cost of record. A dollar figure appears only once a "
            "per-model price is recorded; the console never estimates spend it "
            "cannot source.</p></div>"
        )

    def _stats_page(self) -> bytes:
        counts, _trunc = artifact_inventory(self.results_root)
        analysis = counts.get("Level-1/2", StageInventory())
        charts = []
        for rel in analysis.paths:
            if "level2" not in rel.lower() or not rel.lower().endswith(".json"):
                continue
            try:
                doc = json.loads(
                    (self.results_root / rel).read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                continue
            rate_rows = self._extract_rate_rows(doc)
            if not rate_rows:
                continue
            charts.append(
                "<div class='card'><h2>" + _icon("chart")
                + f"{html.escape(rel)}</h2>"
                + self._bar_chart(rate_rows)
                + f"<p class='note'><a href='/artifacts?path={quote(rel)}'>"
                "open the full validated table &rarr;</a> Diagram is a "
                "presentation of the deterministic Level-2 report; the "
                "artifact is authoritative.</p></div>"
            )
        if analysis.paths:
            listed = "".join(
                f"<li><a href='/artifacts?path={quote(rel)}'>"
                f"{html.escape(rel)}</a></li>" for rel in analysis.paths
            )
            results = (
                "<div class='card'><h2>" + _icon("file") + "Result tables</h2>"
                f"<ul>{listed}</ul></div>"
            )
        else:
            results = (
                "<div class='card'><p class='note'>No Level-1/Level-2 result "
                "tables retained yet. They appear here once measured lanes and "
                "the analysis CLIs have run; diagrams render from the "
                "deterministic Level-2 report.</p></div>"
            )
        body = (
            "<h1>" + _icon("chart", size=22) + "Campaign stats</h1>"
            + self._spend_card()
            + "".join(charts)
            + results
        )
        return _page("Campaign stats", body, active="Stats")

    # -- campaign builder --------------------------------------------------

    def _model_options(self) -> list[tuple[str, str, tuple[str, ...]]]:
        """Selectable targets as (spec, label, supported-modalities).

        Modalities come from each roster entry's ``modalities`` field so the
        builder can hide a target that cannot handle a selected modality (a
        text-only model drops out once image/audio/video is in scope). The
        focal Anthropic/OpenAI pair are text+image multimodal frontier models.
        """

        options: list[tuple[str, str, tuple[str, ...]]] = []
        for env_name, label in (("FABLE", "Fable (focal)"), ("SOL", "Sol (focal)")):
            spec = os.environ.get(env_name, "").strip()
            if spec:
                options.append((spec, label, ("text", "image")))
        registry: dict[str, Any] = {}
        for candidate in ("api-targets.json", "rig/api-targets.example.json"):
            path = self.repo_root / "experiments" / candidate
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                registry = data
                break
        for key, entry in registry.items():
            mods = ("text",)
            if isinstance(entry, dict) and isinstance(entry.get("modalities"), list):
                mods = tuple(
                    str(m) for m in entry["modalities"] if isinstance(m, str)
                ) or ("text",)
            options.append((key, key, mods))
        return options

    def _compose_from_builder(
        self, form: Mapping[str, str],
    ) -> tuple[str, dict[str, str]]:
        """Turn builder selections into a validated run_matrix value map.

        The individual modality/model/framework checkboxes are collected
        client-side into comma-joined hidden fields, so this only reads the
        composed strings and hands them to the same typed build_argv path.
        """

        values: dict[str, str] = {}
        for source, flag in (
            ("corpora", "--corpora"), ("api", "--api"),
            ("local", "--local"), ("attackers", "--attackers"),
            ("judges", "--judges"), ("limit", "--limit"),
            ("sample_seed", "--sample-seed"), ("out", "--out"),
        ):
            raw = str(form.get(source, "")).strip()
            if raw:
                values[flag] = raw
        defense = str(form.get("defense", "")).strip()
        if defense and defense != "none":
            values["--defense"] = defense
        judges = values.get("--judges", "")
        if "llm" in judges.split(","):
            values["--judge-model"] = str(
                form.get("judge_model", "")
            ).strip() or "anthropic:claude-haiku-4-5-20251001"
        mode = str(form.get("mode", "measured"))
        for token, mode_flag, _desc in _BUILD_MODES:
            if token == mode and mode_flag:
                values[mode_flag] = "on"
        # Bind the operator-local registries so a hosted lane resolves its
        # roster and source receipt exactly as the runbook expects.
        for relative, flag in (
            ("experiments/api-targets.json", "--api-config"),
            ("experiments/source-instances.json", "--source-config"),
        ):
            if (self.repo_root / relative).is_file():
                values[flag] = relative
        return "run_matrix", values

    def _build_page(self) -> bytes:
        # Mode radios.
        mode_html = "".join(
            "<label class='radio'>"
            f"<input type='radio' name='mode' value='{token}'"
            + (" checked" if token == "dry_run" else "") + ">"
            f"<span><strong>{html.escape(token.replace('_', ' '))}</strong> "
            f"<span class='fieldhint'>{html.escape(desc)}</span></span></label>"
            for token, _flag, desc in _BUILD_MODES
        )
        # Modality chips select arms by membership: an arm belongs to every
        # modality it carries, so a text+image arm answers to both chips.
        registry_arms = set(self._registry_keys(
            "source-instances.json", "rig/source-instances.example.json"
        ))
        modality_chips = "".join(
            f"<button type='button' class='chip modchip' data-mod='{mod}'>"
            f"{html.escape(mod)}</button>"
            for mod in _MODALITIES
        )

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
                    f"data-mods='{','.join(mods)}' "
                    f"data-arm='{html.escape(arm)}'>"
                    f"<span>{html.escape(arm)} {_mod_tags(mods)}{note}</span>"
                    "</label>"
                )
            arm_groups.append(
                f"<div class='modgroup'><h3>{html.escape(signature)}</h3>"
                "<div class='checkgrid'>" + "".join(boxes) + "</div></div>"
            )
        # Target model checkboxes (carry supported modalities so a target that
        # cannot handle a selected modality is hidden from scope).
        model_boxes = "".join(
            "<label class='check modelrow' "
            f"data-mods='{','.join(mods)}'>"
            f"<input type='checkbox' class='modelbox' "
            f"data-model='{html.escape(value)}'>"
            f"<span>{html.escape(label)} "
            + "".join(f"<span class='modtag'>{html.escape(m)}</span>"
                      for m in mods)
            + "</span></label>"
            for value, label, mods in self._model_options()
        ) or "<p class='note'>No targets configured. Add them on the "\
             "<a href='/config?file=api-targets'>Config</a> page.</p>"
        # Local target field (free text: backend:model specs).
        # Framework checkboxes (carry supported modalities so the wizard can
        # flag ones that cannot drive a chosen modality).
        framework_boxes = "".join(
            "<label class='check fwrow' "
            f"data-mods='{','.join(mods)}'>"
            f"<input type='checkbox' class='fwbox' data-fw='{html.escape(fw)}'"
            + (" checked" if fw == "replay" else "") + ">"
            f"<span><strong>{html.escape(fw)}</strong> "
            f"<span class='fieldhint'>{html.escape(desc)}</span>"
            "<span class='fwflag'></span></span></label>"
            for fw, desc, mods in _FRAMEWORKS
        )
        # Judge checkboxes.
        judge_boxes = (
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='rules' checked><span><strong>rules</strong> "
            "<span class='fieldhint'>deterministic rule scorer (free)</span>"
            "</span></label>"
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='llm'><span><strong>llm</strong> "
            "<span class='fieldhint'>hosted Haiku judge (metered per response)"
            "</span></span></label>"
        )
        defense_opts = "".join(
            f"<option value='{d}'>{d}</option>"
            for d in ("none", "input", "output", "both")
        )
        body = (
            "<h1>" + _icon("flask", size=22) + "Campaign builder</h1>"
            "<p class='note'>Compose a lane by choosing modalities, target "
            "models, and attack frameworks. On build it opens as a "
            "<code>run_matrix</code> job through the same typed, validated "
            "path - nothing here bypasses the allowlist. Paid modes spend real "
            "money; review the composed command on the job page.</p>"
            "<form method='post' action='/build' id='builder'>"
            # hidden composed fields
            "<input type='hidden' name='corpora'><input type='hidden' name='api'>"
            "<input type='hidden' name='attackers'>"
            "<input type='hidden' name='judges'>"
            "<div class='card'><h2>" + _icon("play") + "Mode</h2>"
            "<div class='radios'>" + mode_html + "</div></div>"
            "<div class='card'><h2>" + _icon("grid") + "Modality scope</h2>"
            "<p class='note'>The campaign's modalities. All are enabled for a "
            "fresh build; unchecking one hides the arms, target models, and "
            "frameworks that need it. A multimodal arm needs every one of its "
            "modalities in scope; a target model must support all of them.</p>"
            "<div class='checkgrid'>" + "".join(
                "<label class='check'><input type='checkbox' class='modbox' "
                f"data-mod='{m}' checked><span><strong>{m}</strong></span>"
                "</label>" for m in _MODALITIES
            ) + "</div></div>"
            "<div class='card'><h2>" + _icon("box") + "Arms &amp; corpora</h2>"
            "<p class='note'>Only arms whose modalities are all in scope appear "
            "here; use a modality chip to bulk-select a group.</p>"
            "<div class='chips'>" + modality_chips + "</div>"
            + "".join(arm_groups) + "</div>"
            "<div class='card'><h2>" + _icon("coins") + "Target models</h2>"
            "<div class='checkgrid'>" + model_boxes + "</div>"
            "<label class='fieldlabel'>Local targets (backend:model, comma "
            "list)</label>"
            "<input type='text' name='local' class='wide' "
            "placeholder='e.g. vllm:Qwen/Qwen3-VL-...'></div>"
            "<div class='card'><h2>" + _icon("pulse") + "Attack frameworks</h2>"
            "<div class='checkgrid'>" + framework_boxes + "</div></div>"
            "<div class='card'><h2>" + _icon("receipt") + "Judges &amp; defense"
            "</h2><div class='checkgrid'>" + judge_boxes + "</div>"
            "<label class='fieldlabel'>Defense</label>"
            f"<select name='defense'>{defense_opts}</select></div>"
            "<div class='card'><h2>" + _icon("coins") + "Sampling &amp; output"
            "</h2><div class='cols'>"
            "<div><label class='fieldlabel'>--limit "
            "<span class='fieldhint'>cluster subsample; required on paid hosted "
            "lanes</span></label>"
            "<input type='number' name='limit' step='1'></div>"
            "<div><label class='fieldlabel'>--sample-seed "
            "<span class='fieldhint'>fix &amp; record for a reproducible subset"
            "</span></label><input type='number' name='sample_seed' value='0'>"
            "</div>"
            "<div><label class='fieldlabel'>--out</label>"
            "<input type='text' name='out' value='runs/thesis/lane'></div>"
            "</div></div>"
            "<div class='buildbar'><button type='submit'>" + _icon("play", size=15)
            + "Build &amp; start job</button>"
            "<span id='buildpreview' class='note'></span></div>"
            "</form>"
            + _BUILDER_SCRIPT
        )
        return _page("Campaign builder", body, active="Build")

    @staticmethod
    def _budget_card() -> str:
        rows = "".join(
            f"<tr><td>{html.escape(name)}</td>"
            f"<td><strong>{html.escape(amount)}</strong></td>"
            f"<td>{html.escape(role)}</td></tr>"
            for name, amount, role in _PROVIDER_BUDGETS
        )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Provider budgets</h2>"
            "<div class='scroll'><table><tr><th>Provider</th><th>Prepaid</th>"
            "<th>Funds</th></tr>" + rows + "</table></div>"
            "<p class='note'>Recorded prepaid budgets (ledger 11.22). The "
            "Anthropic balance is the constraint because the Haiku judge is "
            "metered on every judged response, local lanes included. Exact "
            "per-lane <code>--limit</code> and call caps are set from the "
            "diagnostic-canary cost projections and posted here before any "
            "measured lane. This card spends nothing.</p></div>"
        )

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
        normalized = json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
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
            body = (
                "<h1>" + _icon("sliders", size=22) + "Configuration</h1>"
                "<p class='note'>Edit the operator-local registries in place. "
                "Saves are JSON-validated and the prior version is backed up "
                "under the console state directory. These files are read fresh "
                "by each run, so an edit takes effect on the next job. Secrets "
                "live only in <code>~/.ura_env</code> and are never shown or "
                "editable here.</p>" + "".join(cards)
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
        body = (
            "<h1>" + _icon("sliders", size=22)
            + f"Edit {html.escape(key)}</h1>"
            f"<p class='crumbs'><a href='/config'>Configuration</a>"
            f"<span class='sep'>/</span>{html.escape(relative)}</p>"
            + banner
            + f"<p class='note'>{html.escape(description)}</p>"
            "<form method='post' action='/config'>"
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

    def _overview(self) -> bytes:
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
        stats = (
            "<div class='cols'>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{len(jobs)}</span>"
            "<span class='label'>jobs this session</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot blue'></span>"
            f"{len(running)}</span>"
            "<span class='label'>running now</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot red'></span>"
            f"{len(failed)}</span>"
            "<span class='label'>failed this session</span></div></div>"
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
            + self._warnings_html()
            + stats
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
        rows = []
        tallies = {"running": 0, "complete": 0, "failed": 0}
        for job_id in sorted(self.jobs, reverse=True):
            job = self.jobs[job_id]
            state = job.state()
            if state in tallies:
                tallies[state] += 1
            tone = {"running": "blue", "complete": "green", "failed": "red"}.get(
                state, "gray"
            )
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
            "underlying CLI message is authoritative.</p></div>"
            if state == "failed" else ""
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


def _serve(app: RigWebApp, host: str, port: int) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            form: dict[str, str] = {}
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
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

    server = ThreadingHTTPServer((host, port), Handler)
    print(json.dumps({
        "status": "serving",
        "url": f"http://{host}:{port}/",
        "results_root": str(app.results_root),
        "state_dir": str(app.state_dir),
    }, sort_keys=True))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


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
        "--selftest-sleep", type=float, default=None,
        help="UI diagnostic only: sleep this many seconds and exit",
    )
    args = parser.parse_args(argv)
    if args.selftest_sleep is not None:
        time.sleep(args.selftest_sleep)
        print("rig-web selftest complete")
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
