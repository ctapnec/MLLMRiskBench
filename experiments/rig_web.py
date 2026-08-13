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


@dataclass(frozen=True)
class CommandParam:
    flag: str
    kind: str  # str | int | float | path | flag
    required: bool = False
    help: str = ""


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
    CommandParam("--models", "str"),
    CommandParam("--api", "str"),
    CommandParam("--local", "str"),
    CommandParam("--corpora", "str"),
    CommandParam("--attackers", "str"),
    CommandParam("--judges", "str"),
    CommandParam("--judge-model", "str"),
    CommandParam("--defense", "str"),
    CommandParam("--defense-guard", "str"),
    CommandParam("--guardrail-model", "str"),
    CommandParam("--guardrail-revision", "str"),
    CommandParam("--guardrail-device", "str"),
    CommandParam("--defense-guardrail-model", "str"),
    CommandParam("--defense-guardrail-revision", "str"),
    CommandParam("--defense-guardrail-device", "str"),
    CommandParam("--group", "str"),
    CommandParam("--attacker-config", "path"),
    CommandParam("--reset-open-circuits", "flag"),
    CommandParam("--source-config", "path"),
    CommandParam("--api-config", "path"),
    CommandParam("--local-config", "path"),
    CommandParam("--limit", "int"),
    CommandParam("--sample-seed", "int"),
    CommandParam("--seeds", "str"),
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
form.cmd input[type=text] { width:100%; padding:.38rem .55rem;
  border:1px solid var(--line); border-radius:8px; background:var(--bg);
  color:var(--ink); font-size:.86rem; }
form.cmd input[type=text]:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
button { display:inline-flex; gap:.4rem; align-items:center;
  background:var(--accent); border:0; color:var(--accent-ink);
  font-weight:600; border-radius:9px; padding:.48rem 1rem; cursor:pointer;
  font-size:.9rem; }
button:hover { filter:brightness(1.08); }
button.danger { background:#a4262f; color:#fff; }
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
.pipeline .node.present text.count { fill:var(--accent); font-weight:700; }
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
"""


_NAV_LINKS = (
    ("/", "grid", "Dashboard"),
    ("/commands", "terminal", "Run"),
    ("/jobs", "pulse", "Jobs"),
    ("/artifacts", "folder", "Artifacts"),
)


def _page(title: str, body: str) -> bytes:
    links = "".join(
        f"<a href='{href}'>{_icon(icon, size=16)}{label}</a>"
        for href, icon, label in _NAV_LINKS
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
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


def artifact_inventory(root: Path) -> tuple[dict[str, int], bool]:
    """Count retained artifact files by kind under the results root.

    Bounded, presence-only walk: at most ``_INVENTORY_MAX_ENTRIES`` directory
    entries and ``_INVENTORY_MAX_DEPTH`` levels are visited, lazily, so one
    pathological flat directory cannot stall the dashboard.  Returns the
    counts plus a truncation flag (counts are a lower bound when True).
    Counting a file says nothing about its validity.
    """

    counts: dict[str, int] = {label: 0 for label, _ in _PIPELINE_STAGES}
    seen = 0
    root = root.resolve()
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            for entry in directory.iterdir():
                seen += 1
                if seen > _INVENTORY_MAX_ENTRIES:
                    return counts, True
                if entry.is_dir():
                    if depth + 1 <= _INVENTORY_MAX_DEPTH:
                        stack.append((entry, depth + 1))
                    continue
                name = entry.name.lower()
                for label, suffixes in _PIPELINE_STAGES:
                    if any(name.endswith(suffix) for suffix in suffixes):
                        counts[label] += 1
                if name.endswith((".json", ".csv")) and any(
                    marker in name for marker in _ANALYSIS_MARKERS
                ):
                    counts["Level-1/2"] += 1
        except OSError:
            continue
    return counts, False


def _pipeline_svg(counts: Mapping[str, int]) -> str:
    node_w, node_h, gap, top = 128, 52, 24, 12
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
        count = counts.get(label, 0)
        cls = "node present" if count else "node"
        count_text = f"{count} file{'s' if count != 1 else ''}" if count else "none yet"
        parts.append(
            f"<g class='{cls}'>"
            f"<rect x='{x}' y='{top}' width='{node_w}' height='{node_h}' "
            "rx='10'/>"
            f"<text x='{x + node_w / 2}' y='{top + 21}' "
            f"text-anchor='middle'>{html.escape(label)}</text>"
            f"<text class='count' x='{x + node_w / 2}' y='{top + 38}' "
            f"text-anchor='middle'>{html.escape(count_text)}</text>"
            "</g>"
        )
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
        body = (
            "<h1>" + _icon("grid", size=22) + "Dashboard</h1>"
            + stats
            + "<div class='card'><h2>" + _icon("chart") + "Campaign pipeline"
            "</h2>" + _pipeline_svg(counts) +
            "<p class='note'>Counts are retained-file presence under the "
            "results root only; presence never asserts validity, "
            "authorization, or measurement status."
            + (" Inventory scan truncated at its entry cap; counts are a "
               "lower bound." if truncated else "")
            + "</p></div>"
            + running_html +
            "<div class='card'><h2>" + _icon("file") + "Campaign bindings"
            "</h2>" + self._campaign_context() + "</div>"
            "<div class='card'><h2>" + _icon("logo") + "Boundaries</h2>"
            "<p class='note'>Allowlisted commands only; no arbitrary shell. "
            "Dry-run/canary/probe artifacts stay diagnostic; measured "
            "claims come only from validated artifacts and the maintained "
            "analysis CLIs.</p></div>"
        )
        return _page("URA rig console", body)

    def _command_card(self, name: str) -> str:
        entry = self.commands[name]
        fields = []
        for param in entry.params:
            required = (
                "<span class='req' title='required'>*</span>"
                if param.required else ""
            )
            input_html = (
                f"<input type='checkbox' name='{html.escape(param.flag)}'>"
                if param.kind == "flag"
                else f"<input type='text' name='{html.escape(param.flag)}'>"
            )
            fields.append(
                f"<label>{html.escape(param.flag)}{required} "
                f"<span class='kind'>{html.escape(param.kind)}</span>"
                "</label>" + input_html
            )
        return (
            "<details class='cmd'><summary>" + _icon("terminal")
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
            + "".join(sections)
        )
        return _page("Run a command", body)

    def _jobs_page(self) -> bytes:
        rows = []
        for job_id in sorted(self.jobs, reverse=True):
            job = self.jobs[job_id]
            state = job.state()
            tone = {"running": "blue", "complete": "green", "failed": "red"}.get(
                state, "gray"
            )
            started = time.strftime(
                "%H:%M:%S", time.localtime(job.started_at)
            )
            rows.append(
                f"<tr><td><a href='/jobs/{html.escape(job_id)}'>"
                f"{html.escape(job_id)}</a></td>"
                f"<td>{html.escape(job.command)}</td>"
                f"<td><span class='dot {tone}'></span>"
                f"<span class='badge {tone}'>{html.escape(state)}</span></td>"
                f"<td>{started}</td>"
                f"<td>{job.runtime_seconds():,.0f}s</td>"
                f"<td>{'' if job.exit_code() is None else job.exit_code()}"
                "</td></tr>"
            )
        table = (
            "<div class='card scroll'><table><tr><th>Job</th><th>Command</th>"
            "<th>State</th><th>Started</th><th>Runtime</th><th>Exit</th></tr>"
            + "".join(rows) + "</table></div>"
            if rows else
            "<div class='card'><p class='note'>No jobs this session. Start "
            "one from the <a href='/commands'>Run</a> page.</p></div>"
        )
        return _page("Jobs", "<h1>" + _icon("pulse", size=22) + "Jobs</h1>" + table)

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
        return _page(f"Job {job.job_id}", body)

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
        return _page("Artifacts", body)

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
        return 200, "text/html; charset=utf-8", _page(relative, body)


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
