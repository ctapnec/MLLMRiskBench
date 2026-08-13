"""Rig-local web interface over the maintained experiment CLIs.

A thin, single-operator, localhost-only convenience surface (WEB-001): it
starts allowlisted ``python -m experiments.*`` commands from typed forms,
monitors and stops those jobs, streams their logs, and browses retained
artifacts with explicit diagnostic/measured and pending/N/A/error badges.

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
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


_REPO_ROOT = Path(__file__).resolve().parents[1]
_MAX_RENDER_BYTES = 4 * 1024 * 1024
_LOG_TAIL_BYTES = 64 * 1024
_CSV_PREVIEW_ROWS = 200


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
                *common_out,
            ),
        ),
        Command(
            "webui_selftest", "experiments.rig_web",
            "UI diagnostic only: sleep briefly and exit",
            (
                CommandParam("--selftest-sleep", "float"),
            ),
        ),
    ]
    return {entry.name: entry for entry in entries}


COMMANDS = _commands()


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


_STYLE = """
:root { color-scheme: light dark; --bg:#f5f6f8; --card:#ffffff; --ink:#1c2733;
  --muted:#5c6b7a; --line:#dde3ea; --accent:#0b64c0; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12181f; --card:#1a222c; --ink:#e8eef4; --muted:#93a4b5;
    --line:#2a3542; --accent:#5aa2e8; } }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui, "Segoe UI", sans-serif;
  background:var(--bg); color:var(--ink); }
main { max-width:1100px; margin:0 auto; padding:1.2rem; }
nav { background:var(--card); border-bottom:1px solid var(--line);
  padding:.7rem 1.2rem; display:flex; gap:1.2rem; flex-wrap:wrap; }
nav a { color:var(--accent); text-decoration:none; font-weight:600; }
nav span.title { font-weight:700; }
h1 { font-size:1.25rem; } h2 { font-size:1.05rem; margin-top:1.6rem; }
.card { background:var(--card); border:1px solid var(--line);
  border-radius:10px; padding:1rem 1.2rem; margin:.8rem 0; }
table { border-collapse:collapse; width:100%; font-size:.86rem; }
th, td { border:1px solid var(--line); padding:.3rem .55rem; text-align:left;
  vertical-align:top; }
th { background:color-mix(in srgb, var(--card) 70%, var(--bg)); }
.scroll { overflow-x:auto; }
pre { background:color-mix(in srgb, var(--card) 60%, var(--bg));
  border:1px solid var(--line); border-radius:8px; padding:.8rem;
  overflow-x:auto; font-size:.82rem; white-space:pre-wrap; }
.badge { display:inline-block; border-radius:999px; padding:.05rem .6rem;
  font-size:.75rem; font-weight:600; margin:0 .25rem .25rem 0;
  border:1px solid transparent; }
.badge.amber { background:#7a5200; color:#ffe9c2; }
.badge.blue { background:#0b4c8c; color:#dcecfd; }
.badge.green { background:#1d6b35; color:#d9f4e1; }
.badge.red { background:#8c1d24; color:#fde0e2; }
.badge.gray { background:#4a5563; color:#e3e8ee; }
form.cmd { display:grid; grid-template-columns:minmax(180px,240px) 1fr;
  gap:.35rem .8rem; align-items:center; }
form.cmd label { color:var(--muted); font-size:.85rem; }
form.cmd input[type=text] { width:100%; padding:.3rem .5rem;
  border:1px solid var(--line); border-radius:6px; background:var(--bg);
  color:var(--ink); }
button { background:var(--accent); border:0; color:#fff; font-weight:600;
  border-radius:7px; padding:.42rem .9rem; cursor:pointer; }
button.danger { background:#8c1d24; }
a { color:var(--accent); }
p.note { color:var(--muted); font-size:.85rem; }
"""


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<link rel='stylesheet' href='/static/style.css'></head><body>"
        "<nav><span class='title'>URA rig console</span>"
        "<a href='/'>Overview</a><a href='/commands'>Commands</a>"
        "<a href='/jobs'>Jobs</a><a href='/artifacts'>Artifacts</a></nav>"
        f"<main>{body}"
        "<p class='note'>The CLI and filesystem artifacts remain "
        "authoritative. This console never reinterprets experiment "
        "semantics; diagnostic evidence never authorizes a campaign.</p>"
        "</main></body></html>"
    ).encode("utf-8")


def _badges_html(badges: list[tuple[str, str]]) -> str:
    return "".join(
        f"<span class='badge {html.escape(tone)}'>{html.escape(label)}</span>"
        for label, tone in badges
    )


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

    def state(self) -> str:
        if self.process is None:
            return "unknown"
        code = self.process.poll()
        if code is None:
            return "running"
        return "complete" if code == 0 else "failed"

    def exit_code(self) -> int | None:
        return None if self.process is None else self.process.poll()


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

    def _overview(self) -> bytes:
        running = [job for job in self.jobs.values() if job.state() == "running"]
        body = (
            "<h1>Rig overview</h1>"
            "<div class='card'><h2>State</h2>"
            f"<p>Results root: <code>{html.escape(str(self.results_root))}</code><br>"
            f"Job state dir: <code>{html.escape(str(self.state_dir))}</code><br>"
            f"Jobs this session: {len(self.jobs)} ({len(running)} running)</p>"
            "</div>"
            "<div class='card'><h2>Boundaries</h2><p>Allowlisted commands "
            "only; no arbitrary shell. Dry-run/canary/probe artifacts stay "
            "diagnostic; measured claims come only from validated artifacts "
            "and the maintained analysis CLIs.</p></div>"
        )
        return _page("URA rig console", body)

    def _commands_page(self) -> bytes:
        sections = []
        for name in sorted(self.commands):
            entry = self.commands[name]
            fields = []
            for param in entry.params:
                input_html = (
                    f"<input type='checkbox' name='{html.escape(param.flag)}'>"
                    if param.kind == "flag"
                    else f"<input type='text' name='{html.escape(param.flag)}'>"
                )
                fields.append(
                    f"<label>{html.escape(param.flag)}"
                    f" ({html.escape(param.kind)})</label>{input_html}"
                )
            sections.append(
                f"<div class='card'><h2>{html.escape(name)}</h2>"
                f"<p class='note'>{html.escape(entry.description)} "
                f"(<code>python -m {html.escape(entry.module)}</code>)</p>"
                "<form class='cmd' method='post' action='/jobs'>"
                f"<input type='hidden' name='command' value='{html.escape(name)}'>"
                + "".join(fields)
                + "<span></span><button type='submit'>Start job</button>"
                "</form></div>"
            )
        return _page("Commands", "<h1>Allowlisted commands</h1>" + "".join(sections))

    def _jobs_page(self) -> bytes:
        rows = []
        for job_id in sorted(self.jobs, reverse=True):
            job = self.jobs[job_id]
            state = job.state()
            tone = {"running": "blue", "complete": "green", "failed": "red"}.get(
                state, "gray"
            )
            rows.append(
                f"<tr><td><a href='/jobs/{html.escape(job_id)}'>"
                f"{html.escape(job_id)}</a></td>"
                f"<td>{html.escape(job.command)}</td>"
                f"<td><span class='badge {tone}'>{html.escape(state)}</span></td>"
                f"<td>{'' if job.exit_code() is None else job.exit_code()}</td></tr>"
            )
        table = (
            "<div class='card scroll'><table><tr><th>Job</th><th>Command</th>"
            "<th>State</th><th>Exit</th></tr>" + "".join(rows) + "</table></div>"
            if rows else "<div class='card'><p>No jobs this session.</p></div>"
        )
        return _page("Jobs", "<h1>Jobs</h1>" + table)

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
            "<div class='card'><h2>Failure</h2><p>The command exited with "
            f"code {job.exit_code()}. Standard error is shown below; the "
            "underlying CLI message is authoritative.</p></div>"
            if state == "failed" else ""
        )
        body = (
            f"<h1>Job {html.escape(job.job_id)}</h1>"
            f"<p><span class='badge {tone}'>{html.escape(state)}</span></p>"
            f"<div class='card'><h2>Command</h2><pre>{html.escape(' '.join(job.argv))}</pre>"
            f"{stop_form}</div>"
            + failure +
            f"<div class='card'><h2>stdout</h2><pre>{html.escape(stdout_tail)}</pre></div>"
            f"<div class='card'><h2>stderr</h2><pre>{html.escape(stderr_tail)}</pre></div>"
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
        if relative:
            parent = "/".join(relative.replace("\\", "/").split("/")[:-1])
            rows.append(
                f"<tr><td><a href='/artifacts?path={html.escape(parent)}'>..</a>"
                "</td><td></td></tr>"
            )
        for entry in entries:
            child = f"{relative}/{entry.name}".lstrip("/")
            size = "" if entry.is_dir() else f"{entry.stat().st_size:,} B"
            rows.append(
                f"<tr><td><a href='/artifacts?path={html.escape(child)}'>"
                f"{html.escape(entry.name)}{'/' if entry.is_dir() else ''}</a></td>"
                f"<td>{size}</td></tr>"
            )
        body = (
            f"<h1>Artifacts: /{html.escape(relative)}</h1>"
            "<div class='card scroll'><table><tr><th>Name</th><th>Size</th></tr>"
            + "".join(rows) + "</table></div>"
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
                    f"<h1>{html.escape(relative)}</h1><div class='card'><p>"
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
            f"<h1>{html.escape(relative)}</h1>"
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
