"""Overview, command, job, and artifact pages."""

from __future__ import annotations

import csv
import html
import io
import json
import os
import shutil
import time
from pathlib import Path
from urllib.parse import quote

from .catalog import (
    _MAX_RENDER_BYTES,
    _CSV_PREVIEW_ROWS,
    CommandParam,
    _PARAM_HELP,
    _SUGGEST_STATIC,
    COMMAND_GROUPS,
    _contained,
    evidence_badges,
    _icon,
)

from .ui import _page, _badges_html, _human_size, _human_duration, _crumbs

from .artifacts import _PIPELINE_STAGES, artifact_inventory, _pipeline_svg, Job


class PagesMixin:
    @staticmethod
    def _playbook_card() -> str:
        steps = (
            (
                "1",
                "Author revision receipt",
                "project_revision",
                {
                    "--expected-revision": "&lt;40-hex pin&gt;",
                    "--out": "runs/thesis/project-revision",
                },
            ),
            (
                "2",
                "Preflight (no calls)",
                "rig_check",
                {"--dry-run": "on", "--api": "$FABLE", "--corpora": "synth"},
            ),
            (
                "3",
                "Attestation probe (paid)",
                "run_matrix",
                {"--attestation-probe": "on", "--api": "$FABLE", "--out": "runs/thesis/attest"},
            ),
            (
                "4",
                "Diagnostic canary (paid)",
                "run_matrix",
                {
                    "--diagnostic-canary": "on",
                    "--api": "$FABLE",
                    "--corpora": "strongreject_official",
                    "--sample-seed": "0",
                    "--out": "runs/thesis/canary",
                },
            ),
            (
                "5",
                "Measured lane (paid)",
                "run_matrix",
                {
                    "--api": "$FABLE,$SOL",
                    "--corpora": "strongreject_official",
                    "--attackers": "replay,crescendo",
                    "--judges": "rules,llm",
                    "--judge-model": "anthropic:claude-haiku-4-5-20251001",
                    "--limit": "&lt;set from canary&gt;",
                    "--sample-seed": "0",
                    "--out": "runs/thesis/measured",
                },
            ),
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
            )
            if counts
            else "counts unknown"
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
                    f"{html.escape(str(name))} {html.escape(str(summary.get(name, 0)))}"
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
            f"<p class='note'>Last error: <code>{html.escape(health['last_error'])}</code></p>"
            if health["last_error"]
            else ""
        )
        return (
            "<div class='card'><h2>"
            + _icon("disk")
            + "Console database</h2>"
            + note
            + f"<p><span class='badge {tone}'>{state}</span> "
            f"schema v{health['schema_version']} - {html.escape(count_text)}"
            "</p>" + error + "<form method='post' action='/db/reindex' "
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
                spend_value = self._fmt_money(sum(r["cost"] for r in billable), "USD")
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
            if running_rows
            else ""
        )
        stage_sections = []
        for label, _suffixes in _PIPELINE_STAGES:
            stage = counts.get(label)
            if stage is None or not stage.paths:
                continue
            items = "".join(
                f"<li><a href='/artifacts?path={quote(path)}'>{html.escape(path)}</a></li>"
                for path in stage.paths
            )
            total = stage.count + stage.superseded
            if total > len(stage.paths):
                items += f"<li class='note'>first {len(stage.paths)} of {total} shown</li>"
            summary = f"{html.escape(label)}: {stage.count} current"
            if stage.superseded:
                summary += f", {stage.superseded} archived"
            stage_sections.append(
                f"<details class='stagefiles'><summary>{summary}</summary>"
                f"<ul>{items}</ul></details>"
            )
        stage_files = "".join(stage_sections)
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 10000);</script>" if running else ""
        )
        body = (
            "<h1>"
            + _icon("grid", size=22)
            + "Dashboard</h1>"
            + self._health_banner()
            + self._warnings_html()
            + stats
            + self._dashboard_hardware_card()
            + self._db_card(reindexed)
            + "<div class='card'><h2>"
            + _icon("chart")
            + "Campaign pipeline"
            "</h2>"
            + _pipeline_svg(counts)
            + "<p class='note'>Click a stage to browse its files. Counts are "
            "retained-file presence under the results root only; presence "
            "never asserts validity, authorization, or measurement status. "
            "“archived” counts files under a "
            "<code>superseded/</code> directory (kept as history, not "
            "current - for example an earlier pin's revision receipt)."
            + (
                " Inventory scan truncated at its entry cap; counts are a lower bound."
                if truncated
                else ""
            )
            + "</p>"
            + stage_files
            + "</div>"
            + self._next_hint(counts)
            + self._playbook_card()
            + running_html
            + self._budget_card()
            + self._policy_card()
            + "<div class='card'><h2>"
            + _icon("file")
            + "Campaign bindings"
            "</h2>" + self._campaign_context() + "</div>"
            "<div class='card'><h2>" + _icon("logo") + "Boundaries</h2>"
            "<p class='note'>Allowlisted commands only; no arbitrary shell. "
            "Dry-run/canary/probe artifacts stay diagnostic; measured "
            "claims come only from validated artifacts and the maintained "
            "analysis CLIs.</p></div>" + refresh
        )
        return _page("URA rig console", body, active="Dashboard")

    def _param_input(self, param: CommandParam) -> str:
        flag = html.escape(param.flag)
        if param.kind == "flag":
            return f"<input type='checkbox' name='{flag}'>"
        if param.choices:
            options = "".join(
                f"<option value='{html.escape(choice)}'>{html.escape(choice)}</option>"
                for choice in param.choices
            )
            return (
                f"<select name='{flag}'><option value=''>(default)</option>" + options + "</select>"
            )
        if param.kind == "int":
            return f"<input type='number' step='1' name='{flag}'>"
        if param.kind == "float":
            return f"<input type='number' step='any' name='{flag}'>"
        listattr = f" list='dl-{html.escape(param.suggest)}'" if param.suggest else ""
        return f"<input type='text' name='{flag}'{listattr}>"

    def _command_card(self, name: str) -> str:
        entry = self.commands[name]
        fields = []
        for param in entry.params:
            required = "<span class='req' title='required'>*</span>" if param.required else ""
            help_text = param.help or _PARAM_HELP.get(param.flag, "")
            title = f" title='{html.escape(help_text)}'" if help_text else ""
            hint = f"<span class='fieldhint'>{html.escape(help_text)}</span>" if help_text else ""
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
            + _icon("play", size=15)
            + "Start job</button>"
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
            ["synth"]
            + self._registry_keys("source-instances.json", "rig/source-instances.example.json")
        )
        lists["api"] = tuple(
            ["mock"] + self._registry_keys("api-targets.json", "rig/api-targets.example.json")
        )
        return "".join(
            f"<datalist id='dl-{html.escape(key)}'>"
            + "".join(f"<option value='{html.escape(value)}'></option>" for value in values)
            + "</datalist>"
            for key, values in lists.items()
        )

    def _commands_page(self) -> bytes:
        grouped: set[str] = set()
        sections = []

        def card(name: str) -> str:
            if name not in {"capture_t3mp3st", "harmbench_capture"}:
                return self._command_card(name)
            label = "T3MP3ST Capture" if name == "capture_t3mp3st" else "HarmBench Prepare"
            return (
                f"<details class='cmd' data-name='{html.escape(name)}'><summary>"
                f"{_icon('flask')}<strong>{html.escape(label)}</strong>"
                "<span class='desc'>Validated capture-first workflow</span></summary>"
                "<p class='note'>Open the Build workflow for field validation and "
                "an exact-command review before any process starts.</p>"
                "<p><a href='/build#prepared-workflows'>Open in Build</a></p></details>"
            )

        for title, icon, ref, names in COMMAND_GROUPS:
            cards = "".join(card(name) for name in names if name in self.commands)
            if not cards:
                continue
            grouped.update(names)
            sections.append(
                f"<div class='group-head'>{_icon(icon, size=20)}"
                f"<h2>{html.escape(title)}</h2>"
                f"<span class='ref'>{html.escape(ref)}</span></div>" + cards
            )
        leftovers = "".join(card(name) for name in sorted(set(self.commands) - grouped))
        if leftovers:
            sections.append(
                f"<div class='group-head'>{_icon('file', size=20)}<h2>Other</h2></div>" + leftovers
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
            '"details.cmd input[name=command][value=\'"+cmd+"\']");'
            "if(card){var det=card.closest('details.cmd');det.open=true;"
            "params.forEach(function(val,key){"
            "if(key==='cmd'){return;}"
            'var field=det.querySelector("[name=\'"+key+"\']");'
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
            tone = {
                "running": "blue",
                "complete": "green",
                "failed": "red",
                "orphaned": "amber",
            }.get(state, "gray")
            started = time.strftime("%H:%M:%S", time.localtime(job.started_at))
            stop = (
                "<form class='inline' method='post' "
                f"action='/jobs/{html.escape(job_id)}/stop'>"
                "<button class='danger small' type='submit'>Stop</button>"
                "</form>"
                if state == "running"
                else ""
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
            chips + "<p><input id='jobfilter' type='text' "
            "placeholder='Type to filter jobs...' "
            "aria-label='filter jobs'></p>"
        )
        table = (
            "<div class='card scroll'><table id='jobstable'>"
            "<tr><th>Job</th><th>Command</th>"
            "<th>State</th><th>Started</th><th>Runtime</th><th>Exit</th>"
            "<th></th></tr>" + "".join(rows) + "</table></div>"
            if rows
            else "<div class='card'><p class='note'>No jobs this session. Start "
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
            if rows
            else ""
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 5000);</script>"
            if tallies["running"]
            else ""
        )
        return _page(
            "Jobs",
            "<h1>"
            + _icon("pulse", size=22)
            + "Jobs</h1>"
            + self._health_banner()
            + controls
            + table
            + script
            + refresh,
            active="Jobs",
        )

    def _job_page(self, job: Job) -> bytes:
        state = job.state()
        tone = {"running": "blue", "complete": "green", "failed": "red"}.get(state, "gray")
        stdout_tail = self._log_tail(job, "stdout") or "(empty)"
        stderr_tail = self._log_tail(job, "stderr") or "(empty)"
        stop_form = (
            f"<form method='post' action='/jobs/{html.escape(job.job_id)}/stop'>"
            "<button class='danger' type='submit'>Stop job</button></form>"
            if state == "running"
            else ""
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 2000);</script>"
            if state == "running"
            else ""
        )
        failure = (
            "<div class='card'><h2>" + _icon("pulse") + "Failure</h2>"
            "<p>The command exited with "
            f"code {job.exit_code()}. Standard error is shown below; the "
            "underlying CLI message is authoritative.</p>"
            + (f"<pre>{html.escape(job.failure)}</pre>" if job.failure else "")
            + "</div>"
            if state == "failed"
            else ""
        )
        builder = ""
        if job.builder_params:
            rows = "".join(
                f"<tr><td>{html.escape(key)}</td><td><code>{html.escape(value)}</code></td></tr>"
                for key, value in sorted(job.builder_params.items())
            )
            reopen = "".join(
                f"<input type='hidden' name='{html.escape(key)}' value='{html.escape(value)}'>"
                for key, value in sorted(job.builder_params.items())
            )
            builder = (
                "<div class='card'><h2>"
                + _icon("flask")
                + "Builder parameters</h2><div class='scroll'><table>"
                + rows
                + "</table></div><p class='note'>The raw campaign-"
                "builder selections this job was composed from (persisted "
                "with the job).</p><form method='post' action='/build'>"
                + reopen
                + "<button type='submit' class='ghost'>Review this exact "
                "lane in the builder</button></form></div>"
            )
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in job.argv)
            + "</div>"
        )
        retained_links: list[str] = []
        for flag in ("--out", "--output", "--artifact-out", "--attacker-config-out"):
            if flag not in job.argv:
                continue
            index = job.argv.index(flag)
            if index + 1 >= len(job.argv):
                continue
            candidate = Path(job.argv[index + 1]).expanduser()
            if not candidate.is_absolute():
                candidate = self.repo_root / candidate
            try:
                resolved = candidate.resolve(strict=True)
                relative = resolved.relative_to(self.results_root.resolve()).as_posix()
            except (OSError, ValueError):
                continue
            retained_links.append(
                f"<a href='/artifacts?path={quote(relative)}'>"
                f"{html.escape(flag)}: {html.escape(relative)}</a>"
            )
        retained = (
            "<p class='note'>Retained output: " + " &middot; ".join(retained_links) + "</p>"
            if retained_links
            else ""
        )
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.started_at))
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
        stop_failure = (
            "<div class='notice red'><strong>Stop could not be confirmed."
            "</strong><p class='note'>"
            + html.escape(job.stop_error)
            + " Check the rig for a surviving process and terminate it "
            "manually; this run's usage/cost may be incomplete.</p></div>"
            if job.stop_error
            else ""
        )
        body = (
            f"<h1>{_icon('terminal', size=22)}Job {html.escape(job.job_id)}"
            "</h1>"
            + meta
            + stop_failure
            + "<div class='card'><h2>"
            + _icon("file")
            + "Command</h2>"
            + argv_chips
            + retained
            + stop_form
            + "</div>"
            + builder
            + failure
            + "<div class='card'><h2>"
            + _icon("chart")
            + "stdout</h2>"
            f"<pre>{html.escape(stdout_tail)}</pre></div>"
            "<div class='card'><h2>" + _icon("pulse") + "stderr</h2>"
            f"<pre>{html.escape(stderr_tail)}</pre></div>" + refresh
        )
        return _page(f"Job {job.job_id}", body, active="Jobs")

    # -- artifact browsing -------------------------------------------------

    def _artifacts(self, relative: str) -> tuple[int, str, bytes]:
        target = _contained(self.results_root, relative)
        if target.is_dir():
            return 200, "text/html; charset=utf-8", self._directory_page(target, relative)
        if not target.is_file():
            return 404, "text/plain; charset=utf-8", b"no such artifact"
        return self._file_page(target, relative)

    def _directory_page(self, directory: Path, relative: str) -> bytes:
        entries = sorted(directory.iterdir(), key=lambda item: (item.is_file(), item.name))
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
            "<tr><th>Name</th><th>Size</th></tr>" + "".join(rows) + "</table></div>"
            if rows
            else "<div class='card'><p class='note'>Empty directory.</p></div>"
        )
        body = "<h1>" + _icon("folder", size=22) + "Artifacts</h1>" + _crumbs(relative) + listing
        return _page("Artifacts", body, active="Artifacts")

    def _file_page(self, target: Path, relative: str) -> tuple[int, str, bytes]:
        suffix = target.suffix.lower()
        if suffix == ".png":
            return 200, "image/png", target.read_bytes()
        if target.stat().st_size > _MAX_RENDER_BYTES:
            return (
                200,
                "text/html; charset=utf-8",
                _page(
                    "Artifact",
                    "<h1>"
                    + _icon("file", size=22)
                    + f"{html.escape(relative)}</h1>"
                    + _crumbs(relative)
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
                    rows.append("<tr><td colspan='99'>(truncated preview)</td></tr>")
                    break
                tag = "th" if index == 0 else "td"
                rows.append(
                    "<tr>"
                    + "".join(f"<{tag}>{html.escape(cell)}</{tag}>" for cell in row)
                    + "</tr>"
                )
            rendered = "<div class='card scroll'><table>" + "".join(rows) + "</table></div>"
        else:
            rendered = f"<pre>{html.escape(text)}</pre>"
        body = (
            "<h1>"
            + _icon("file", size=22)
            + f"{html.escape(target.name)}</h1>"
            + _crumbs(relative)
            + (f"<p>{badges_html}</p>" if badges_html else "")
            + rendered
        )
        return (
            200,
            "text/html; charset=utf-8",
            _page(relative, body, active="Artifacts"),
        )
