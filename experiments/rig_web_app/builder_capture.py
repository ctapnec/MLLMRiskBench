"""Prepared-attacker capture and builder composition workflows."""

from __future__ import annotations

import html
import math
import os
import re
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse

from .catalog import _ARM_CATALOG, _BUILD_MODES, build_argv, _icon

from .ui import _page


class BuilderCaptureMixin:
    @classmethod
    def _projection_params(cls, params: Mapping[str, str]) -> dict[str, str]:
        """Normalized grid identity for safe preflight reuse."""

        attackers = {
            item.strip() for item in str(params.get("attackers", "")).split(",") if item.strip()
        }
        return {
            key: str(value).strip()
            for key, value in params.items()
            if (
                key not in cls._PROJECTION_CAP_FIELDS
                and not key.startswith(("t3cap_", "hcap_"))
                and (key not in {"t3_artifact", "t3_artifact_sha"} or "t3mp3st" in attackers)
                and (key != "harm_config" or "harmbench" in attackers)
                and str(value).strip()
            )
        }

    def _capture_output(self, raw: str, *, label: str) -> Path:
        if not raw:
            raise ValueError(f"{label} is required")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        if candidate.is_symlink():
            raise ValueError(f"{label} cannot be a symlink")
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(self.results_root.resolve())
            resolved.relative_to(self.repo_root.resolve())
        except (OSError, ValueError) as exc:
            raise ValueError(f"{label} must be under the repository results root") from exc
        return resolved

    def _capture_values(
        self,
        kind: str,
        params: Mapping[str, str],
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        """Validate and compose one capture-first workflow before a job exists."""

        errors: dict[str, str] = {}

        def required(field_name: str, label: str) -> str:
            value = params.get(field_name, "").strip()
            if not value:
                errors[field_name] = f"{label} is required"
            return value

        def integer(
            field_name: str,
            *,
            positive: bool = False,
            nonnegative: bool = False,
        ) -> str:
            raw = required(field_name, field_name.replace("_", " "))
            if not raw:
                return raw
            try:
                value = int(raw)
            except ValueError:
                errors[field_name] = "must be an integer"
            else:
                if positive and value <= 0:
                    errors[field_name] = "must be a positive integer"
                elif nonnegative and value < 0:
                    errors[field_name] = "must be a non-negative integer"
            return raw

        if kind == "t3mp3st":
            corpus = required("t3cap_corpus", "corpus arm")
            limit = integer("t3cap_limit", nonnegative=True)
            seed = integer("t3cap_sample_seed")
            endpoint = required("t3cap_endpoint", "loopback planning endpoint")
            revision = required("t3cap_revision", "upstream revision")
            provider = required("t3cap_provider", "source provider")
            model = required("t3cap_model", "source model")
            out = required("t3cap_out", "capture output directory")
            timeout = params.get("t3cap_timeout", "").strip()
            if corpus and corpus not in {
                arm for arm, mods, reason in _ARM_CATALOG if mods == ("text",) and not reason
            }:
                errors["t3cap_corpus"] = "select a runnable text corpus arm"
            if revision and re.fullmatch(r"[0-9a-fA-F]{40}", revision) is None:
                errors["t3cap_revision"] = "must be an exact 40-hex commit"
            if endpoint:
                try:
                    parsed = urlparse(endpoint)
                    port = parsed.port
                except ValueError:
                    parsed, port = None, None
                if (
                    parsed is None
                    or parsed.scheme != "http"
                    or parsed.hostname not in {"127.0.0.1", "::1"}
                    or port is None
                    or parsed.path != "/api/general/plan"
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                ):
                    errors["t3cap_endpoint"] = (
                        "must be the exact HTTP planning route on a literal "
                        "loopback address with an explicit port"
                    )
            if out:
                try:
                    out_path = self._capture_output(
                        out,
                        label="capture output directory",
                    )
                    if out_path.exists() and not out_path.is_dir():
                        raise ValueError("capture output must be a directory")
                    out = str(out_path)
                except ValueError as exc:
                    errors["t3cap_out"] = str(exc)
            if timeout:
                try:
                    timeout_value = float(timeout)
                except ValueError:
                    timeout_value = 0
                if not math.isfinite(timeout_value) or not 0 < timeout_value <= 3600:
                    errors["t3cap_timeout"] = "must be in (0, 3600]"
            values = {
                "--corpus": corpus,
                "--limit": limit,
                "--sample-seed": seed,
                "--endpoint": endpoint,
                "--upstream-revision": revision,
                "--source-provider": provider,
                "--source-model": model,
                "--out": out,
            }
            if timeout:
                values["--timeout-seconds"] = timeout
            source_config = self.repo_root / "experiments" / "source-instances.json"
            if source_config.is_file():
                values["--source-config"] = str(source_config)
            return (
                "capture_t3mp3st",
                {flag: value for flag, value in values.items() if value},
                errors,
            )

        if kind != "harmbench":
            raise ValueError(f"unknown prepared workflow {kind!r}")
        repo_raw = required("hcap_repo", "HarmBench checkout")
        revision = required("hcap_revision", "upstream revision")
        source_raw = required("hcap_source", "official behavior CSV")
        corpus = required("hcap_corpus", "logical corpus arm")
        methods_raw = required("hcap_methods", "at least one method")
        experiment = required("hcap_experiment", "experiment")
        limit = integer("hcap_limit", nonnegative=True)
        seed = integer("hcap_sample_seed")
        cases = integer("hcap_cases", positive=True)
        artifact_raw = required("hcap_artifact_out", "capture artifact output")
        config_raw = required("hcap_config_out", "attacker config output")
        if revision and re.fullmatch(r"[0-9a-fA-F]{40}", revision) is None:
            errors["hcap_revision"] = "must be an exact 40-hex commit"
        if cases:
            try:
                if int(cases) > 1000:
                    errors["hcap_cases"] = "must be in [1, 1000]"
            except ValueError:
                pass
        if corpus and corpus not in {
            arm for arm, mods, reason in _ARM_CATALOG if mods == ("text",) and not reason
        }:
            errors["hcap_corpus"] = "select a runnable text corpus arm"
        methods = self._split_list(methods_raw)
        supported_methods = {
            "PEZ",
            "GBDA",
            "UAT",
            "AutoPrompt",
            "PAP-top5",
            "GCG",
            "GCG-Multi",
            "GCG-Transfer",
            "AutoDAN",
            "PAIR",
            "TAP",
            "DirectRequest",
            "HumanJailbreaks",
            "ZeroShot",
        }
        if (
            not methods
            or len(methods) != len(set(methods))
            or any(method not in supported_methods for method in methods)
        ):
            errors["hcap_methods"] = "use unique supported text methods separated by commas"
        repo = Path(repo_raw).expanduser() if repo_raw else Path()
        source = Path(source_raw).expanduser() if source_raw else Path()
        if repo_raw and (not repo.is_absolute() or not repo.is_dir() or repo.is_symlink()):
            errors["hcap_repo"] = "must be an existing absolute non-symlink directory"
        if source_raw and (not source.is_absolute() or not source.is_file() or source.is_symlink()):
            errors["hcap_source"] = "must be an existing absolute non-symlink file"
        artifact_out, config_out = artifact_raw, config_raw
        for field_name, raw, label in (
            ("hcap_artifact_out", artifact_raw, "capture artifact output"),
            ("hcap_config_out", config_raw, "attacker config output"),
        ):
            if not raw:
                continue
            try:
                resolved = self._capture_output(raw, label=label)
            except ValueError as exc:
                errors[field_name] = str(exc)
                continue
            if resolved.suffix.lower() != ".json":
                errors[field_name] = f"{label} must end in .json"
            elif resolved.exists():
                errors[field_name] = f"{label} already exists; choose a new path"
            if field_name == "hcap_artifact_out":
                artifact_out = str(resolved)
            else:
                config_out = str(resolved)
        if artifact_out and config_out and artifact_out == config_out:
            errors["hcap_config_out"] = "artifact and config outputs must differ"
        python = params.get("hcap_python", "").strip()
        timeout = params.get("hcap_timeout", "").strip()
        if python and (not Path(python).is_absolute() or not Path(python).is_file()):
            errors["hcap_python"] = "must be an existing absolute executable path"
        if timeout:
            try:
                timeout_value = float(timeout)
            except ValueError:
                timeout_value = 0
            if not math.isfinite(timeout_value) or timeout_value <= 0:
                errors["hcap_timeout"] = "must be a positive finite number"
        credentials = self._split_list(params.get("hcap_credentials", ""))
        if len(credentials) != len(set(credentials)) or any(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None for name in credentials
        ):
            errors["hcap_credentials"] = "use unique environment variable names"
        values = {
            "--repo": str(repo),
            "--revision": revision,
            "--source": str(source),
            "--corpus-name": corpus,
            "--experiment": experiment,
            "--limit": limit,
            "--sample-seed": seed,
            "--cases-per-method": cases,
            "--artifact-out": artifact_out,
            "--attacker-config-out": config_out,
        }
        for index, method in enumerate(methods):
            values["--method" if index == 0 else f"--method#{index}"] = method
        if python:
            values["--python"] = python
        if timeout:
            values["--timeout-seconds"] = timeout
        for index, name in enumerate(credentials):
            values["--credential-env" if index == 0 else f"--credential-env#{index}"] = name
        return "harmbench_capture", values, errors

    def _capture_preview_page(
        self,
        kind: str,
        command: str,
        values: Mapping[str, str],
        params: Mapping[str, str],
    ) -> bytes:
        label = "T3MP3ST capture" if kind == "t3mp3st" else "HarmBench prepare"
        argv = build_argv(command, values, commands=self.commands)
        chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in argv)
            + "</div>"
        )
        hidden = "".join(
            f"<input type='hidden' name='{html.escape(key)}' value='{html.escape(value)}'>"
            for key, value in sorted(params.items())
        )
        action = "/build/t3mp3st/capture" if kind == "t3mp3st" else "/build/harmbench/prepare"
        body = (
            f"<h1>{_icon('flask', size=22)}Review {label}</h1>"
            "<div class='notice amber'><strong>Out-of-band paid/compute step."
            "</strong><p class='note'>Capture may invoke the configured source "
            "model or generation scripts. It does not call the measured target "
            "or judges. Review the exact command before starting.</p></div>"
            "<div class='card'><h2>Exact command</h2>" + chips + "</div>"
            f"<form method='post' action='{action}'>"
            + hidden
            + "<input type='hidden' name='confirm' value='yes'>"
            "<div class='buildbar'><button type='submit'>"
            + _icon("play", size=15)
            + f"Start {label}</button>"
            "<a href='/build'><button type='button' class='ghost'>Back to "
            "builder</button></a></div></form>"
        )
        return _page(f"Review {label}", body, active="Build")

    def _handle_capture(
        self,
        kind: str,
        form: Mapping[str, str],
    ) -> tuple[int, str, bytes]:
        confirmed = str(form.get("confirm", "")).strip() == "yes"
        prefix = "t3cap_" if kind == "t3mp3st" else "hcap_"
        params = {key: str(value).strip() for key, value in form.items() if key.startswith(prefix)}
        command, values, errors = self._capture_values(kind, params)
        if errors:
            return (
                200,
                "text/html; charset=utf-8",
                self._build_page(
                    prefill={**params, "attackers": kind},
                    errors=errors,
                ),
            )
        if not confirmed:
            return (
                200,
                "text/html; charset=utf-8",
                self._capture_preview_page(
                    kind,
                    command,
                    values,
                    params,
                ),
            )
        job = self.start_job(command, values)
        return 303, f"/jobs/{job.job_id}", b""

    def _compose_from_builder(
        self,
        form: Mapping[str, str],
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        """Turn builder selections into a validated run_matrix value map.

        The individual modality/model/framework checkboxes are collected
        client-side into comma-joined hidden fields, so this only reads the
        composed strings and hands them to the same typed build_argv path.
        Returns ``(command, values, params)`` where ``params`` is the raw
        builder form (persisted with the job and replayed on re-render).
        """

        params = {
            key: str(value).strip()
            for key, value in form.items()
            if (not key.startswith(("t3cap_", "hcap_")) and str(value).strip())
        }
        attackers = set(self._split_list(params.get("attackers", "")))
        if "t3mp3st" not in attackers:
            params.pop("t3_artifact", None)
            params.pop("t3_artifact_sha", None)
        if "harmbench" not in attackers:
            params.pop("harm_config", None)
        mode = params.get("mode", "measured")
        dry = mode == "dry_run" or (
            mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        values: dict[str, str] = {}
        for source, flag in (
            ("corpora", "--corpora"),
            ("api", "--api"),
            ("local", "--local"),
            ("attackers", "--attackers"),
            ("judges", "--judges"),
            ("limit", "--limit"),
            ("sample_seed", "--sample-seed"),
            ("seeds", "--seeds"),
            ("max_queries", "--max-queries"),
            ("max_turns", "--max-turns"),
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
            ("dtype", "--dtype"),
            ("quantization", "--quantization"),
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
            # The DEFENSE guardrail is a distinct model/revision/device from the
            # SCORING guardrail (below) by construction; wire its fields only
            # when the defense guard is a model-backed guardrail.
            if guard == "guardrail":
                for src, flag in (
                    ("defense_guardrail_model", "--defense-guardrail-model"),
                    ("defense_guardrail_revision", "--defense-guardrail-revision"),
                    ("defense_guardrail_device", "--defense-guardrail-device"),
                ):
                    if params.get(src):
                        values[flag] = params[src]
        judges = values.get("--judges", "")
        # The SCORING guardrail is the judge cascade's `guardrail` grader - a
        # separate identity from the defense guard so a tested guard never grades
        # its own output.  Wire its model/revision/device when it is in the
        # cascade.
        if "guardrail" in judges.split(","):
            for src, flag in (
                ("guardrail_model", "--guardrail-model"),
                ("guardrail_revision", "--guardrail-revision"),
                ("guardrail_device", "--guardrail-device"),
            ):
                if params.get(src):
                    values[flag] = params[src]
        if "llm" in judges.split(","):
            # A dry lane must grade with the offline mock LLM - never a real,
            # metered hosted judge - so a "no calls, no spend" mode cannot
            # silently issue paid Haiku judge calls.
            values["--judge-model"] = (
                "mock"
                if dry
                else (params.get("judge_model", "") or "anthropic:claude-haiku-4-5-20251001")
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
            # is also launched with those env vars scrubbed). It always uses
            # MockTarget, so do not attach a real target or generated local
            # config that run_matrix correctly treats as unused input.
            for flag in (
                "--project-revision",
                "--project-revision-sha256",
                "--source-conformance",
                "--source-conformance-sha256",
            ):
                values.pop(flag, None)
            values.pop("--api", None)
            values.pop("--local", None)
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
        if not dry and values.get("--local"):
            selected = self._split_list(values["--local"])
            local_cfg = self._materialize_selected_local_config(
                selected,
                default_quantization=params.get("quantization", ""),
                quantization_overrides={
                    key.removeprefix("quantization::"): value
                    for key, value in params.items()
                    if key.startswith("quantization::")
                },
            )
            values["--local-config"] = str(local_cfg)
        return "run_matrix", values, params

    @staticmethod
    def _split_list(raw: str) -> list[str]:
        return [item.strip() for item in raw.split(",") if item.strip()]
