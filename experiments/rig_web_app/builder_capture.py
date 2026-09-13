"""Prepared-attacker capture and builder composition workflows."""

from __future__ import annotations

import hashlib
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
    _BUILDER_FIELDS = frozenset({
        "campaign_id",
        "work_kind",
        "campaign_name",
        "retained_source_campaign",
        "retained_source_runs",
        "retained_sources_job",
        "retained_budget_caps",
        "retained_pricing_date",
        "retained_budget_job",
        "retained_replays_job",
        "retained_network_counts",
        "retained_programs_job",
        "retained_collection_workers",
        "retained_native_judging_job",
        "retained_native_verify_model",
        "retained_native_verify_artifacts",
        "retained_haiku_model",
        "retained_haiku_limit",
        "retained_haiku_seed",
        "retained_haiku_cost",
        "retained_haiku_job",
        "retained_inventory_job",
        "retained_inventory_items_job",
        "retained_inventory_plan_job",
        "retained_inventory_limit",
        "retained_inventory_seed",
        "mode",
        "canary_dry",
        "corpora",
        "api",
        "local",
        "attackers",
        "judges",
        "judge_model",
        "ack_hosted_judge_data_transfer",
        "approximate_common_metrics",
        "defense",
        "defense_guard",
        "guardrail_model",
        "guardrail_revision",
        "guardrail_device",
        "defense_guardrail_model",
        "defense_guardrail_revision",
        "defense_guardrail_device",
        "project_revision",
        "project_revision_sha",
        "source_conformance",
        "source_conformance_sha",
        "scope",
        "max_age",
        "limit",
        "sample_seed",
        "sampling_policy",
        "seeds",
        "max_queries",
        "max_turns",
        "target_answer_retries",
        "group",
        "exclude_tool_conditioned",
        "reset_open_circuits",
        "verify_model_sha256",
        "lock_stale_seconds",
        "cap_target",
        "cap_judge",
        "cap_http",
        "local_budget_hours",
        "deadline",
        "dtype",
        "quantization",
        "out",
        "t3_artifact",
        "t3_artifact_sha",
        "harm_config",
        "ideator_manifest",
        "ideator_manifest_sha",
        "ideator_pair_limit",
        "engine_runtime_config",
        "engine_runtime_config_sha",
        "nanogcg_model_id",
        "nanogcg_model_revision",
        "nanogcg_suffix",
        "nanogcg_suffix_source",
        "_api_config_snapshot_sha256",
        "_local_config_snapshot_sha256",
        "_source_config_snapshot_sha256",
        "_attacker_config_snapshot_sha256",
        "_engine_runtime_config_snapshot_sha256",
        "_execution_config_bundle_sha256",
        "_execution_snapshot_sha256",
    })
    _CAPTURE_FIELDS = frozenset({
        "t3cap_corpus",
        "t3cap_limit",
        "t3cap_sample_seed",
        "t3cap_endpoint",
        "t3cap_revision",
        "t3cap_provider",
        "t3cap_model",
        "t3cap_out",
        "t3cap_timeout",
        "hcap_repo",
        "hcap_revision",
        "hcap_source",
        "hcap_corpus",
        "hcap_methods",
        "hcap_experiment",
        "hcap_limit",
        "hcap_sample_seed",
        "hcap_cases",
        "hcap_artifact_out",
        "hcap_config_out",
        "hcap_python",
        "hcap_credentials",
        "hcap_timeout",
    })
    _BUILDER_UI_ONLY_FIELDS = frozenset({"_judge_model_ui", "local_choice"})

    def _validate_builder_form_keys(self, form: Mapping[str, str]) -> None:
        """Reject unknown or malformed builder keys before any composition."""

        for key in form:
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 4096
                or any(ord(character) < 32 or ord(character) == 127 for character in key)
            ):
                raise ValueError("builder form contains a malformed field name")
            if key in (
                self._BUILDER_FIELDS
                | self._CAPTURE_FIELDS
                | self._BUILDER_UI_ONLY_FIELDS
            ):
                continue
            if re.fullmatch(r"att_(?:path|sha)(?:[1-9]|1[0-2])", key):
                continue
            if key.startswith("quantization::") and key != "quantization::":
                continue
            raise ValueError("builder form contains an unsupported field name")

    def _projection_params(self, params: Mapping[str, str]) -> dict[str, str]:
        """Normalized grid identity for safe preflight reuse."""

        params = self._durable_builder_params(params)
        attackers = {
            item.strip() for item in str(params.get("attackers", "")).split(",") if item.strip()
        }
        return {
            key: str(value).strip()
            for key, value in params.items()
            if (
                key not in self._PROJECTION_CAP_FIELDS
                and key not in self._PROJECTION_OPERATIONAL_FIELDS
                and not key.startswith(("t3cap_", "hcap_"))
                and (key not in {"t3_artifact", "t3_artifact_sha"} or "t3mp3st" in attackers)
                and (key != "harm_config" or "harmbench" in attackers)
                and (
                    key not in {"ideator_manifest", "ideator_manifest_sha"}
                    or "ideator" in attackers
                )
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
        except (OSError, ValueError) as exc:
            raise ValueError(f"{label} must be under the configured results root") from exc
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
            framework_lock = framework_env_root = framework_state_root = ""
            try:
                lock_path, env_root, state_root = (
                    self.framework_runtimes.capture_binding_paths()
                )
                framework_lock = str(lock_path)
                framework_env_root = str(env_root)
                framework_state_root = str(state_root)
            except (OSError, RuntimeError, TypeError, ValueError):
                errors["t3cap_revision"] = (
                    "verified T3MP3ST framework runtime paths are unavailable"
                )
            values = {
                "--corpus": corpus,
                "--limit": limit,
                "--sample-seed": seed,
                "--endpoint": endpoint,
                "--upstream-revision": revision,
                "--framework-lock": framework_lock,
                "--framework-env-root": framework_env_root,
                "--framework-state-root": framework_state_root,
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
        launch_ticket = self._new_launch_ticket(
            params,
            purpose=f"capture:{kind}",
        )
        action = "/build/t3mp3st/capture" if kind == "t3mp3st" else "/build/harmbench/prepare"
        body = (
            f"<h1>{_icon('flask', size=22)}Review {label}</h1>"
            "<div class='notice amber'><strong>Out-of-band paid/compute step."
            "</strong><p class='note'>Capture may invoke the configured source "
            "model or generation scripts. It does not call the measured target "
            "or judges. Review the exact command before starting.</p></div>"
            "<div class='card'><h2>Exact command</h2>" + chips + "</div>"
            + self._campaign_banner(params.get("campaign_id", ""))
            + f"<form method='post' action='{action}'>"
            + "<input type='hidden' name='launch_ticket' value='"
            + html.escape(launch_ticket)
            + "'>"
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
        data = dict(form)
        confirm_value = str(data.pop("confirm", "")).strip()
        launch_ticket = str(data.pop("launch_ticket", "")).strip()
        prefix = "t3cap_" if kind == "t3mp3st" else "hcap_"

        def confirmation_error() -> tuple[int, str, bytes]:
            return (
                200,
                "text/html; charset=utf-8",
                self._build_page(
                    prefill={"attackers": kind},
                    errors={
                        prefix + ("out" if kind == "t3mp3st" else "artifact_out"): (
                            "the confirmation expired or was changed; review "
                            "the capture command again"
                        )
                    },
                ),
            )

        if launch_ticket or confirm_value:
            ticket_params = (
                self._launch_ticket_params(
                    launch_ticket,
                    purpose=f"capture:{kind}",
                )
                if launch_ticket
                else None
            )
            if confirm_value != "yes" or ticket_params is None or data:
                return confirmation_error()
            params = ticket_params
            confirmed = True
        else:
            try:
                self._validate_builder_form_keys(data)
            except ValueError:
                return confirmation_error()
            params = {
                key: str(value).strip()
                for key, value in data.items()
                if key.startswith(prefix) or key == "campaign_id"
            }
            confirmed = False
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
        job = self.start_job(command, values, campaign_id=params.get("campaign_id", ""))
        return 303, f"/jobs/{job.job_id}", b""

    def _builder_params(self, form: Mapping[str, str]) -> dict[str, str]:
        """Normalize builder fields without materializing runtime config."""

        self._validate_builder_form_keys(form)
        if form.get("campaign_id"):
            self.db.require_workspace(str(form["campaign_id"]))

        params = {
            key: str(value).strip()
            for key, value in form.items()
            if (
                key not in self._CAPTURE_FIELDS
                and key not in self._BUILDER_UI_ONLY_FIELDS
                and str(value).strip()
            )
        }
        work_kind = params.get("work_kind", "campaign" if params.get("campaign_id") else "run")
        if work_kind not in {"run", "campaign"}:
            raise ValueError("Choose Campaign or Single run")
        if work_kind == "run":
            params.pop("campaign_id", None)
            params.pop("campaign_name", None)
        elif not params.get("campaign_id"):
            name = params.get("campaign_name", "")
            if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
                raise ValueError("Enter a campaign name or select an existing campaign")
        attackers = set(self._split_list(params.get("attackers", "")))
        if "t3mp3st" not in attackers:
            params.pop("t3_artifact", None)
            params.pop("t3_artifact_sha", None)
        if "harmbench" not in attackers:
            params.pop("harm_config", None)
        if "ideator" not in attackers:
            params.pop("ideator_manifest", None)
            params.pop("ideator_manifest_sha", None)
            params.pop("ideator_pair_limit", None)
        if "nanogcg" not in attackers:
            for field in (
                "nanogcg_model_id",
                "nanogcg_model_revision",
                "nanogcg_suffix",
                "nanogcg_suffix_source",
            ):
                params.pop(field, None)
        return params

    def _compose_from_builder(
        self,
        form: Mapping[str, str],
        *,
        execution_snapshot: Mapping[str, bytes] | None = None,
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        """Turn builder selections into a validated run_matrix value map.

        The individual modality/model/framework checkboxes are collected
        client-side into comma-joined hidden fields, so this only reads the
        composed strings and hands them to the same typed build_argv path.
        Returns ``(command, values, params)`` where ``params`` is the raw
        builder form (persisted with the job and replayed on re-render).
        """

        params = self._builder_params(form)
        mode = params.get("mode", "measured")
        dry = mode == "dry_run" or (
            mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        snapshot = dict(execution_snapshot or {})
        if snapshot:
            snapshot = self._validate_execution_snapshot(params, snapshot)
        if not dry and not snapshot:
            for field, env_name in (
                ("project_revision", "URA_PROJECT_REVISION_MANIFEST"),
                ("project_revision_sha", "URA_PROJECT_REVISION_SHA256"),
                ("source_conformance", "URA_SOURCE_CONFORMANCE_MANIFEST"),
                ("source_conformance_sha", "URA_SOURCE_CONFORMANCE_SHA256"),
            ):
                if not params.get(field) and os.environ.get(env_name):
                    params[field] = os.environ[env_name]
        if snapshot:
            params = {key: str(value) for key, value in params.items()}
        else:
            params = self._bind_selected_execution_config_identity(params)
        if params.get("api") and not params.get("target_answer_retries"):
            # The browser synchronizes this field, but composition is also a
            # server-side boundary. A direct or restored hosted form must not
            # fall through to Runner's local default of one answer retry.
            params["target_answer_retries"] = "0"
        values: dict[str, str] = {}
        for source, flag in (
            ("corpora", "--corpora"),
            ("api", "--api"),
            ("local", "--local"),
            ("attackers", "--attackers"),
            ("judges", "--judges"),
            ("limit", "--limit"),
            ("sample_seed", "--sample-seed"),
            ("sampling_policy", "--sampling-policy"),
            ("seeds", "--seeds"),
            ("max_queries", "--max-queries"),
            ("max_turns", "--max-turns"),
            ("target_answer_retries", "--target-answer-retries"),
            ("group", "--group"),
            ("lock_stale_seconds", "--lock-stale-seconds"),
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
        if params.get("exclude_tool_conditioned") == "on":
            values["--exclude-tool-conditioned"] = "on"
        if params.get("verify_model_sha256") == "on":
            values["--verify-model-sha256"] = "on"
        if params.get("reset_open_circuits") == "on" and mode == "measured":
            # A measured-lane resume control only (validation rejects it for
            # dry runs, probes, and canaries); never composed by default.
            values["--reset-open-circuits"] = "on"
        if not dry and not values.get("--limit"):
            # Every non-dry lane carries an explicit --limit: a blank field is
            # never "full corpus" on the CLI (its argparse default is 50
            # clusters).  Validation admits a blank limit only for a local-only
            # measured lane, whose documented policy is the complete release
            # (--limit 0); hosted paid lanes must type an explicit positive
            # bound or 0 for a separately approved full cohort.  The
            # retained params carry the same value so the review page, the
            # ceilings card, and the preflight identity all agree.
            values["--limit"] = "0"
            params["limit"] = "0"
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
            # metered judge - so a "no calls, no spend" mode cannot silently
            # issue a hosted or local model call.
            values["--judge-model"] = (
                "mock"
                if dry
                else params.get("judge_model", "")
            )
        if params.get("ack_hosted_judge_data_transfer") == "on" and not dry:
            values["--ack-hosted-judge-data-transfer"] = "on"
        if params.get("approximate_common_metrics") == "on":
            values["--approximate-common-metrics"] = "on"
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
            # synthetic corpus regardless of the arm checkboxes (the builder's
            # "Synthetic (offline)" synth arm is for the ordinary dry lane) and
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
        api_config, api_config_sha256 = self._materialize_selected_api_config(
            params,
            snapshot_payload=snapshot.get("api_config"),
        )
        if api_config is not None and api_config_sha256 is not None:
            values["--api-config"] = str(api_config)
            values["--api-config-sha256"] = api_config_sha256
        source_config, source_config_sha256 = (
            self._materialize_selected_source_config(
                params,
                snapshot_payload=snapshot.get("source_config"),
            )
        )
        if source_config is not None and source_config_sha256 is not None:
            values["--source-config"] = str(source_config)
            values["--source-config-sha256"] = source_config_sha256
        source_receipt, source_receipt_sha256 = (
            self._materialize_selected_source_conformance(
                params,
                snapshot_payload=snapshot.get("source_conformance"),
            )
        )
        if source_receipt is not None and source_receipt_sha256 is not None:
            values["--source-conformance"] = str(source_receipt)
            values["--source-conformance-sha256"] = source_receipt_sha256
        project_receipt, project_receipt_sha256 = (
            self._materialize_selected_project_revision(
                params,
                snapshot_payload=snapshot.get("project_revision"),
            )
        )
        if project_receipt is not None and project_receipt_sha256 is not None:
            values["--project-revision"] = str(project_receipt)
            values["--project-revision-sha256"] = project_receipt_sha256
        live_attestations = self._materialize_selected_live_attestations(
            params,
            execution_snapshot=snapshot,
        )
        materialized_iterator = iter(live_attestations)
        for index in range(1, self._MAX_ATT_ROWS + 1):
            if not str(params.get(f"att_path{index}", "")).strip():
                continue
            attestation_path, attestation_sha256 = next(materialized_iterator)
            values[f"--live-attestation#{index}"] = str(attestation_path)
            values[f"--live-attestation-sha256#{index}"] = attestation_sha256
        judge_model = values.get("--judge-model", "")
        judge_local = (
            judge_model
            if judge_model.startswith(("vllm:", "ollama:"))
            else ""
        )
        if not dry and (values.get("--local") or judge_local):
            selected = self._split_list(values.get("--local", ""))
            if judge_local and judge_local not in selected:
                selected.append(judge_local)
            local_cfg = self._materialize_selected_local_config(
                selected,
                default_quantization=params.get("quantization", ""),
                quantization_overrides={
                    key.removeprefix("quantization::"): value
                    for key, value in params.items()
                    if key.startswith("quantization::")
                },
                require_live_ollama=True,
                snapshot_payload=snapshot.get("local_config"),
            )
            values["--local-config"] = str(local_cfg)
            values["--local-config-sha256"] = hashlib.sha256(
                local_cfg.read_bytes()
            ).hexdigest()
            _identities, private_config, durable_digest = (
                self._local_config_projection(values)
            )
            if private_config != local_cfg or durable_digest is None:
                self._unlink_transient_local_config(local_cfg)
                raise ValueError("selected local config lacks a durable identity")
            prior_digest = params.get("_local_config_snapshot_sha256", "")
            if prior_digest and prior_digest != durable_digest:
                self._unlink_transient_local_config(local_cfg)
                raise ValueError(
                    "selected local registry/model changed after review; "
                    "review the lane again"
                )
            params["_local_config_snapshot_sha256"] = durable_digest
        engine_runtime_config, engine_runtime_config_sha256 = (
            self._materialize_selected_engine_runtime_config(
                params,
                snapshot_payload=snapshot.get("engine_runtime_config"),
            )
        )
        if (
            engine_runtime_config is not None
            and engine_runtime_config_sha256 is not None
        ):
            values["--engine-runtime-config"] = str(engine_runtime_config)
            values["--engine-runtime-config-sha256"] = (
                engine_runtime_config_sha256
            )
        params = self._bind_execution_config_bundle_identity(params)
        return "run_matrix", values, params

    @staticmethod
    def _split_list(raw: str) -> list[str]:
        return [item.strip() for item in raw.split(",") if item.strip()]
