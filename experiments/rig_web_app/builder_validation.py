"""Builder validation, projection, ceilings, and preview rendering."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from pathlib import Path
from typing import Mapping

from .catalog import (
    _ARM_CATALOG,
    _SOURCE_METRIC_ARMS,
    _INELIGIBLE_ARMS,
    _INELIGIBLE_REASONS,
    _ATTACKER_NAMES,
    _NATIVE_ONLY_ATTACKERS,
    _FRAMEWORKS,
    _BUILD_MODES,
    build_argv,
    _icon,
)

from .ui import _page

from .artifacts import _argv_out_dir


class BuilderValidationMixin:
    def _preflight_output_dir(self, params: Mapping[str, str]) -> Path:
        """Dedicated no-call output, separate from the measured run tree."""

        normalized = self._projection_params(params)
        condition = hashlib.sha256(
            json.dumps(
                normalized,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()[:16]
        return self.results_root / "preflight" / f"builder-{condition}"

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
        judges_list = self._split_list(params.get("judges", ""))
        seeds = self._split_list(params.get("seeds", "") or "0")
        targets = len(api) + len(local)
        real_corpora = [arm for arm in corpora if arm != "synth"]
        att_rows: list[tuple[str, str]] = []
        for index in range(1, self._MAX_ATT_ROWS + 1):
            path = params.get(f"att_path{index}", "")
            sha = params.get(f"att_sha{index}", "")
            if path or sha:
                att_rows.append((path, sha))

        allowed_modes = {token for token, _flag, _desc in _BUILD_MODES}
        if mode not in allowed_modes:
            errors["mode"] = "select a supported execution mode"

        def reject_duplicates(field: str, values: list[str]) -> None:
            duplicates = sorted(value for value in set(values) if values.count(value) > 1)
            if duplicates:
                errors[field] = "entries must be unique; duplicates: " + ", ".join(duplicates)

        reject_duplicates("models", [*api, *local])
        reject_duplicates("corpora", corpora)
        reject_duplicates("attackers", attackers)
        reject_duplicates("judges", judges_list)
        harm_requirements: tuple[str, int, int, int] | None = None

        known_arms = {arm for arm, _mods, _reason in _ARM_CATALOG} | {"synth"}
        unknown_arms = sorted(set(corpora) - known_arms)
        if unknown_arms:
            errors["corpora"] = "unknown corpus arm(s): " + ", ".join(unknown_arms)
        unknown_attackers = sorted(set(attackers) - set(_ATTACKER_NAMES))
        if unknown_attackers:
            errors["attackers"] = "unknown attack framework(s): " + ", ".join(unknown_attackers)
        for attacker, error_field in (
            ("t3mp3st", "t3_replay"),
            ("harmbench", "harm_replay"),
        ):
            if attacker not in attackers:
                continue
            try:
                self._prepared_attacker_entries({**params, "attackers": attacker})
                if attacker == "harmbench":
                    harm_requirements = self._harmbench_replay_requirements(params)
            except ValueError as exc:
                errors[error_field] = str(exc)
        unknown_judges = sorted(set(judges_list) - {"rules", "llm", "guardrail"})
        if unknown_judges:
            errors["judges"] = "unknown judge(s): " + ", ".join(unknown_judges)
        if params.get("defense", "none") not in {"none", "input", "output", "both"}:
            errors["defense"] = "select none, input, output, or both"
        if params.get("defense_guard", "rules") not in {"rules", "guardrail"}:
            errors["defense_guard"] = "select rules or guardrail"
        if params.get("dtype", "") not in {"", "auto", "bfloat16", "float16"}:
            errors["dtype"] = "select auto, bfloat16, or float16"

        model_options = self._model_options()
        target_mods = {(kind, value): set(mods) for value, _label, mods, kind in model_options}
        unknown_api = sorted(value for value in api if ("api", value) not in target_mods)
        unknown_local = sorted(value for value in local if ("local", value) not in target_mods)
        if unknown_api or unknown_local:
            details = []
            if unknown_api:
                details.append("hosted: " + ", ".join(unknown_api))
            if unknown_local:
                details.append("local: " + ", ".join(unknown_local))
            errors["models"] = "unknown target selection(s): " + "; ".join(details)
        if local and mode != "dry_run" and not canary_dry and not unknown_local:
            from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

            catalog, _configured = self._local_entry_catalog()
            unknown_fit_without_precision = []
            incompatible = []
            for spec in local:
                entry = catalog.get(spec, {})
                if spec.startswith("ollama:"):
                    try:
                        self._validate_ollama_local_entry(spec, entry)
                    except ValueError as exc:
                        errors.setdefault("models", str(exc))
                    continue
                if not spec.startswith("vllm:"):
                    continue
                try:
                    self._validated_local_modalities(
                        spec, entry, project_richer=True
                    )
                    self._local_gpu_memory_utilization(spec, entry)
                    max_model_len = self._local_max_model_len(spec, entry)
                    max_tokens = self._local_max_tokens(spec, entry)
                    fit = self._effective_local_profile(
                        spec,
                        entry,
                        default_quantization=params.get("quantization", ""),
                        model_quantization=params.get(f"quantization::{spec}", ""),
                    ).get("fits")
                except ValueError as exc:
                    errors.setdefault("models", str(exc))
                    continue
                if max_model_len is not None and max_tokens > max_model_len:
                    errors.setdefault(
                        "models",
                        f"local target {spec!r} max_tokens must not exceed "
                        "max_model_len",
                    )
                    continue
                model_quantization = str(params.get(f"quantization::{spec}", "")).strip().lower()
                if fit is None:
                    if model_quantization in {"", "auto"}:
                        unknown_fit_without_precision.append(spec)
                elif fit is False:
                    incompatible.append(spec)
            if incompatible:
                errors.setdefault(
                    "models",
                    "live local target is known incompatible with this "
                    "hardware: " + ", ".join(incompatible),
                )
            elif unknown_fit_without_precision:
                errors.setdefault(
                    "models",
                    "live local target hardware fit is unknown; choose an "
                    "explicit per-model precision before running: "
                    + ", ".join(unknown_fit_without_precision),
                )
            unpinned = []
            for spec in local:
                entry = catalog.get(spec, {})
                revision = entry.get("revision")
                digest = entry.get("digest")
                revision_ok = (
                    isinstance(revision, str)
                    and re.fullmatch(
                        r"[0-9a-fA-F]{40,64}",
                        revision,
                    )
                    is not None
                )
                digest_ok = (
                    isinstance(digest, str)
                    and re.fullmatch(
                        r"[0-9a-fA-F]{64}",
                        digest,
                    )
                    is not None
                )
                backend, _separator, model = spec.partition(":")
                digest_identity = backend.lower() == "ollama" or (
                    backend.lower() == "vllm" and _is_explicit_local_path(model)
                )
                identity_ok = (
                    digest_ok and not revision if digest_identity else revision_ok and not digest
                )
                if not identity_ok:
                    unpinned.append(spec)
            if unpinned:
                errors.setdefault(
                    "models",
                    "live hub vLLM targets require a 40-64 hex revision; "
                    "explicit local checkpoints and Ollama targets require a "
                    "64-hex digest: " + ", ".join(unpinned),
                )

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
        sample_seed_value = require_int("sample_seed")
        max_queries_value = require_int("max_queries", positive=True)
        max_turns_value = require_int("max_turns", positive=True)
        if harm_requirements is not None:
            captured_corpus, captured_limit, captured_seed, minimum = harm_requirements
            if corpora != [captured_corpus]:
                errors["corpora"] = (
                    "HarmBench replay requires exactly its captured corpus arm: " + captured_corpus
                )
            if limit != captured_limit:
                errors["limit"] = f"HarmBench replay requires its captured limit {captured_limit}"
            effective_seed = 0 if sample_seed_value is None else sample_seed_value
            if effective_seed != captured_seed:
                errors["sample_seed"] = (
                    f"HarmBench replay requires its captured sample seed {captured_seed}"
                )
            if max_queries_value is None or max_queries_value < minimum:
                errors["max_queries"] = (
                    f"HarmBench replay requires at least {minimum} queries "
                    "(methods x cases per method)"
                )
            if max_turns_value is None or max_turns_value < minimum:
                errors["max_turns"] = (
                    f"HarmBench replay requires at least {minimum} turns "
                    "(methods x cases per method)"
                )

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

        has_project = env_or("project_revision", "URA_PROJECT_REVISION_MANIFEST") and env_or(
            "project_revision_sha", "URA_PROJECT_REVISION_SHA256"
        )
        has_source = env_or("source_conformance", "URA_SOURCE_CONFORMANCE_MANIFEST") and env_or(
            "source_conformance_sha", "URA_SOURCE_CONFORMANCE_SHA256"
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
                    errors[cap] = "required: a finite positive ceiling before any non-dry run"

        def require_live_admission() -> None:
            if not params.get("scope", ""):
                errors["scope"] = "required for live execution"
            age = params.get("max_age", "")
            try:
                age_value = float(age) if age else 0.0
            except ValueError:
                age_value = 0.0
            if not 0 < age_value <= 8760:
                errors["max_age"] = "required: maximum attestation age in hours, in (0, 8760]"
            if not att_rows:
                errors["att"] = "at least one live-attestation receipt/digest pair is required"
            if not has_project:
                errors["project_revision"] = (
                    "required: validated project-revision receipt and digest "
                    "(field or campaign environment)"
                )
            if real_corpora and not has_source:
                errors["source_conformance"] = (
                    "required: validated source-conformance receipt and digest for real source arms"
                )
            require_caps_and_deadline()

        for path, sha in att_rows:
            if not path or not sha:
                errors["att"] = (
                    "every receipt row needs both the receipt path and its exact 64-hex digest"
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
        if not judges_list:
            errors["judges"] = "select at least one judge"
        if len(local) > 1:
            errors["models"] = (
                "one local target per process (vLLM/Ollama engines must not "
                "accumulate on the rig GPUs)"
            )

        # -- exact modality + agentic + guardrail-separation admission --------
        # Server-side and complete: a target/attacker must serve EVERY modality
        # an arm carries (not merely share one), agentic arms are rejected, and
        # the scoring and defense guardrails must be distinct identities.  This
        # is the real gate; the client-side filter is only convenience.
        # Native-only attackers cannot be replayed through the common Runner
        # (run_matrix rejects them); reject before any subprocess with the real
        # action rather than letting the CLI fail after launch.
        native_selected = [a for a in attackers if a in _NATIVE_ONLY_ATTACKERS]
        if native_selected:
            errors["attackers"] = (
                f"{', '.join(native_selected)} "
                + ("is a" if len(native_selected) == 1 else "are")
                + " native-artifact integration(s); run_matrix cannot replay "
                "them through the common Runner. Import their native traces "
                "with the native_import command instead"
            )
        arm_mods = {arm: set(mods) for arm, mods, _r in _ARM_CATALOG}
        fw_mods = {fw: set(mods) for fw, _d, mods in _FRAMEWORKS}
        for arm in real_corpora:
            if arm in _INELIGIBLE_ARMS:
                errors["corpora"] = f"{arm} is common-metric-ineligible: {_INELIGIBLE_REASONS[arm]}"
                continue
            if arm in _SOURCE_METRIC_ARMS:
                metric, allowed = _SOURCE_METRIC_ARMS[arm]
                unsupported = [a for a in attackers if a not in allowed]
                if unsupported:
                    errors["attackers"] = (
                        f"arm {arm} is scored only by the implemented "
                        f"'{metric}' source metric, which run_matrix admits "
                        f"solely for the {'/'.join(allowed)} attacker; remove "
                        f"{', '.join(unsupported)} or the grid contains "
                        "unscored cells"
                    )
            needed = arm_mods.get(arm)
            if needed is None:
                continue  # unknown arm id: left to the CLI's own registry check
            for kind, target in [("api", value) for value in api] + [
                ("local", value) for value in local
            ]:
                have = target_mods.get((kind, target))
                if have is not None and not needed <= have:
                    errors["models"] = (
                        f"target {target} serves {sorted(have) or ['text']} but "
                        f"arm {arm} requires all of {sorted(needed)}"
                    )
            for attacker in attackers:
                can = fw_mods.get(attacker)
                if can is not None and not needed <= can:
                    errors["attackers"] = (
                        f"attacker {attacker} drives {sorted(can)} but arm "
                        f"{arm} requires all of {sorted(needed)}"
                    )
        if "guardrail" in judges_list and not params.get("guardrail_model", ""):
            errors["guardrail_model"] = "the scoring guardrail judge requires a guardrail model"
        scoring_guardrail = "guardrail" in judges_list
        defense_guardrail = params.get("defense_guard", "") == "guardrail" and params.get(
            "defense", ""
        ) not in ("", "none")
        if (
            scoring_guardrail
            and re.fullmatch(r"[0-9a-fA-F]{40,64}", params.get("guardrail_revision", "")) is None
        ):
            errors["guardrail_revision"] = (
                "the scoring guardrail requires an immutable 40-64 hex revision"
            )
        if defense_guardrail:
            if not params.get("defense_guardrail_model", ""):
                errors["defense_guardrail_model"] = (
                    "the defense guardrail requires a defense guardrail model"
                )
            if (
                re.fullmatch(
                    r"[0-9a-fA-F]{40,64}",
                    params.get("defense_guardrail_revision", ""),
                )
                is None
            ):
                errors["defense_guardrail_revision"] = (
                    "the defense guardrail requires an immutable 40-64 hex revision"
                )
            if not params.get("defense_guardrail_device", ""):
                errors["defense_guardrail_device"] = (
                    "the defense guardrail requires an explicit device"
                )
        scoring_g = params.get("guardrail_model", "")
        defense_g = params.get("defense_guardrail_model", "")
        if (
            scoring_guardrail
            and defense_guardrail
            and scoring_g
            and defense_g
            and scoring_g == defense_g
        ):
            errors["defense_guardrail_model"] = (
                "the scoring guard and the defense guard must be distinct "
                "models - a tested guard must never grade its own output"
            )
        if (
            mode != "dry_run"
            and not canary_dry
            and real_corpora
            and "llm" in judges_list
            and params.get("judge_model", "").strip().lower() == "mock"
        ):
            errors["judge_model"] = "a real-source live lane cannot use the mock LLM judge"

        if mode == "dry_run":
            forbid_live_fields("a diagnostic dry run cannot consume or produce live attestation")
        elif mode == "attestation_probe":
            if targets != 1:
                errors["models"] = "an attestation probe takes exactly one target"
            if len(corpora) != 1:
                errors["corpora"] = "an attestation probe takes exactly one corpus"
            if attackers != ["replay"]:
                errors["attackers"] = "an attestation probe uses exactly the replay attacker"
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
                errors["source_conformance"] = "required for a real-source probe corpus"
            if att_rows:
                errors["att"] = "an attestation probe cannot consume prior attestations"
            if params.get("max_age", ""):
                errors["max_age"] = "an attestation probe cannot consume prior attestations"
            require_caps_and_deadline()
        elif mode == "diagnostic_canary":
            if limit != 1:
                errors["limit"] = (
                    "a diagnostic canary requires exactly --limit 1 (all rows "
                    "in that source cluster are retained)"
                )
            if len(attackers) != 1:
                errors["attackers"] = "a diagnostic canary takes exactly one attacker"
            if len(seeds) != 1:
                errors["seeds"] = "a diagnostic canary takes exactly one seed"
            if canary_dry:
                # The dry canary is composed as offline-synthetic (corpora
                # synth, no targets, no receipts): the operator only picks the
                # attacker/seed/limit, so no arm or target selection is
                # required, and live-attestation fields are forbidden.
                forbid_live_fields("a dry canary cannot consume or produce live attestation")
            else:
                if len(corpora) != 1:
                    errors["corpora"] = "a live canary takes exactly one corpus"
                if targets != 1:
                    errors["models"] = "a live canary takes exactly one target model"
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

    def _read_lane_projection(
        self,
        params: Mapping[str, str],
    ) -> tuple[dict[str, int] | None, str]:
        """The required target/judge/HTTP upper bounds from a no-call preflight.

        Only a successful console preflight carrying the same normalized grid
        parameters can authorize the preview. The three provisional planning
        caps may change to the preflight's printed totals; every other builder
        field remains exact. Its stdout names the content-addressed projection,
        which is validated before any bound is used.
        """

        from ura.lane_projection import validate_lane_projection  # noqa: PLC0415

        out_rel = params.get("out", "")
        if not out_rel:
            return None, "select an output directory and run the preflight"
        normalized = self._projection_params(params)
        preflights = sorted(
            (
                job
                for job in self.jobs.values()
                if "--preflight-only" in job.argv
                and self._projection_params(job.builder_params or {}) == normalized
                and job.state() == "complete"
            ),
            key=lambda job: job.started_at,
            reverse=True,
        )
        if not preflights:
            return None, (
                "no successful no-call preflight for these exact selections: "
                "run the preflight below"
            )
        prefix = "prospective no-call lane projection written: "
        for job in preflights:
            preflight_out = _argv_out_dir(job.argv)
            if not preflight_out:
                continue
            unresolved_out = Path(preflight_out)
            out_dir = (
                unresolved_out if unresolved_out.is_absolute() else self.repo_root / unresolved_out
            ).resolve()
            artifact = ""
            for line in reversed(self._log_tail(job, "stdout").splitlines()):
                if prefix not in line:
                    continue
                try:
                    announcement = json.loads(line.split(prefix, 1)[1])
                except (TypeError, ValueError):
                    continue
                if isinstance(announcement, Mapping):
                    artifact = str(announcement.get("artifact", ""))
                break
            if not artifact or Path(artifact).name != artifact:
                continue
            candidate = (out_dir / artifact).resolve()
            if candidate.parent != out_dir:
                continue
            try:
                doc = validate_lane_projection(json.loads(candidate.read_text(encoding="utf-8")))
            except (OSError, TypeError, ValueError):
                continue
            projection = doc["call_projection"]
            return {
                key: int(projection[key])
                for key in ("target_calls", "judge_calls", "http_attempts")
            }, ""
        return None, "the matching preflight's lane projection is missing or invalid"

    def _ceilings_card(self, params: Mapping[str, str]) -> tuple[str, bool]:
        """The call-ceiling summary shown before a non-dry job starts.

        Returns ``(html, caps_cover_projection)``: the boolean is true only
        when an exact, valid no-call projection exists and every entered
        ceiling covers it.
        """

        api = self._split_list(params.get("api", ""))
        local = self._split_list(params.get("local", ""))
        corpora = self._split_list(params.get("corpora", ""))
        attackers = self._split_list(params.get("attackers", ""))
        seeds = self._split_list(params.get("seeds", "") or "0")
        grid_cells = max(1, len(api) + len(local)) * max(1, len(corpora)) * max(1, len(attackers))
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
                (
                    "cap_target",
                    "--max-total-target-calls",
                    "hard circuit-breaker on model-under-test calls",
                ),
                (
                    "cap_judge",
                    "--max-total-judge-calls",
                    "hard circuit-breaker on hosted judge calls",
                ),
                (
                    "cap_http",
                    "--max-total-http-attempts",
                    "hard cap on transport attempts, retries included",
                ),
                ("deadline", "--deadline-seconds", "wall-clock admission deadline for the lane"),
                (
                    "limit",
                    "--limit",
                    "cluster subsample per corpus (cluster sibling rows are all "
                    "retained, so row counts can exceed this)",
                ),
                ("max_queries", "--max-queries", "target calls per datapoint and seed"),
                ("max_turns", "--max-turns", "conversation turns per datapoint and seed"),
            )
        )
        # No-call projection: the required upper bounds from the CLI preflight
        # (never estimated here).  Compare each entered ceiling against its
        # projected requirement; a shortfall blocks Start.
        projection, why = self._read_lane_projection(params)
        caps_ok = projection is not None
        if projection is not None:
            proj_rows = []
            for label, cap_field, proj_key in (
                ("target calls", "cap_target", "target_calls"),
                ("judge calls", "cap_judge", "judge_calls"),
                ("HTTP attempts", "cap_http", "http_attempts"),
            ):
                required = projection[proj_key]
                entered_raw = params.get(cap_field, "")
                try:
                    entered = int(entered_raw) if entered_raw else None
                except ValueError:
                    entered = None
                covers = entered is not None and entered >= required
                if not covers:
                    caps_ok = False
                proj_rows.append(
                    f"<tr><td>{label}</td><td><strong>{required:,}</strong></td>"
                    f"<td>{html.escape(entered_raw) or '(unset)'}</td>"
                    "<td>"
                    + (
                        "<span class='badge green'>covers</span>"
                        if covers
                        else "<span class='badge red'>below required</span>"
                    )
                    + "</td></tr>"
                )
            projection_html = (
                "<h3>No-call projection (from the CLI preflight)</h3>"
                "<div class='scroll'><table><tr><th>Call kind</th>"
                "<th>Projected required</th><th>Your ceiling</th><th></th></tr>"
                + "".join(proj_rows)
                + "</table></div>"
                + (
                    ""
                    if caps_ok
                    else "<div class='notice red'><strong>A ceiling is below the "
                    "projected requirement.</strong><p class='note'>Raise the "
                    "flagged ceiling(s) to at least the projected upper bound "
                    "before starting; run_matrix would reject the lane "
                    "otherwise.</p></div>"
                )
            )
        else:
            projection_html = (
                "<h3>No-call projection</h3><p class='note'>" + html.escape(why) + ".</p>"
            )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Calculated call "
            "ceilings</h2>"
            f"<p><strong>{html.escape(shape)}</strong></p>"
            "<div class='scroll'><table><tr><th>Ceiling</th><th>Value</th>"
            "<th>Meaning</th></tr>"
            + rows
            + "</table></div>"
            + projection_html
            + "<p class='note'>The entered ceilings are the binding budget "
            "guards; run_matrix rejects the lane if they cannot cover its "
            "exact no-call projection. The projection above is computed by the "
            "CLI preflight from the real corpus (a call bound, not a price "
            "estimate), never estimated here.</p></div>"
        ), caps_ok

    def _preview_page(
        self,
        command: str,
        values: Mapping[str, str],
        params: Mapping[str, str],
    ) -> bytes:
        """Exact argv + ceilings confirmation before a non-dry job starts."""

        argv = build_argv(command, values, commands=self.commands)
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in argv)
            + "</div>"
        )
        hidden = "".join(
            f"<input type='hidden' name='{html.escape(key)}' value='{html.escape(value)}'>"
            for key, value in sorted(params.items())
        )
        mode = params.get("mode", "measured")
        ceilings_html, caps_ok = self._ceilings_card(params)
        # A "Run no-call preflight" action composes the SAME grid with
        # --preflight-only (no calls) so the operator can produce the projection
        # this page reads and compares against.
        preflight_hidden = "".join(
            f"<input type='hidden' name='{html.escape(key)}' value='{html.escape(value)}'>"
            for key, value in sorted(params.items())
        )
        preflight_form = (
            "<form method='post' action='/build'>"
            + preflight_hidden
            + "<input type='hidden' name='confirm' value='yes'>"
            "<input type='hidden' name='preflight_only' value='yes'>"
            "<button type='submit' class='ghost' "
            "data-busy='Running the no-call preflight projection...'>"
            + _icon("pulse", size=15)
            + "Run no-call preflight (projection, no calls)</button></form> "
        )
        start_button = (
            "<button type='submit'>" + _icon("play", size=15) + "Start this job</button>"
            if caps_ok
            else "<button type='submit' disabled>"
            + _icon("play", size=15)
            + "Start blocked: run preflight / cover its projection</button>"
        )
        body = (
            "<h1>" + _icon("play", size=22) + "Confirm paid execution</h1>"
            "<div class='notice amber'><strong>This mode spends real "
            "money.</strong><p class='note'>Mode: "
            f"<code>{html.escape(mode)}</code>. Review the exact command and "
            "ceilings below; nothing has started yet.</p></div>"
            "<div class='card'><h2>"
            + _icon("terminal")
            + "Exact command</h2>"
            + argv_chips
            + preflight_form
            + "</div>"
            + ceilings_html
            + "<form method='post' action='/build'>"
            + hidden
            + "<input type='hidden' name='confirm' value='yes'>"
            "<div class='buildbar'>"
            + start_button
            + "<a href='/build'><button type='button' class='ghost'>Back to "
            "builder</button></a></div></form>"
        )
        return _page("Confirm execution", body, active="Build")
