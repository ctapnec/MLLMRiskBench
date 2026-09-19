"""Campaign setup defaults and discovery of its already completed transport checks."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import hashlib
import json
import os
import html
from datetime import datetime, timezone
from pathlib import Path

from ura.live_attestation import load_live_attestation_file


class BuilderSetupMixin:
    def _transport_check_form(self, campaign_id):
        options = _ui_template(
            "<option value=''>[[text:builder_setup.choose_a_completed_probe]]</option>"
        )
        for row in self.db.completed_probe_jobs(campaign_id) or []:
            params = json.loads(row["builder_params"] or "{}")
            label = " - ".join(
                (
                    row["campaign_name"] or _ui_text("builder_setup.standalone"),
                    params.get("local") or params.get("api") or _ui_text("builder_setup.model"),
                    params.get("corpora") or _ui_text("builder_setup.input"),
                    row["job_id"],
                )
            )
            options += (
                "<option value='"
                + html.escape(row["job_id"])
                + "'>"
                + html.escape(label)
                + "</option>"
            )
        return (
            _ui_template(
                "<details class='cmd' data-name='live_attestation saved transport checks'><summary><span class='name'>live_attestation</span><span class='desc'>[[text:builder_setup.use_a_completed_probe]]</span></summary><div class='inner'><p>[[text:builder_setup.select_the_probe_by_name_its_scope_output_location_and_campaign_a]]</p><form class='cmd' method='post' action='/jobs'><input type='hidden' name='command' value='live_attestation'><input type='hidden' name='campaign_id' value='"
            )
            + html.escape(campaign_id)
            + _ui_template(
                "'><label>[[text:builder_setup.completed_probe]]</label><select name='probe_job' required>"
            )
            + options
            + _ui_template(
                "</select><span></span><button type='submit' data-busy='[[attr:builder_setup.preparing_the_saved_transport_check]]'>[[text:builder_setup.prepare_transport_check]]</button></form></div></details>"
            )
        )

    def _transport_check_from_job(self, job_id, campaign_id):
        rows = self.db.completed_probe_jobs(campaign_id) or []
        row = next((row for row in rows if row["job_id"] == job_id), None)
        if row is None:
            raise ValueError(_ui_text("builder_setup.select_a_completed_probe_from_this_campaign"))
        params = json.loads(row["builder_params"] or "{}")
        owner = row["campaign_id"] or ""
        scope = params.get("scope", "")
        root = Path(row["out_dir"]).resolve(strict=True)
        if not scope or not root.is_relative_to(self.results_root.resolve()):
            raise ValueError(
                _ui_text("builder_setup.the_completed_probe_has_no_usable_scope_or_output")
            )
        for prior in self.db.completed_workspace_transport_jobs(owner) or []:
            argv = json.loads(prior["argv"])
            if all(flag in argv for flag in ("--probe-root", "--execution-scope-id", "--out")):
                if (
                    Path(argv[argv.index("--probe-root") + 1]).resolve() == root
                    and argv[argv.index("--execution-scope-id") + 1] == scope
                    and Path(argv[argv.index("--out") + 1]).is_file()
                ):
                    return owner, {}, prior["job_id"]
        return (
            owner,
            {
                "--probe-root": str(root),
                "--execution-scope-id": scope,
                "--out": str(root.parent / ("transport-" + job_id + ".json")),
            },
            "",
        )

    def _campaign_transport_receipts(self, params):
        owner = params.get("campaign_id", "")
        targets = set(
            self._split_list(params.get("local", "")) + self._split_list(params.get("api", ""))
        )
        scope = params.get("scope", "")
        if not targets or not scope:
            return [], _ui_text("builder_setup.select_models_to_match_completed_transport_checks")
        try:
            maximum_age = float(params.get("max_age") or "24")
            if not 0 < maximum_age <= 8760:
                raise ValueError("age")
            snapshot = self._project_revision_snapshot(params)
            if snapshot is None:
                return [], _ui_text("builder_setup.the_runner_project_receipt_is_not_configured")
            _, project_sha = snapshot
        except (OSError, ValueError):
            return [], _ui_text(
                "builder_setup.the_runner_project_receipt_or_maximum_age_needs_attention"
            )
        rows = self.db.completed_workspace_transport_jobs(owner)
        if rows is None:
            return [], _ui_text("builder_setup.the_campaign_job_index_is_unavailable")
        candidates = []
        now = datetime.now(timezone.utc)
        for row in rows:
            try:
                argv = json.loads(row["argv"])
                if "--out" not in argv:
                    continue
                path = Path(argv[argv.index("--out") + 1])
                if not path.is_absolute():
                    path = self.repo_root / path
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or not 0 < path.stat().st_size <= 4 * 1024 * 1024
                ):
                    continue
                path = path.resolve(strict=True)
                if not path.is_relative_to(self.results_root.resolve()):
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                manifest, _ = load_live_attestation_file(path, digest)
                records = [
                    record
                    for record in manifest["records"]
                    if record["requested_target_spec"] in targets
                    and record["execution_scope_id"] == scope
                ]
                if not records:
                    continue
                observed = [
                    datetime.fromisoformat(record["observed_at_utc"].replace("Z", "+00:00"))
                    for record in records
                ]
                if any(
                    record["probe"]["project_revision"]["sha256"] != project_sha
                    for record in records
                ):
                    continue
                if any(
                    not 0 <= (now - stamp).total_seconds() / 3600 <= maximum_age
                    for stamp in observed
                ):
                    continue
                keys = {
                    (record["requested_target_spec"], tuple(record["exact_input_modalities"]))
                    for record in records
                }
                candidates.append((min(observed), str(path), digest, keys, row["job_id"]))
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                continue
        selected, seen = [], set()
        for _, path, digest, keys, job_id in sorted(candidates, reverse=True):
            # Select whole existing files, never rewrite or splice their records.
            if keys & seen:
                continue
            selected.append(
                {"path": path, "sha256": digest, "keys": sorted(keys), "job_id": job_id}
            )
            seen.update(keys)
            if len(selected) == self._MAX_ATT_ROWS:
                break
        if not selected:
            return [], _ui_text(
                "builder_setup.no_matching_current_transport_checks_found_in_this_campaign_compl"
            )
        descriptions = [model + ": " + "+".join(modalities) for model, modalities in sorted(seen)]
        return selected, (
            _ui_text("builder_setup.found")
            + str(len(selected))
            + _ui_text("builder_setup.completed_transport_check_s")
            + "; ".join(descriptions)
            + _ui_text(
                "builder_setup.selected_automatically_on_review_exact_route_and_input_coverage_a"
            )
        )

    def _automatic_campaign_setup(self, params, *, refresh=False):
        """Resolve an editable form once; never rebind a confirmed snapshot."""
        if params.get("setup_mode") != "automatic":
            return params
        if not refresh and params.get("_setup_resolved") == "yes":
            return params
        params = dict(params)
        owner = params.get("campaign_id", "")
        if not owner and params.get("work_kind") == "campaign":
            return params  # Assigned immediately after the campaign is created.
        saved = self.db.workspace_definition(owner) if owner else {}
        params["scope"] = (
            saved.get("scope")
            or params.get("scope")
            or ("campaign-" + owner if owner else "standalone")
        )
        for field, variable in (
            ("project_revision", "URA_PROJECT_REVISION_MANIFEST"),
            ("project_revision_sha", "URA_PROJECT_REVISION_SHA256"),
            ("source_conformance", "URA_SOURCE_CONFORMANCE_MANIFEST"),
            ("source_conformance_sha", "URA_SOURCE_CONFORMANCE_SHA256"),
        ):
            if os.environ.get(variable):
                params[field] = os.environ[variable]
        # Stable per configuration, so save/review/preflight use the same output.
        # Existing manually named probe directories and historical jobs are untouched.
        presentation = {
            "out",
            "campaign_id",
            "campaign_name",
            "campaign_guide",
            "work_kind",
            "modality_scope",
            "setup_mode",
            "max_age",
        }
        identity = {
            key: value
            for key, value in params.items()
            if key not in presentation and not key.startswith(("_", "att_path", "att_sha"))
        }
        suffix = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:12]
        mode = params.get("mode", "measured")
        base = (
            self.results_root.resolve() / "campaigns" / owner
            if owner
            else self.results_root.resolve() / "standalone"
        )
        directory = str(base / (mode + "-" + suffix))
        attempts = self.db.automatic_output_attempts(directory) or []
        terminal = {
            row["out_dir"]
            for row in attempts
            if row["state"] in {"complete", "failed", "stopped", "interrupted"}
        }
        candidate = directory
        number = 1
        while candidate in terminal:
            number += 1
            candidate = directory + "-attempt-" + str(number)
        params["out"] = candidate
        for i in range(1, self._MAX_ATT_ROWS + 1):
            params.pop(f"att_path{i}", None)
            params.pop(f"att_sha{i}", None)
        offline = mode == "dry_run" or (
            mode == "diagnostic_canary" and params.get("canary_dry") == "on"
        )
        if offline or mode == "attestation_probe":
            params.pop("max_age", None)
            if offline:
                params.pop("scope", None)
        else:
            params["max_age"] = "24"
            selected, _ = self._campaign_transport_receipts(params)
            for i, receipt in enumerate(selected, 1):
                params[f"att_path{i}"] = receipt["path"]
                params[f"att_sha{i}"] = receipt["sha256"]
        params["_setup_resolved"] = "yes"
        return params
