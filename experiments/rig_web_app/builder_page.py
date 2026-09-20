"""Build-page rendering for campaign composition."""

from __future__ import annotations


from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import hashlib
import html
import json
import math
import os
import re
from typing import Mapping

from ura.targets.api import canonical_api_target_identity
from ura.sampling import (
    DEFAULT_SAMPLING_POLICY,
    SEEDED_PSEUDORANDOM_CLUSTER_PREFIX,
    SOURCE_ORDER_CLUSTER_PREFIX,
)

from .catalog import (
    _MODALITIES,
    _ARM_CATALOG,
    _AGGREGATOR_ARMS,
    _SOURCE_METRIC_ARMS,
    _NATIVE_ONLY_ATTACKERS,
    _BUILDER_OMITTED_ATTACKERS,
    _CLI_ONLY_ATTACKERS,
    _FRAMEWORKS,
    _BUILD_MODES,
    _RUNBOOK_GROUP,
    _LOCAL_BUDGET_HELP,
    _icon,
    _arm_head,
)

from .ui import _BUILDER_SCRIPT, _page, _page_tablist, _page_tabpanel
from .reports import load_pricing, rate_for


class BuilderPageMixin:
    def _ollama_service_card(
        self,
        status: Mapping[str, object],
        roster: Mapping[str, object],
        *,
        action_state: str = "",
        action_error: str = "",
        campaign_id: str = "",
    ) -> str:
        """Render lifecycle controls outside the campaign-builder form."""

        state = str(status.get("state", "unknown"))
        if state not in {"stopped", "starting", "external", "owned", "ambiguous", "busy", "error"}:
            state = "unknown"
        tone = {
            "owned": "green",
            "external": "blue",
            "starting": "amber",
            "ambiguous": "amber",
            "busy": "amber",
            "error": "red",
            "stopped": "gray",
        }.get(state, "red")
        state_copy = {
            "owned": _ui_text("builder_page.running_and_owned_by_this_console_process"),
            "external": (
                _ui_text(
                    "builder_page.running_externally_discovery_is_read_only_and_pulls_are_disabled"
                )
            ),
            "starting": _ui_text(
                "builder_page.console_owned_process_is_starting_the_api_is_not_ready_yet"
            ),
            "ambiguous": (
                _ui_text(
                    "builder_page.api_reachable_but_listener_ownership_is_unverified_pulls_are_disa"
                )
            ),
            "busy": _ui_text(
                "builder_page.another_ollama_mutation_or_inference_holds_the_endpoint_lock"
            ),
            "error": (
                _ui_text(
                    "builder_page.console_owned_process_residue_could_not_be_fully_cleaned_stop_can"
                )
            ),
            "stopped": _ui_text(
                "builder_page.no_compatible_daemon_is_reachable_on_the_loopback_endpoint"
            ),
            "unknown": _ui_text("builder_page.daemon_state_could_not_be_classified"),
        }[state]
        can_stop = status.get("can_stop") is True
        loaded_value = status.get("loaded_models")
        loaded = (
            [str(value) for value in loaded_value if isinstance(value, str)][:16]
            if isinstance(loaded_value, list)
            else []
        )
        roster_models = roster.get("models")
        models = roster_models if isinstance(roster_models, list) else []
        roster_issues = roster.get("issues")
        issues = roster_issues if isinstance(roster_issues, list) else []

        feedback = ""
        bounded_error = action_error.strip()[:1000]
        if bounded_error:
            feedback = (
                _ui_template(
                    "<div class='notice red'><strong>[[text:builder_page.ollama_action_failed]]</strong> "
                )
                + html.escape(bounded_error)
                + "</div>"
            )
        elif action_state in {
            "stopped",
            "starting",
            "external",
            "owned",
            "ambiguous",
            "busy",
            "error",
        }:
            feedback = (
                _ui_template(
                    "<div class='notice green'><strong>[[text:builder_page.ollama_action_completed]]</strong> [[text:builder_page.current_state]] "
                )
                + html.escape(_ui_label(state))
                + ".</div>"
            )

        diagnostics: list[str] = []
        for value in (status.get("warning"), status.get("last_error")):
            if isinstance(value, str) and value.strip() and value.strip() not in diagnostics:
                diagnostics.append(value.strip())
        roster_error = roster.get("error")
        if isinstance(roster_error, str) and roster_error.strip():
            diagnostics.append(roster_error.strip())
        diagnostics.extend(
            str(value).strip() for value in issues[:8] if isinstance(value, str) and value.strip()
        )
        diagnostic_html = (
            _ui_template("<details><summary>[[text:builder_page.discovery_diagnostics]]")
            + str(len(diagnostics))
            + ")</summary><ul>"
            + "".join(f"<li>{html.escape(value)}</li>" for value in diagnostics)
            + "</ul></details>"
            if diagnostics
            else ""
        )

        loaded_html = (
            _ui_template("<p class='note'>[[text:builder_page.loaded_now]] ")
            + ", ".join(f"<code>{html.escape(value)}</code>" for value in loaded)
            + (
                _ui_text("builder_page.and_more")
                if isinstance(loaded_value, list) and len(loaded_value) > 16
                else ""
            )
            + ".</p>"
            if loaded
            else (
                _ui_template(
                    "<p class='note'>[[text:builder_page.no_loaded_model_is_reported_by]] <code>/api/ps</code>.</p>"
                )
            )
        )

        start_disabled = "" if state == "stopped" else " disabled"
        stop_disabled = "" if can_stop else " disabled"
        pull_disabled = "" if status.get("can_pull") is True else " disabled"
        return (
            _ui_template(
                "<div class='card' id='ollama-service'><h2>[[text:builder_page.local_ollama_service]]</h2>"
            )
            + feedback
            + "<p><span class='badge "
            + tone
            + "'>"
            + html.escape(_ui_label("absent" if state == "stopped" else state))
            + "</span> "
            + html.escape(state_copy)
            + _ui_template(".</p><p class='note'>[[text:builder_page.fixed_loopback_api]] <code>")
            + html.escape(str(status.get("base_url", "http://127.0.0.1:11434")))
            + _ui_template(
                "</code>[[text:builder_page.discovery_and_inference_use_bounded_standard_library_http_no_olla]] <a href='/ollama/status'>[[text:builder_page.json_status]]</a>.</p>"
            )
            + "<p><strong>"
            + str(len(models))
            + _ui_template(
                " [[text:builder_page.exact_live_candidate_s]]</strong>[[text:builder_page.vllm_availability_never_excludes_an_installed_ollama_tag]]</p>"
            )
            + loaded_html
            + diagnostic_html
            + (
                _ui_template(
                    "<div class='workflow-actions'><form class='inline' method='get' action='/build#ollama-service'><button class='ghost' type='submit'>[[text:builder_page.status]]</button></form><form class='inline' method='post' action='/ollama/start' data-busy><button type='submit'"
                )
                + f"{start_disabled}"
                + _ui_template(
                    ">[[text:builder_page.start]]</button></form><form class='inline' method='post' action='/ollama/stop' data-busy><button class='danger' type='submit'"
                )
                + f"{stop_disabled}"
                + _ui_template(
                    ">[[text:builder_page.stop]]</button></form></div><h3>[[text:builder_page.pull_a_model]]</h3><p class='note'>[[text:builder_page.enter_the_daemon_model_tag_without_the]] <code>ollama:</code> [[text:builder_page.target_prefix_the_typed_job_streams_bounded_download_progress_job]] <span class='badge blue'>[[text:builder_page.downloading]]</span> [[text:builder_page.only_while_its_explicit_activity_is_live_a_successful_pull_automa]]</p><form class='cmd' method='post' action='/ollama/pull' data-busy><input type='hidden' name='campaign_id' data-builder-campaign value='"
                )
            )
            + html.escape(campaign_id)
            + (
                _ui_template(
                    "'><label for='ollama-pull-model'>[[text:builder_page.exact_model_tag]]</label><input id='ollama-pull-model' type='text' name='model' maxlength='256' autocomplete='off' placeholder='llama3.2:3b' required"
                )
                + f"{pull_disabled}"
                + "><span></span><button type='submit'"
                + f"{pull_disabled}"
                + _ui_template(">[[text:builder_page.pull_model]]</button></form></div>")
            )
        )

    def _framework_runtime_panel(
        self,
        *,
        action_state: str = "",
        action_error: str = "",
    ) -> str:
        """Render one state-derived installer action per isolated environment."""

        snapshot = self.framework_runtimes.snapshot()
        feedback = ""
        if action_error:
            feedback = (
                _ui_template(
                    "<div class='notice red'><strong>[[text:builder_page.runtime_action_was_not_launched]]</strong> "
                )
                + html.escape(action_error[:500])
                + "</div>"
            )
        elif action_state == "launched":
            feedback = _ui_template(
                "<div class='notice blue'><strong>[[text:builder_page.named_runtime_session_launched]]</strong> [[text:builder_page.the_installer_owns_the_tmux_screen_process_follow_its_retained_en]]</div>"
            )
        if not snapshot.available:
            return (
                feedback
                + "<div class='card'><h2>"
                + _icon("box")
                + _ui_template(
                    "[[text:builder_page.isolated_framework_runtimes]] <span class='badge red'>[[text:builder_page.unavailable]]</span></h2><p class='note'>"
                )
                + html.escape(snapshot.message)
                + _ui_template(" [[text:builder_page.no_installer_command_was_run]]</p></div>")
            )

        campaign_link = ""
        if snapshot.campaign_state != "idle":
            campaign_link = (
                " <a href='/jobs/campaign/"
                + html.escape(snapshot.campaign_route_id, quote=True)
                + _ui_template("'>[[text:builder_page.open_retained_campaign]]</a>")
            )
        campaign_tone = {
            "running": "blue",
            "complete": "green",
            "failed": "red",
            "orphaned": "amber",
        }.get(snapshot.campaign_state, "gray")
        rows = []
        for index, runtime in enumerate(snapshot.rows, start=1):
            latest = runtime.latest
            latest_reports_running = latest is not None and latest.status == "running"
            if latest_reports_running and snapshot.campaign_state == "running":
                state_text = f"{_ui_label(latest.action)}" + _ui_text("builder_page.running")
                tone = "blue"
                next_action = (
                    runtime.plan_action
                    if runtime.plan_action in {"install", "resume", "verify"}
                    else ""
                )
                history = _ui_text(
                    "builder_page.the_retained_task_log_has_no_terminal_event_the_exact_plan_remain"
                )
            elif latest_reports_running:
                campaign_label = (
                    snapshot.campaign_status_tag.strip()
                    or snapshot.campaign_state.strip()
                    or "unknown"
                )
                state_text = f"{_ui_label(latest.action)} {campaign_label}"
                tone = {
                    "failed": "red",
                    "orphaned": "amber",
                    "unknown": "amber",
                    "complete": "amber",
                }.get(snapshot.campaign_state, "gray")
                next_action = (
                    runtime.plan_action
                    if runtime.plan_action in {"install", "resume", "verify"}
                    else ""
                )
                history = (
                    _ui_text(
                        "builder_page.the_retained_task_log_has_no_terminal_event_but_the_enclosing_cam"
                    )
                    + f"{campaign_label}"
                    + _ui_text(
                        "builder_page.this_action_is_not_reported_as_live_the_exact_current_plan_remain"
                    )
                )
            elif runtime.plan_action == "install":
                state_text = _ui_text("builder_page.not_installed")
                tone = "gray"
                next_action = "install"
                history = _ui_text("builder_page.no_environment_for_this_lock_is_published")
            elif runtime.plan_action == "resume":
                state_text = _ui_text("builder_page.partial_install_retained")
                tone = "amber"
                next_action = "resume"
                history = _ui_text(
                    "builder_page.resume_continues_the_exact_retained_staging_environment"
                )
            elif runtime.plan_action == "verify":
                state_text = _ui_text("builder_page.published_receipt_present")
                tone = "blue"
                next_action = "verify"
                history = _ui_text(
                    "builder_page.this_page_does_not_rehash_the_environment_verify_checks_the_curre"
                )
            else:
                state_text = _ui_text("builder_page.conflicting_unverified_path")
                tone = "red"
                next_action = ""
                history = _ui_text(
                    "builder_page.automatic_replacement_is_refused_follow_the_lock_s_repair_guidanc"
                )

            if latest is not None and latest.status != "running":
                when = (_ui_text("builder_page.at") + f"{latest.at}") if latest.at else ""
                if latest.status == "passed" and latest.action == "verify":
                    history = (
                        _ui_text("builder_page.last_full_verification_passed")
                        + f"{when}"
                        + _ui_text(
                            "builder_page.current_bytes_are_not_implicitly_rehashed_on_page_load"
                        )
                    )
                elif latest.status == "passed" and latest.action in {"install", "resume"}:
                    history = (
                        _ui_text("builder_page.publish_verification_passed") + f"{when}" + ". "
                    ) + history
                elif latest.status == "passed" and latest.action == "adopt":
                    history = (
                        _ui_text("builder_page.runtime_adoption_and_verification_passed")
                        + f"{when}"
                        + ". "
                    ) + history
                elif latest.status == "failed":
                    attempted = latest.action or _ui_text("builder_page.installer_action")
                    history = (
                        _ui_text("builder_page.last")
                        + f"{attempted}"
                        + _ui_text("builder_page.failed")
                        + f"{when}"
                        + ". "
                    ) + history

            action_html = _ui_template(
                "<span class='note'>[[text:builder_page.manual_repair_required]]</span>"
            )
            if next_action:
                label = {
                    "install": _ui_text("builder_page.install"),
                    "resume": _ui_text("builder_page.resume"),
                    "verify": _ui_text("builder_page.verify_now"),
                }[next_action]
                action_html = (
                    (
                        _ui_template(
                            "<form class='inline' method='post' action='/build/framework-runtimes' data-busy='[[attr:builder_page.launching_named_framework_runtime_session]]' id='framework-runtime-action-"
                        )
                        + f"{index}"
                        + "'><input type='hidden' name='framework' value='"
                    )
                    + html.escape(runtime.framework, quote=True)
                    + "'><input type='hidden' name='action' value='"
                    + next_action
                    + "'><button type='submit' class='small'>"
                    + label
                    + "</button></form>"
                )
            rows.append(
                "<tr><td><strong>"
                + html.escape(runtime.display_name)
                + "</strong><br><code>"
                + html.escape(runtime.framework)
                + "</code></td><td>"
                + html.escape(runtime.version)
                + "</td><td>"
                + html.escape(runtime.runtime)
                + "<br><span class='note'>"
                + html.escape(runtime.kind)
                + "</span></td><td><span class='badge "
                + tone
                + "'>"
                + html.escape(state_text)
                + "</span><br><span class='note'>"
                + html.escape(history)
                + "</span></td><td>"
                + action_html
                + "</td></tr>"
            )
        return (
            feedback
            + "<div class='card'><h2>"
            + _icon("box")
            + _ui_template(
                "[[text:builder_page.isolated_framework_runtimes]] <span class='badge blue'>[[text:builder_page.one_environment_per_framework]]</span></h2><p class='note'>[[text:builder_page.the_checked_in_content_lock_selects_every_package_source_and_runt]]</p><dl class='builder-summary'><div><dt>[[text:builder_page.runtime_lock]]</dt><dd><code>sha256:"
            )
            + html.escape(snapshot.lock_id)
            + _ui_template(
                "</code></dd></div><div><dt>[[text:builder_page.managed_environments]]</dt><dd>"
            )
            + str(len(snapshot.rows))
            + _ui_template(
                "</dd></div><div><dt>[[text:builder_page.engineering_campaign]]</dt><dd><span class='badge "
            )
            + campaign_tone
            + "'>"
            + html.escape(snapshot.campaign_status_tag)
            + "</span>"
            + campaign_link
            + _ui_template(
                "</dd></div></dl><p class='action-row'><a class='button ghost' href='/build#build-runtimes'>[[text:builder_page.refresh_status]]</a> <a class='button ghost' href='/jobs'>[[text:builder_page.open_jobs]]</a></p></div><div class='card scroll'><table><tr><th>[[text:builder_page.framework]]</th><th>[[text:builder_page.version]]</th><th>[[text:builder_page.runtime]]</th><th>[[text:builder_page.installed_state]]</th><th>[[text:builder_page.exact_action]]</th></tr>"
            )
            + "".join(rows)
            + "</table></div>"
        )

    def _build_page(
        self,
        prefill: Mapping[str, str] | None = None,
        errors: Mapping[str, str] | None = None,
        *,
        ollama_state: str = "",
        ollama_error: str = "",
        framework_runtime_state: str = "",
        framework_runtime_error: str = "",
        saved: bool = False,
    ) -> bytes:
        # The private local registry may use an operator workstation path as
        # vLLM's runtime locator.  Builder HTML is retained in browser history
        # and may be copied into evidence, so it receives the same content-only
        # identity boundary as Jobs/SQLite.  Unknown/tampered explicit paths
        # have no trustworthy identity and are omitted rather than echoed.
        from .artifacts import assert_durable_job_state_path_free  # noqa: PLC0415

        durable_local_identities = self._catalog_local_identities()

        def durable_ui_text(value: object) -> str:
            projected = str(value)
            for runtime_spec, identity in sorted(
                durable_local_identities.items(),
                key=lambda item: len(item[0]),
                reverse=True,
            ):
                projected = projected.replace(runtime_spec, identity)
                # Defensive coverage for an exception that mentions only the
                # locator portion instead of the complete ``vllm:`` spec.
                runtime_path = runtime_spec.partition(":")[2]
                if runtime_path:
                    projected = projected.replace(
                        runtime_path,
                        identity.removeprefix("vllm:"),
                    )
            try:
                assert_durable_job_state_path_free([projected], None)
            except ValueError:
                return _ui_text("builder_page.private_explicit_local_value_omitted")
            return projected

        safe_prefill: dict[str, str] = {}
        for key, value in dict(prefill or {}).items():
            safe_key = durable_ui_text(key)
            safe_value = durable_ui_text(value)
            # Multiple private locators can intentionally share a content
            # digest.  A presentation collision must not silently choose one.
            if safe_key in safe_prefill and safe_prefill[safe_key] != safe_value:
                safe_prefill[safe_key] = _ui_text(
                    "builder_page.private_explicit_local_value_omitted"
                )
            else:
                safe_prefill[safe_key] = safe_value
        prefill = safe_prefill
        setup_mode = prefill.get("setup_mode", "automatic")
        setup_preview = dict(prefill, setup_mode=setup_mode)
        if setup_mode == "automatic":
            setup_preview = self._automatic_campaign_setup(setup_preview, refresh=True)
        transport_records, transport_status = self._campaign_transport_receipts(setup_preview)
        if (
            setup_mode == "automatic"
            and setup_preview.get("mode") == "measured"
            and not transport_records
        ):
            transport_status = _ui_text(
                "builder_page.missing_connection_checks_will_be_included_in_your_reviewed_exper"
            )
        if setup_preview.get("mode", "dry_run") in {"dry_run", "attestation_probe"}:
            transport_status = _ui_text(
                "builder_page.this_mode_does_not_require_an_existing_transport_check_saved_chec"
            )
        setup_controls = (
            _ui_template(
                "<div class='card' id='transport-evidence'><h2>[[text:builder_page.automatic_setup]]</h2><p>[[text:builder_page.choose_the_experiment_not_filenames_the_console_supplies_output_p]]</p><label>[[text:builder_page.setup]] <select name='setup_mode' form='builder' id='setup-mode'><option value='automatic'"
            )
            + (" selected" if setup_mode == "automatic" else "")
            + _ui_template(
                ">[[text:builder_page.automatic_recommended]]</option><option value='manual'"
            )
            + (" selected" if setup_mode == "manual" else "")
            + _ui_template(
                ">[[text:builder_page.advanced_overrides]]</option></select></label><p id='automatic-transport-status' class='note' role='status'>"
            )
            + html.escape(transport_status)
            + _ui_template(
                "</p><p class='note'>[[text:builder_page.existing_completed_checks_are_reused_the_maximum_age_defaults_to]]</p>"
            )
            + _ui_template(
                "<details><summary>[[text:builder_page.advanced_reuse_an_older_diagnostic]]</summary><p><a href='/commands?cmd=live_attestation&amp;campaign_id="
            )
            + html.escape(prefill.get("campaign_id", ""))
            + _ui_template("'>[[text:builder_page.select_a_completed_probe]]</a></p></details>")
            + "<p class='fielderr'>"
            + html.escape((errors or {}).get("att", ""))
            + "</p></div>"
        )
        errors = {
            durable_ui_text(key): durable_ui_text(value)
            for key, value in dict(errors or {}).items()
        }
        selected_judge_model = prefill.get("judge_model", "").strip()
        selected_target_models = {
            model
            for field in ("api", "local")
            for model in self._split_list(prefill.get(field, ""))
        }

        def err(field: str) -> str:
            message = errors.get(field, "")
            return f"<span class='fielderr'>{html.escape(message)}</span>" if message else ""

        def val(field: str, default: str = "") -> str:
            return html.escape(prefill.get(field, default))

        selected_mode = prefill.get("mode", "dry_run")
        # The tool-conditioned exclusion defaults ON for a standalone dry lane
        # (the synth corpus carries rows no Runner attacker can execute) and is
        # disabled and forced OFF otherwise. A re-rendered dry form keeps the
        # operator's choice (an unchecked box is absent from the submission).
        exclude_tool_conditioned_checked = selected_mode == "dry_run" and (
            prefill.get("exclude_tool_conditioned") == "on" if "mode" in prefill else True
        )
        exclude_tool_conditioned_disabled = "" if selected_mode == "dry_run" else " disabled"
        # Mode radios.
        mode_html = "".join(
            "<label class='radio'>"
            f"<input type='radio' name='mode' value='{token}'"
            + (" checked" if token == selected_mode else "")
            + ">"
            f"<span><strong>{html.escape(_ui_label(token))}</strong> "
            f"<span class='fieldhint'>{html.escape(desc)}</span></span></label>"
            for token, _flag, desc in _BUILD_MODES
        )
        mode_html += (
            "<label class='check'><input type='checkbox' name='canary_dry'"
            + (" checked" if prefill.get("canary_dry") == "on" else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.dry_synthetic_canary]]</strong> <span class='fieldhint'>[[text:builder_page.with_diagnostic_canary_run_the_typed_synthetic_canary_offline_moc]]</span></span></label>"
            )
        ) + err("mode")
        # Modality chips select arms by membership: an arm belongs to every
        # modality it carries, so a text+image arm answers to both chips.
        registry_arms = set(
            self._registry_keys("source-instances.json", "rig/source-instances.example.json")
        )
        try:
            source_dispositions = self._source_conformance_arm_dispositions(prefill)
        except ValueError:
            # Admission reports invalid receipt bytes. Rendering must never
            # trust an unvalidated disposition or turn a stale binding into a
            # server error.
            source_dispositions = {}

        # Group EVERY _ARM_CATALOG arm for a readable layout: common lanes first
        # (by modality signature), then the source-metric scored lanes, then the
        # common-metric-ineligible arms. A source-metric arm runs in run_matrix
        # with replay. An ineligible arm remains default-closed and becomes
        # runnable only through the explicit, separately labelled approximate
        # response-proxy opt-in rendered with the judge controls below.
        signatures: dict[str, list[tuple[str, tuple[str, ...], str]]] = {}
        bucket_ranks = {}
        for arm, mods, reason in _ARM_CATALOG:
            if reason and "tool" in mods:
                bucket = _ui_text(
                    "builder_page.source_specific_tool_metric_native_runtime_required_runner_proxy"
                )
            elif reason:
                bucket = _ui_text(
                    "builder_page.source_specific_metric_approximate_proxy_available_evaluator_not"
                )
            elif arm in _SOURCE_METRIC_ARMS:
                bucket = _ui_text(
                    "builder_page.source_specific_metric_runnable_replay_attacker_only"
                )
            else:
                bucket = " + ".join(mods)
            signatures.setdefault(bucket, []).append((arm, mods, reason))
            bucket_ranks[bucket] = (
                2
                if reason and "tool" not in mods
                else 1
                if not reason and arm in _SOURCE_METRIC_ARMS
                else 0
            )
        arm_groups = []

        def _bucket_rank(name: str) -> tuple[int, int, str]:
            return (bucket_ranks[name], len(name), name)

        order = sorted(signatures, key=_bucket_rank)
        for signature in order:
            boxes = []
            for arm, mods, reason in signatures[signature]:
                known = arm in registry_arms
                source_disposition = source_dispositions.get(arm)
                if source_disposition is not None and source_disposition[0] == "blocked":
                    boxes.append(
                        (
                            "<label class='check'><input type='checkbox' class='armbox' disabled data-mods='"
                            + f"{html.escape(','.join(mods))}"
                            + "' data-arm='"
                            + f"{html.escape(arm)}"
                            + "'><span>"
                            + f"{_arm_head(html.escape(arm), mods)}"
                            + _ui_template(
                                "<span class='badge red tip' tabindex='0'>[[text:builder_page.blocked_by_source_receipt]]<span class='tiptext'>"
                            )
                        )
                        + html.escape(source_disposition[1])
                        + "</span></span></span></label>"
                    )
                    continue
                if reason:
                    tool_unavailable = "tool" in mods
                    boxes.append(
                        "<label class='check'>"
                        "<input type='checkbox' class='armbox' "
                        f"data-mods='{html.escape(','.join(mods))}' "
                        f"data-arm='{html.escape(arm)}'>"
                        f"<span>{_arm_head(html.escape(arm), mods)}"
                        "<span class='badge "
                        + ("red" if tool_unavailable else "amber")
                        + " tip' tabindex='0'>"
                        + (
                            _ui_text("builder_page.tool_runtime_required")
                            if tool_unavailable
                            else _ui_text("builder_page.approximate_opt_in")
                        )
                        + f"<span class='tiptext'>{html.escape(reason)}</span>"
                        + "</span>"
                        + "</span></label>"
                    )
                    continue
                if arm in _SOURCE_METRIC_ARMS:
                    # Selectable: a scored source-metric lane (implemented
                    # evaluator, replay only).  Carries its real data-mods.
                    metric, allowed = _SOURCE_METRIC_ARMS[arm]
                    source_note = (
                        _ui_text("builder_page.scored_by_the_implemented")
                        + f"{metric!r}"
                        + _ui_text(
                            "builder_page.evaluator_not_common_harmful_asr_run_matrix_admits_only_the"
                        )
                        + f"{'/'.join(allowed)}"
                        + _ui_text("builder_page.attacker_for_it")
                    )
                    boxes.append(
                        "<label class='check'>"
                        "<input type='checkbox' class='armbox' "
                        f"data-mods='{html.escape(','.join(mods))}' "
                        f"data-arm='{html.escape(arm)}'>"
                        f"<span>{_arm_head(html.escape(arm), mods)}"
                        "<span class='badge amber tip' tabindex='0'>"
                        f"{html.escape(_ui_text('builder_page.source_metric'))}<span class='tiptext'>"
                        f"{html.escape(source_note)}</span></span>"
                        "</span></label>"
                    )
                    continue
                note = (
                    ""
                    if known
                    else _ui_template(
                        " <span class='fieldhint'>[[text:builder_page.not_in_registry_yet]]</span>"
                    )
                )
                agg_badge = (
                    _ui_template(
                        "<span class='badge blue tip' tabindex='0'>[[text:builder_page.aggregator]]<span class='tiptext'>[[text:builder_page.unified_multi_benchmark_aggregator_source_itself_pools_or_spans_m]]</span></span>"
                    )
                    if arm in _AGGREGATOR_ARMS
                    else ""
                )
                boxes.append(
                    "<label class='check'>"
                    f"<input type='checkbox' class='armbox' "
                    f"data-mods='{html.escape(','.join(mods))}' "
                    f"data-arm='{html.escape(arm)}'>"
                    f"<span>{_arm_head(html.escape(arm) + note, mods)}{agg_badge}</span>"
                    "</label>"
                )
            arm_groups.append(
                (
                    "<div class='modgroup'><div class='grouphead'><h3>"
                    + f"{html.escape(signature)}"
                    + _ui_template(
                        "</h3><span class='groupsel'><button type='button' class='linkbtn' data-sel='all'>[[text:builder_page.all]]</button><button type='button' class='linkbtn' data-sel='none'>[[text:builder_page.none]]</button></span></div><div class='checkgrid'>"
                    )
                )
                + "".join(boxes)
                + "</div></div>"
            )
        # The offline synthetic corpus - an ORDINARY --dry-run --corpora synth
        # lane (MockTarget, no source acquisition, no spend), not only the dry
        # diagnostic canary.
        arm_groups.insert(
            0,
            _ui_template(
                "<div class='modgroup'><div class='grouphead'><h3>[[text:builder_page.synthetic_offline]]</h3></div><div class='checkgrid'><label class='check'><input type='checkbox' class='armbox' data-mods='text' data-arm='synth'><span>"
            )
            + _arm_head("synth", ("text",))
            + _ui_template(
                "<span class='fieldhint'>[[text:builder_page.offline_synthetic_corpus_no_source_acquisition_use_with_the_dry_r]]</span></span></label></div></div>"
            ),
        )
        # Target checkboxes carry supported modalities (so an out-of-scope
        # target is hidden) and a kind (hosted API vs on-rig local vLLM).
        from experiments.local_targets import (  # noqa: PLC0415
            installed_vllm_version,
            known_vllm_quantization_issue,
        )
        from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

        local_catalog, explicit_local = self._local_entry_catalog()
        ollama_roster = self._ollama_roster_snapshot()
        ollama_status = self.ollama.status()
        live_ollama_by_spec = {
            str(row.get("spec")): row
            for key in ("models", "excluded")
            for row in ollama_roster.get(key, [])
            if isinstance(row, Mapping) and str(row.get("spec", "")).startswith("ollama:")
        }
        runtime_vllm_version = installed_vllm_version() or self._vllm_roster_version()
        expensive_judges: dict[str, str] = {}

        def _api_provider(value: str) -> str:
            try:
                provider, _model = canonical_api_target_identity(value)
            except (KeyError, ValueError):
                return "unknown"
            return provider

        def _target_box(value: str, label: str, mods: tuple[str, ...], kind: str) -> str:
            runtime_value = value
            private_identity_unavailable = False
            if kind == "local":
                value = durable_local_identities.get(runtime_value, runtime_value)
                backend, separator, model = runtime_value.partition(":")
                if (
                    value == runtime_value
                    and separator == ":"
                    and backend.casefold() == "vllm"
                    and _is_explicit_local_path(model)
                ):
                    private_identity_unavailable = True
                    value = (
                        "vllm:private-checkpoint-unavailable@opaque:"
                        + hashlib.sha256(runtime_value.encode("utf-8")).hexdigest()[:16]
                    )
                if label == runtime_value:
                    label = value
            label = durable_ui_text(label)
            detail = ""
            quant_control = ""
            disabled = ""
            row_attrs = ""
            name_html = html.escape(label)
            control_id = (
                "target-" + hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:16]
            )
            if kind == "api":
                provider = _api_provider(value)
                row_attrs = f" data-provider='{html.escape(provider)}'"
                warning = expensive_judges.get(value)
                if warning:
                    name_html += (
                        _ui_template(
                            " <span class='badge amber tip judge-cost-warning' tabindex='0' role='img' aria-label='[[attr:builder_page.warning_expensive_judge_model]]'>[[text:builder_page.expensive]]<span class='tiptext'>"
                        )
                        + f"{html.escape(warning)}"
                        + "</span></span>"
                    )
            if kind == "local":
                entry = local_catalog.get(runtime_value, {})
                local_config_error = ""
                known_quant_issues: dict[str, str] = {}
                context_limit = None
                generation_limit = None
                thinking_control: bool | str | None = None
                request_timeout: float | None = None
                if private_identity_unavailable:
                    local_config_error = _ui_text(
                        "builder_page.private_explicit_checkpoint_has_no_durable_digest_identity"
                    )
                    disabled = " disabled"
                elif runtime_value.startswith("ollama:"):
                    try:
                        self._validate_ollama_local_entry(runtime_value, entry)
                        context_limit = self._local_ollama_num_ctx(runtime_value, entry)
                        generation_limit = self._local_ollama_num_predict(runtime_value, entry)
                        thinking_control = self._local_ollama_think(runtime_value, entry)
                        request_timeout = self._local_request_timeout(runtime_value, entry)
                    except ValueError as exc:
                        local_config_error = durable_ui_text(exc)
                        disabled = " disabled"
                elif runtime_value.startswith("vllm:"):
                    known_quant_issues = {
                        quantization: issue
                        for quantization in ("fp8", "bitsandbytes")
                        if (
                            issue := known_vllm_quantization_issue(
                                runtime_value,
                                entry.get("revision"),
                                quantization,
                                runtime_vllm_version,
                            )
                        )
                    }
                    try:
                        self._validated_local_modalities(runtime_value, entry, project_richer=True)
                        self._local_gpu_memory_utilization(runtime_value, entry)
                        context_limit = self._local_max_model_len(runtime_value, entry)
                        generation_limit = self._local_max_tokens(runtime_value, entry)
                        request_timeout = self._local_request_timeout(runtime_value, entry)
                        if (
                            isinstance(context_limit, int)
                            and context_limit > 0
                            and generation_limit is not None
                            and generation_limit > context_limit
                        ):
                            raise ValueError(
                                (
                                    _ui_text("builder_page.local_target")
                                    + f"{value!r}"
                                    + _ui_text(
                                        "builder_page.max_tokens_must_not_exceed_max_model_len"
                                    )
                                )
                            )
                    except ValueError as exc:
                        local_config_error = durable_ui_text(exc)
                        disabled = " disabled"
                execution_profile = entry.get("_execution_profile")
                execution_profile_error = entry.get("_execution_profile_error")
                configured_quant = (
                    str(prefill.get(f"quantization::{value}", entry.get("quantization", "auto")))
                    .strip()
                    .lower()
                )
                try:
                    if local_config_error:
                        raise ValueError(local_config_error)
                    profile = self._effective_local_profile(
                        runtime_value,
                        entry,
                        default_quantization=prefill.get("quantization", ""),
                        model_quantization=configured_quant,
                    )
                    if isinstance(execution_profile_error, str):
                        raise ValueError(execution_profile_error)
                    if not isinstance(execution_profile, Mapping):
                        raise ValueError(
                            _ui_text("builder_page.passing_local_model_readiness_profile_required")
                        )
                except ValueError as exc:
                    local_config_error = durable_ui_text(exc)
                    disabled = " disabled"
                    configured_quant = "auto"
                    profile = self._effective_local_profile(
                        runtime_value,
                        {},
                        default_quantization="",
                        model_quantization="auto",
                    )
                quant_control_disabled = disabled
                params = profile.get("parameter_count_b")
                params_text = (
                    (f"{float(params):g}" + _ui_text("builder_page.b_params"))
                    if params is not None
                    else _ui_text("builder_page.params_unknown")
                )
                fit = profile.get("fits")
                fit_data = "true" if fit is True else "false" if fit is False else "unknown"
                params_data = f"{float(params):g}" if params is not None else ""
                row_attrs = (
                    f" data-name='{html.escape(value)}'"
                    f" data-params-b='{html.escape(params_data)}'"
                    f" data-compatible='{fit_data}'"
                )
                fit_text = (
                    _ui_text("builder_page.fits")
                    if fit is True
                    else _ui_text("builder_page.does_not_fit")
                    if fit is False
                    else _ui_text("builder_page.fit_unknown")
                )
                basis = profile.get("multi_gpu_support_basis", "assumed")
                parameter_basis = profile.get("parameter_count_basis", "unknown")
                revision = entry.get("revision")
                digest = entry.get("digest")
                pinned = (
                    isinstance(revision, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", revision)
                ) or (isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest))
                if local_config_error:
                    context_text = _ui_text("builder_page.invalid_local_config")
                elif runtime_value.startswith("ollama:"):
                    context_text = (
                        _ui_text("builder_page.automatic_maximum_gpu_fit_context")
                        if context_limit == "fit"
                        else _ui_text("builder_page.native_maximum_context")
                        if context_limit == "max"
                        else (
                            _ui_text("builder_page.context_cap")
                            + f"{context_limit:,}"
                            + _ui_text("builder_page.tokens")
                        )
                    )
                    if generation_limit == -1:
                        context_text += _ui_text("builder_page.maximum_available_output")
                    else:
                        context_text += (
                            _ui_text("builder_page.output_cap")
                            + f"{generation_limit:,}"
                            + _ui_text("builder_page.tokens")
                        )
                    if thinking_control is not None:
                        context_text += (
                            _ui_text("builder_page.thinking_disabled_2")
                            if thinking_control is False
                            else (_ui_text("builder_page.thinking") + f"{thinking_control}")
                        )
                elif context_limit is not None:
                    context_text = (
                        _ui_text("builder_page.automatic_maximum_gpu_fit_context")
                        if context_limit == -1
                        else (
                            _ui_text("builder_page.context_cap")
                            + f"{context_limit:,}"
                            + _ui_text("builder_page.tokens")
                        )
                    )
                    if generation_limit is None:
                        context_text += _ui_text("builder_page.maximum_available_output")
                    else:
                        context_text += (
                            _ui_text("builder_page.output_cap")
                            + f"{generation_limit:,}"
                            + _ui_text("builder_page.tokens")
                        )
                    if thinking_control is not None:
                        context_text += (
                            _ui_text("builder_page.thinking_disabled_2")
                            if thinking_control is False
                            else (_ui_text("builder_page.thinking") + f"{thinking_control}")
                        )
                else:
                    context_text = _ui_text(
                        "builder_page.native_model_context_maximum_available_output"
                    )
                if request_timeout is not None:
                    context_text += (
                        _ui_text("builder_page.request_deadline") + f"{request_timeout:g}" + "s"
                    )
                if isinstance(execution_profile, Mapping):
                    name_html += _ui_template(
                        " <span class='badge green'>[[text:builder_page.readiness_profiled]]</span>"
                    )
                else:
                    name_html += _ui_template(
                        " <span class='badge amber'>[[text:builder_page.readiness_required]]</span>"
                    )
                # A known non-fit stays disabled. Unknown fit is an explicit UI
                # opt-in; a live run additionally requires a per-model precision.
                if fit is False:
                    disabled = " disabled"
                recommended = str(profile.get("recommended_quantization", "none"))
                precision_bits = profile.get("recommended_precision_bits")
                precision_bits = (
                    int(precision_bits)
                    if isinstance(precision_bits, (int, float))
                    and not isinstance(precision_bits, bool)
                    else 16
                )
                precision_backend = {
                    "none": "",
                    "fp8": "FP8",
                    "bitsandbytes": _ui_text("builder_page.bitsandbytes"),
                    "awq": "AWQ",
                    "gptq": "GPTQ",
                }.get(recommended, recommended)
                precision_label = f"{precision_bits}-bit" + (
                    f" {precision_backend}" if precision_backend else ""
                )
                hardware_required = bool(profile.get("quantization_required_by_hardware"))
                quantization_source = str(profile.get("quantization_source", ""))
                is_override = quantization_source in {
                    "model_override",
                    "command_override",
                }
                if fit is False:
                    precision_status = _ui_text("builder_page.does_not_fit")
                    precision_title = _ui_text(
                        "builder_page.known_incompatible_with_the_detected_hardware"
                    )
                elif fit is None:
                    if configured_quant in {"", "auto"}:
                        quant_label = _ui_text("builder_page.fit_unknown")
                        precision_title = _ui_text(
                            "builder_page.the_operator_must_choose_a_per_model_precision_before_a_live_run"
                        )
                    else:
                        quant_label = f"{precision_label}" + _ui_text(
                            "builder_page.selected_fit_unknown"
                        )
                        precision_title = _ui_text(
                            "builder_page.operator_selected_precision_hardware_fit_remains_unknown"
                        )
                elif hardware_required:
                    precision_status = "required"
                    precision_title = _ui_text(
                        "builder_page.this_precision_is_required_to_fit_this_hardware"
                    )
                elif is_override:
                    precision_status = "override"
                    precision_title = _ui_text(
                        "builder_page.configured_precision_override_not_hardware_required"
                    )
                else:
                    precision_status = ""
                    precision_title = _ui_text(
                        "builder_page.highest_automatically_selected_fitting_precision"
                    )
                if fit is not None:
                    quant_label = precision_label + (
                        f" {precision_status}" if precision_status else ""
                    )
                if known_quant_issues:
                    known_details = " ".join(
                        known_quant_issues[quantization]
                        for quantization in sorted(known_quant_issues)
                    )
                    known_details = durable_ui_text(known_details)
                    name_html += (
                        _ui_template(
                            " <span class='badge amber tip' tabindex='0' role='img' aria-label='[[attr:builder_page.warning_known_unsupported_precision_profile]]'>[[text:builder_page.known_unsupported_precision]]<span class='tiptext'>"
                        )
                        + f"{html.escape(known_details)}"
                        + "</span></span>"
                    )
                precision_tone = (
                    "gray"
                    if fit is None
                    else {16: "green", 8: "blue", 4: "amber"}.get(precision_bits, "gray")
                )
                precision_class = "unknown" if fit is None else str(precision_bits)
                badge_class = (
                    "badge "
                    + f"{precision_tone}"
                    + _ui_text("builder_page.precision_badge_precision")
                    + f"{precision_class}"
                )
                if fit is None:
                    name_html += (
                        f" <span class='{badge_class} tip' tabindex='0'>"
                        f"<span class='precision-label'>{html.escape(quant_label)}</span>"
                        f"<span class='tiptext'>{html.escape(precision_title)}</span>"
                        "</span>"
                    )
                else:
                    name_html += (
                        f" <span class='{badge_class}' "
                        f"title='{html.escape(precision_title, quote=True)}'>"
                        + html.escape(quant_label)
                        + "</span>"
                    )
                if local_config_error:
                    name_html += (
                        " <span class='badge red' title='"
                        + html.escape(local_config_error, quote=True)
                        + _ui_template("'>[[text:builder_page.invalid_local_config]]</span>")
                    )
                displayed_tp = (
                    entry.get("tensor_parallel_size")
                    if isinstance(execution_profile, Mapping)
                    and entry.get("tensor_parallel_size") in {1, 2}
                    else profile.get("recommended_tensor_parallel_size", 1)
                )
                detail = (
                    "<span class='fieldhint'>"
                    + html.escape(
                        durable_ui_text(
                            (
                                f"{params_text}"
                                + " ("
                                + f"{parameter_basis}"
                                + ") - "
                                + f"{profile.get('estimated_vram_gib', '?')}"
                                + _ui_text("builder_page.gib_estimated")
                                + f"{profile.get('available_vram_gib', 0)}"
                                + _ui_text("builder_page.gib_available")
                                + f"{fit_text}"
                                + " - "
                                + f"{quant_label}"
                                + " - TP"
                                + f"{displayed_tp}"
                                + _ui_text("builder_page.multi_gpu")
                                + f"{basis}"
                                + " - "
                                + f"{context_text}"
                                + " - "
                                + f"{(_ui_text('builder_page.pinned') if pinned else _ui_text('builder_page.revision_required'))}"
                            )
                            + (
                                f" - {profile['compatibility_note']}"
                                if profile.get("compatibility_note")
                                else ""
                            )
                        )
                    )
                    + "</span>"
                )
                choices = (
                    ("auto", _ui_text("builder_page.auto_highest_fitting_16_8_4_bit")),
                    ("none", _ui_text("builder_page.16_bit_bf16_fp16")),
                    ("fp8", _ui_text("builder_page.8_bit_fp8")),
                    ("bitsandbytes", _ui_text("builder_page.4_bit_bitsandbytes")),
                    ("awq", _ui_text("builder_page.4_bit_awq")),
                    ("gptq", _ui_text("builder_page.4_bit_gptq")),
                )
                choice_fits: dict[str, str] = {}
                if known_quant_issues and not local_config_error:
                    for choice, _label in choices:
                        try:
                            choice_fit = self._effective_local_profile(
                                runtime_value,
                                entry,
                                default_quantization=prefill.get("quantization", ""),
                                model_quantization=choice,
                            ).get("fits")
                        except ValueError:
                            choice_fit = False
                        choice_fits[choice] = (
                            "true"
                            if choice_fit is True
                            else "false"
                            if choice_fit is False
                            else "unknown"
                        )
                    row_attrs += (
                        " data-profile-overrides='true'"
                        f" data-config-invalid='{'true' if local_config_error else 'false'}'"
                    )
                quant_id = control_id + "-quantization"
                quant_control = (
                    "<div class='modelquant'><label for='"
                    + quant_id
                    + (
                        _ui_template(
                            "'>[[text:builder_page.per_model_quantization]]</label><select id='"
                        )
                        + f"{quant_id}"
                        + "' name='quantization::"
                        + f"{html.escape(value)}"
                        + "'"
                        + f"{quant_control_disabled}"
                        + ">"
                    )
                    + "".join(
                        f"<option value='{choice}'"
                        + (" selected" if choice == configured_quant else "")
                        + (" disabled" if choice in known_quant_issues else "")
                        + (f" data-fit='{choice_fits[choice]}'" if choice in choice_fits else "")
                        + f">{label}"
                        + (
                            _ui_text(
                                "builder_page.unsupported_for_this_exact_vllm_revision_profile"
                            )
                            if choice in known_quant_issues
                            else ""
                        )
                        + "</option>"
                        for choice, label in choices
                    )
                    + "</select></div>"
                )
                row_attrs += " data-backend='vllm'"
            input_type = "radio" if kind == "local" else "checkbox"
            input_name = " name='local_choice'" if kind == "local" else ""
            target_selected = value in selected_target_models
            return (
                "<div class='modelrow' "
                f"data-mods='{html.escape(','.join(mods))}' "
                f"data-kind='{html.escape(kind)}'{row_attrs}>"
                f"<label class='check modelchoice' for='{control_id}'>"
                f"<input id='{control_id}' type='{input_type}' class='modelbox'"
                f"{input_name} "
                f"data-kind='{html.escape(kind)}' "
                f"data-model='{html.escape(value)}' "
                f"data-target-type='{input_type}' "
                f"data-target-selected='{'true' if target_selected else 'false'}'"
                + (" checked" if target_selected else "")
                + f"{disabled}>"
                f"<span class='modelchoice-copy'>{_arm_head(name_html, mods)}"
                f"{detail}</span></label>"
                f"{quant_control}</div>"
            )

        def _ollama_target_box(value: str, label: str, mods: tuple[str, ...]) -> str:
            entry = local_catalog.get(value, {})
            disabled = ""
            problems: list[str] = []
            context_limit = None
            generation_limit = None
            thinking_control: bool | str | None = None
            request_timeout: float | None = None
            live_entry = live_ollama_by_spec.get(value)
            execution_profile = entry.get("_execution_profile")
            execution_profile_error = entry.get("_execution_profile_error")
            try:
                self._validate_ollama_local_entry(value, entry)
                context_limit = self._local_ollama_num_ctx(value, entry)
                generation_limit = self._local_ollama_num_predict(value, entry)
                thinking_control = self._local_ollama_think(value, entry)
                request_timeout = self._local_request_timeout(value, entry)
            except ValueError as exc:
                problems.append(str(exc))
            if isinstance(execution_profile_error, str):
                problems.append(execution_profile_error)
            elif not isinstance(execution_profile, Mapping):
                problems.append(
                    _ui_text("builder_page.passing_local_model_readiness_profile_required")
                )
            manual = value in explicit_local
            if manual and live_entry is None:
                problems.append(
                    _ui_text(
                        "builder_page.manual_entry_is_not_verified_in_the_current_live_daemon_roster"
                    )
                )
            elif manual and live_entry is not None:
                live_digest = str(live_entry.get("digest", "")).lower()
                live_modalities = live_entry.get("modalities")
                configured_modalities = entry.get("modalities")
                modalities_match = (
                    isinstance(live_modalities, list)
                    and isinstance(configured_modalities, list)
                    and list(configured_modalities) == list(live_modalities)
                )
                if str(entry.get("digest", "")).lower() != live_digest or not modalities_match:
                    problems.append(
                        _ui_text(
                            "builder_page.manual_digest_modalities_do_not_match_live_daemon_discovery"
                        )
                    )
            error = "; ".join(dict.fromkeys(problems))
            if error:
                disabled = " disabled"
            digest = entry.get("digest")
            pinned = isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
            control_id = (
                "target-" + hashlib.sha256(f"ollama:{value}".encode("utf-8")).hexdigest()[:16]
            )
            name_html = (
                html.escape(label)
                + _ui_template(" <span class='badge gray'>[[text:builder_page.ollama]]</span>")
                + (
                    _ui_template(
                        " <span class='badge amber'>[[text:builder_page.manual_config]]</span>"
                    )
                    if manual
                    else _ui_template(
                        " <span class='badge green'>[[text:builder_page.live_installed]]</span>"
                    )
                )
                + (
                    _ui_template(
                        " <span class='badge green'>[[text:builder_page.daemon_matched]]</span>"
                    )
                    if manual and live_entry is not None
                    else ""
                )
                + (
                    _ui_template(
                        " <span class='badge green'>[[text:builder_page.readiness_profiled]]</span>"
                    )
                    if isinstance(execution_profile, Mapping)
                    else ""
                )
                + (
                    _ui_template(
                        " <span class='badge amber'>[[text:builder_page.readiness_required]]</span>"
                    )
                    if not isinstance(execution_profile, Mapping)
                    else ""
                )
                + (
                    _ui_template(
                        " <span class='badge red'>[[text:builder_page.invalid_local_config]]</span>"
                    )
                    if error
                    else ""
                )
            )
            pin_text = (
                _ui_text("builder_page.digest_pinned")
                if pinned
                else _ui_text("builder_page.64_hex_digest_required_for_live_use")
            )
            context_detail = (
                _ui_text("builder_page.automatic_maximum_gpu_fit_context_2")
                if context_limit == "fit"
                else _ui_text("builder_page.native_maximum_context_2")
                if context_limit == "max"
                else (
                    _ui_text("builder_page.context_cap_2")
                    + f"{context_limit:,}"
                    + _ui_text("builder_page.tokens")
                )
                if isinstance(context_limit, int)
                else _ui_text("builder_page.invalid_context_policy")
            )
            context_detail += (
                _ui_text("builder_page.maximum_available_output")
                if generation_limit == -1
                else (
                    _ui_text("builder_page.output_cap")
                    + f"{generation_limit:,}"
                    + _ui_text("builder_page.tokens")
                )
                if isinstance(generation_limit, int)
                else _ui_text("builder_page.invalid_output_policy")
            )
            if request_timeout is not None:
                context_detail += (
                    _ui_text("builder_page.request_deadline") + f"{request_timeout:g}" + "s"
                )
            detail = (
                _ui_template("<span class='fieldhint'>[[text:builder_page.local_ollama_daemon]] ")
                + html.escape("/".join(mods))
                + " - "
                + pin_text
                + _ui_text("builder_page.precision_is_fixed_by_the_pulled_ollama_artifact")
                + context_detail
                + (
                    _ui_text("builder_page.thinking_disabled")
                    if thinking_control is False
                    else (
                        _ui_text("builder_page.thinking_copy")
                        + f"{html.escape(str(thinking_control))}"
                    )
                    if thinking_control is not None
                    else ""
                )
                + (" - " + html.escape(error) if error else "")
                + "</span>"
            )
            target_selected = value in selected_target_models
            return (
                "<div class='modelrow' "
                f"data-mods='{html.escape(','.join(mods))}' data-kind='local' "
                f"data-backend='ollama' data-name='{html.escape(value)}'>"
                f"<label class='check modelchoice' for='{control_id}'>"
                f"<input id='{control_id}' type='radio' class='modelbox' "
                "name='local_choice' data-kind='local' "
                f"data-model='{html.escape(value)}' data-target-type='radio' "
                f"data-target-selected='{'true' if target_selected else 'false'}'"
                + (" checked" if target_selected else "")
                + f"{disabled}>"
                f"<span class='modelchoice-copy'>{_arm_head(name_html, mods)}"
                f"{detail}</span></label></div>"
            )

        options = self._model_options()

        # Cost warnings are derived from the operator's effective-dated pricing
        # table.  Only exact maxima among at least two comparable, fully priced
        # models in the same currency are marked; missing/null/mixed prices never
        # turn into an invented "expensive" label.
        comparable: dict[str, list[tuple[str, float]]] = {}
        pricing = load_pricing(self.repo_root)
        for spec, _label, _mods, kind in options:
            if kind != "api":
                continue
            try:
                provider, model = canonical_api_target_identity(spec)
            except (KeyError, ValueError):
                continue
            rate, _why = rate_for(pricing, provider, model)
            if not isinstance(rate, Mapping):
                continue
            currency = rate.get("currency")
            per_million = rate.get("per_million_tokens")
            if (
                not isinstance(currency, str)
                or re.fullmatch(r"[A-Za-z]{3}", currency) is None
                or not isinstance(per_million, Mapping)
            ):
                continue
            values = [per_million.get(category) for category in ("input", "output")]
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
                for value in values
            ):
                continue
            comparable.setdefault(currency.upper(), []).append(
                (spec, sum(float(value) for value in values))
            )
        for currency, entries in comparable.items():
            if len(entries) < 2:
                continue
            maximum = max(score for _spec, score in entries)
            for spec, score in entries:
                if score == maximum:
                    expensive_judges[spec] = (
                        _ui_text(
                            "builder_page.highest_configured_current_input_output_judging_rate_among_compar"
                        )
                        + f"{currency}"
                        + _ui_text("builder_page.models")
                        + f"{score:g}"
                        + " "
                        + f"{currency}"
                        + _ui_text(
                            "builder_page.per_one_million_input_output_tokens_actual_cost_depends_on_record"
                        )
                    )
        api_boxes = "".join(
            _target_box(v, lbl, mods, kind) for v, lbl, mods, kind in options if kind == "api"
        )
        vllm_boxes = "".join(
            _target_box(v, lbl, mods, kind)
            for v, lbl, mods, kind in options
            if kind == "local" and v.startswith("vllm:")
        )
        ollama_boxes = "".join(
            _ollama_target_box(v, lbl, mods)
            for v, lbl, mods, kind in options
            if kind == "local" and v.startswith("ollama:")
        )
        providers = sorted(
            {_api_provider(value) for value, _label, _mods, kind in options if kind == "api"}
        )
        provider_options = _ui_template(
            "<option value='all' selected>[[text:builder_page.all]]</option>"
        ) + "".join(
            f"<option value='{html.escape(provider)}'>{html.escape(provider)}</option>"
            for provider in providers
        )
        model_boxes = (
            _ui_template(
                "<section class='picker-model-panel' data-picker-panel='api' hidden><div class='grouphead'><h3>[[text:builder_page.hosted_api]]</h3><span class='fieldhint' id='api-filter-count'></span></div><div class='targetfilters'><div class='fieldcell'><label class='fieldlabel' for='api-provider-filter'>[[text:builder_page.provider]]</label><select id='api-provider-filter' aria-label='[[attr:builder_page.hosted_api_provider]]'>"
            )
            + provider_options
            + "</select></div></div><div class='checkgrid' "
            "id='api-target-list'>"
            + (
                api_boxes
                or _ui_template(
                    "<p class='note'>[[text:builder_page.no_hosted_targets_configured]]</p>"
                )
            )
            + _ui_template(
                "</div><p class='filter-empty' id='api-filter-empty'>[[text:builder_page.no_hosted_models_match_the_current_provider_and_modality_filters]]</p></section><section class='picker-model-panel' data-picker-panel='local' hidden><div class='grouphead'><h3>[[text:builder_page.local_vllm_on_rig_gpus]]</h3><span class='fieldhint' id='local-filter-count'></span></div><div class='targetfilters'><div class='fieldcell'><label class='fieldlabel' for='local-name-filter'>[[text:builder_page.name_contains]]</label><input class='wide' id='local-name-filter' type='search' autocomplete='off' placeholder='[[attr:builder_page.type_to_filter_model_names]]'></div><div class='fieldcell'><label class='fieldlabel' for='local-param-range'>[[text:builder_page.maximum_parameters]] <span class='fieldhint'>[[text:builder_page.billions_0_01b_10m_3000b_3t]]</span></label><div class='paramfilter'><input id='local-param-range' type='range' min='0.01' max='3000' step='0.01' value='3000' aria-label='[[attr:builder_page.maximum_parameters_slider]]'><input class='wide' id='local-param-number' type='number' min='0.01' max='3000' step='0.01' value='3000' aria-label='[[attr:builder_page.maximum_parameters_in_billions]]'></div></div><label class='compatfilter'><input type='checkbox' id='local-compatible-filter' checked><span class='compatcopy'><strong>[[text:builder_page.automatic_16_8_4_bit_fit]]</strong><span class='fieldhint'>[[text:builder_page.show_only_models_estimated_to_fit_this_hardware_at_automatically]]</span></span></label><label class='compatfilter'><input type='checkbox' id='local-unknown-filter'><span class='compatcopy'><strong>[[text:builder_page.include_unknown_fit]]</strong><span class='fieldhint'>[[text:builder_page.show_models_whose_fit_cannot_be_estimated_live_runs_require_an_ex]]</span></span></label></div><div class='checkgrid' id='vllm-target-list'>"
            )
            + (
                vllm_boxes
                or _ui_template(
                    "<p class='note'>[[text:builder_page.no_vllm_targets_configured]]</p>"
                )
            )
            + _ui_template(
                "</div><p class='filter-empty' id='local-filter-empty'>[[text:builder_page.no_local_vllm_models_match_all_active_filters]]</p><div class='grouphead'><h3>[[text:builder_page.local_ollama_local_daemon]]</h3></div><div class='checkgrid' id='ollama-target-list'>"
            )
            + (
                ollama_boxes
                or _ui_template(
                    "<p class='note'>[[text:builder_page.no_exact_ollama_candidate_is_available_start_or_connect_to_the_lo]] <a href='/config?file=local-targets'>local-targets</a> [[text:builder_page.escape_remains_visibly_flagged_and_must_match_live_discovery]]</p>"
                )
            )
            + "</div>"
            + _ui_template(
                "<p class='note'>[[text:builder_page.hosted_rosters_are_edited_on_the]] <a href='/config?file=api-targets'>api-targets</a> [[text:builder_page.and]] <a href='/config?file=local-targets'>local-targets</a> [[text:builder_page.config_pages_local_vllm_targets_also_include_the_vllm_roster]]"
            )
            + (
                (
                    _ui_text("builder_page.synced_to_vllm")
                    + f"{html.escape(str(self._vllm_roster_version()))}"
                )
                if self._vllm_roster_version()
                else _ui_template(
                    "[[text:builder_page.curated_default_run]] <code>local_targets --refresh</code> [[text:builder_page.to_sync_it_to_the_rig_s_vllm_version]]"
                )
            )
            + _ui_template(
                "[[text:builder_page.hub_backed_vllm_models_require_an_explicit_sealed_acquisition_job]]</p></section>"
            )
        )
        target_selector = _ui_template(
            "<div class='model-picker-selection'><button type='button' class='ghost' data-open-model-picker='target' aria-controls='model-picker' aria-expanded='false'>[[text:builder_page.choose_target_models]]</button><output id='target-model-summary' class='selection-summary' aria-live='polite'>[[text:builder_page.no_target_models_selected]]</output></div>"
        )
        judge_selector = (
            (
                "<input type='hidden' id='judge-model-input' name='judge_model' value='"
                + f"{html.escape(selected_judge_model)}"
                + _ui_template(
                    "'><div class='model-picker-selection'><button type='button' class='ghost' data-open-model-picker='judge' aria-controls='model-picker' aria-expanded='false'>[[text:builder_page.choose_llm_judge_model]]</button><output id='judge-model-summary' class='selection-summary' aria-live='polite'>"
                )
            )
            + (
                html.escape(selected_judge_model)
                if selected_judge_model
                else _ui_text("builder_page.no_llm_judge_model_selected")
            )
            + "</output></div>"
        )
        model_picker_modal = (
            _ui_template(
                "<div id='model-picker' class='model-picker' role='dialog' aria-modal='true' aria-labelledby='model-picker-title' aria-hidden='true' hidden><div class='model-picker-shell'><div class='model-picker-head'><div><p class='wizard-kicker'>[[text:builder_page.model_selector]]</p><h2 id='model-picker-title'>[[text:builder_page.choose_models]]</h2></div><button type='button' class='ghost small' data-close-model-picker aria-label='[[attr:builder_page.close_model_selector]]'>[[text:builder_page.close]]</button></div><div class='wizard-steps' aria-label='[[attr:builder_page.selection_steps]]'><button type='button' class='wizard-step on' data-picker-step='runtime' aria-controls='model-picker-runtime' aria-current='step'>[[text:builder_page.1_runtime]]</button><button type='button' class='wizard-step' data-picker-step='models' aria-controls='model-picker-models' disabled>[[text:builder_page.2_filter_and_choose]]</button></div><section id='model-picker-runtime' class='picker-runtime-step'><p class='note'>[[text:builder_page.where_will_this_model_run]]</p><div class='picker-runtime-grid'><button type='button' class='picker-runtime-choice' data-picker-kind='api'><strong>[[text:builder_page.hosted_api]]</strong><span>[[text:builder_page.filter_by_provider_or_show_all_configured_hosted_routes_hosted_ca]]</span></button><button type='button' class='picker-runtime-choice' data-picker-kind='local'><strong>[[text:builder_page.local_rig]]</strong><span>[[text:builder_page.use_the_full_vllm_fit_parameter_name_and_precision_filters_or_an]]</span></button></div></section><section id='model-picker-models' class='picker-model-step' hidden><p id='model-picker-role-note' class='fieldhint picker-role-note'></p>"
            )
            + model_boxes
            + _ui_template(
                "</section><div class='model-picker-foot'><span class='fieldhint'>[[text:builder_page.disabled_rows_failed_exact_configuration_or_hardware_admission_ch]]</span><button type='button' data-close-model-picker>[[text:builder_page.done]]</button></div></div></div>"
            )
        )
        gpu_rows = "".join(
            "<li><code>GPU "
            + html.escape(str(gpu.get("index", "?")))
            + "</code> "
            + html.escape(str(gpu.get("name", "unknown")))
            + " - "
            + html.escape(str(gpu.get("vram_gib", "?")))
            + _ui_text("builder_page.gib_vram")
            + (
                " - SM " + html.escape(str(gpu["compute_capability"]))
                if gpu.get("compute_capability")
                else ""
            )
            + (" - PCI " + html.escape(str(gpu["pci_bus_id"])) if gpu.get("pci_bus_id") else "")
            + "</li>"
            for gpu in self.gpu_hardware.get("gpus", [])
            if isinstance(gpu, Mapping)
        )
        cpu_name = str(self.system_hardware.get("cpu_model") or "unknown")
        ram_gib = self.system_hardware.get("total_ram_gib")
        ram_text = (
            (f"{ram_gib}" + _ui_text("builder_page.gib_ram"))
            if ram_gib is not None
            else _ui_text("builder_page.unknown_ram")
        )
        system_summary = (
            "<p><strong>"
            + html.escape(cpu_name)
            + _ui_template("</strong> [[text:builder_page.message]] ")
            + html.escape(ram_text)
            + " - "
            + html.escape(str(self.system_hardware.get("platform") or "unknown"))
            + "</p>"
        )
        hardware_card = (
            _ui_template(
                "<div class='card' id='local-hardware'><h2>[[text:builder_page.local_hardware]]</h2>"
            )
            + system_summary
            + (
                "<p><strong>"
                + html.escape(str(self.gpu_hardware.get("gpu_count", 0)))
                + _ui_text("builder_page.nvidia_gpu_s")
                + html.escape(str(self.gpu_hardware.get("aggregate_vram_gib", 0)))
                + _ui_template(" [[text:builder_page.gib_aggregate_vram]]</strong></p><ul>")
                + gpu_rows
                + "</ul>"
                if self.gpu_hardware.get("available")
                else _ui_template(
                    "<div class='notice amber'>[[text:builder_page.no_nvidia_gpu_was_detected_model_fit_is_unknown]]</div>"
                )
            )
            + (
                _ui_template("<p class='note'>[[text:builder_page.vllm]] ")
                + html.escape(str(installed_vllm_version()))
                + _ui_template(" [[text:builder_page.is_installed]]</p>")
                if installed_vllm_version()
                else _ui_template(
                    "<p class='note'>[[text:builder_page.vllm_is_not_installed_in_this_console_environment_planning_remain]]</p>"
                )
            )
            + _ui_template(
                "<p class='note'>[[text:builder_page.automatic_4_bit_serving_uses]] <code>bitsandbytes</code>[[text:builder_page.an_optional_runtime_dependency_fit_values_are_conservative_estima]]</p></div>"
            )
        )
        ollama_card = self._ollama_service_card(
            ollama_status,
            ollama_roster,
            action_state=ollama_state,
            action_error=ollama_error,
            campaign_id=prefill.get("campaign_id", ""),
        )
        framework_runtime_panel = self._framework_runtime_panel(
            action_state=framework_runtime_state,
            action_error=framework_runtime_error,
        )
        # (local targets are selected as checkboxes above, not free text)
        # Framework checkboxes (carry supported modalities so the wizard can
        # flag ones that cannot drive a chosen modality).  A native-artifact
        # attacker (runner_replay_eligible False) is shown DISABLED with its
        # real action - the native-import path - never as a common-runner lane.
        attackers_selected = (
            set(self._split_list(prefill.get("attackers", "")))
            if "attackers" in prefill
            else {"replay"}
        )

        def _framework_box(fw: str, desc: str, mods: tuple[str, ...]) -> str:
            if fw in _NATIVE_ONLY_ATTACKERS:
                # The (identical) native-import explanation lives in a tooltip on
                # the badge rather than repeated inline under every native-only
                # framework, which cluttered the grid.
                return (
                    "<label class='check fwrow disabled' data-mods='"
                    + f"{html.escape(','.join(mods))}"
                    + "'><input type='checkbox' class='fwbox' disabled data-fw='"
                    + f"{html.escape(fw)}"
                    + "'><span><strong>"
                    + f"{html.escape(fw)}"
                    + _ui_template(
                        "</strong> <span class='badge gray tip' tabindex='0' role='button' aria-label='[[attr:builder_page.native_only_why_this_framework_is_disabled]]'>[[text:builder_page.native_only]]<span class='tiptext'>"
                    )
                    + f"{html.escape(desc)}"
                    + _ui_template(
                        " [[text:builder_page.a_native_artifact_integration_run_matrix_cannot_replay_it_through]] <code>native_import</code> [[text:builder_page.command]]</span></span></span></label>"
                    )
                )
            cli_only_reason = _CLI_ONLY_ATTACKERS.get(fw)
            if cli_only_reason:
                return (
                    "<label class='check fwrow disabled' data-mods='"
                    + f"{html.escape(','.join(mods))}"
                    + "'><input type='checkbox' class='fwbox' disabled data-fw='"
                    + f"{html.escape(fw)}"
                    + "'><span><strong>"
                    + f"{html.escape(fw)}"
                    + _ui_template(
                        "</strong> <span class='badge gray tip cli-only-framework-badge' tabindex='0' role='button' aria-label='[[attr:builder_page.cli_only_why_this_framework_is_disabled]]'>[[text:builder_page.cli_only_precomputed_input]]<span class='tiptext'>"
                    )
                    + f"{html.escape(desc)}"
                    + " - "
                    + f"{html.escape(cli_only_reason)}"
                    + "</span></span></span></label>"
                )
            prepared_badge = ""
            prepared_control = ""
            if fw in {"t3mp3st", "harmbench", "ideator", "nanogcg"}:
                if fw == "t3mp3st":
                    detail = _ui_text(
                        "builder_page.capture_a_validated_planning_bundle_first_measured_replay_checks"
                    )
                    badge = _ui_text("builder_page.capture_replay_copy")
                elif fw == "harmbench":
                    detail = _ui_text(
                        "builder_page.prepare_generated_cases_first_measured_replay_checks_the_capture"
                    )
                    badge = _ui_text("builder_page.prepare_replay_copy")
                elif fw == "nanogcg":
                    detail = _ui_text(
                        "builder_page.provide_an_exact_precomputed_suffix_for_replay_live_nanogcg_gener"
                    )
                    badge = _ui_text("builder_page.precomputed_replay")
                else:
                    detail = _ui_text(
                        "builder_page.provide_an_exact_source_mapped_ura_ideator_seed_pairs_2_manifest"
                    )
                    badge = _ui_text("builder_page.verified_seed_pair_replay")
                prepared_badge = (
                    "<span class='badge blue tip prepared-framework-badge' "
                    "tabindex='0'>"
                    + badge
                    + f"<span class='tiptext'>{html.escape(detail)}</span></span>"
                )
                prepared_control = (
                    f" aria-controls='prepared-{html.escape(fw)}'"
                    f" aria-expanded='{'true' if fw in attackers_selected else 'false'}'"
                )
            return (
                "<label class='check fwrow' "
                f"data-mods='{html.escape(','.join(mods))}'>"
                f"<input type='checkbox' class='fwbox' data-fw='{html.escape(fw)}'"
                + prepared_control
                + (" checked" if fw in attackers_selected else "")
                + ">"
                f"<span><strong>{html.escape(fw)}</strong> "
                f"<span class='fieldhint'>{html.escape(desc)}</span>"
                + prepared_badge
                + "<span class='fwflag'></span></span></label>"
            )

        framework_boxes = "".join(
            _framework_box(fw, desc, mods)
            for fw, desc, mods in _FRAMEWORKS
            if fw not in _BUILDER_OMITTED_ATTACKERS
        )
        # Judge checkboxes.  A fresh page is a dry lane, whose documented
        # default cascade is rules,llm with the offline mock judge (runbook
        # section 8; compose forces --judge-model mock on every dry lane): a
        # rules-only cascade fails closed on the first row the rules stage
        # cannot classify confidently, so it is not a completing default.
        judges_selected = set(
            self._split_list(
                prefill.get(
                    "judges",
                    "rules,llm" if selected_mode == "dry_run" else "rules",
                )
            )
        )
        judge_boxes = (
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='rules'"
            + (" checked" if "rules" in judges_selected else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.rules]]</strong> <span class='fieldhint'>[[text:builder_page.deterministic_rule_scorer_free]]</span></span></label><label class='check'><input type='checkbox' class='judgebox' data-judge='llm'"
            )
            + (" checked" if "llm" in judges_selected else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.llm]]</strong> <span class='fieldhint'>[[text:builder_page.explicit_hosted_or_local_model_judge_hosted_calls_are_metered]]</span></span></label><label class='check'><input type='checkbox' class='judgebox' data-judge='guardrail'"
            )
            + (" checked" if "guardrail" in judges_selected else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.guardrail]]</strong> <span class='fieldhint'>[[text:builder_page.model_backed_guardrail_grader_set_the_scoring_guardrail_model_bel]]</span></span></label>"
            )
        )
        approximate_metrics_control = (
            "<label class='check'><input type='checkbox' "
            "name='approximate_common_metrics'"
            + (" checked" if prefill.get("approximate_common_metrics") == "on" else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.approximate_common_security_metrics]]</strong> <span class='fieldhint'>[[text:builder_page.explicit_opt_in_for_separate_supplementary_response_proxies_when]]</span></span></label>"
            )
            + err("approximate_common_metrics")
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
            f"<option value='{d}'" + (" selected" if d == guard_selected else "") + f">{d}</option>"
            for d in ("rules", "guardrail")
        )
        dtype_selected = prefill.get("dtype", "")
        dtype_opts = "".join(
            f"<option value='{d}'"
            + (" selected" if d == dtype_selected else "")
            + f">{d or _ui_text('builder_page.default_auto')}</option>"
            for d in ("", "auto", "bfloat16", "float16")
        )

        def text_field(
            field: str,
            label: str,
            hint: str,
            *,
            default: str = "",
            kind: str = "text",
            placeholder: str = "",
        ) -> str:
            current = prefill.get(field, default)
            attrs = f" value='{html.escape(current)}'" if current else ""
            ph = f" placeholder='{html.escape(placeholder)}'" if placeholder else ""
            step = " step='any'" if kind == "number" else ""
            return (
                f"<div class='fieldcell'><label class='fieldlabel'>"
                f"{html.escape(label)} "
                f"<span class='fieldhint'>{html.escape(hint)}</span></label>"
                f"<input class='wide' type='{kind}'{step} "
                f"name='{html.escape(field)}'{attrs}{ph}>{err(field)}</div>"
            )

        engine_runtime_fields = (
            _ui_template(
                "<section class='workflow-panel'><h3>[[text:builder_page.isolated_framework_runtimes]] <span class='badge blue'>[[text:builder_page.explicit_venvs]]</span></h3><p class='note'>[[text:builder_page.required_only_for_selected_pyrit_0_14_0_deepteam_1_0_7_h4rm3l_0_2]] <code>python -m experiments.engine_runtime_config</code>[[text:builder_page.the_managed_environments_and_their_current_verification_state_are]] <a href='#build-runtimes'>[[text:builder_page.runtimes]]</a> [[text:builder_page.tab_the_console_holds_its_exact_bytes_behind_the_launch_ticket_an]]</p><div class='cols'>"
            )
            + text_field(
                "engine_runtime_config",
                _ui_text("builder_page.runtime_config"),
                _ui_text("builder_page.private_ura_engine_runtime_config_1_file"),
                placeholder="C:/private/engine-runtimes.json",
            )
            + text_field(
                "engine_runtime_config_sha",
                _ui_text("builder_page.runtime_config_sha_256"),
                _ui_text("builder_page.exact_64_lowercase_hex_byte_digest"),
                placeholder=_ui_text("builder_page.64_lowercase_hex_characters"),
            )
            + "</div></section>"
        )

        selected_prepared = attackers_selected & {
            "t3mp3st",
            "harmbench",
            "ideator",
            "nanogcg",
        }

        def visibility(name: str) -> str:
            return (
                " aria-hidden='false'"
                if name in selected_prepared
                else " hidden aria-hidden='true'"
            )

        workflows_visibility = (
            " aria-hidden='false'" if selected_prepared else " hidden aria-hidden='true'"
        )
        ideator_available_pairs: int | None = None
        if "ideator" in selected_prepared:
            try:
                ideator_entry = self._prepared_attacker_entries(
                    {**prefill, "attackers": "ideator"}
                ).get("ideator")
                raw_pairs = (
                    ideator_entry.get("seed_pairs") if isinstance(ideator_entry, Mapping) else None
                )
                if isinstance(raw_pairs, list):
                    ideator_available_pairs = len(raw_pairs)
            except (OSError, TypeError, ValueError):
                ideator_available_pairs = None
        raw_ideator_limit = prefill.get("ideator_pair_limit", "") or "0"
        try:
            parsed_ideator_limit = int(raw_ideator_limit)
        except ValueError:
            parsed_ideator_limit = -1
        if ideator_available_pairs is None:
            ideator_pair_status = _ui_text(
                "builder_page.available_and_selected_pair_counts_appear_after_the_complete_mani"
            )
            ideator_available_attr = ""
        else:
            effective_ideator_pairs = (
                ideator_available_pairs
                if parsed_ideator_limit == 0
                else min(max(parsed_ideator_limit, 0), ideator_available_pairs)
            )
            ideator_pair_status = (
                f"{effective_ideator_pairs}"
                + _ui_text("builder_page.selected_of")
                + f"{ideator_available_pairs}"
                + _ui_text("builder_page.verified_pairs_in_manifest_order")
            )
            ideator_available_attr = str(ideator_available_pairs)
        from .prepared_inputs import picker

        prepared_workflow_fields = (
            "<div class='prepared-workflows' id='prepared-workflows'"
            + workflows_visibility
            + _ui_template(
                "><p class='note'>[[text:builder_page.prepared_replay_and_model_backed_attack_inputs_are_explicitly_bou]]</p><div class='workflow-grid'><section class='workflow-panel prepared-fields' id='prepared-t3mp3st' data-prepared='t3mp3st'"
            )
            + visibility("t3mp3st")
            + _ui_template(
                "><h3>[[text:builder_page.t3mp3st]] <span class='badge blue'>[[text:builder_page.capture_replay]]</span></h3>"
            )
            + picker(self, "t3mp3st")
            + _ui_template(
                "<div class='workflow-step'><h4>[[text:builder_page.create_attack_material]]</h4><p class='note'>[[text:builder_page.calls_only_the_pinned_loopback_planning_service]]</p><div class='cols'>"
            )
            + text_field(
                "t3cap_corpus",
                _ui_text("builder_page.corpus_arm"),
                _ui_text("builder_page.exact_text_arm_to_capture"),
                default="strongreject_official",
            )
            + text_field(
                "t3cap_limit",
                _ui_text("builder_page.limit"),
                _ui_text("builder_page.selected_source_clusters"),
                default="1",
                kind="number",
            )
            + text_field(
                "t3cap_sample_seed",
                _ui_text("builder_page.sample_seed"),
                _ui_text("builder_page.reproducible_subset"),
                default="0",
                kind="number",
            )
            + text_field(
                "t3cap_endpoint",
                _ui_text("builder_page.planning_endpoint"),
                _ui_text("builder_page.literal_loopback_api_general_plan_route"),
                default="http://127.0.0.1:3333/api/general/plan",
            )
            + text_field(
                "t3cap_provider",
                _ui_text("builder_page.source_provider"),
                _ui_text("builder_page.op_general_provider"),
            )
            + text_field(
                "t3cap_model",
                _ui_text("builder_page.source_model"),
                _ui_text("builder_page.op_general_model"),
            )
            + text_field(
                "t3cap_timeout",
                _ui_text("builder_page.timeout_seconds"),
                _ui_text("builder_page.per_planning_request"),
                default="120",
                kind="number",
            )
            + _ui_template(
                "</div><details><summary>[[text:builder_page.advanced_capture_overrides]]</summary><div class='cols'>"
            )
            + text_field(
                "t3cap_revision",
                _ui_text("builder_page.upstream_revision"),
                _ui_text("builder_page.automatic_from_installed_runtime"),
            )
            + text_field(
                "t3cap_out",
                _ui_text("builder_page.output_directory"),
                _ui_text("builder_page.automatic_fresh_results_directory"),
            )
            + _ui_template(
                "</div></details><div class='workflow-actions'><button type='submit' class='ghost' formaction='/build/t3mp3st/capture' formmethod='post'>[[text:builder_page.review_capture]]</button></div></div><details class='workflow-step'><summary>[[text:builder_page.advanced_import_or_current_saved_material]]</summary><p class='note'>[[text:builder_page.completed_captures_attach_automatically_a_manually_imported_bundl]]</p>"
            )
            + err("t3_replay")
            + "<div class='cols'>"
            + text_field(
                "t3_artifact",
                _ui_text("builder_page.plan_bundle"),
                _ui_text("builder_page.ura_t3mp3st_plan_bundle_1_path"),
            )
            + text_field(
                "t3_artifact_sha",
                _ui_text("builder_page.bundle_sha_256"),
                _ui_text("builder_page.exact_capture_digest"),
            )
            + "</div></details></section>"
            "<section class='workflow-panel prepared-fields' id='prepared-harmbench' "
            "data-prepared='harmbench'"
            + visibility("harmbench")
            + _ui_template(
                "><h3>[[text:builder_page.harmbench]] <span class='badge blue'>[[text:builder_page.prepare_replay]]</span></h3>"
            )
            + picker(self, "harmbench")
            + _ui_template(
                "<div class='workflow-step'><h4>[[text:builder_page.create_attack_material]]</h4><p class='note'>[[text:builder_page.runs_the_pinned_text_only_harmbench_generation_scripts]]</p><div class='cols'>"
            )
            + text_field(
                "hcap_corpus",
                _ui_text("builder_page.logical_corpus_arm"),
                _ui_text("builder_page.bundle_identity"),
                default="harmbench_text",
            )
            + text_field(
                "hcap_methods",
                _ui_text("builder_page.methods"),
                _ui_text("builder_page.comma_separated_text_methods"),
                default="PEZ,PAP-top5",
            )
            + text_field(
                "hcap_experiment",
                _ui_text("builder_page.experiment"),
                _ui_text("builder_page.harmbench_model_setup"),
                default="llama2_7b",
            )
            + text_field(
                "hcap_limit",
                _ui_text("builder_page.limit"),
                _ui_text("builder_page.selected_source_clusters"),
                default="1",
                kind="number",
            )
            + text_field(
                "hcap_sample_seed",
                _ui_text("builder_page.sample_seed"),
                _ui_text("builder_page.reproducible_subset"),
                default="0",
                kind="number",
            )
            + text_field(
                "hcap_cases",
                _ui_text("builder_page.cases_per_method"),
                _ui_text("builder_page.bounded_generated_cases"),
                default="1",
                kind="number",
            )
            + _ui_template(
                "</div><details><summary>[[text:builder_page.advanced_capture_overrides]]</summary><div class='cols'>"
            )
            + text_field(
                "hcap_repo",
                _ui_text("builder_page.harmbench_checkout"),
                _ui_text("builder_page.automatic_installed_checkout"),
            )
            + text_field(
                "hcap_revision",
                _ui_text("builder_page.upstream_revision"),
                _ui_text("builder_page.automatic_installed_revision"),
            )
            + text_field(
                "hcap_source",
                _ui_text("builder_page.behavior_csv"),
                _ui_text("builder_page.automatic_official_text_behaviors"),
            )
            + text_field(
                "hcap_artifact_out",
                _ui_text("builder_page.capture_artifact"),
                _ui_text("builder_page.automatic_saved_output"),
            )
            + text_field(
                "hcap_config_out",
                _ui_text("builder_page.attacker_config"),
                _ui_text("builder_page.automatic_saved_configuration"),
            )
            + text_field(
                "hcap_python",
                _ui_text("builder_page.python_executable"),
                _ui_text("builder_page.automatic_isolated_framework_environment"),
            )
            + text_field(
                "hcap_credentials",
                _ui_text("builder_page.credential_env_names"),
                _ui_text("builder_page.comma_separated_names"),
            )
            + text_field(
                "hcap_timeout",
                _ui_text("builder_page.timeout_seconds"),
                _ui_text("builder_page.positive_finite_value"),
                kind="number",
            )
            + _ui_template(
                "</div></details><div class='workflow-actions'><button type='submit' class='ghost' formaction='/build/harmbench/prepare' formmethod='post'>[[text:builder_page.review_prepare]]</button></div></div><details class='workflow-step'><summary>[[text:builder_page.advanced_import_or_current_saved_material]]</summary><p class='note'>[[text:builder_page.completed_captures_attach_automatically_use_this_field_only_to_im]]</p>"
            )
            + err("harm_replay")
            + "<div class='cols'>"
            + text_field(
                "harm_config",
                _ui_text("builder_page.capture_config"),
                _ui_text("builder_page.generated_attackers_json_path"),
            )
            + "</div></details></section>"
            "<section class='workflow-panel prepared-fields' id='prepared-nanogcg' "
            "data-prepared='nanogcg'"
            + visibility("nanogcg")
            + _ui_template(
                "><h3>[[text:builder_page.nanogcg]] <span class='badge blue'>[[text:builder_page.precomputed_replay_2]]</span></h3><p class='note'>[[text:builder_page.live_nanogcg_optimization_is_disabled_until_its_isolated_runtime]]</p>"
            )
            + err("nanogcg")
            + _ui_template(
                "<div class='workflow-step'><h4>[[text:builder_page.precomputed_suffix_replay]]</h4><div class='cols'>"
            )
            + text_field(
                "nanogcg_suffix",
                _ui_text("builder_page.exact_suffix"),
                _ui_text("builder_page.non_empty_replay_payload_no_model_is_loaded"),
            )
            + text_field(
                "nanogcg_suffix_source",
                _ui_text("builder_page.suffix_source"),
                _ui_text("builder_page.paper_artifact_or_retained_run_identity"),
            )
            + "</div></div></section>"
            "<section class='workflow-panel prepared-fields' id='prepared-ideator' "
            "data-prepared='ideator'"
            + visibility("ideator")
            + _ui_template(
                "><h3>[[text:builder_page.ideator]] <span class='badge blue'>[[text:builder_page.verified_seed_pair_replay_2]]</span></h3><p class='note'>[[text:builder_page.ideator_uses_imported_source_mapped_text_image_pairs_select_the_s]]</p>"
            )
            + err("ideator")
            + _ui_template(
                "<div class='workflow-step'><h4>[[text:builder_page.precomputed_text_image_pairs]]</h4><div class='cols'>"
            )
            + text_field(
                "ideator_manifest",
                _ui_text("builder_page.seed_pair_manifest"),
                _ui_text("builder_page.source_mapped_v2_path_under_results_v1_is_legacy"),
            )
            + _ui_template(
                "<details><summary>[[text:builder_page.advanced_identity_override]]</summary>"
            )
            + text_field(
                "ideator_manifest_sha",
                _ui_text("builder_page.manifest_identity"),
                _ui_text("builder_page.automatic_from_the_selected_file"),
            )
            + "</details>"
            + text_field(
                "ideator_pair_limit",
                _ui_text("builder_page.replay_pair_limit"),
                _ui_text("builder_page.0_all_verified_pairs_positive_n_ordered_manifest_prefix"),
                default="0",
                kind="number",
            )
            + "</div><p class='note' id='ideator-pair-status' data-available='"
            + html.escape(ideator_available_attr)
            + "' aria-live='polite'>"
            + html.escape(ideator_pair_status)
            + "</p></div></section></div></div>"
        )

        selected_arms = self._split_list(prefill.get("corpora", ""))
        selected_arm_count = len(selected_arms)
        synthetic_canary = (
            selected_mode == "diagnostic_canary" and prefill.get("canary_dry") == "on"
        )
        effective_arm_count = 1 if synthetic_canary else selected_arm_count
        raw_limit = prefill.get("limit", "")
        if synthetic_canary and not raw_limit:
            raw_limit = "1"
        try:
            parsed_limit = int(raw_limit) if raw_limit else None
        except ValueError:
            parsed_limit = None
        range_value = parsed_limit if parsed_limit is not None and parsed_limit >= 0 else 50
        projection_view, _projection_reason = self._read_lane_projection(prefill)
        projected_arm_counts: dict[str, dict[str, int]] = {}
        if isinstance(projection_view, Mapping):
            raw_projected_arms = projection_view.get("arms")
            if isinstance(raw_projected_arms, list):
                for raw_arm in raw_projected_arms:
                    if not isinstance(raw_arm, Mapping):
                        projected_arm_counts = {}
                        break
                    arm_id = raw_arm.get("logical_source_arm")
                    integer_fields = (
                        "total_records",
                        "selected_records",
                        "total_clusters",
                        "selected_clusters",
                        "limit",
                        "sample_seed",
                    )
                    if (
                        not isinstance(arm_id, str)
                        or not arm_id
                        or any(
                            isinstance(raw_arm.get(field), bool)
                            or not isinstance(raw_arm.get(field), int)
                            for field in integer_fields
                        )
                    ):
                        projected_arm_counts = {}
                        break
                    projected_arm_counts[arm_id] = {
                        field: int(raw_arm[field]) for field in integer_fields
                    }
        exact_arm_cardinality = (
            not synthetic_canary
            and bool(selected_arms)
            and set(projected_arm_counts) == set(selected_arms)
        )
        range_max = (
            max(item["total_clusters"] for item in projected_arm_counts.values())
            if exact_arm_cardinality
            else 1
        )
        range_render_value = min(range_value, range_max)
        sampling_disabled = "" if effective_arm_count else " disabled"
        range_field_hidden = "" if exact_arm_cardinality else " hidden"
        range_disabled = "" if exact_arm_cardinality else " disabled"
        if exact_arm_cardinality:
            effective_clusters = sum(
                item["total_clusters"]
                if parsed_limit == 0
                else min(
                    parsed_limit if parsed_limit is not None and parsed_limit > 0 else 50,
                    item["total_clusters"],
                )
                for item in projected_arm_counts.values()
            )
            selected_records = sum(
                item["selected_records"] for item in projected_arm_counts.values()
            )
            sampling_status = (
                _ui_text("builder_page.exact_projection")
                + f"{effective_clusters}"
                + _ui_text("builder_page.clusters_across")
                + f"{selected_arm_count}"
                + _ui_text(
                    "builder_page.independently_capped_arms_the_current_selection_expands_to"
                )
                + f"{selected_records}"
                + _ui_text("builder_page.converted_rows")
            )
        elif effective_arm_count:
            sampling_status = _ui_text(
                "builder_page.enter_a_non_negative_cluster_limit_now_the_exact_slider_range_and"
            )
        else:
            sampling_status = _ui_text("builder_page.select_one_or_more_arms_to_configure_sampling")
        sampling_arm_label = (
            _ui_text("builder_page.synthetic_arm_selected_automatically")
            if synthetic_canary
            else (
                f"{selected_arm_count}"
                + _ui_text("builder_page.arm_copy")
                + f"{('s' if selected_arm_count != 1 else '')}"
                + " selected"
            )
        )
        if exact_arm_cardinality:
            inventory_rows = "".join(
                "<tr><td><code>"
                + html.escape(arm_id)
                + "</code></td><td>"
                + f"{item['total_clusters']:,}"
                + "</td><td>"
                + f"{item['total_records']:,}"
                + "</td></tr>"
                for arm_id, item in sorted(projected_arm_counts.items())
            )
            sampling_inventory = (
                _ui_template(
                    "<div class='scroll' id='sample-arm-inventory'><table><tr><th>[[text:builder_page.arm]]</th><th>[[text:builder_page.available_clusters]]</th><th>[[text:builder_page.available_converted_rows]]</th></tr>"
                )
                + inventory_rows
                + "</table></div>"
            )
        else:
            sampling_inventory = _ui_template(
                "<p class='note' id='sample-arm-inventory'>[[text:builder_page.no_exact_arm_cardinality_is_claimed_until_the_matching_no_call_pr]]</p>"
            )
        arm_cardinality_json = html.escape(
            json.dumps(
                projected_arm_counts if exact_arm_cardinality else {},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        sample_seed = prefill.get("sample_seed", "0")
        sampling_policy = prefill.get("sampling_policy", DEFAULT_SAMPLING_POLICY)
        sampling_policy_options = "".join(
            "<option value='"
            + html.escape(value)
            + "'"
            + (" selected" if sampling_policy == value else "")
            + ">"
            + html.escape(label)
            + "</option>"
            for value, label in (
                (
                    SEEDED_PSEUDORANDOM_CLUSTER_PREFIX,
                    _ui_text("builder_page.seeded_pseudorandom_cluster_prefix_default"),
                ),
                (SOURCE_ORDER_CLUSTER_PREFIX, _ui_text("builder_page.source_order_cluster_prefix")),
            )
        )
        if sampling_policy not in {
            SEEDED_PSEUDORANDOM_CLUSTER_PREFIX,
            SOURCE_ORDER_CLUSTER_PREFIX,
        }:
            sampling_policy_options = (
                "<option value='"
                + html.escape(sampling_policy)
                + _ui_template(
                    "' selected>[[text:builder_page.unsupported_submitted_policy]]</option>"
                )
                + sampling_policy_options
            )
        sampling_fields = (
            "<section class='sample-size-control' id='sample-size-control' aria-hidden='false'"
            + " data-arm-cardinalities='"
            + arm_cardinality_json
            + "'"
            + _ui_template(
                "><div class='sample-size-head'><div><h3>[[text:builder_page.per_arm_sample_size]]</h3><p class='note'>[[text:builder_page.the_same_value_applies_independently_to_every_selected_arm]] <strong>[[text:builder_page.0_full_selected_release]]</strong>[[text:builder_page.a_positive_value_is_the_maximum_source_cluster_count_per_selected]]</p></div><span class='badge blue' id='sample-arm-count'>"
            )
            + html.escape(sampling_arm_label)
            + "</span></div>"
            "<p id='sample-arm-prerequisite' class='note'"
            + (" hidden" if effective_arm_count else "")
            + _ui_template(
                ">[[text:builder_page.select_a_corpus_in]] <a href='#input-corpora'>[[text:builder_page.pipeline_arms_corpora]]</a> [[text:builder_page.to_enable_the_limit_sample_seed_and_sampling_policy_below_these_c]]</p><div class='sample-size-grid'><div class='fieldcell sample-range-field'"
            )
            + range_field_hidden
            + (
                _ui_template(
                    "><label class='fieldlabel' for='sample-limit-range'>[[text:builder_page.sample_size_range]] <span class='fieldhint'>[[text:builder_page.exact_validated_maximum_0_is_full_mode]]</span></label><input id='sample-limit-range' type='range' min='0' max='"
                )
                + f"{range_max}"
                + "' step='1' value='"
                + f"{range_render_value}"
                + "'"
            )
            + range_disabled
            + _ui_template(
                " aria-describedby='sample-limit-status'></div><div class='fieldcell'><label class='fieldlabel' for='sample-limit-number'>--limit <span class='fieldhint'>[[text:builder_page.non_negative_clusters_per_selected_arm]]</span></label><input class='wide' id='sample-limit-number' type='number' min='0' step='1' name='limit'"
            )
            + (f" value='{html.escape(raw_limit)}'" if raw_limit else "")
            + sampling_disabled
            + ">"
            + err("limit")
            + _ui_template(
                "</div><div class='fieldcell'><label class='fieldlabel' for='sample-seed-input'>--sample-seed <span class='fieldhint'>[[text:builder_page.randomized_policy_seed_request_bound_for_both]]</span></label><input class='wide' id='sample-seed-input' type='number' step='1' name='sample_seed' value='"
            )
            + html.escape(sample_seed)
            + "'"
            + sampling_disabled
            + ">"
            + err("sample_seed")
            + _ui_template(
                "</div><div class='fieldcell'><label class='fieldlabel' for='sampling-policy-select'>--sampling-policy <span class='fieldhint'>[[text:builder_page.whole_cluster_prefix_ordering]]</span></label><select class='wide' id='sampling-policy-select' name='sampling_policy'"
            )
            + sampling_disabled
            + ">"
            + sampling_policy_options
            + "</select>"
            + err("sampling_policy")
            + "</div></div><p class='fieldhint' id='sample-limit-status' "
            "aria-live='polite'>"
            + html.escape(sampling_status)
            + "</p>"
            + sampling_inventory
            + "</section>"
        )

        # Repeatable live-attestation receipt/digest rows.
        att_rows_html = []
        prefilled_rows = [
            index
            for index in range(1, self._MAX_ATT_ROWS + 1)
            if prefill.get(f"att_path{index}") or prefill.get(f"att_sha{index}")
        ]
        visible_rows = max(prefilled_rows or [1])
        for index in range(1, visible_rows + 1):
            att_rows_html.append(
                (
                    "<div class='attrow' data-row='"
                    + f"{index}"
                    + "'><input class='wide' type='text' name='att_path"
                    + f"{index}"
                    + "' placeholder='runs/thesis/attest/receipt.live-attestation.json' value='"
                    + f"{val(f'att_path{index}')}"
                    + "'><input class='wide' type='text' name='att_sha"
                    + f"{index}"
                    + _ui_template(
                        "' placeholder='[[attr:builder_page.exact_64_hex_sha256]]' value='"
                    )
                    + f"{val(f'att_sha{index}')}"
                    + "'></div>"
                )
            )
        env_project = os.environ.get("URA_PROJECT_REVISION_MANIFEST", "")
        env_project_sha = os.environ.get("URA_PROJECT_REVISION_SHA256", "")
        env_source = os.environ.get("URA_SOURCE_CONFORMANCE_MANIFEST", "")
        env_source_sha = os.environ.get("URA_SOURCE_CONFORMANCE_SHA256", "")
        project_refresh = ""
        if env_project and env_project_sha:
            different_project = bool(prefill.get("project_revision_sha")) and (
                prefill.get("project_revision_sha") != env_project_sha
            )
            project_refresh = (
                "<div class='action-row'><button type='button' class='ghost' "
                "id='use-current-project-receipt' data-path='"
                + html.escape(env_project, quote=True)
                + "' data-sha='"
                + html.escape(env_project_sha, quote=True)
                + _ui_template(
                    "'>[[text:builder_page.use_current_project_receipt]]</button></div><p id='project-receipt-refresh-status' class='note' role='status'>"
                )
                + (
                    _ui_text(
                        "builder_page.this_saved_receipt_differs_from_the_console_s_current_project_rec"
                    )
                    if different_project
                    else ""
                )
                + _ui_template(
                    "[[text:builder_page.after_a_software_update_use_the_current_receipt_and_review_prepar]]</p>"
                )
            )
        error_summary = ""
        if errors:
            items = "".join(
                f"<li><strong>{html.escape(field)}</strong>: {html.escape(message)}</li>"
                for field, message in sorted(errors.items())
            )
            error_summary = (
                _ui_template(
                    "<div class='notice red'><strong>[[text:builder_page.the_lane_was_not_started]]</strong><ul>"
                )
                + f"{items}"
                + _ui_template(
                    "</ul><p class='note'>[[text:builder_page.each_problem_is_also_flagged_next_to_its_control_below_nothing_wa]]</p></div>"
                )
            )
        build_tabs = (
            ("build-general", _ui_text("builder_page.general")),
            ("build-runtimes", _ui_text("builder_page.runtimes")),
            ("build-pipeline", _ui_text("builder_page.pipeline")),
            ("build-evaluation", _ui_text("builder_page.evaluation")),
            ("build-admission", _ui_text("builder_page.admission")),
            ("build-execution", _ui_text("builder_page.execution")),
        )
        build_default = "build-general"
        error_fields = set(errors)
        error_panel_fields = (
            ("build-general", {"work_kind", "campaign_name", "campaign_id", "campaign_guide"}),
            (
                "build-pipeline",
                {
                    "mode",
                    "corpora",
                    "models",
                    "attackers",
                    "engine_runtime_config",
                    "nanogcg",
                    "ideator",
                    "t3_replay",
                    "harm_replay",
                },
            ),
            (
                "build-evaluation",
                {
                    "judges",
                    "judge_model",
                    "approximate_common_metrics",
                    "ack_hosted_judge_data_transfer",
                    "defense",
                    "defense_guard",
                    "guardrail_model",
                    "guardrail_revision",
                    "guardrail_device",
                    "defense_guardrail_model",
                    "defense_guardrail_revision",
                    "defense_guardrail_device",
                },
            ),
            (
                "build-admission",
                {
                    "project_revision",
                    "project_revision_sha",
                    "source_conformance",
                    "source_conformance_sha",
                    "scope",
                    "max_age",
                    "att",
                },
            ),
        )
        if errors:
            build_default = "build-execution"
            if any(field.startswith(("t3cap_", "hcap_")) for field in error_fields):
                build_default = "build-pipeline"
            else:
                for panel_id, panel_fields in error_panel_fields:
                    if error_fields & panel_fields:
                        build_default = panel_id
                        break
        elif framework_runtime_state or framework_runtime_error:
            build_default = "build-runtimes"
        general_panel = (
            "<div class='card' id='pipeline-details'><h2>"
            + _icon("flask")
            + _ui_template(
                "[[text:builder_page.current_pipeline]]</h2><p class='note'>[[text:builder_page.a_live_summary_of_the_controls_across_every_builder_section_recei]]</p><dl class='builder-summary' aria-live='polite'><div><dt>[[text:builder_page.composition]]</dt><dd id='build-summary-composition'>[[text:builder_page.initializing]]</dd></div><div><dt>[[text:builder_page.evaluation]]</dt><dd id='build-summary-evaluation'>[[text:builder_page.initializing]]</dd></div><div><dt>[[text:builder_page.admission]]</dt><dd id='build-summary-admission'>[[text:builder_page.initializing]]</dd></div><div><dt>[[text:builder_page.trajectory]]</dt><dd id='build-summary-trajectory'>[[text:builder_page.initializing]]</dd></div><div><dt>[[text:builder_page.budget_guards]]</dt><dd id='build-summary-budget'>[[text:builder_page.initializing]]</dd></div><div><dt>[[text:builder_page.local_serving]]</dt><dd id='build-summary-local'>[[text:builder_page.initializing]]</dd></div><div><dt>[[text:builder_page.output]]</dt><dd id='build-summary-output'>[[text:builder_page.initializing]]</dd></div></dl><p class='fieldlabel'>[[text:builder_page.high_level_composition_preview]] <span class='fieldhint'>[[text:builder_page.not_the_final_reviewed_command]]</span></p><code id='buildpreview'>run_matrix ([[text:builder_page.initializing_current_choices]])</code></div>"
            )
        )
        from .builder_sources import source_panel
        from .campaign_flow import panel as campaign_panel

        details = general_panel
        general_panel = campaign_panel(self, dict(prefill)) + source_panel(
            self, dict(prefill), unified=True
        )
        general_panel += (
            _ui_template(
                "<section class='card' id='pipeline-review'><h2>[[text:builder_page.review_your_selected_work]]</h2><p>[[text:builder_page.preparation_runs_automatically_review_the_workload_before_startin]]</p><div class='campaign-actions'><button form='builder' type='submit' class='ghost' data-save-campaign formaction='/build/save'>[[text:builder_page.save_campaign]]</button><button form='builder' type='submit' data-review-campaign>[[text:builder_page.review_campaign]]</button></div></section><details class='card'><summary>[[text:builder_page.pipeline_details_and_cli_preview]]</summary>"
            )
            + details
            + "</details>"
        )
        general_panel += self._operation_links(prefill.get("campaign_id", ""))
        from .campaign_assessment import panel as assessment_panel

        if prefill.get("campaign_id"):
            general_panel += (
                _ui_template(
                    '<details class="card"><summary>[[text:builder_page.additional_assessment_of_saved_answers]]</summary>'
                )
                + assessment_panel(prefill["campaign_id"])
                + "</details>"
            )
        force_default = (
            " data-force-default='true'"
            if errors or framework_runtime_state or framework_runtime_error
            else ""
        )
        body = (
            "<h1>"
            + _icon("flask", size=22)
            + _ui_template("[[text:builder_page.build]]</h1>")
            + (
                _ui_template(
                    '<p class="notice green" role="status">[[text:builder_page.campaign_saved_continue_editing_or_compose_your_experiment_below]]</p>'
                )
                if saved
                else ""
            )
            + _ui_template(
                "<p>[[text:builder_page.define_a_campaign_or_an_independent_run_select_your_models_inputs]]</p>"
            )
            + error_summary
            + self._build_work_choice(dict(prefill))
            + "<div class='page-tabs' data-page-tabs data-tab-key='build-"
            + html.escape(prefill.get("campaign_id") or prefill.get("work_kind", "run"), quote=True)
            + "' "
            + f"data-default-tab='{build_default}'{force_default}>"
            + _page_tablist(
                _ui_text("builder_page.builder_sections"), build_tabs, default=build_default
            )
            + _page_tabpanel("build-general", general_panel)
            + _page_tabpanel(
                "build-runtimes",
                hardware_card
                + ollama_card
                + "<div id='framework-runtimes'>"
                + framework_runtime_panel
                + "</div>",
            )
            + "<form method='post' action='/build/review' id='builder'>"
            "<input type='hidden' name='_refresh_setup' value='yes'>"
            # hidden composed fields
            "<input type='hidden' name='corpora'><input type='hidden' name='api'>"
            "<input type='hidden' name='local'>"
            "<input type='hidden' name='attackers'>"
            "<input type='hidden' name='judges'>"
            "<input type='hidden' name='modality_scope'>"
            "<section class='page-tabpanel' id='build-pipeline' role='tabpanel' "
            "aria-labelledby='build-pipeline-tab' tabindex='0' "
            "data-page-panel='build-pipeline'>"
            "<div class='card'><h2>"
            + _icon("play")
            + _ui_template("[[text:builder_page.mode]]</h2><div class='radios'>")
            + mode_html
            + "</div></div>"
            "<div class='card'><h2>"
            + _icon("grid")
            + _ui_template(
                "[[text:builder_page.modality_scope]]</h2><p class='note'>[[text:builder_page.input_modalities_all_enabled_for_a_fresh_build_turn_one_off_to_hi]]</p><div class='modscope'>"
            )
            + "".join(
                "<label class='modtoggle'><input type='checkbox' class='modbox' "
                f"data-mod='{m}'"
                + (
                    " checked"
                    if m in self._split_list(prefill.get("modality_scope", ",".join(_MODALITIES)))
                    else ""
                )
                + f"><span>{html.escape(m)}</span></label>"
                for m in _MODALITIES
            )
            + "</div></div>"
            "<div class='card' id='input-corpora'><h2>"
            + _icon("box")
            + _ui_template(
                "[[text:builder_page.arms_corpora]]</h2><p class='note'>[[text:builder_page.arms_in_the_current_modality_scope_each_shows_its_modality_tags_u]]</p>"
            )
            + err("corpora")
            + "".join(arm_groups)
            + "</div>"
            "<div class='card' id='target-models'><h2>"
            + _icon("coins")
            + _ui_template("[[text:builder_page.target_models]]</h2>")
            + err("models")
            + _ui_template(
                "<p class='note'>[[text:builder_page.use_the_shared_selector_to_choose_one_or_more_hosted_targets_and]]</p>"
            )
            + target_selector
            + "</div>"
            "<div class='card' id='attack-frameworks'><h2>"
            + _icon("pulse")
            + _ui_template("[[text:builder_page.attack_frameworks]]</h2>")
            + err("attackers")
            + "<div class='checkgrid'>"
            + framework_boxes
            + "</div>"
            + engine_runtime_fields
            + prepared_workflow_fields
            + "</div>"
            "</section><section class='page-tabpanel' id='build-evaluation' "
            "role='tabpanel' aria-labelledby='build-evaluation-tab' tabindex='0' "
            "data-page-panel='build-evaluation'>"
            "<div class='card' id='evaluation-judges'><h2>"
            + _icon("receipt")
            + _ui_template("[[text:builder_page.judges_defense]]</h2>")
            + err("judges")
            + "<div class='checkgrid'>"
            + judge_boxes
            + approximate_metrics_control
            + "</div>"
            + err("judge_model")
            + _ui_template(
                "<p class='note'>[[text:builder_page.the_llm_judge_uses_an_explicitly_selected_hosted_or_local_configu]]</p>"
            )
            + judge_selector
            + err("ack_hosted_judge_data_transfer")
            + "<label class='check hosted-judge-transfer-ack'>"
            + "<input type='checkbox' name='ack_hosted_judge_data_transfer'"
            + (" checked" if prefill.get("ack_hosted_judge_data_transfer") == "on" else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.hosted_judge_data_transfer_acknowledgement]]</strong> "
            )
            + _ui_text("builder_page.i_understand_that_target_responses_the_harmful_source_request")
            + _ui_text(
                "builder_page.and_source_reference_grading_context_may_be_sent_to_the_selected"
            )
            + _ui_text(
                "builder_page.second_provider_and_may_be_subject_to_that_provider_s_retention"
            )
            + _ui_text(
                "builder_page.usage_and_corpus_license_terms_i_reviewed_those_terms_for_this"
            )
            + _ui_template("[[text:builder_page.live_condition]]</span></label>")
            + "<div class='cols'>"
            + (
                "<div class='fieldcell'><label class='fieldlabel'>--defense</label><select name='defense'>"
                + f"{defense_opts}"
                + "</select>"
                + f"{err('defense')}"
                + _ui_template(
                    "</div><div class='fieldcell'><label class='fieldlabel'>--defense-guard <span class='fieldhint'>[[text:builder_page.guard_used_when_a_defense_is_on]]</span></label><select name='defense_guard'>"
                )
                + f"{guard_opts}"
                + "</select>"
            )
            + err("defense_guard")
            + _ui_template(
                "</div></div><h3>[[text:builder_page.scoring_guardrail]] <span class='fieldhint'>[[text:builder_page.the_judge_cascade_s]] <code>guardrail</code> [[text:builder_page.grader_add]] <code>guardrail</code> [[text:builder_page.to_the_judges_above_to_use_it]]</span></h3><div class='cols'>"
            )
            + text_field(
                "guardrail_model",
                "--guardrail-model",
                _ui_text("builder_page.scoring_guardrail_model_id"),
                placeholder="meta-llama/Llama-Guard-3-8B",
            )
            + _ui_template(
                "</div><p class='note'>[[text:builder_page.revision_and_device_are_automatic_the_installed_model_revision_is]]</p><h3>[[text:builder_page.defense_guardrail]] <span class='fieldhint'>[[text:builder_page.the_model_backed_defense_guard_defense_guard_guardrail_must_be_a]]</span></h3><div class='cols'>"
            )
            + text_field(
                "defense_guardrail_model",
                "--defense-guardrail-model",
                _ui_text("builder_page.defense_guardrail_model_id_distinct_from_scoring"),
            )
            + text_field(
                "defense_guardrail_revision",
                "--defense-guardrail-revision",
                _ui_text("builder_page.required_immutable_40_64_hex_revision"),
            )
            + text_field(
                "defense_guardrail_device",
                "--defense-guardrail-device",
                _ui_text("builder_page.required_explicit_device"),
            )
            + "</div></div>"
            "</section><section class='page-tabpanel' id='build-admission' "
            "role='tabpanel' aria-labelledby='build-admission-tab' tabindex='0' "
            "data-page-panel='build-admission'>"
            + setup_controls
            + _ui_template(
                "<fieldset id='advanced-setup-fields'><legend>[[text:builder_page.advanced_overrides]]</legend><div class='card'><h2>"
            )
            + _icon("receipt")
            + _ui_template(
                "[[text:builder_page.receipts_fail_closed_admission]]</h2><p class='note'>[[text:builder_page.every_non_dry_run_requires_the_validated_project_revision_receipt]]</p><div class='cols'>"
            )
            + text_field(
                "project_revision",
                "--project-revision",
                _ui_text("builder_page.ura_project_revision_1_receipt_path"),
                default=env_project,
            )
            + text_field(
                "project_revision_sha",
                "--project-revision-sha256",
                _ui_text("builder_page.exact_byte_digest"),
                default=env_project_sha,
            )
            + text_field(
                "source_conformance",
                "--source-conformance",
                _ui_text("builder_page.ura_source_conformance_1_receipt_path"),
                default=env_source,
            )
            + text_field(
                "source_conformance_sha",
                "--source-conformance-sha256",
                _ui_text("builder_page.exact_byte_digest"),
                default=env_source_sha,
            )
            + "</div>"
            + project_refresh
            + "</div>"
            "<div class='card' id='advanced-transport-evidence'><h2>"
            + _icon("logo")
            + _ui_template(
                "[[text:builder_page.execution_scope_live_attestation]]</h2><p class='note'>[[text:builder_page.probes_create_attestations_live_canaries_and_measured_lanes_consu]]</p><div class='cols'>"
            )
            + text_field(
                "scope",
                "--execution-scope-id",
                _ui_text("builder_page.non_secret_account_runtime_scope_label"),
            )
            + text_field(
                "max_age",
                "--live-attestation-max-age-hours",
                _ui_text("builder_page.maximum_receipt_age_in_0_8760"),
                kind="number",
            )
            + _ui_template(
                "</div><label class='fieldlabel'>[[text:builder_page.live_attestation_receipt_digest_pairs]]</label>"
            )
            + err("att")
            + "<div id='attrows'>"
            + "".join(att_rows_html)
            + _ui_template(
                "</div><button type='button' class='ghost' id='addatt'>[[text:builder_page.add_receipt_row]]</button></div></fieldset></section><section class='page-tabpanel' id='build-execution' role='tabpanel' aria-labelledby='build-execution-tab' tabindex='0' data-page-panel='build-execution'><div class='card'><h2>"
            )
            + _icon("sliders")
            + _ui_template("[[text:builder_page.sampling_turns]]</h2>")
            + sampling_fields
            + "<div class='cols'>"
            + text_field(
                "seeds",
                "--seeds",
                _ui_text("builder_page.comma_list_of_trajectory_seeds"),
                default="0",
            )
            + text_field(
                "max_queries",
                "--max-queries",
                _ui_text("builder_page.max_target_calls_per_datapoint_and_seed"),
                kind="number",
            )
            + text_field(
                "max_turns",
                "--max-turns",
                _ui_text("builder_page.max_conversation_turns_per_datapoint_and_seed"),
                kind="number",
            )
            + text_field(
                "target_answer_retries",
                "--target-answer-retries",
                _ui_text(
                    "builder_page.additional_attempts_for_empty_malformed_binary_control_like_or_sy"
                ),
                default="1",
                kind="number",
            )
            + _ui_template(
                "</div></div><details class='card'><summary>[[text:builder_page.advanced_execution_and_recovery_options]]</summary><h2>"
            )
            + _icon("chart")
            + _ui_template(
                "[[text:builder_page.aggregation_row_admission_resume]]</h2><p class='note'>[[text:builder_page.the_same_group_reset_open_circuits_and_lock_stale_seconds_the_doc]]</p><div class='cols'>"
            )
            + text_field(
                "group",
                "--group",
                _ui_text(
                    "builder_page.comma_list_of_aggregation_keys_the_runbook_s_measured_lanes_pass"
                ),
                default=_RUNBOOK_GROUP,
            ).replace(
                "name='group'",
                "name='group' list='dl-build-group'",
            )
            + "<datalist id='dl-build-group'>"
            + "".join(
                f"<option value='{html.escape(value)}'></option>" for value in (_RUNBOOK_GROUP,)
            )
            + "</datalist>"
            + text_field(
                "lock_stale_seconds",
                "--lock-stale-seconds",
                _ui_text(
                    "builder_page.optional_positive_integer_diagnostic_stale_age_metadata_only_lock"
                ),
                kind="number",
            )
            + "</div>"
            + err("exclude_tool_conditioned")
            + "<label class='check'><input type='checkbox' "
            "name='exclude_tool_conditioned'"
            + (" checked" if exclude_tool_conditioned_checked else "")
            + exclude_tool_conditioned_disabled
            + _ui_template(
                "><span><strong>[[text:builder_page.exclude_tool_conditioned_rows_exclude_tool_conditioned]]</strong> <span class='fieldhint'>[[text:builder_page.drop_source_rows_no_runner_attacker_can_execute_with_a_recorded_e]]</span></span></label>"
            )
            + err("reset_open_circuits")
            + "<label class='check'><input type='checkbox' "
            "name='reset_open_circuits'"
            + (" checked" if prefill.get("reset_open_circuits") == "on" else "")
            + _ui_template(
                "><span><strong>[[text:builder_page.reset_open_circuits_reset_open_circuits]]</strong> <span class='fieldhint'>[[text:builder_page.measured_lane_resume_only_operator_acknowledgement_that_the_provi]]</span></span></label></details><div class='card' id='execution-budgets'><h2>"
            )
            + _icon("coins")
            + _ui_template(
                "[[text:builder_page.call_ceilings_deadline_budget_guards]]</h2><p class='note'>[[text:builder_page.the_workload_check_calculates_target_judge_and_transport_limits_r]]</p><label class='checkrow'><input type='checkbox' name='automatic_caps'"
            )
            + (
                " checked"
                if prefill.get("automatic_caps") == "on"
                or not any(prefill.get(k) for k in ("cap_target", "cap_judge", "cap_http"))
                else ""
            )
            + _ui_template(
                "><span>[[text:builder_page.calculate_call_limits_automatically]]</span></label><details><summary>[[text:builder_page.manual_call_limit_overrides]]</summary><p>[[text:builder_page.uncheck_automatic_calculation_to_use_these_limits]]</p><div class='cols'>"
            )
            + text_field(
                "cap_target",
                "--max-total-target-calls",
                _ui_text("builder_page.hard_cap_on_target_calls"),
                kind="number",
            )
            + text_field(
                "cap_judge",
                "--max-total-judge-calls",
                _ui_text("builder_page.hard_cap_on_model_backed_judge_calls_hosted_or_local"),
                kind="number",
            )
            + text_field(
                "cap_http",
                "--max-total-http-attempts",
                _ui_text("builder_page.hard_cap_on_transport_attempts"),
                kind="number",
            )
            + "</div></details><div class='cols'>"
            + text_field(
                "local_budget_hours",
                _ui_text("builder_page.local_process_wall_time_cap_hours"),
                _LOCAL_BUDGET_HELP,
                kind="number",
            )
            + text_field(
                "deadline",
                "--deadline-seconds",
                _ui_text(
                    "builder_page.durable_call_start_window_from_first_invocation_not_a_completion"
                ),
                default="3600",
                kind="number",
            )
            + "</div></div>"
            "<div class='card' id='local-serving'><h2>"
            + _icon("disk")
            + _ui_template("[[text:builder_page.local_model_serving]]</h2>")
            + err("verify_model_sha256")
            + "<label class='checkrow'><input type='checkbox' name='verify_model_sha256'"
            + (" checked" if prefill.get("verify_model_sha256") == "on" else "")
            + (
                _ui_template(
                    "><span><strong>[[text:builder_page.full_model_sha_verification_slow_optional]]</strong><br>[[text:builder_page.off_by_default_reuse_installed_models_after_checking_file_metadat]]</span></label><p class='muted'>[[text:builder_page.a_model_without_an_explicit_context_cap_uses_its_native_context_c]]</p><div class='cols'><div class='fieldcell'><label class='fieldlabel'>--dtype</label><select name='dtype'>"
                )
                + f"{dtype_opts}"
                + "</select>"
            )
            + err("dtype")
            + "</div>"
            + text_field(
                "quantization",
                "--quantization",
                _ui_text(
                    "builder_page.default_override_bitsandbytes_awq_gptq_fp8_per_model_config_wins"
                ),
                placeholder="(auto-detect)",
            )
            + "</div></div>"
            "<div class='card'><h2>"
            + _icon("folder")
            + _ui_template(
                "[[text:builder_page.output]]</h2><p id='automatic-output-note' class='note'>[[text:builder_page.the_output_directory_is_assigned_automatically_from_this_run_s_se]]</p><fieldset id='advanced-output-fields'><div class='cols'>"
            )
            + text_field(
                "out",
                "--out",
                _ui_text("builder_page.output_directory_under_the_rig_results_root"),
                default="runs/thesis/lane",
            )
            + "</div></fieldset></div>"
            + _ui_template(
                "<div class='buildbar'><button type='submit' class='ghost' data-save-campaign formaction='/build/save'>[[text:builder_page.save_campaign]]</button><button type='submit' data-review-campaign>"
            )
            + _icon("play", size=15)
            + _ui_template("[[text:builder_page.compose_review]]</button></div></section>")
            + model_picker_modal
            + "</form></div>"
            + "<script>(()=>{const c=document.querySelector('select[name=campaign_id][form=builder]');"
            "const name=document.querySelector('[name=campaign_name]');const fields=document.getElementById('build-campaign-fields');"
            "function update(){const campaign=document.querySelector('[name=work_kind]:checked').value==='campaign';"
            "fields.hidden=!campaign;c.disabled=!campaign;name.disabled=!campaign||!!c.value;name.required=campaign&&!c.value;"
            "document.querySelector('[name=campaign_guide]').disabled=!campaign;"
            "document.getElementById('build-campaign-name').hidden=!!c.value;"
            "document.querySelectorAll('[data-save-campaign]').forEach(e=>{e.hidden=!campaign;});"
            "document.querySelectorAll('[data-builder-campaign]').forEach(e=>{e.value=campaign?c.value:'';});}"
            "document.querySelectorAll('[name=work_kind]').forEach(e=>e.addEventListener('change',update));"
            "c.addEventListener('change',()=>{window.location.assign(c.value?'/build?campaign_id='+encodeURIComponent(c.value)"
            "+'#build-general':'/build?work_kind=campaign#build-general');});update();})();</script>"
            "<script type='application/json' id='builder-prefill'>"
            + json.dumps(
                {
                    "corpora": self._split_list(prefill.get("corpora", "")),
                    "api": self._split_list(prefill.get("api", "")),
                    "local": self._split_list(prefill.get("local", "")),
                    "attackers": self._split_list(prefill.get("attackers", "replay")),
                }
            ).replace("</", "<\\/")
            + "</script>"
            + _BUILDER_SCRIPT
            + "<script>(()=>{const choice=document.getElementById('setup-mode');"
            "function sync(){const automatic=choice.value==='automatic';"
            "['advanced-setup-fields','advanced-output-fields'].forEach(id=>{const field=document.getElementById(id);"
            "field.hidden=automatic;field.disabled=automatic;});"
            "document.getElementById('automatic-output-note').hidden=!automatic;"
            "document.getElementById('automatic-transport-status').hidden=!automatic;}"
            "choice.addEventListener('change',sync);sync();})();</script>"
        )
        return _page(
            _ui_text("builder_page.campaign_builder"), body, active=_ui_text("builder_page.build")
        )
