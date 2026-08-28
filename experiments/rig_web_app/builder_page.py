"""Build-page rendering for campaign composition."""

from __future__ import annotations

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
    ) -> str:
        """Render lifecycle controls outside the campaign-builder form."""

        state = str(status.get("state", "unknown"))
        if state not in {
            "stopped", "starting", "external", "owned", "ambiguous", "busy", "error"
        }:
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
            "owned": "running and owned by this console process",
            "external": (
                "running externally; discovery is read-only and pulls are disabled"
            ),
            "starting": "console-owned process is starting; the API is not ready yet",
            "ambiguous": (
                "API reachable, but listener ownership is unverified; pulls are disabled"
            ),
            "busy": "another Ollama mutation or inference holds the endpoint lock",
            "error": (
                "console-owned process residue could not be fully cleaned; Stop can retry"
            ),
            "stopped": "no compatible daemon is reachable on the loopback endpoint",
            "unknown": "daemon state could not be classified",
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
        roster_excluded = roster.get("excluded")
        excluded = roster_excluded if isinstance(roster_excluded, list) else []
        roster_issues = roster.get("issues")
        issues = roster_issues if isinstance(roster_issues, list) else []

        feedback = ""
        bounded_error = action_error.strip()[:1000]
        if bounded_error:
            feedback = (
                "<div class='notice red'><strong>Ollama action failed.</strong> "
                + html.escape(bounded_error)
                + "</div>"
            )
        elif action_state in {
            "stopped", "starting", "external", "owned", "ambiguous", "busy", "error"
        }:
            feedback = (
                "<div class='notice green'><strong>Ollama action completed.</strong> "
                "Current state: "
                + html.escape(state)
                + ".</div>"
            )

        diagnostics: list[str] = []
        for value in (status.get("warning"), status.get("last_error")):
            if (
                isinstance(value, str)
                and value.strip()
                and value.strip() not in diagnostics
            ):
                diagnostics.append(value.strip())
        roster_error = roster.get("error")
        if isinstance(roster_error, str) and roster_error.strip():
            diagnostics.append(roster_error.strip())
        diagnostics.extend(
            str(value).strip()
            for value in issues[:8]
            if isinstance(value, str) and value.strip()
        )
        diagnostic_html = (
            "<details><summary>Discovery diagnostics ("
            + str(len(diagnostics))
            + ")</summary><ul>"
            + "".join(f"<li>{html.escape(value)}</li>" for value in diagnostics)
            + "</ul></details>"
            if diagnostics
            else ""
        )

        excluded_rows = []
        for row in excluded:
            if not isinstance(row, Mapping):
                continue
            overlaps = row.get("overlap_with")
            overlap_text = (
                ", ".join(
                    str(value) for value in overlaps if isinstance(value, str)
                )
                if isinstance(overlaps, list)
                else "normalized vLLM identity"
            )
            excluded_rows.append(
                "<li><code>"
                + html.escape(str(row.get("spec", "unknown")))
                + "</code> overlaps "
                + html.escape(overlap_text or "normalized vLLM identity")
                + "</li>"
            )
        excluded_html = (
            "<details><summary>Excluded vLLM overlaps ("
            + str(len(excluded_rows))
            + ")</summary><p class='note'>These live tags are not automatic "
            "testing candidates and cannot be enabled by a manual entry. "
            "Use a distinct Ollama model identity for testing.</p><ul>"
            + "".join(excluded_rows)
            + "</ul></details>"
            if excluded_rows
            else ""
        )
        loaded_html = (
            "<p class='note'>Loaded now: "
            + ", ".join(f"<code>{html.escape(value)}</code>" for value in loaded)
            + (
                " and more"
                if isinstance(loaded_value, list) and len(loaded_value) > 16
                else ""
            )
            + ".</p>"
            if loaded
            else (
                "<p class='note'>No loaded model is reported by "
                "<code>/api/ps</code>.</p>"
            )
        )

        start_disabled = "" if state == "stopped" else " disabled"
        stop_disabled = "" if can_stop else " disabled"
        pull_disabled = "" if status.get("can_pull") is True else " disabled"
        return (
            "<div class='card' id='ollama-service'><h2>Local Ollama service</h2>"
            + feedback
            + "<p><span class='badge "
            + tone
            + "'>"
            + html.escape("absent" if state == "stopped" else state)
            + "</span> "
            + html.escape(state_copy)
            + ".</p><p class='note'>Fixed loopback API: <code>"
            + html.escape(
                str(status.get("base_url", "http://127.0.0.1:11434"))
            )
            + "</code>. Discovery and inference use bounded standard-library "
            "HTTP; no Ollama Python SDK is required. "
            "<a href='/ollama/status'>JSON status</a>.</p>"
            + "<p><strong>"
            + str(len(models))
            + " exact live candidate(s)</strong>; "
            + str(len(excluded))
            + " normalized vLLM overlap(s) excluded.</p>"
            + loaded_html
            + diagnostic_html
            + excluded_html
            + "<div class='workflow-actions'>"
            "<form class='inline' method='get' action='/build#ollama-service'>"
            "<button class='ghost' type='submit'>Status</button></form>"
            "<form class='inline' method='post' action='/ollama/start' data-busy>"
            f"<button type='submit'{start_disabled}>Start</button></form>"
            "<form class='inline' method='post' action='/ollama/stop' data-busy>"
            f"<button class='danger' type='submit'{stop_disabled}>Stop</button>"
            "</form></div><h3>Pull a model</h3>"
            "<p class='note'>Enter the daemon model tag without the "
            "<code>ollama:</code> target prefix. The typed job streams bounded "
            "download progress; Jobs shows "
            "<span class='badge blue'>downloading</span> only while its explicit "
            "activity is live.</p>"
            "<form class='cmd' method='post' action='/ollama/pull' data-busy>"
            "<label for='ollama-pull-model'>Exact model tag</label>"
            f"<input id='ollama-pull-model' type='text' name='model' "
            f"maxlength='256' autocomplete='off' placeholder='llama3.2:3b' "
            f"required{pull_disabled}>"
            "<span></span>"
            f"<button type='submit'{pull_disabled}>Pull model</button></form></div>"
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
                "<div class='notice red'><strong>Runtime action was not launched.</strong> "
                + html.escape(action_error[:500])
                + "</div>"
            )
        elif action_state == "launched":
            feedback = (
                "<div class='notice blue'><strong>Named runtime session launched.</strong> "
                "The installer owns the tmux/screen process. Follow its retained "
                "engineering campaign in Jobs or Stats; no duplicate console Job "
                "was created.</div>"
            )
        if not snapshot.available:
            return (
                feedback
                + "<div class='card'><h2>"
                + _icon("box")
                + "Isolated framework runtimes <span class='badge red'>unavailable"
                "</span></h2><p class='note'>"
                + html.escape(snapshot.message)
                + " No installer command was run.</p></div>"
            )

        campaign_link = ""
        if snapshot.campaign_state != "idle":
            campaign_link = (
                " <a href='/jobs/campaign/"
                + html.escape(snapshot.campaign_route_id, quote=True)
                + "'>Open retained campaign</a>"
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
                state_text = f"{latest.action.capitalize()} running"
                tone = "blue"
                next_action = (
                    runtime.plan_action if runtime.plan_action in {"install", "resume", "verify"}
                    else ""
                )
                history = (
                    "The retained task log has no terminal event. The exact plan remains "
                    "authoritative: dispatch safely rejoins an identical live named session, "
                    "or lets the installer lock reject a conflicting live operation."
                )
            elif latest_reports_running:
                campaign_label = (
                    snapshot.campaign_status_tag.strip()
                    or snapshot.campaign_state.strip()
                    or "unknown"
                )
                state_text = f"{latest.action.capitalize()} {campaign_label}"
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
                    "The retained task log has no terminal event, but the enclosing "
                    f"campaign is {campaign_label}; this action is not reported as "
                    "live. The exact current plan remains authoritative."
                )
            elif runtime.plan_action == "install":
                state_text = "Not installed"
                tone = "gray"
                next_action = "install"
                history = "No environment for this lock is published."
            elif runtime.plan_action == "resume":
                state_text = "Partial install retained"
                tone = "amber"
                next_action = "resume"
                history = "Resume continues the exact retained staging environment."
            elif runtime.plan_action == "verify":
                state_text = "Published receipt present"
                tone = "blue"
                next_action = "verify"
                history = (
                    "This page does not rehash the environment; Verify checks the "
                    "current installed bytes against the receipt."
                )
            else:
                state_text = "Conflicting unverified path"
                tone = "red"
                next_action = ""
                history = "Automatic replacement is refused; follow the lock's repair guidance."

            if latest is not None and latest.status != "running":
                when = f" at {latest.at}" if latest.at else ""
                if latest.status == "passed" and latest.action == "verify":
                    history = (
                        f"Last full verification passed{when}. Current bytes are "
                        "not implicitly rehashed on page load."
                    )
                elif latest.status == "passed" and latest.action in {"install", "resume"}:
                    history = f"Publish verification passed{when}. " + history
                elif latest.status == "passed" and latest.action == "adopt":
                    history = f"Runtime adoption and verification passed{when}. " + history
                elif latest.status == "failed":
                    attempted = latest.action or "installer action"
                    history = f"Last {attempted} failed{when}. " + history

            action_html = "<span class='note'>manual repair required</span>"
            if next_action:
                label = {
                    "install": "Install",
                    "resume": "Resume",
                    "verify": "Verify now",
                }[next_action]
                action_html = (
                    "<form class='inline' method='post' "
                    "action='/build/framework-runtimes' "
                    "data-busy='Launching named framework runtime session...' "
                    f"id='framework-runtime-action-{index}'>"
                    "<input type='hidden' name='framework' value='"
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
            + "Isolated framework runtimes <span class='badge blue'>one environment "
            "per framework</span></h2><p class='note'>The checked-in content lock "
            "selects every package, source, and runtime. UI requests contain only "
            "one exact framework name and its currently required action; there is "
            "no shell, path, package, provider, or model input. Install, resume, and "
            "full verification run in installer-owned named tmux (screen fallback) "
            "with a credential-free environment.</p><dl class='builder-summary'>"
            "<div><dt>Runtime lock</dt><dd><code>sha256:"
            + html.escape(snapshot.lock_id)
            + "</code></dd></div><div><dt>Managed environments</dt><dd>"
            + str(len(snapshot.rows))
            + "</dd></div><div><dt>Engineering campaign</dt><dd><span class='badge "
            + campaign_tone
            + "'>"
            + html.escape(snapshot.campaign_status_tag)
            + "</span>"
            + campaign_link
            + "</dd></div></dl><p><a class='button ghost' "
            "href='/build#build-runtimes'>Refresh status</a> "
            "<a class='button ghost' href='/jobs'>Open Jobs</a></p></div>"
            "<div class='card scroll'><table><tr><th>Framework</th><th>Version</th>"
            "<th>Runtime</th><th>Installed state</th><th>Exact action</th></tr>"
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
                return "private explicit-local value omitted"
            return projected

        safe_prefill: dict[str, str] = {}
        for key, value in dict(prefill or {}).items():
            safe_key = durable_ui_text(key)
            safe_value = durable_ui_text(value)
            # Multiple private locators can intentionally share a content
            # digest.  A presentation collision must not silently choose one.
            if safe_key in safe_prefill and safe_prefill[safe_key] != safe_value:
                safe_prefill[safe_key] = "private explicit-local value omitted"
            else:
                safe_prefill[safe_key] = safe_value
        prefill = safe_prefill
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
        exclude_tool_conditioned_checked = (
            selected_mode == "dry_run"
            and (
                prefill.get("exclude_tool_conditioned") == "on"
                if "mode" in prefill
                else True
            )
        )
        exclude_tool_conditioned_disabled = (
            "" if selected_mode == "dry_run" else " disabled"
        )
        # Mode radios.
        mode_html = "".join(
            "<label class='radio'>"
            f"<input type='radio' name='mode' value='{token}'"
            + (" checked" if token == selected_mode else "")
            + ">"
            f"<span><strong>{html.escape(token.replace('_', ' '))}</strong> "
            f"<span class='fieldhint'>{html.escape(desc)}</span></span></label>"
            for token, _flag, desc in _BUILD_MODES
        )
        mode_html += (
            "<label class='check'><input type='checkbox' name='canary_dry'"
            + (" checked" if prefill.get("canary_dry") == "on" else "")
            + ">"
            "<span><strong>dry (synthetic) canary</strong> "
            "<span class='fieldhint'>with diagnostic canary: run the typed "
            "synthetic canary offline (MockTarget, --corpora synth, no "
            "spend)</span></span></label>"
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
        for arm, mods, reason in _ARM_CATALOG:
            if reason and "tool" in mods:
                bucket = (
                    "source-specific tool metric - native runtime required "
                    "(Runner proxy unavailable)"
                )
            elif reason:
                bucket = (
                    "source-specific metric - approximate proxy available "
                    "(evaluator not integrated)"
                )
            elif arm in _SOURCE_METRIC_ARMS:
                bucket = "source-specific metric - runnable (replay attacker only)"
            else:
                bucket = " + ".join(mods)
            signatures.setdefault(bucket, []).append((arm, mods, reason))
        arm_groups = []

        def _bucket_rank(name: str) -> tuple[int, int, str]:
            if "approximate proxy available" in name:
                return (2, len(name), name)
            if name.startswith("source-specific metric"):
                return (1, len(name), name)
            return (0, len(name), name)

        order = sorted(signatures, key=_bucket_rank)
        for signature in order:
            boxes = []
            for arm, mods, reason in signatures[signature]:
                known = arm in registry_arms
                source_disposition = source_dispositions.get(arm)
                if (
                    source_disposition is not None
                    and source_disposition[0] == "blocked"
                ):
                    boxes.append(
                        "<label class='check'>"
                        "<input type='checkbox' class='armbox' disabled "
                        f"data-mods='{html.escape(','.join(mods))}' "
                        f"data-arm='{html.escape(arm)}'>"
                        f"<span>{_arm_head(html.escape(arm), mods)}"
                        "<span class='badge red tip' tabindex='0'>"
                        "blocked by source receipt"
                        "<span class='tiptext'>"
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
                            "tool runtime required"
                            if tool_unavailable
                            else "⚠ approximate opt-in"
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
                        f"Scored by the implemented {metric!r} evaluator, not "
                        "common harmful-ASR; run_matrix admits only the "
                        f"{'/'.join(allowed)} attacker for it."
                    )
                    boxes.append(
                        "<label class='check'>"
                        "<input type='checkbox' class='armbox' "
                        f"data-mods='{html.escape(','.join(mods))}' "
                        f"data-arm='{html.escape(arm)}'>"
                        f"<span>{_arm_head(html.escape(arm), mods)}"
                        "<span class='badge amber tip' tabindex='0'>"
                        "source-metric<span class='tiptext'>"
                        f"{html.escape(source_note)}</span></span>"
                        "</span></label>"
                    )
                    continue
                note = "" if known else " <span class='fieldhint'>(not in registry yet)</span>"
                agg_badge = (
                    "<span class='badge blue tip' tabindex='0'>aggregator"
                    "<span class='tiptext'>Unified / multi-benchmark aggregator "
                    "source: itself pools or spans many upstream safety corpora. "
                    "URA reuses its corpus but drops any pooled composite.</span>"
                    "</span>"
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
                "<div class='modgroup'><div class='grouphead'>"
                f"<h3>{html.escape(signature)}</h3>"
                "<span class='groupsel'>"
                "<button type='button' class='linkbtn' data-sel='all'>All"
                "</button><button type='button' class='linkbtn' "
                "data-sel='none'>None</button></span></div>"
                "<div class='checkgrid'>" + "".join(boxes) + "</div></div>"
            )
        # The offline synthetic corpus - an ORDINARY --dry-run --corpora synth
        # lane (MockTarget, no source acquisition, no spend), not only the dry
        # diagnostic canary.
        arm_groups.insert(
            0,
            "<div class='modgroup'><div class='grouphead'>"
            "<h3>Synthetic (offline)</h3></div><div class='checkgrid'>"
            "<label class='check'><input type='checkbox' class='armbox' "
            "data-mods='text' data-arm='synth'>"
            "<span>"
            + _arm_head("synth", ("text",))
            + "<span class='fieldhint'>offline synthetic corpus - no source "
            "acquisition; use with the dry-run mode (no calls, no spend)</span>"
            "</span></label></div></div>",
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
                        " <span class='badge amber tip judge-cost-warning' "
                        "tabindex='0' role='img' aria-label='Warning: expensive "
                        "judge model'>"
                        "&#9888; expensive"
                        f"<span class='tiptext'>{html.escape(warning)}</span></span>"
                    )
            if kind == "local":
                entry = local_catalog.get(runtime_value, {})
                local_config_error = ""
                known_quant_issues: dict[str, str] = {}
                context_limit = None
                if private_identity_unavailable:
                    local_config_error = (
                        "private explicit checkpoint has no durable digest identity"
                    )
                    disabled = " disabled"
                elif runtime_value.startswith("ollama:"):
                    try:
                        self._validate_ollama_local_entry(runtime_value, entry)
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
                        self._validated_local_modalities(
                            runtime_value, entry, project_richer=True
                        )
                        self._local_gpu_memory_utilization(runtime_value, entry)
                        context_limit = self._local_max_model_len(runtime_value, entry)
                        generation_limit = self._local_max_tokens(runtime_value, entry)
                        if (
                            context_limit is not None
                            and generation_limit > context_limit
                        ):
                            raise ValueError(
                                f"local target {value!r} max_tokens must not "
                                "exceed max_model_len"
                            )
                    except ValueError as exc:
                        local_config_error = durable_ui_text(exc)
                        disabled = " disabled"
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
                    f"{float(params):g}B params" if params is not None else "params unknown"
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
                    "fits" if fit is True else "does not fit" if fit is False else "fit unknown"
                )
                basis = profile.get("multi_gpu_support_basis", "assumed")
                parameter_basis = profile.get("parameter_count_basis", "unknown")
                revision = entry.get("revision")
                digest = entry.get("digest")
                pinned = (
                    isinstance(revision, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", revision)
                ) or (isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest))
                if local_config_error:
                    context_text = "invalid local config"
                elif context_limit is not None:
                    context_text = f"context cap {context_limit:,} tokens"
                else:
                    context_text = "native model context"
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
                    "bitsandbytes": "BitsAndBytes",
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
                    precision_status = "does not fit"
                    precision_title = "Known incompatible with the detected hardware."
                elif fit is None:
                    if configured_quant in {"", "auto"}:
                        quant_label = "fit unknown"
                        precision_title = (
                            "The operator must choose a per-model precision before a live run."
                        )
                    else:
                        quant_label = f"{precision_label} selected · fit unknown"
                        precision_title = (
                            "Operator-selected precision; hardware fit remains unknown."
                        )
                elif hardware_required:
                    precision_status = "required"
                    precision_title = "This precision is required to fit this hardware."
                elif is_override:
                    precision_status = "override"
                    precision_title = "Configured precision override; not hardware-required."
                else:
                    precision_status = ""
                    precision_title = "Highest automatically selected fitting precision."
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
                        " <span class='badge amber tip' tabindex='0' role='img' "
                        "aria-label='Warning: known unsupported precision profile'>"
                        "&#9888; known unsupported precision"
                        f"<span class='tiptext'>{html.escape(known_details)}</span>"
                        "</span>"
                    )
                precision_tone = (
                    "gray"
                    if fit is None
                    else {16: "green", 8: "blue", 4: "amber"}.get(precision_bits, "gray")
                )
                precision_class = "unknown" if fit is None else str(precision_bits)
                badge_class = f"badge {precision_tone} precision-badge precision-{precision_class}"
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
                        + "'>invalid local config</span>"
                    )
                detail = (
                    "<span class='fieldhint'>"
                    + html.escape(
                        durable_ui_text(
                        f"{params_text} ({parameter_basis}) · "
                        f"{profile.get('estimated_vram_gib', '?')} GiB "
                        f"estimated / {profile.get('available_vram_gib', 0)} GiB available "
                        f"· {fit_text} · {quant_label} · TP"
                        f"{profile.get('recommended_tensor_parallel_size', 1)} · "
                        f"multi-GPU {basis} · {context_text} · "
                        f"{'pinned' if pinned else 'revision required'}"
                        + (
                            f" · {profile['compatibility_note']}"
                            if profile.get("compatibility_note")
                            else ""
                        )
                        )
                    )
                    + "</span>"
                )
                choices = (
                    ("auto", "auto (highest fitting 16/8/4-bit)"),
                    ("none", "16-bit (BF16/FP16)"),
                    ("fp8", "8-bit FP8"),
                    ("bitsandbytes", "4-bit BitsAndBytes"),
                    ("awq", "4-bit AWQ"),
                    ("gptq", "4-bit GPTQ"),
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
                    "<div class='modelquant'><label for='" + quant_id + "'>"
                    "Per-model quantization</label>"
                    f"<select id='{quant_id}' "
                    f"name='quantization::{html.escape(value)}'{quant_control_disabled}>"
                    + "".join(
                        f"<option value='{choice}'"
                        + (" selected" if choice == configured_quant else "")
                        + (" disabled" if choice in known_quant_issues else "")
                        + (
                            f" data-fit='{choice_fits[choice]}'"
                            if choice in choice_fits
                            else ""
                        )
                        + f">{label}"
                        + (
                            " - unsupported for this exact vLLM/revision profile"
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
            live_entry = live_ollama_by_spec.get(value)
            overlap_warning = self._ollama_overlap_warning(
                value, live_entry or entry
            )
            try:
                self._validate_ollama_local_entry(value, entry)
            except ValueError as exc:
                problems.append(str(exc))
            manual = value in explicit_local
            if overlap_warning:
                problems.append(overlap_warning)
            if manual and live_entry is None:
                problems.append(
                    "manual entry is not verified in the current live daemon roster"
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
                if (
                    str(entry.get("digest", "")).lower() != live_digest
                    or not modalities_match
                ):
                    problems.append(
                        "manual digest/modalities do not match live daemon discovery"
                    )
            error = "; ".join(dict.fromkeys(problems))
            if error:
                disabled = " disabled"
            digest = entry.get("digest")
            pinned = isinstance(digest, str) and re.fullmatch(
                r"[0-9a-fA-F]{64}", digest
            )
            control_id = "target-" + hashlib.sha256(
                f"ollama:{value}".encode("utf-8")
            ).hexdigest()[:16]
            name_html = (
                html.escape(label)
                + " <span class='badge gray'>Ollama</span>"
                + (
                    " <span class='badge amber'>manual config</span>"
                    if manual
                    else " <span class='badge green'>live installed</span>"
                )
                + (
                    " <span class='badge green'>daemon matched</span>"
                    if manual and live_entry is not None
                    else ""
                )
                + (
                    " <span class='badge amber tip' tabindex='0' role='img' "
                    "aria-label='Warning: ambiguous Ollama and vLLM identity'>"
                    "&#9888; overlaps vLLM"
                    f"<span class='tiptext'>{html.escape(overlap_warning)}</span>"
                    "</span>"
                    if overlap_warning
                    else ""
                )
                + (
                    " <span class='badge red'>invalid local config</span>"
                    if error
                    else ""
                )
            )
            pin_text = "digest pinned" if pinned else "64-hex digest required for live use"
            detail = (
                "<span class='fieldhint'>local Ollama daemon - "
                + html.escape("/".join(mods))
                + " - "
                + pin_text
                + "; precision is fixed by the pulled Ollama artifact"
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
                        "Highest configured current input + output judging rate "
                        f"among comparable {currency} models: {score:g} {currency} "
                        "per one million input + output tokens. Actual cost depends "
                        "on recorded usage."
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
            {
                _api_provider(value)
                for value, _label, _mods, kind in options
                if kind == "api"
            }
        )
        provider_options = "<option value='all' selected>All</option>" + "".join(
            f"<option value='{html.escape(provider)}'>{html.escape(provider)}</option>"
            for provider in providers
        )
        model_boxes = (
            "<section class='picker-model-panel' data-picker-panel='api' hidden>"
            "<div class='grouphead'><h3>Hosted API</h3>"
            "<span class='fieldhint' id='api-filter-count'></span></div>"
            "<div class='targetfilters'><div class='fieldcell'>"
            "<label class='fieldlabel' for='api-provider-filter'>Provider</label>"
            "<select id='api-provider-filter' aria-label='Hosted API provider'>"
            + provider_options
            + "</select></div></div><div class='checkgrid' "
            "id='api-target-list'>"
            + (api_boxes or "<p class='note'>No hosted targets configured.</p>")
            + "</div><p class='filter-empty' id='api-filter-empty'>No hosted "
            "models match the current provider and modality filters.</p>"
            "</section><section class='picker-model-panel' "
            "data-picker-panel='local' hidden>"
            "<div class='grouphead'><h3>Local vLLM (on-rig GPUs)</h3>"
            "<span class='fieldhint' id='local-filter-count'></span></div>"
            "<div class='targetfilters'><div class='fieldcell'>"
            "<label class='fieldlabel' for='local-name-filter'>Name contains</label>"
            "<input class='wide' id='local-name-filter' type='search' "
            "autocomplete='off' placeholder='Type to filter model names'>"
            "</div><div class='fieldcell'><label class='fieldlabel' "
            "for='local-param-range'>Maximum parameters "
            "<span class='fieldhint'>(billions; 0.01B = 10M, 3000B = 3T)"
            "</span></label><div class='paramfilter'>"
            "<input id='local-param-range' type='range' min='0.01' max='3000' "
            "step='0.01' value='3000' aria-label='Maximum parameters slider'>"
            "<input class='wide' id='local-param-number' type='number' "
            "min='0.01' max='3000' step='0.01' value='3000' "
            "aria-label='Maximum parameters in billions'></div></div>"
            "<label class='compatfilter'><input type='checkbox' "
            "id='local-compatible-filter' checked><span class='compatcopy'>"
            "<strong>Automatic 16/8/4-bit fit</strong>"
            "<span class='fieldhint'>Show only models estimated to fit this "
            "hardware at automatically selected 16-, 8-, or 4-bit precision."
            "</span></span></label>"
            "<label class='compatfilter'><input type='checkbox' "
            "id='local-unknown-filter'><span class='compatcopy'>"
            "<strong>Include unknown fit</strong>"
            "<span class='fieldhint'>Show models whose fit cannot be estimated. "
            "Live runs require an explicit per-model precision."
            "</span></span></label></div>"
            "<div class='checkgrid' id='vllm-target-list'>"
            + (vllm_boxes or "<p class='note'>No vLLM targets configured.</p>")
            + "</div><p class='filter-empty' id='local-filter-empty'>No local "
            "vLLM models match all active filters.</p>"
            "<div class='grouphead'><h3>Local Ollama (local daemon)</h3>"
            "</div><div class='checkgrid' id='ollama-target-list'>"
            + (
                ollama_boxes
                or "<p class='note'>No exact Ollama candidate is available. "
                "Start or connect to the loopback daemon and pull a model above. "
                "Live rows come only from stable tag/digest inventory plus "
                "explicit show capabilities. A manual "
                "<a href='/config?file=local-targets'>local-targets</a> escape "
                "remains visibly flagged and must match live discovery.</p>"
            )
            + "</div>"
            + "<p class='note'>Hosted rosters are edited on the "
            "<a href='/config?file=api-targets'>api-targets</a> and "
            "<a href='/config?file=local-targets'>local-targets</a> Config "
            "pages. Local vLLM targets also include the vLLM roster ("
            + (
                f"synced to vLLM {html.escape(str(self._vllm_roster_version()))}"
                if self._vllm_roster_version()
                else "curated default - run <code>local_targets --refresh</code> "
                "to sync it to the rig's vLLM version"
            )
            + "); Hub-backed vLLM models require an explicit sealed acquisition "
            "job before a measured or preflight run. Automatic Ollama "
            "targets come only from the live loopback roster. Hosted targets "
            "spend API budget; both local "
            "backends avoid hosted API spend.</p></section>"
        )
        target_selector = (
            "<div class='model-picker-selection'><button type='button' class='ghost' "
            "data-open-model-picker='target' aria-controls='model-picker' "
            "aria-expanded='false'>Choose target models</button>"
            "<output id='target-model-summary' class='selection-summary' "
            "aria-live='polite'>No target models selected</output></div>"
        )
        judge_selector = (
            f"<input type='hidden' id='judge-model-input' name='judge_model' "
            f"value='{html.escape(selected_judge_model)}'>"
            "<div class='model-picker-selection'><button type='button' class='ghost' "
            "data-open-model-picker='judge' aria-controls='model-picker' "
            "aria-expanded='false'>Choose LLM judge model</button>"
            "<output id='judge-model-summary' class='selection-summary' "
            "aria-live='polite'>"
            + (
                html.escape(selected_judge_model)
                if selected_judge_model
                else "No LLM judge model selected"
            )
            + "</output></div>"
        )
        model_picker_modal = (
            "<div id='model-picker' class='model-picker' role='dialog' "
            "aria-modal='true' aria-labelledby='model-picker-title' "
            "aria-hidden='true' hidden>"
            "<div class='model-picker-shell'><div class='model-picker-head'>"
            "<div><p class='wizard-kicker'>Model selector</p>"
            "<h2 id='model-picker-title'>Choose models</h2></div>"
            "<button type='button' class='ghost small' data-close-model-picker "
            "aria-label='Close model selector'>Close</button></div>"
            "<div class='wizard-steps' aria-label='Selection steps'>"
            "<button type='button' class='wizard-step on' "
            "data-picker-step='runtime' aria-controls='model-picker-runtime' "
            "aria-current='step'>1. Runtime</button>"
            "<button type='button' class='wizard-step' data-picker-step='models' "
            "aria-controls='model-picker-models' disabled>"
            "2. Filter and choose</button></div>"
            "<section id='model-picker-runtime' class='picker-runtime-step'>"
            "<p class='note'>Where will this model run?</p>"
            "<div class='picker-runtime-grid'>"
            "<button type='button' class='picker-runtime-choice' "
            "data-picker-kind='api'><strong>Hosted API</strong>"
            "<span>Filter by provider or show all configured hosted routes. "
            "Hosted calls may spend API budget.</span></button>"
            "<button type='button' class='picker-runtime-choice' "
            "data-picker-kind='local'><strong>Local rig</strong>"
            "<span>Use the full vLLM fit, parameter, name, and precision filters, "
            "or an exact pulled Ollama artifact.</span></button></div></section>"
            "<section id='model-picker-models' class='picker-model-step' hidden>"
            "<p id='model-picker-role-note' class='fieldhint picker-role-note'></p>"
            + model_boxes
            + "</section><div class='model-picker-foot'>"
            "<span class='fieldhint'>Disabled rows failed exact configuration or "
            "hardware admission checks.</span>"
            "<button type='button' data-close-model-picker>Done</button>"
            "</div></div></div>"
        )
        gpu_rows = "".join(
            "<li><code>GPU "
            + html.escape(str(gpu.get("index", "?")))
            + "</code> "
            + html.escape(str(gpu.get("name", "unknown")))
            + " · "
            + html.escape(str(gpu.get("vram_gib", "?")))
            + " GiB VRAM"
            + (
                " · SM " + html.escape(str(gpu["compute_capability"]))
                if gpu.get("compute_capability")
                else ""
            )
            + (" · PCI " + html.escape(str(gpu["pci_bus_id"])) if gpu.get("pci_bus_id") else "")
            + "</li>"
            for gpu in self.gpu_hardware.get("gpus", [])
            if isinstance(gpu, Mapping)
        )
        cpu_name = str(self.system_hardware.get("cpu_model") or "unknown")
        ram_gib = self.system_hardware.get("total_ram_gib")
        ram_text = f"{ram_gib} GiB RAM" if ram_gib is not None else "unknown RAM"
        system_summary = (
            "<p><strong>"
            + html.escape(cpu_name)
            + "</strong> &middot; "
            + html.escape(ram_text)
            + " &middot; "
            + html.escape(str(self.system_hardware.get("platform") or "unknown"))
            + "</p>"
        )
        hardware_card = (
            "<div class='card'><h2>Local hardware</h2>"
            + system_summary
            + (
                "<p><strong>"
                + html.escape(str(self.gpu_hardware.get("gpu_count", 0)))
                + " NVIDIA GPU(s), "
                + html.escape(str(self.gpu_hardware.get("aggregate_vram_gib", 0)))
                + " GiB aggregate VRAM</strong></p><ul>"
                + gpu_rows
                + "</ul>"
                if self.gpu_hardware.get("available")
                else "<div class='notice amber'>No NVIDIA GPU was detected; model fit is unknown.</div>"
            )
            + (
                "<p class='note'>vLLM "
                + html.escape(str(installed_vllm_version()))
                + " is installed.</p>"
                if installed_vllm_version()
                else "<p class='note'>vLLM is not installed in this console environment. "
                "Planning remains available; execution will fail closed until installed.</p>"
            )
            + "<p class='note'>Automatic 4-bit serving uses "
            "<code>bitsandbytes</code>, an optional runtime dependency. "
            "Fit values are conservative estimates, not allocation guarantees.</p></div>"
        )
        ollama_card = self._ollama_service_card(
            ollama_status,
            ollama_roster,
            action_state=ollama_state,
            action_error=ollama_error,
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
                    "<label class='check fwrow disabled' "
                    f"data-mods='{html.escape(','.join(mods))}'>"
                    f"<input type='checkbox' class='fwbox' disabled "
                    f"data-fw='{html.escape(fw)}'>"
                    f"<span><strong>{html.escape(fw)}</strong> "
                    "<span class='badge gray tip' tabindex='0' role='button' "
                    "aria-label='native-only: why this framework is disabled'>"
                    "native-only"
                    f"<span class='tiptext'>{html.escape(desc)} - a "
                    "native-artifact integration; run_matrix cannot replay it "
                    "through the common Runner. Import its native traces with "
                    "the <code>native_import</code> command.</span>"
                    "</span></span></label>"
                )
            cli_only_reason = _CLI_ONLY_ATTACKERS.get(fw)
            if cli_only_reason:
                return (
                    "<label class='check fwrow disabled' "
                    f"data-mods='{html.escape(','.join(mods))}'>"
                    f"<input type='checkbox' class='fwbox' disabled "
                    f"data-fw='{html.escape(fw)}'>"
                    f"<span><strong>{html.escape(fw)}</strong> "
                    "<span class='badge gray tip cli-only-framework-badge' "
                    "tabindex='0' role='button' "
                    "aria-label='CLI-only: why this framework is disabled'>"
                    "CLI-only (precomputed input)"
                    f"<span class='tiptext'>{html.escape(desc)} - "
                    f"{html.escape(cli_only_reason)}</span>"
                    "</span></span></label>"
                )
            prepared_badge = ""
            prepared_control = ""
            if fw in {"t3mp3st", "harmbench", "ideator", "nanogcg"}:
                if fw == "t3mp3st":
                    detail = (
                        "Capture a validated planning bundle first; measured replay "
                        "checks the exact selected corpus and digest before calls."
                    )
                    badge = "capture + replay"
                elif fw == "harmbench":
                    detail = (
                        "Prepare generated cases first; measured replay checks the "
                        "capture config, corpus, and digest before calls."
                    )
                    badge = "prepare + replay"
                elif fw == "nanogcg":
                    detail = (
                        "Provide an exact precomputed suffix for replay. Live "
                        "nanoGCG generation remains disabled until its isolated "
                        "runtime handshake is implemented."
                    )
                    badge = "precomputed replay"
                else:
                    detail = (
                        "Provide an exact source-mapped ura-ideator-seed-pairs/2 "
                        "manifest. Legacy v1 manifests remain accepted. Build "
                        "verifies and snapshots every declared PNG before launch."
                    )
                    badge = "verified seed-pair replay"
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
            + "><span><strong>rules</strong> "
            "<span class='fieldhint'>deterministic rule scorer (free)</span>"
            "</span></label>"
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='llm'"
            + (" checked" if "llm" in judges_selected else "")
            + "><span><strong>llm</strong> "
            "<span class='fieldhint'>explicit hosted or local model judge; "
            "hosted calls are metered"
            "</span></span></label>"
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='guardrail'"
            + (" checked" if "guardrail" in judges_selected else "")
            + "><span><strong>guardrail</strong> "
            "<span class='fieldhint'>model-backed guardrail grader; set the "
            "scoring guardrail model below (distinct from any defense guard)"
            "</span></span></label>"
        )
        approximate_metrics_control = (
            "<label class='check'><input type='checkbox' "
            "name='approximate_common_metrics'"
            + (
                " checked"
                if prefill.get("approximate_common_metrics") == "on"
                else ""
            )
            + "><span><strong>⚠ approximate common-security metrics</strong> "
            "<span class='fieldhint'>explicit opt-in for separate supplementary "
            "response proxies when a source evaluator is not integrated. "
            "Non-authoritative; never replaces source-native metrics. Reliability "
            "is an uncalibrated heuristic indicator, not probability or accuracy."
            "</span></span></label>"
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
            + f">{d or '(default: auto)'}</option>"
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
            "<section class='workflow-panel'><h3>Isolated framework runtimes "
            "<span class='badge blue'>explicit venvs</span></h3>"
            "<p class='note'>Required only for selected PyRIT 0.14.0, DeepTeam "
            "1.0.7, h4rm3l 0.2.4, or Spikee 0.9.1 lanes. Each framework must "
            "have its own virtual environment. Build the content-addressed file "
            "with <code>python -m experiments.engine_runtime_config</code>. The "
            "managed environments and their current verification state are in "
            "the <a href='#build-runtimes'>Runtimes</a> tab. The "
            "console holds its exact bytes behind the launch ticket and stores "
            "only path-free runtime identities; completion is published only "
            "after the closing seal verifies.</p><div class='cols'>"
            + text_field(
                "engine_runtime_config",
                "Runtime config",
                "private ura-engine-runtime-config/1 file",
                placeholder="C:/private/engine-runtimes.json",
            )
            + text_field(
                "engine_runtime_config_sha",
                "Runtime config SHA-256",
                "exact 64-lowercase-hex byte digest",
                placeholder="64 lowercase hex characters",
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
            " aria-hidden='false'"
            if selected_prepared
            else " hidden aria-hidden='true'"
        )
        ideator_available_pairs: int | None = None
        if "ideator" in selected_prepared:
            try:
                ideator_entry = self._prepared_attacker_entries(
                    {**prefill, "attackers": "ideator"}
                ).get("ideator")
                raw_pairs = (
                    ideator_entry.get("seed_pairs")
                    if isinstance(ideator_entry, Mapping)
                    else None
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
            ideator_pair_status = (
                "Available and selected pair counts appear after the complete "
                "manifest and image inventory validate."
            )
            ideator_available_attr = ""
        else:
            effective_ideator_pairs = (
                ideator_available_pairs
                if parsed_ideator_limit == 0
                else min(max(parsed_ideator_limit, 0), ideator_available_pairs)
            )
            ideator_pair_status = (
                f"{effective_ideator_pairs} selected of "
                f"{ideator_available_pairs} verified pairs in manifest order."
            )
            ideator_available_attr = str(ideator_available_pairs)
        prepared_workflow_fields = (
            "<div class='prepared-workflows' id='prepared-workflows'" + workflows_visibility + ">"
            "<p class='note'>Prepared replay and model-backed attack inputs are "
            "explicitly bound before execution. Measured runs still use the normal "
            "admission and budget gates."
            "</p><div class='workflow-grid'>"
            "<section class='workflow-panel prepared-fields' id='prepared-t3mp3st' "
            "data-prepared='t3mp3st'" + visibility("t3mp3st") + ">"
            "<h3>T3MP3ST <span class='badge blue'>Capture - Replay</span></h3>"
            "<div class='workflow-step'><h4>1. Capture plan bundle</h4>"
            "<p class='note'>Calls only the pinned loopback planning service.</p>"
            "<div class='cols'>"
            + text_field(
                "t3cap_corpus",
                "Corpus arm",
                "exact text arm to capture",
                default="strongreject_official",
            )
            + text_field(
                "t3cap_limit", "Limit", "selected source clusters", default="1", kind="number"
            )
            + text_field(
                "t3cap_sample_seed",
                "Sample seed",
                "reproducible subset",
                default="0",
                kind="number",
            )
            + text_field(
                "t3cap_endpoint",
                "Planning endpoint",
                "literal-loopback /api/general/plan route",
                default="http://127.0.0.1:3333/api/general/plan",
            )
            + text_field("t3cap_revision", "Upstream revision", "exact 40-hex commit")
            + text_field("t3cap_provider", "Source provider", "Op General provider")
            + text_field("t3cap_model", "Source model", "Op General model")
            + text_field(
                "t3cap_out",
                "Output directory",
                "retained under results",
                default="runs/t3mp3st-captures",
            )
            + text_field(
                "t3cap_timeout",
                "Timeout seconds",
                "per planning request",
                default="120",
                kind="number",
            )
            + "</div><div class='workflow-actions'><button type='submit' class='ghost' "
            "formaction='/build/t3mp3st/capture' formmethod='post'>Review capture"
            "</button></div></div>"
            "<div class='workflow-step'><h4>2. Measured replay</h4>"
            "<p class='note'>Use the bundle path and SHA-256 printed by capture.</p>"
            + err("t3_replay")
            + "<div class='cols'>"
            + text_field("t3_artifact", "Plan bundle", "ura-t3mp3st-plan-bundle/1 path")
            + text_field("t3_artifact_sha", "Bundle SHA-256", "exact capture digest")
            + "</div></div></section>"
            "<section class='workflow-panel prepared-fields' id='prepared-harmbench' "
            "data-prepared='harmbench'" + visibility("harmbench") + ">"
            "<h3>HarmBench <span class='badge blue'>Prepare - Replay</span></h3>"
            "<div class='workflow-step'><h4>1. Prepare generated cases</h4>"
            "<p class='note'>Runs the pinned text-only HarmBench generation scripts.</p>"
            "<div class='cols'>"
            + text_field(
                "hcap_repo",
                "HarmBench checkout",
                "clean pinned checkout",
                default="/data/HarmBench",
            )
            + text_field("hcap_revision", "Upstream revision", "exact 40-hex commit")
            + text_field("hcap_source", "Behavior CSV", "official text behaviors")
            + text_field(
                "hcap_corpus", "Logical corpus arm", "bundle identity", default="harmbench_text"
            )
            + text_field(
                "hcap_methods", "Methods", "comma-separated text methods", default="PEZ,PAP-top5"
            )
            + text_field(
                "hcap_experiment", "Experiment", "HarmBench model setup", default="llama2_7b"
            )
            + text_field(
                "hcap_limit", "Limit", "selected source clusters", default="1", kind="number"
            )
            + text_field(
                "hcap_sample_seed", "Sample seed", "reproducible subset", default="0", kind="number"
            )
            + text_field(
                "hcap_cases",
                "Cases per method",
                "bounded generated cases",
                default="1",
                kind="number",
            )
            + text_field(
                "hcap_artifact_out",
                "Capture artifact",
                "retained JSON under results",
                default="runs/harmbench-captures/capture.json",
            )
            + text_field(
                "hcap_config_out",
                "Attacker config",
                "generated replay config JSON",
                default="runs/harmbench-captures/attackers.json",
            )
            + "</div><details><summary>Optional runtime settings</summary>"
            "<div class='cols'>"
            + text_field("hcap_python", "Python executable", "blank uses this environment")
            + text_field("hcap_credentials", "Credential env names", "comma-separated names")
            + text_field("hcap_timeout", "Timeout seconds", "positive finite value", kind="number")
            + "</div></details><div class='workflow-actions'>"
            "<button type='submit' class='ghost' "
            "formaction='/build/harmbench/prepare' formmethod='post'>Review prepare"
            "</button></div></div>"
            "<div class='workflow-step'><h4>2. Measured replay</h4>"
            "<p class='note'>Use the attacker config path printed by prepare.</p>"
            + err("harm_replay")
            + "<div class='cols'>"
            + text_field("harm_config", "Capture config", "generated attackers.json path")
            + "</div></div></section>"
            "<section class='workflow-panel prepared-fields' id='prepared-nanogcg' "
            "data-prepared='nanogcg'" + visibility("nanogcg") + ">"
            "<h3>NanoGCG <span class='badge blue'>Precomputed replay</span></h3>"
            "<p class='note'>Live NanoGCG optimization is disabled until its isolated "
            "runtime handshake is implemented. Supply an exact precomputed suffix "
            "and its retained source; this path loads no framework model.</p>"
            + err("nanogcg")
            + "<div class='workflow-step'><h4>Precomputed suffix replay</h4>"
            "<div class='cols'>"
            + text_field(
                "nanogcg_suffix",
                "Exact suffix",
                "non-empty replay payload; no model is loaded",
            )
            + text_field(
                "nanogcg_suffix_source",
                "Suffix source",
                "paper, artifact, or retained run identity",
            )
            + "</div></div></section>"
            "<section class='workflow-panel prepared-fields' id='prepared-ideator' "
            "data-prepared='ideator'" + visibility("ideator") + ">"
            "<h3>IDEATOR <span class='badge blue'>Verified seed-pair replay"
            "</span></h3>"
            "<p class='note'>Live IDEATOR generation remains disabled. Prefer an "
            "exact source-mapped <code>ura-ideator-seed-pairs/2</code> JSON manifest "
            "under the results root; it binds every pair to one admitted source "
            "row. Legacy <code>ura-ideator-seed-pairs/1</code> manifests remain "
            "accepted for previously reviewed pairs. Build verifies the manifest "
            "and PNG bytes, captures them in the review ticket, and materializes "
            "private replay copies at launch.</p>"
            + err("ideator")
            + "<div class='workflow-step'><h4>Precomputed text-image pairs</h4>"
            "<div class='cols'>"
            + text_field(
                "ideator_manifest",
                "Seed-pair manifest",
                "source-mapped v2 path under results (v1 is legacy)",
            )
            + text_field(
                "ideator_manifest_sha",
                "Manifest SHA-256",
                "exact 64-hex digest of the manifest bytes",
            )
            + text_field(
                "ideator_pair_limit",
                "Replay pair limit",
                "0 = all verified pairs; positive N = ordered manifest prefix",
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
            selected_mode == "diagnostic_canary"
            and prefill.get("canary_dry") == "on"
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
        sampling_hidden = (
            " aria-hidden='false'"
            if effective_arm_count
            else " hidden aria-hidden='true'"
        )
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
                f"Exact projection: {effective_clusters} clusters across "
                f"{selected_arm_count} independently capped arms; the current "
                f"selection expands to {selected_records} converted rows."
            )
        elif effective_arm_count:
            sampling_status = (
                "Enter a non-negative cluster limit now. The exact slider range and "
                "per-arm record fanout appear after a matching no-call preflight."
            )
        else:
            sampling_status = "Select one or more arms to configure sampling"
        sampling_arm_label = (
            "Synthetic arm selected automatically"
            if synthetic_canary
            else f"{selected_arm_count} arm{'s' if selected_arm_count != 1 else ''} selected"
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
                "<div class='scroll' id='sample-arm-inventory'><table>"
                "<tr><th>Arm</th><th>Available clusters</th>"
                "<th>Available converted rows</th></tr>"
                + inventory_rows
                + "</table></div>"
            )
        else:
            sampling_inventory = (
                "<p class='note' id='sample-arm-inventory'>No exact arm cardinality "
                "is claimed until the matching no-call preflight validates it.</p>"
            )
        arm_cardinality_json = html.escape(
            json.dumps(
                projected_arm_counts if exact_arm_cardinality else {},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        sample_seed = prefill.get("sample_seed", "0")
        sampling_policy = prefill.get(
            "sampling_policy", DEFAULT_SAMPLING_POLICY
        )
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
                    "Seeded pseudorandom cluster prefix (default)",
                ),
                (SOURCE_ORDER_CLUSTER_PREFIX, "Source-order cluster prefix"),
            )
        )
        if sampling_policy not in {
            SEEDED_PSEUDORANDOM_CLUSTER_PREFIX,
            SOURCE_ORDER_CLUSTER_PREFIX,
        }:
            sampling_policy_options = (
                "<option value='"
                + html.escape(sampling_policy)
                + "' selected>Unsupported submitted policy</option>"
                + sampling_policy_options
            )
        sampling_fields = (
            "<section class='sample-size-control' id='sample-size-control'"
            + sampling_hidden
            + " data-arm-cardinalities='"
            + arm_cardinality_json
            + "'"
            + ">"
            "<div class='sample-size-head'><div><h3>Per-arm sample size</h3>"
            "<p class='note'>The same value applies independently to every selected "
            "arm. <strong>0 = full selected release</strong>; a positive value is "
            "the maximum source-cluster count per selected arm, with all sibling "
            "rows retained. Choose whether the cluster prefix comes from the "
            "seeded pseudorandom ordering or source order; selected rows keep source "
            "order.</p></div>"
            "<span class='badge blue' id='sample-arm-count'>"
            + html.escape(sampling_arm_label)
            + "</span></div>"
            "<div class='sample-size-grid'><div class='fieldcell sample-range-field'"
            + range_field_hidden
            + ">"
            "<label class='fieldlabel' for='sample-limit-range'>Sample-size range "
            "<span class='fieldhint'>exact validated maximum; 0 is full mode</span></label>"
            f"<input id='sample-limit-range' type='range' min='0' max='{range_max}' "
            f"step='1' value='{range_render_value}'"
            + range_disabled
            + " aria-describedby='sample-limit-status'>"
            "</div><div class='fieldcell'>"
            "<label class='fieldlabel' for='sample-limit-number'>--limit "
            "<span class='fieldhint'>non-negative clusters per selected arm</span>"
            "</label><input class='wide' id='sample-limit-number' type='number' "
            "min='0' step='1' name='limit'"
            + (f" value='{html.escape(raw_limit)}'" if raw_limit else "")
            + sampling_disabled
            + ">"
            + err("limit")
            + "</div><div class='fieldcell'>"
            "<label class='fieldlabel' for='sample-seed-input'>--sample-seed "
            "<span class='fieldhint'>randomized-policy seed; request-bound for both"
            "</span></label><input class='wide' id='sample-seed-input' type='number' "
            "step='1' name='sample_seed' value='"
            + html.escape(sample_seed)
            + "'"
            + sampling_disabled
            + ">"
            + err("sample_seed")
            + "</div><div class='fieldcell'>"
            "<label class='fieldlabel' for='sampling-policy-select'>--sampling-policy "
            "<span class='fieldhint'>whole-cluster prefix ordering</span></label>"
            "<select class='wide' id='sampling-policy-select' name='sampling_policy'"
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
                f"<li><strong>{html.escape(field)}</strong>: {html.escape(message)}</li>"
                for field, message in sorted(errors.items())
            )
            error_summary = (
                "<div class='notice red'><strong>The lane was not started."
                f"</strong><ul>{items}</ul><p class='note'>Each problem is "
                "also flagged next to its control below. Nothing was "
                "composed or executed.</p></div>"
            )
        build_tabs = (
            ("build-general", "General"),
            ("build-runtimes", "Runtimes"),
            ("build-pipeline", "Pipeline"),
            ("build-evaluation", "Evaluation"),
            ("build-admission", "Admission"),
            ("build-execution", "Execution"),
        )
        build_default = "build-general"
        error_fields = set(errors)
        error_panel_fields = (
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
            hardware_card
            + ollama_card
            + "<div class='card'><h2>"
            + _icon("flask")
            + "Current pipeline</h2>"
            "<p class='note'>A live summary of the controls across every builder "
            "section. Receipt rows report presence only; Compose &amp; review "
            "produces the exact validated command before execution.</p>"
            "<dl class='builder-summary' aria-live='polite'>"
            "<div><dt>Composition</dt><dd id='build-summary-composition'>"
            "initializing</dd></div>"
            "<div><dt>Evaluation</dt><dd id='build-summary-evaluation'>"
            "initializing</dd></div>"
            "<div><dt>Admission</dt><dd id='build-summary-admission'>"
            "initializing</dd></div>"
            "<div><dt>Trajectory</dt><dd id='build-summary-trajectory'>"
            "initializing</dd></div>"
            "<div><dt>Budget guards</dt><dd id='build-summary-budget'>"
            "initializing</dd></div>"
            "<div><dt>Local serving</dt><dd id='build-summary-local'>"
            "initializing</dd></div>"
            "<div><dt>Output</dt><dd id='build-summary-output'>"
            "initializing</dd></div></dl>"
            "<p class='fieldlabel'>High-level composition preview "
            "<span class='fieldhint'>(not the final reviewed command)</span></p>"
            "<code id='buildpreview'>run_matrix (initializing current choices)</code>"
            "</div>"
        )
        force_default = (
            " data-force-default='true'"
            if errors or framework_runtime_state or framework_runtime_error
            else ""
        )
        body = (
            "<h1>" + _icon("flask", size=22) + "Campaign builder</h1>"
            "<p class='note'>Compose a lane by choosing modalities, target "
            "models, and attack frameworks. On build it opens as a "
            "<code>run_matrix</code> job through the same typed, validated "
            "path - nothing here bypasses the allowlist. Paid modes show the "
            "exact command and its call ceilings for confirmation before "
            "anything starts.</p>"
            + error_summary
            + "<div class='page-tabs' data-page-tabs data-tab-key='build' "
            + f"data-default-tab='{build_default}'{force_default}>"
            + _page_tablist("Builder sections", build_tabs, default=build_default)
            + _page_tabpanel("build-general", general_panel)
            + _page_tabpanel("build-runtimes", framework_runtime_panel)
            + "<form method='post' action='/build' id='builder'>"
            # hidden composed fields
            "<input type='hidden' name='corpora'><input type='hidden' name='api'>"
            "<input type='hidden' name='local'>"
            "<input type='hidden' name='attackers'>"
            "<input type='hidden' name='judges'>"
            "<section class='page-tabpanel' id='build-pipeline' role='tabpanel' "
            "aria-labelledby='build-pipeline-tab' tabindex='0' "
            "data-page-panel='build-pipeline'>"
            "<div class='card'><h2>" + _icon("play") + "Mode</h2>"
            "<div class='radios'>" + mode_html + "</div></div>"
            "<div class='card'><h2>" + _icon("grid") + "Modality scope</h2>"
            "<p class='note'>The campaign's modalities - all enabled for a "
            "fresh build. Turn one off to hide the arms, target models, and "
            "frameworks that need it.</p>"
            "<div class='modscope'>"
            + "".join(
                "<label class='modtoggle'><input type='checkbox' class='modbox' "
                f"data-mod='{m}' checked><span>{html.escape(m)}</span></label>"
                for m in _MODALITIES
            )
            + "</div></div>"
            "<div class='card'><h2>" + _icon("box") + "Arms &amp; corpora</h2>"
            "<p class='note'>Arms in the current modality scope. Each shows its "
            "modality tags; use All / None per group for bulk selection.</p>"
            + err("corpora")
            + "".join(arm_groups)
            + "</div>"
            "<div class='card'><h2>"
            + _icon("coins")
            + "Target models</h2>"
            + err("models")
            + "<p class='note'>Use the shared selector to choose one or more "
            "hosted targets and at most one local runtime target. To compare "
            "multiple local models, run each local model as a separate job/grid "
            "under the same reviewed rig plan.</p>"
            + target_selector
            + "</div>"
            "<div class='card'><h2>"
            + _icon("pulse")
            + "Attack frameworks</h2>"
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
            "<div class='card'><h2>" + _icon("receipt") + "Judges &amp; defense"
            "</h2>"
            + err("judges")
            + "<div class='checkgrid'>"
            + judge_boxes
            + approximate_metrics_control
            + "</div>"
            + err("judge_model")
            + "<p class='note'>The LLM judge uses an explicitly selected hosted "
            "or local configured model. Dry lanes still replace it with the "
            "offline mock and make no provider call.</p>"
            + judge_selector
            + err("ack_hosted_judge_data_transfer")
            + "<label class='check hosted-judge-transfer-ack'>"
            + "<input type='checkbox' name='ack_hosted_judge_data_transfer'"
            + (
                " checked"
                if prefill.get("ack_hosted_judge_data_transfer") == "on"
                else ""
            )
            + "><span><strong>Hosted-judge data transfer acknowledgement</strong> "
            + "I understand that target responses, the harmful source request, "
            + "and source/reference grading context may be sent to the selected "
            + "second provider and may be subject to that provider's retention, "
            + "usage, and corpus-license terms. I reviewed those terms for this "
            + "live condition.</span></label>"
            + "<div class='cols'>"
            + "<div class='fieldcell'><label class='fieldlabel'>--defense</label>"
            f"<select name='defense'>{defense_opts}</select>{err('defense')}"
            "</div>"
            "<div class='fieldcell'><label class='fieldlabel'>--defense-guard "
            "<span class='fieldhint'>guard used when a defense is on</span>"
            f"</label><select name='defense_guard'>{guard_opts}</select>"
            + err("defense_guard")
            + "</div>"
            "</div>"
            "<h3>Scoring guardrail <span class='fieldhint'>the judge cascade's "
            "<code>guardrail</code> grader; add <code>guardrail</code> to the "
            "judges above to use it</span></h3><div class='cols'>"
            + text_field(
                "guardrail_model",
                "--guardrail-model",
                "scoring guardrail model id",
                placeholder="meta-llama/Llama-Guard-3-8B",
            )
            + text_field(
                "guardrail_revision",
                "--guardrail-revision",
                "required immutable 40-64 hex revision",
            )
            + text_field("guardrail_device", "--guardrail-device", "device, e.g. cuda:0 (optional)")
            + "</div>"
            "<h3>Defense guardrail <span class='fieldhint'>the model-backed "
            "defense guard (defense-guard = guardrail); MUST be a different "
            "model from the scoring guardrail - a guard never grades its own "
            "output</span></h3><div class='cols'>"
            + text_field(
                "defense_guardrail_model",
                "--defense-guardrail-model",
                "defense guardrail model id (distinct from scoring)",
            )
            + text_field(
                "defense_guardrail_revision",
                "--defense-guardrail-revision",
                "required immutable 40-64 hex revision",
            )
            + text_field(
                "defense_guardrail_device", "--defense-guardrail-device", "required explicit device"
            )
            + "</div></div>"
            "</section><section class='page-tabpanel' id='build-admission' "
            "role='tabpanel' aria-labelledby='build-admission-tab' tabindex='0' "
            "data-page-panel='build-admission'>"
            "<div class='card'><h2>" + _icon("receipt") + "Receipts (fail-closed admission)</h2>"
            "<p class='note'>Every non-dry run requires the validated "
            "project-revision receipt; every real source arm requires the "
            "validated source-conformance receipt. Prefilled from the "
            "exported campaign environment when present.</p><div class='cols'>"
            + text_field(
                "project_revision",
                "--project-revision",
                "ura-project-revision/1 receipt path",
                default=env_project,
            )
            + text_field(
                "project_revision_sha",
                "--project-revision-sha256",
                "exact byte digest",
                default=env_project_sha,
            )
            + text_field(
                "source_conformance",
                "--source-conformance",
                "ura-source-conformance/1 receipt path",
                default=env_source,
            )
            + text_field(
                "source_conformance_sha",
                "--source-conformance-sha256",
                "exact byte digest",
                default=env_source_sha,
            )
            + "</div></div>"
            "<div class='card'><h2>" + _icon("logo") + "Execution scope &amp; live attestation</h2>"
            "<p class='note'>Probes create attestations; live canaries and "
            "measured lanes consume them (repeatable receipt/digest rows, "
            "paired in order).</p><div class='cols'>"
            + text_field("scope", "--execution-scope-id", "non-secret account/runtime scope label")
            + text_field(
                "max_age",
                "--live-attestation-max-age-hours",
                "maximum receipt age in (0, 8760]",
                kind="number",
            )
            + "</div><label class='fieldlabel'>Live-attestation receipt / "
            "digest pairs</label>"
            + err("att")
            + "<div id='attrows'>"
            + "".join(att_rows_html)
            + "</div>"
            "<button type='button' class='ghost' id='addatt'>"
            "Add receipt row</button></div>"
            "</section><section class='page-tabpanel' id='build-execution' "
            "role='tabpanel' aria-labelledby='build-execution-tab' tabindex='0' "
            "data-page-panel='build-execution'>"
            "<div class='card'><h2>"
            + _icon("sliders")
            + "Sampling &amp; turns</h2>"
            + sampling_fields
            + "<div class='cols'>"
            + text_field("seeds", "--seeds", "comma list of trajectory seeds", default="0")
            + text_field(
                "max_queries",
                "--max-queries",
                "max target calls per datapoint and seed",
                kind="number",
            )
            + text_field(
                "max_turns",
                "--max-turns",
                "max conversation turns per datapoint and seed",
                kind="number",
            )
            + "</div></div>"
            "<div class='card'><h2>"
            + _icon("chart")
            + "Aggregation, row admission &amp; resume</h2>"
            "<p class='note'>The same --group, --reset-open-circuits, and "
            "--lock-stale-seconds the documented CLI lanes pass (runbook "
            "sections 8-13, 17), plus the standalone-dry-only "
            "--exclude-tool-conditioned diagnostic; the composed command is "
            "identical to the CLI's.</p><div class='cols'>"
            + text_field(
                "group",
                "--group",
                "comma list of aggregation keys; the runbook's measured lanes "
                "pass this CLI default explicitly. Level-2 export requires at "
                "least these eight keys; narrower groupings are rejected at "
                "export; blank inherits the CLI default",
                default=_RUNBOOK_GROUP,
            ).replace(
                "name='group'",
                "name='group' list='dl-build-group'",
            )
            + "<datalist id='dl-build-group'>"
            + "".join(
                f"<option value='{html.escape(value)}'></option>"
                for value in (_RUNBOOK_GROUP,)
            )
            + "</datalist>"
            + text_field(
                "lock_stale_seconds",
                "--lock-stale-seconds",
                "optional positive integer; diagnostic stale-age metadata only "
                "(locks are never removed automatically)",
                kind="number",
            )
            + "</div>"
            + err("exclude_tool_conditioned")
            + "<label class='check'><input type='checkbox' "
            "name='exclude_tool_conditioned'"
            + (" checked" if exclude_tool_conditioned_checked else "")
            + exclude_tool_conditioned_disabled
            + "><span><strong>Exclude tool-conditioned rows "
            "(--exclude-tool-conditioned)</strong> "
            "<span class='fieldhint'>drop source rows no Runner attacker can "
            "execute with a recorded exclusion count instead of failing the "
            "request; available only for a standalone dry run and on by default "
            "there (the synth corpus carries such rows)</span></span></label>"
            + err("reset_open_circuits")
            + "<label class='check'><input type='checkbox' "
            "name='reset_open_circuits'"
            + (" checked" if prefill.get("reset_open_circuits") == "on" else "")
            + "><span><strong>Reset open circuits (--reset-open-circuits)"
            "</strong> <span class='fieldhint'>measured-lane resume only: "
            "operator acknowledgement that the provider/judge fault behind an "
            "open circuit was corrected before rerunning the identical lane "
            "(runbook section 17); never a default</span></span></label>"
            "</div>"
            "<div class='card'><h2>"
            + _icon("coins")
            + "Call ceilings &amp; deadline (budget guards)</h2>"
            "<p class='note'>Required finite positive ceilings on every "
            "non-dry run; run_matrix refuses a lane they cannot cover.</p>"
            "<div class='cols'>"
            + text_field(
                "cap_target", "--max-total-target-calls", "hard cap on target calls", kind="number"
            )
            + text_field(
                "cap_judge",
                "--max-total-judge-calls",
                "hard cap on model-backed judge calls (hosted or local)",
                kind="number",
            )
            + text_field(
                "cap_http",
                "--max-total-http-attempts",
                "hard cap on transport attempts",
                kind="number",
            )
            + text_field(
                "local_budget_hours",
                "Local process wall-time cap (hours)",
                _LOCAL_BUDGET_HELP,
                kind="number",
            )
            + text_field(
                "deadline",
                "--deadline-seconds",
                "durable call-start window from first invocation; not a "
                "completion timeout and does not interrupt an admitted call",
                kind="number",
            )
            + "</div></div>"
            "<div class='card'><h2>" + _icon("disk") + "Local serving (vLLM)</h2><div class='cols'>"
            "<div class='fieldcell'><label class='fieldlabel'>--dtype</label>"
            f"<select name='dtype'>{dtype_opts}</select>"
            + err("dtype")
            + "</div>"
            + text_field(
                "quantization",
                "--quantization",
                "default override: bitsandbytes, awq, gptq, fp8; "
                "per-model config wins; empty uses hardware fit",
                placeholder="(auto-detect)",
            )
            + "</div></div>"
            "<div class='card'><h2>" + _icon("folder") + "Output</h2>"
            "<div class='cols'>"
            + text_field(
                "out",
                "--out",
                "output directory under the rig results root",
                default="runs/thesis/lane",
            )
            + "</div></div>"
            + "<div class='buildbar'><button type='submit'>"
            + _icon("play", size=15)
            + "Compose &amp; review</button></div>"
            "</section>"
            + model_picker_modal
            + "</form></div>"
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
        )
        return _page("Campaign builder", body, active="Build")
