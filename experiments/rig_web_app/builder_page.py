"""Build-page rendering for campaign composition."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from typing import Mapping

from .catalog import (
    _MODALITIES,
    _ARM_CATALOG,
    _SOURCE_METRIC_ARMS,
    _NATIVE_ONLY_ATTACKERS,
    _BUILDER_OMITTED_ATTACKERS,
    _FRAMEWORKS,
    _BUILD_MODES,
    _icon,
    _arm_head,
)

from .ui import _BUILDER_SCRIPT, _page


class BuilderPageMixin:
    def _build_page(
        self,
        prefill: Mapping[str, str] | None = None,
        errors: Mapping[str, str] | None = None,
    ) -> bytes:
        prefill = dict(prefill or {})
        errors = dict(errors or {})

        def err(field: str) -> str:
            message = errors.get(field, "")
            return f"<span class='fielderr'>{html.escape(message)}</span>" if message else ""

        def val(field: str, default: str = "") -> str:
            return html.escape(prefill.get(field, default))

        selected_mode = prefill.get("mode", "dry_run")
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

        # Group ALL 39 catalogue arms for a readable layout: common lanes first
        # (by modality signature), then the source-metric scored lanes, then the
        # common-metric-ineligible arms. A source-metric arm runs in run_matrix
        # with replay. An ineligible arm remains selectable so the server can
        # return its exact fail-before-subprocess reason; it never becomes a
        # scored lane merely because the builder exposes the choice.
        signatures: dict[str, list[tuple[str, tuple[str, ...], str]]] = {}
        for arm, mods, reason in _ARM_CATALOG:
            if reason:
                bucket = "source-specific metric - not yet runnable (evaluator not integrated)"
            elif arm in _SOURCE_METRIC_ARMS:
                bucket = "source-specific metric - runnable (replay attacker only)"
            else:
                bucket = " + ".join(mods)
            signatures.setdefault(bucket, []).append((arm, mods, reason))
        arm_groups = []

        def _bucket_rank(name: str) -> tuple[int, int, str]:
            if "not yet runnable" in name:
                return (2, len(name), name)
            if name.startswith("source-specific metric"):
                return (1, len(name), name)
            return (0, len(name), name)

        order = sorted(signatures, key=_bucket_rank)
        for signature in order:
            boxes = []
            for arm, mods, reason in signatures[signature]:
                known = arm in registry_arms
                if reason:
                    boxes.append(
                        "<label class='check'>"
                        "<input type='checkbox' class='armbox' "
                        f"data-mods='{html.escape(','.join(mods))}' "
                        f"data-arm='{html.escape(arm)}'>"
                        f"<span>{_arm_head(html.escape(arm), mods)}"
                        "<span class='badge gray tip' tabindex='0'>no evaluator"
                        f"<span class='tiptext'>{html.escape(reason)}</span>"
                        "</span>"
                        "</span></label>"
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
                boxes.append(
                    "<label class='check'>"
                    f"<input type='checkbox' class='armbox' "
                    f"data-mods='{html.escape(','.join(mods))}' "
                    f"data-arm='{html.escape(arm)}'>"
                    f"<span>{_arm_head(html.escape(arm) + note, mods)}</span>"
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
        from experiments.local_targets import installed_vllm_version  # noqa: PLC0415

        local_catalog, _explicit_local = self._local_entry_catalog()

        def _target_box(value: str, label: str, mods: tuple[str, ...], kind: str) -> str:
            detail = ""
            quant_control = ""
            disabled = ""
            row_attrs = ""
            name_html = html.escape(label)
            control_id = (
                "target-" + hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:16]
            )
            if kind == "api":
                provider = value.partition(":")[0].strip().lower() or "unknown"
                row_attrs = f" data-provider='{html.escape(provider)}'"
            if kind == "local":
                entry = local_catalog.get(value, {})
                configured_quant = (
                    str(prefill.get(f"quantization::{value}", entry.get("quantization", "auto")))
                    .strip()
                    .lower()
                )
                profile = self._effective_local_profile(
                    value,
                    entry,
                    default_quantization=prefill.get("quantization", ""),
                    model_quantization=configured_quant,
                )
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
                detail = (
                    "<span class='fieldhint'>"
                    + html.escape(
                        f"{params_text} ({parameter_basis}) · "
                        f"{profile.get('estimated_vram_gib', '?')} GiB "
                        f"estimated / {profile.get('available_vram_gib', 0)} GiB available "
                        f"· {fit_text} · {quant_label} · TP"
                        f"{profile.get('recommended_tensor_parallel_size', 1)} · "
                        f"multi-GPU {basis} · {'pinned' if pinned else 'revision required'}"
                        + (
                            f" · {profile['compatibility_note']}"
                            if profile.get("compatibility_note")
                            else ""
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
                quant_id = control_id + "-quantization"
                quant_control = (
                    "<div class='modelquant'><label for='" + quant_id + "'>"
                    "Per-model quantization</label>"
                    f"<select id='{quant_id}' "
                    f"name='quantization::{html.escape(value)}'{disabled}>"
                    + "".join(
                        f"<option value='{choice}'"
                        + (" selected" if choice == configured_quant else "")
                        + f">{label}</option>"
                        for choice, label in choices
                    )
                    + "</select></div>"
                )
            input_type = "radio" if kind == "local" else "checkbox"
            input_name = " name='local_choice'" if kind == "local" else ""
            return (
                "<div class='modelrow' "
                f"data-mods='{html.escape(','.join(mods))}' "
                f"data-kind='{html.escape(kind)}'{row_attrs}>"
                f"<label class='check modelchoice' for='{control_id}'>"
                f"<input id='{control_id}' type='{input_type}' class='modelbox'"
                f"{input_name} "
                f"data-kind='{html.escape(kind)}' "
                f"data-model='{html.escape(value)}'{disabled}>"
                f"<span>{_arm_head(name_html, mods)}{detail}</span></label>"
                f"{quant_control}</div>"
            )

        options = self._model_options()
        api_boxes = "".join(
            _target_box(v, lbl, mods, kind) for v, lbl, mods, kind in options if kind == "api"
        )
        local_boxes = "".join(
            _target_box(v, lbl, mods, kind) for v, lbl, mods, kind in options if kind == "local"
        )
        providers = sorted(
            {
                value.partition(":")[0].strip().lower() or "unknown"
                for value, _label, _mods, kind in options
                if kind == "api"
            }
        )
        provider_options = "<option value='all' selected>All</option>" + "".join(
            f"<option value='{html.escape(provider)}'>{html.escape(provider)}</option>"
            for provider in providers
        )
        model_boxes = (
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
            "<div class='checkgrid' id='local-target-list'>"
            + (local_boxes or "<p class='note'>No local targets configured.</p>")
            + "</div><p class='filter-empty' id='local-filter-empty'>No local "
            "models match all active filters.</p>"
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
            + "); vLLM downloads a chosen model on first run. Hosted targets "
            "spend API budget; local vLLM targets use the rig's GPUs "
            "(no API spend).</p>"
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
            prepared_badge = ""
            prepared_control = ""
            if fw in {"t3mp3st", "harmbench"}:
                detail = (
                    "Capture a validated planning bundle first; measured replay "
                    "checks the exact selected corpus and digest before calls."
                    if fw == "t3mp3st"
                    else "Prepare generated cases first; measured replay checks the "
                    "capture config, corpus, and digest before calls."
                )
                prepared_badge = (
                    "<span class='badge blue tip prepared-framework-badge' "
                    "tabindex='0'>"
                    + ("capture + replay" if fw == "t3mp3st" else "prepare + replay")
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
        # Judge checkboxes.
        judges_selected = set(self._split_list(prefill.get("judges", "rules")))
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
            "<span class='fieldhint'>hosted Haiku judge (metered per response)"
            "</span></span></label>"
            "<label class='check'><input type='checkbox' class='judgebox' "
            "data-judge='guardrail'"
            + (" checked" if "guardrail" in judges_selected else "")
            + "><span><strong>guardrail</strong> "
            "<span class='fieldhint'>model-backed guardrail grader; set the "
            "scoring guardrail model below (distinct from any defense guard)"
            "</span></span></label>"
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

        selected_prepared = attackers_selected & {"t3mp3st", "harmbench"}

        def visibility(name: str) -> str:
            return (
                " aria-hidden='false'"
                if name in selected_prepared
                else " hidden aria-hidden='true'"
            )

        workflows_visibility = (
            " aria-hidden='false'"
            if selected_prepared & {"t3mp3st", "harmbench"}
            else " hidden aria-hidden='true'"
        )
        prepared_workflow_fields = (
            "<div class='prepared-workflows' id='prepared-workflows'" + workflows_visibility + ">"
            "<p class='note'>Capture or prepare is an out-of-band paid/compute "
            "step. Measured replay still uses the normal admission and budget gates."
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
            + "</div></div></section></div></div>"
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
        body = (
            "<h1>" + _icon("flask", size=22) + "Campaign builder</h1>"
            "<p class='note'>Compose a lane by choosing modalities, target "
            "models, and attack frameworks. On build it opens as a "
            "<code>run_matrix</code> job through the same typed, validated "
            "path - nothing here bypasses the allowlist. Paid modes show the "
            "exact command and its call ceilings for confirmation before "
            "anything starts.</p>"
            + error_summary
            + hardware_card
            + "<form method='post' action='/build' id='builder'>"
            # hidden composed fields
            "<input type='hidden' name='corpora'><input type='hidden' name='api'>"
            "<input type='hidden' name='local'>"
            "<input type='hidden' name='attackers'>"
            "<input type='hidden' name='judges'>"
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
            + model_boxes
            + "</div>"
            "<div class='card'><h2>"
            + _icon("pulse")
            + "Attack frameworks</h2>"
            + err("attackers")
            + "<div class='checkgrid'>"
            + framework_boxes
            + "</div>"
            + prepared_workflow_fields
            + "</div>"
            "<div class='card'><h2>" + _icon("receipt") + "Judges &amp; defense"
            "</h2>"
            + err("judges")
            + "<div class='checkgrid'>"
            + judge_boxes
            + "</div><div class='cols'>"
            + text_field(
                "judge_model",
                "--judge-model",
                "target id for the LLM judge (default: the Haiku campaign judge)",
                placeholder="anthropic:claude-haiku-4-5-20251001",
            )
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
            "<div class='card'><h2>"
            + _icon("sliders")
            + "Sampling &amp; turns</h2><div class='cols'>"
            + text_field(
                "limit",
                "--limit",
                "cluster subsample; required on paid hosted lanes; "
                "probes need 1-2, canaries exactly 1",
                kind="number",
            )
            + text_field(
                "sample_seed",
                "--sample-seed",
                "fix and record for a reproducible subset",
                default="0",
                kind="number",
            )
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
                "hard cap on hosted judge calls",
                kind="number",
            )
            + text_field(
                "cap_http",
                "--max-total-http-attempts",
                "hard cap on transport attempts",
                kind="number",
            )
            + text_field(
                "deadline", "--deadline-seconds", "wall-clock deadline for the lane", kind="number"
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
            "<div class='buildbar'><button type='submit'>"
            + _icon("play", size=15)
            + "Compose &amp; review</button>"
            "<span id='buildpreview' class='note'></span></div>"
            "</form>"
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
