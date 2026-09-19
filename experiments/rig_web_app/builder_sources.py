"""Select indexed local runs in Build; prepare their inputs in a background job."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from uuid import uuid4


def source_runs(db, campaign_id: str) -> list[dict]:
    """Read the index only. Response quality and judge labels never select runs."""
    db.require_workspace(campaign_id)
    rows = db._query(
        "SELECT a.model,a.corpus,r.condition_id,"
        "substr(r.response_id,1,instr(r.response_id,':')-1) AS run_id,"
        "MIN(json_extract(r.details,'$.source_ref')) AS source_ref,COUNT(*) AS responses "
        "FROM campaign_responses r JOIN campaign_assignments a "
        "ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id "
        "WHERE r.campaign_id=? AND a.evidence_class='measured' "
        "AND (a.model LIKE 'ollama:%' OR a.model LIKE 'vllm:%') "
        "AND instr(r.response_id,':')>1 "
        "GROUP BY a.model,a.corpus,r.condition_id,run_id "
        "ORDER BY a.model,a.corpus,run_id,r.condition_id",
        (campaign_id,),
    )
    if rows is None:
        raise ValueError(_ui_text("builder_sources.the_saved_local_input_index_is_unavailable"))
    return [dict(row) for row in rows]


def selected_runs(params: dict[str, str], rows: list[dict]) -> list[dict]:
    try:
        ids = json.loads(params.get("retained_source_runs", "[]"))
    except (TypeError, ValueError) as exc:
        raise ValueError(_ui_text("builder_sources.choose_the_saved_local_runs_again")) from exc
    if not isinstance(ids, list) or not ids or any(not isinstance(key, str) for key in ids):
        raise ValueError(_ui_text("builder_sources.select_at_least_one_saved_local_run"))
    if len(ids) != len(set(ids)):
        raise ValueError(_ui_text("builder_sources.select_each_saved_run_once"))
    chosen = [row for row in rows if row["run_id"] in ids]
    if len(chosen) != len(ids) or {row["run_id"] for row in chosen} != set(ids):
        raise ValueError(
            _ui_text(
                "builder_sources.a_selected_run_is_absent_or_ambiguous_choose_its_source_again"
            )
        )
    return chosen


def source_arguments(rows: list[dict], results_root: Path, output: Path) -> dict[str, str]:
    """Resolve only selected locators, not a recursive results-store inventory."""
    roots = set()
    for row in rows:
        reference = row.get("source_ref")
        if not isinstance(reference, str):
            raise ValueError(
                _ui_text("builder_sources.a_selected_run_has_no_retained_artifact_location")
            )
        location, separator, number = reference.rpartition(":")
        if not separator or not number.isdigit():
            raise ValueError(
                _ui_text("builder_sources.a_selected_run_has_an_invalid_retained_artifact_location")
            )
        path = Path(location)
        if not path.is_absolute():
            path = results_root / path
        root = path.parent.resolve(strict=True)
        if not root.is_dir():
            raise ValueError(
                _ui_text("builder_sources.a_selected_results_directory_is_unavailable")
            )
        roots.add(root)
    # Nested explicit grids share one reader root; exact run IDs still restrict
    # the inventory, so unrelated runs never become selected automatically.
    roots = {
        root
        for root in roots
        if not any(root != other and root.is_relative_to(other) for other in roots)
    }
    values = {"--out": str(output)}
    for index, root in enumerate(sorted(roots)):
        values["--source-root" + (f"#{index}" if index else "")] = str(root)
    for index, row in enumerate(rows):
        values["--run-id" + (f"#{index}" if index else "")] = row["run_id"]
    return values


def source_panel(app, params: dict[str, str], *, unified=False) -> str:
    """Preparation is a distinct action, not an ignored Runner input switch."""
    selected = params.get("retained_source_campaign", "")
    campaigns = app.db.workspaces()
    if campaigns is None:
        return _ui_template(
            "<p class='notice red'>[[text:builder_sources.saved_input_campaign_index_unavailable]]</p>"
        )

    def escape(value):
        return html.escape(str(value), quote=True)

    options = _ui_template(
        "<option value=''>[[text:builder_sources.choose_a_source_campaign]]</option>"
    ) + "".join(
        "<option value='"
        + row["campaign_id"]
        + "'"
        + (" selected" if selected == row["campaign_id"] else "")
        + ">"
        + escape(row["name"])
        + "</option>"
        for row in campaigns
    )
    content = (
        _ui_template(
            "<section class='card source-preparation' id='retained-inputs'><h2>[[text:builder_sources.reuse_local_inputs_for_an_api_comparison]]</h2><p>[[text:builder_sources.use_the_same_questions_images_and_attack_prompts_from_saved_local]]</p><div class='source-steps' aria-label='[[attr:builder_sources.input_reuse_workflow]]'><span>[[text:builder_sources.1_choose_a_campaign]]</span><span>[[text:builder_sources.2_select_saved_runs_and_limits]]</span><span>[[text:builder_sources.3_review_and_start]]</span></div><div class='source-campaign-row'><label class='campaign-field'>[[text:builder_sources.source_campaign]] <select name='retained_source_campaign' form='builder'>"
        )
        + options
        + _ui_template(
            "</select></label><button type='submit' form='builder' formaction='/build/source-runs' class='ghost'>[[text:builder_sources.show_saved_runs]]</button></div>"
        )
    )
    if selected:
        rows = source_runs(app.db, selected)
        try:
            chosen = json.loads(params.get("retained_source_runs", "[]"))
        except ValueError:
            chosen = []
        if not isinstance(chosen, list):
            chosen = []
        chosen = [key for key in chosen if any(row["run_id"] == key for row in rows)]
        content += (
            _ui_template(
                "<fieldset class='source-run-fieldset'><legend>[[text:builder_sources.saved_local_runs]]</legend><label class='campaign-field'>[[text:builder_sources.find_a_model_or_corpus]]<input type='search' id='source-run-search' placeholder='[[attr:builder_sources.filter_saved_runs]]'></label><div class='source-run-picker' aria-describedby='retained-source-help'>"
            )
            + "".join(
                "<label class='source-run-choice'><input type='checkbox' data-source-run value='"
                + escape(row["run_id"])
                + "'"
                + (" checked" if row["run_id"] in chosen else "")
                + ">"
                + "<span><strong>"
                + escape(row["model"])
                + "</strong><span>"
                + escape(
                    (
                        f"{row['corpus']}"
                        + " - "
                        + f"{row['responses']:,}"
                        + _ui_text("builder_sources.saved_outputs")
                    )
                )
                + "</span><small>Run: "
                + escape(row["run_id"])
                + "</small></span></label>"
                for row in rows
            )
            + (
                _ui_template(
                    "<p>[[text:builder_sources.no_measured_local_runs_are_indexed_in_this_campaign]]</p>"
                )
                if not rows
                else ""
            )
            + "</div><p id='source-run-count' aria-live='polite'>"
            + str(len(chosen))
            + _ui_template(
                " [[text:builder_sources.run_s_selected]]</p></fieldset><input type='hidden' form='builder' name='retained_source_runs' id='retained-source-runs' value='"
            )
            + escape(json.dumps(chosen))
            + _ui_template(
                "'><p class='note' id='retained-source-help'>[[text:builder_sources.missing_and_truncated_responses_are_included_only_measured_local]]</p><script>document.addEventListener('DOMContentLoaded',()=>{const boxes=Array.from(document.querySelectorAll('[data-source-run]'));const hidden=document.getElementById('retained-source-runs');const sync=()=>{const chosen=boxes.filter(o=>o.checked);hidden.value=JSON.stringify(chosen.map(o=>o.value));document.getElementById('source-run-count').textContent=chosen.length+' run(s) selected';};boxes.forEach(o=>o.addEventListener('change',sync));document.getElementById('builder')?.addEventListener('submit',sync);document.getElementById('source-run-search').addEventListener('input',e=>{const term=e.target.value.toLowerCase();boxes.forEach(o=>{const row=o.closest('label');row.hidden=!row.textContent.toLowerCase().includes(term);});});});</script>"
            )
        )
    job_id = params.get("retained_sources_job", "")
    if job_id:
        content += (
            "<p><a href='/jobs/"
            + escape(job_id)
            + _ui_template(
                "'>[[text:builder_sources.open_the_input_preparation_job_and_its_artifacts]]</a></p>"
            )
        )
        content += (
            "<input type='hidden' form='builder' name='retained_sources_job' value='"
            + escape(job_id)
            + "'>"
        )
    from .builder_budget import budget_panel
    from .builder_collection import collection_panel
    from .builder_native_judging import native_judging_panel
    from .builder_haiku_judging import haiku_judging_panel

    automatic = ""
    if selected:
        automatic = budget_panel(app, params, automatic=True)
        if not unified:
            automatic += (
                _ui_template(
                    "<section class='card' id='automatic-comparison'><h2>[[text:builder_sources.prepare_and_review_the_comparison]]</h2><p>[[text:builder_sources.input_extraction_forecasting_replay_preparation_and_execution_set]]</p><label class='checkrow'><input type='checkbox' form='builder' name='retained_network_counts'"
                )
                + (" checked" if params.get("retained_network_counts") == "on" else "")
                + _ui_template(
                    "><span>[[text:builder_sources.allow_provider_token_counting_for_the_selected_prompts_and_images]]</span></label><button form='builder' formaction='/build/prepare-operation/matched'>[[text:builder_sources.prepare_comparison_and_review]]</button></section>"
                )
            )
    # Retain old prepared collections without making their internal stages a
    # required part of a new operator workflow.
    hidden = "".join(
        "<input type='hidden' form='builder' name='"
        + field
        + "' value='"
        + escape(params[field])
        + "'>"
        for field in ("retained_replays_job", "retained_programs_job")
        if params.get(field)
    )
    legacy = (
        collection_panel(params)
        + native_judging_panel(app, params)
        + haiku_judging_panel(app, params)
    )
    if unified:
        legacy = (
            _ui_template(
                '<details class="card"><summary>[[text:builder_sources.earlier_prepared_collections_and_assessments]]</summary>'
            )
            + legacy
            + "</details>"
            if params.get("retained_programs_job")
            else ""
        )
        return (
            "<div data-saved-inputs>"
            + content
            + "</section>"
            + automatic
            + hidden
            + "</div>"
            + legacy
        )
    return content + "</section>" + automatic + hidden + legacy


def prepare_selected_inputs(app, params: dict[str, str]):
    if params.get("work_kind") != "campaign" and not params.get("campaign_id"):
        raise ValueError(
            _ui_text(
                "builder_sources.select_campaign_to_reuse_saved_local_inputs_for_an_api_comparison"
            )
        )
    rows = selected_runs(params, source_runs(app.db, params.get("retained_source_campaign", "")))
    output_root = (app.results_root / "rig-web" / "prepared-inputs").resolve()
    values = source_arguments(rows, app.results_root, output_root / (uuid4().hex + ".json"))
    params = app._save_build_campaign(params)
    job = app.start_job("retained_local_sources", values, campaign_id=params["campaign_id"])
    app._save_build_campaign(dict(params, retained_sources_job=job.job_id))
    return job
