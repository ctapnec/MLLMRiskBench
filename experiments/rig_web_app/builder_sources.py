"""Select indexed local runs in Build; prepare their inputs in a background job."""
from __future__ import annotations

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
        "ORDER BY a.model,a.corpus,run_id,r.condition_id", (campaign_id,),
    )
    if rows is None:
        raise ValueError("The saved local-input index is unavailable")
    return [dict(row) for row in rows]


def selected_runs(params: dict[str, str], rows: list[dict]) -> list[dict]:
    try:
        ids = json.loads(params.get("retained_source_runs", "[]"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Choose the saved local runs again") from exc
    if not isinstance(ids, list) or not ids or any(not isinstance(key, str) for key in ids):
        raise ValueError("Select at least one saved local run")
    if len(ids) != len(set(ids)):
        raise ValueError("Select each saved run once")
    chosen = [row for row in rows if row["run_id"] in ids]
    if len(chosen) != len(ids) or {row["run_id"] for row in chosen} != set(ids):
        raise ValueError("A selected run is absent or ambiguous; choose its source again")
    return chosen


def source_arguments(rows: list[dict], results_root: Path, output: Path) -> dict[str, str]:
    """Resolve only selected locators, not a recursive results-store inventory."""
    roots = set()
    for row in rows:
        reference = row.get("source_ref")
        if not isinstance(reference, str):
            raise ValueError("A selected run has no retained artifact location")
        location, separator, number = reference.rpartition(":")
        if not separator or not number.isdigit():
            raise ValueError("A selected run has an invalid retained artifact location")
        path = Path(location)
        if not path.is_absolute():
            path = results_root / path
        root = path.parent.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("A selected results directory is unavailable")
        roots.add(root)
    # Nested explicit grids share one reader root; exact run IDs still restrict
    # the inventory, so unrelated runs never become selected automatically.
    roots = {root for root in roots if not any(root != other and root.is_relative_to(other) for other in roots)}
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
        return "<p class='notice red'>Saved-input campaign index unavailable.</p>"
    def escape(value):
        return html.escape(str(value), quote=True)
    options = "<option value=''>Choose a source campaign</option>" + "".join(
        "<option value='" + row["campaign_id"] + "'" + (" selected" if selected == row["campaign_id"] else "")
        + ">" + escape(row["name"]) + "</option>" for row in campaigns
    )
    content = (
        "<section class='card source-preparation' id='retained-inputs'><h2>Reuse local inputs for an API comparison</h2>"
        "<p>Use the same questions, images and attack prompts from saved local runs to compare API models. "
        "This prepares an input selection only: it does not change the current pipeline's corpus or launch any model.</p>"
        "<div class='source-steps' aria-label='Input reuse workflow'><span>1. Choose a campaign</span>"
        "<span>2. Select saved runs and limits</span><span>3. Review and start</span></div>"
        "<div class='source-campaign-row'><label class='campaign-field'>Source campaign "
        "<select name='retained_source_campaign' form='builder'>" + options + "</select></label>"
        "<button type='submit' form='builder' formaction='/build/source-runs' class='ghost'>Show saved runs</button></div>"
    )
    if selected:
        rows = source_runs(app.db, selected)
        try:
            chosen = json.loads(params.get("retained_source_runs", "[]"))
        except ValueError:
            chosen = []
        if not isinstance(chosen, list):
            chosen = []
        chosen = [key for key in chosen if any(row['run_id'] == key for row in rows)]
        content += (
            "<fieldset class='source-run-fieldset'><legend>Saved local runs</legend>"
            "<label class='campaign-field'>Find a model or corpus<input type='search' id='source-run-search' "
            "placeholder='Filter saved runs'></label><div class='source-run-picker' aria-describedby='retained-source-help'>"
            + "".join("<label class='source-run-choice'><input type='checkbox' data-source-run value='"
                + escape(row["run_id"]) + "'" + (" checked" if row["run_id"] in chosen else "") + ">"
                + "<span><strong>" + escape(row['model']) + "</strong><span>"
                + escape(f"{row['corpus']} - {row['responses']:,} saved outputs")
                + "</span><small>Run: " + escape(row['run_id']) + "</small></span></label>" for row in rows)
            + ("<p>No measured local runs are indexed in this campaign.</p>" if not rows else "")
            + "</div><p id='source-run-count' aria-live='polite'>" + str(len(chosen)) + " run(s) selected</p>"
            "</fieldset><input type='hidden' form='builder' name='retained_source_runs' "
            "id='retained-source-runs' value='" + escape(json.dumps(chosen)) + "'>"
            "<p class='note' id='retained-source-help'>Missing and truncated responses are included. Only measured local records are listed; "
            "the preparation job checks that the selected original grids are complete and usable as input sources. "
            "This list is not a model-quality filter.</p>"
            "<script>document.addEventListener('DOMContentLoaded',()=>{const boxes=Array.from(document.querySelectorAll('[data-source-run]'));"
            "const hidden=document.getElementById('retained-source-runs');"
            "const sync=()=>{const chosen=boxes.filter(o=>o.checked);hidden.value=JSON.stringify(chosen.map(o=>o.value));"
            "document.getElementById('source-run-count').textContent=chosen.length+' run(s) selected';};"
            "boxes.forEach(o=>o.addEventListener('change',sync));document.getElementById('builder')?.addEventListener('submit',sync);"
            "document.getElementById('source-run-search').addEventListener('input',e=>{const term=e.target.value.toLowerCase();"
            "boxes.forEach(o=>{const row=o.closest('label');row.hidden=!row.textContent.toLowerCase().includes(term);});});"
            "});</script>"
        )
    job_id = params.get("retained_sources_job", "")
    if job_id:
        content += "<p><a href='/jobs/" + escape(job_id) + "'>Open the input preparation job and its artifacts</a></p>"
        content += "<input type='hidden' form='builder' name='retained_sources_job' value='" + escape(job_id) + "'>"
    from .builder_budget import budget_panel
    from .builder_collection import collection_panel
    from .builder_native_judging import native_judging_panel
    from .builder_haiku_judging import haiku_judging_panel
    automatic = ''
    if selected:
        automatic = budget_panel(app, params, automatic=True)
        if not unified:
            automatic += ("<section class='card' id='automatic-comparison'><h2>Prepare and review the comparison</h2>"
            "<p>Input extraction, forecasting, replay preparation and execution setup run automatically on one progress page. "
            "You will review the workload and costs before any generation starts. Select enough saved inputs and "
            "request capacity for at least two whole input clusters: a connection check and separate measured inputs.</p>"
            "<label class='checkrow'><input type='checkbox' form='builder' name='retained_network_counts'"+
            (' checked' if params.get('retained_network_counts') == 'on' else '')+
            "><span>Allow provider token counting for the selected prompts and images (no generation)</span></label>"
            "<button form='builder' formaction='/build/prepare-operation/matched'>Prepare comparison and review</button></section>")
    # Retain old prepared collections without making their internal stages a
    # required part of a new operator workflow.
    hidden = ''.join("<input type='hidden' form='builder' name='"+field+"' value='"+escape(params[field])+"'>"
        for field in ('retained_replays_job', 'retained_programs_job') if params.get(field))
    legacy = collection_panel(params) + native_judging_panel(app,params) + haiku_judging_panel(app,params)
    if unified:
        legacy = ('<details class="card"><summary>Earlier prepared collections and assessments</summary>'+legacy+'</details>'
                  if params.get('retained_programs_job') else '')
        return '<div data-saved-inputs>'+content+'</section>'+automatic+hidden+'</div>'+legacy
    return content + '</section>' + automatic + hidden + legacy


def prepare_selected_inputs(app, params: dict[str, str]):
    if params.get("work_kind") != "campaign" and not params.get("campaign_id"):
        raise ValueError("Select Campaign to reuse saved local inputs for an API comparison")
    rows = selected_runs(params, source_runs(app.db, params.get("retained_source_campaign", "")))
    output_root = (app.results_root / "rig-web" / "prepared-inputs").resolve()
    values = source_arguments(rows, app.results_root, output_root / (uuid4().hex + ".json"))
    params = app._save_build_campaign(params)
    job = app.start_job("retained_local_sources", values, campaign_id=params["campaign_id"])
    app._save_build_campaign(dict(params, retained_sources_job=job.job_id))
    return job
