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


def source_panel(app, params: dict[str, str]) -> str:
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
        "<section class='card'><h2>Prepare a matched follow-on</h2>"
        "<p>Select saved local runs to prepare the same inputs for a later hosted comparison. "
        "This separate preparation does not change the current pipeline's corpus or launch any model.</p>"
        "<div class='campaign-actions'><label class='campaign-field'>Source campaign "
        "<select name='retained_source_campaign' form='builder'>" + options + "</select></label>"
        "<button type='submit' form='builder' formaction='/build/source-runs' class='ghost'>Choose source runs</button></div>"
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
            "<label class='campaign-field'>Saved local runs "
            "<select id='retained-source-run-select' multiple size='8' aria-describedby='retained-source-help'>"
            + "".join("<option value='" + escape(row["run_id"]) + "'"
                + (" selected" if row["run_id"] in chosen else "") + ">"
                + escape(f"{row['model']} | {row['corpus']} | {row['responses']:,} saved outputs | {row['run_id']}")
                + "</option>" for row in rows)
            + "</select></label><input type='hidden' form='builder' name='retained_source_runs' "
            "id='retained-source-runs' value='" + escape(json.dumps(chosen)) + "'>"
            "<p class='note' id='retained-source-help'>Use Ctrl/Cmd or Shift to select several runs. "
            "Missing and truncated responses are included. Only measured local records are listed; "
            "the preparation job checks that the selected original grids are complete and usable as input sources. "
            "This list is not a model-quality filter.</p>"
            "<button type='submit' form='builder' formaction='/build/prepare-inputs'>Prepare selected inputs</button>"
            "<script>document.addEventListener('DOMContentLoaded',()=>{const select=document.getElementById('retained-source-run-select');"
            "const hidden=document.getElementById('retained-source-runs');"
            "const sync=()=>{hidden.value=JSON.stringify(Array.from(select.selectedOptions,o=>o.value));};"
            "select.addEventListener('change',sync);document.getElementById('builder')?.addEventListener('submit',sync);"
            "});</script>"
        )
    job_id = params.get("retained_sources_job", "")
    if job_id:
        content += "<p><a href='/jobs/" + escape(job_id) + "'>Open the input preparation job and its artifacts</a></p>"
        content += "<input type='hidden' form='builder' name='retained_sources_job' value='" + escape(job_id) + "'>"
    from .builder_budget import budget_panel
    return content + "</section>" + budget_panel(app, params)


def prepare_selected_inputs(app, params: dict[str, str]):
    if params.get("work_kind") != "campaign" and not params.get("campaign_id"):
        raise ValueError("Select Campaign to prepare a matched follow-on")
    rows = selected_runs(params, source_runs(app.db, params.get("retained_source_campaign", "")))
    output_root = (app.results_root / "rig-web" / "prepared-inputs").resolve()
    values = source_arguments(rows, app.results_root, output_root / (uuid4().hex + ".json"))
    params = app._save_build_campaign(params)
    job = app.start_job("retained_local_sources", values, campaign_id=params["campaign_id"])
    app._save_build_campaign(dict(params, retained_sources_job=job.job_id))
    return job
