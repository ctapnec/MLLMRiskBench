"""Compare indexed job outputs without rebuilding campaigns or reading models."""

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text
import csv
import html
import io
import json
from pathlib import Path
from urllib.parse import urlencode

from .ui import _page
from .workspace_comparison import coverage_chart
from .workspace_charts import EXPORT_SCRIPT, SERIES


def choices(app):
    rows = app.db._query(
        "SELECT r.*,m.campaign_id,c.name AS campaign_name FROM ("
        + app.db._CAMPAIGN_ROWS
        + ") r JOIN campaign_members m ON m.member_id=r.job_id AND m.member_kind IN ('job','external') "
        "JOIN campaigns c ON c.campaign_id=m.campaign_id WHERE r.command='run_matrix' AND r.kind='measured' "
        "ORDER BY r.created_at DESC,r.job_id"
    )
    if rows is None:
        raise ValueError(_ui_text("stats_jobs.job_index_unavailable"))
    return [dict(row) for row in rows if row["out_dir"]]


def directory(app, row):
    path = Path(row["out_dir"])
    return (path if path.is_absolute() else app.repo_root / path).resolve()


def outputs(app, job, roster):
    root = directory(app, job)
    # A shared/resumed output directory is not attributable to one job.
    # Do not silently credit the same retained answers to both executions.
    for other in roster:
        path = directory(app, other)
        if other["job_id"] != job["job_id"] and (
            path.is_relative_to(root) or root.is_relative_to(path)
        ):
            raise ValueError(
                _ui_text(
                    "stats_jobs.this_job_shares_an_output_history_with_another_job_compare_its_ca"
                )
            )
    prefix = str(root) + "/"
    rows = app.db._query(
        "SELECT a.*,r.outcome,r.truncated,r.details FROM campaign_assignments a "
        "JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.assignment_id=a.assignment_id "
        "AND r.response_id=a.response_id WHERE a.campaign_id=? AND a.evidence_class='measured' "
        "AND substr(json_extract(r.details,'$.source_ref'),1,?)=? ORDER BY a.model,a.condition_id,a.input_id",
        (job["campaign_id"], len(prefix), prefix),
    )
    if rows is None:
        raise ValueError(_ui_text("stats_jobs.indexed_job_outputs_unavailable"))
    return [dict(row) for row in rows]


def summarize(rows):
    from collections import defaultdict

    groups = defaultdict(
        lambda: dict(
            outputs=0,
            usable=0,
            missing=0,
            policy=0,
            other=0,
            truncated=0,
            truncation_unknown=0,
            input_tokens=0,
            output_tokens=0,
            usage_known=0,
        )
    )
    for row in rows:
        key = tuple(row[k] for k in ("model", "condition_id", "corpus", "framework", "modality"))
        value = groups[key]
        value["outputs"] += 1
        value[row["outcome"] if row["outcome"] in {"usable", "missing", "policy"} else "other"] += 1
        value["truncated"] += row["truncated"] == 1
        value["truncation_unknown"] += row["truncated"] is None
        details = json.loads(row["details"])
        if all(type(details.get(k)) is int for k in ("input_tokens", "output_tokens")):
            value["usage_known"] += 1
            for k in ("input_tokens", "output_tokens"):
                value[k] += details[k]
    return [
        dict(zip(("model", "condition_id", "corpus", "framework", "modality"), key), **values)
        for key, values in groups.items()
    ]


def overlap(left, right):
    from collections import Counter

    def keys(rows):
        return Counter(
            tuple(r[k] for k in ("input_id", "corpus", "framework", "modality")) for r in rows
        )

    a, b = keys(left), keys(right)
    counts = dict(matched=0, left_only=0, right_only=0, ambiguous=0)
    for key in a.keys() | b.keys():
        name = (
            "ambiguous"
            if a[key] > 1 or b[key] > 1
            else "matched"
            if key in a and key in b
            else "left_only"
            if key in a
            else "right_only"
        )
        counts[name] += 1
    return counts


def outcome_chart(row):
    """Keep each job/model/condition/task separate; unknown outcomes stay explicit."""
    total = row["outputs"]
    if not total:
        return ""
    segments = []
    labels = []
    offset = 0
    categories = (
        ("usable", _ui_text("stats_jobs.usable")),
        ("missing", _ui_text("stats_jobs.missing")),
        ("policy", _ui_text("stats_jobs.policy_refusal")),
        ("other", _ui_text("stats_jobs.other")),
    )
    for (key, label), color in zip(categories, SERIES):
        count = row[key]
        size = 100 * count / total
        if count:
            segments.append(
                f"<rect x='{offset:.6f}' y='0' width='{size:.6f}' height='8' "
                f"style='fill:{color}' data-category='{key}' data-count='{count}'>"
                f"<title>{label}: {count}/{total} ({size:.1f}%)</title></rect>"
            )
        labels.append(
            f"<span><span aria-hidden='true' style='display:inline-block;width:.8em;height:.8em;background:{color}'></span> "
            f"{label}: {count:,} ({size:.1f}%)</span>"
        )
        offset += size
    caption = " / ".join(
        str(row[k]) for k in ("side", "model", "condition_id", "corpus", "framework", "modality")
    )
    return (
        "<figure style='margin:1.25rem 0'><figcaption style='overflow-wrap:anywhere'>"
        + html.escape(caption)
        + (
            " - "
            + f"{total:,}"
            + _ui_template(
                " [[text:stats_jobs.saved_outcomes]]</figcaption><svg xmlns='http://www.w3.org/2000/svg' role='img' aria-label='[[attr:stats_jobs.job_outcome_composition]]' viewBox='0 0 100 8' preserveAspectRatio='none' style='width:100%;height:1.6rem;margin:.5rem 0'><title>[[text:stats_jobs.job_outcome_composition]]</title><desc>[[text:stats_jobs.saved_measured_outcomes_for_this_job_model_generation_condition_a]]</desc>"
            )
        )
        + "".join(segments)
        + "</svg><div style='display:flex;flex-wrap:wrap;gap:.4rem 1rem'>"
        + "".join(labels)
        + "</div></figure>"
    )


def response(app, query):
    roster = choices(app)
    selected = {}
    data = {}
    reports = []
    for side in ("left", "right"):
        key = query.get(side + "_job", "")
        if key:
            selected[side] = next((r for r in roster if r["job_id"] == key), None)
            if selected[side] is None:
                raise ValueError(_ui_text("stats_jobs.choose_an_indexed_measured_job"))
            data[side] = outputs(app, selected[side], roster)
            reports.extend(
                dict(side=side, job=key, campaign=selected[side]["campaign_id"], **r)
                for r in summarize(data[side])
            )
    if query.get("download") == "csv":
        if len(selected) != 2:
            raise ValueError(_ui_text("stats_jobs.select_two_jobs_before_downloading"))
        stream = io.StringIO(newline="")
        fields = [
            "side",
            "job",
            "campaign",
            "model",
            "condition_id",
            "corpus",
            "framework",
            "modality",
            "outputs",
            "usable",
            "missing",
            "policy",
            "other",
            "truncated",
            "truncation_unknown",
            "input_tokens",
            "output_tokens",
            "usage_known",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in reports:
            writer.writerow(
                {
                    k: "'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v
                    for k, v in row.items()
                }
            )
        return 200, "text/csv; charset=utf-8", stream.getvalue().encode("utf-8-sig")
    esc = html.escape
    body = _ui_template("<h1>[[text:stats_jobs.stats]]</h1>") + app._work_view_tabs(
        "stats", "compare"
    )
    body += _ui_template(
        '<section class="card"><h2>[[text:stats_jobs.compare_saved_job_outputs]]</h2><p><a href="/stats?view=compare">[[text:stats_jobs.compare_whole_campaigns]]</a></p>'
    )
    body += _ui_template(
        "<p>[[text:stats_jobs.choose_measured_jobs_with_indexed_answers_and_exclusive_output_di]]</p>"
    )
    body += '<form method="get" action="/stats"><input type="hidden" name="view" value="compare"><input type="hidden" name="scope" value="jobs"><div class="campaign-grid">'
    for side in ("left", "right"):
        body += (
            '<label class="campaign-field">'
            + html.escape(_ui_label(side))
            + _ui_template(' [[text:stats_jobs.job]]<select name="')
            + side
            + _ui_template(
                '_job" required><option value="">[[text:stats_jobs.choose_measured_job]]</option>'
            )
        )
        for row in roster:
            body += (
                '<option value="'
                + esc(row["job_id"])
                + '"'
                + (" selected" if query.get(side + "_job") == row["job_id"] else "")
                + ">"
                + esc(row["campaign_name"] + " / " + row["job_id"] + " / " + row["state"])
                + "</option>"
            )
        body += "</select></label>"
    body += _ui_template(
        '</div><div class="action-row"><button>[[text:stats_jobs.compare_job_outputs]]</button></div></form></section>'
    )
    if len(selected) == 2:
        body += _ui_template(
            '<section class="card"><h2>[[text:stats_jobs.input_overlap]]</h2>'
        ) + coverage_chart(overlap(data["left"], data["right"]))
        body += _ui_template(
            "<p>[[text:stats_jobs.exact_indexed_inputs_corpus_framework_and_modality_repeated_input]]</p></section>"
        )
        body += _ui_template(
            '<section class="card"><h2>[[text:stats_jobs.outcomes_by_model_condition_and_task]]</h2><p>[[text:stats_jobs.truncation_is_independent_of_output_usability_unknown_token_usage]]</p>'
        )
        body += "".join(outcome_chart(row) for row in reports)
        headers = (
            _ui_text("stats_jobs.side"),
            _ui_text("stats_jobs.model_condition"),
            _ui_text("stats_jobs.corpus_framework_modality"),
            _ui_text("stats_jobs.saved"),
            _ui_text("stats_jobs.usable"),
            _ui_text("stats_jobs.missing"),
            _ui_text("stats_jobs.policy_refusal"),
            _ui_text("stats_jobs.other"),
            _ui_text("stats_jobs.truncated_unknown"),
            _ui_text("stats_jobs.known_token_usage"),
        )
        body += (
            '<div class="scroll"><table><thead><tr>'
            + "".join("<th>" + h + "</th>" for h in headers)
            + "</tr></thead><tbody>"
        )
        for row in reports:
            cells = (
                row["side"],
                row["model"] + " / " + row["condition_id"],
                row["corpus"] + " / " + row["framework"] + " / " + row["modality"],
                row["outputs"],
                row["usable"],
                row["missing"],
                row["policy"],
                row["other"],
                str(row["truncated"]) + " / " + str(row["truncation_unknown"]),
                (
                    str(row["input_tokens"])
                    + _ui_text("stats_jobs.in")
                    + str(row["output_tokens"])
                    + _ui_text("stats_jobs.out")
                    + str(row["usage_known"])
                    + "/"
                    + str(row["outputs"])
                    + _ui_text("stats_jobs.outputs")
                )
                if row["usage_known"]
                else _ui_text("stats_jobs.not_recorded"),
            )
            body += "<tr>" + "".join("<td>" + esc(str(v)) + "</td>" for v in cells) + "</tr>"
        body += "</tbody></table></div>"
        if not reports:
            body += _ui_template(
                "<p>[[text:stats_jobs.no_indexed_outcomes_resolve_to_these_jobs_use_their_campaign_repo]]</p>"
            )
        body += (
            '<div id="campaign-exports" class="action-row"><a data-campaign-export download="job-comparison.csv" href="/stats?'
            + esc(urlencode(dict(query, download="csv")), quote=True)
            + _ui_template(
                '">[[text:stats_jobs.export_these_job_statistics_csv]]</a></div><p id="campaign-export-status" role="status"></p></section>'
            )
            + EXPORT_SCRIPT
        )
    return (
        200,
        "text/html; charset=utf-8",
        _page(_ui_text("stats_jobs.compare_jobs"), body, active=_ui_text("stats_jobs.stats")),
    )
