"""Recorded classifier evaluation in Stats, without fitting or reading datasets."""

from __future__ import annotations


from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import csv
import html
import io
import json
import math
from pathlib import Path
from urllib.parse import quote, urlencode

from .builder_replays import argument
from .ui import _page
from .workspace_charts import CHART_STYLE, EXPORT_SCRIPT

TASKS = {
    "harmful_compliance": _ui_text("svm_stats.harmful_compliance"),
    "over_refusal": _ui_text("svm_stats.over_refusal"),
    "judge_disagreement": _ui_text("svm_stats.local_haiku_disagreement"),
}
ESTIMATORS = {
    "linear_svm": _ui_text("svm_stats.linear_svm"),
    "logistic": _ui_text("svm_stats.logistic_regression"),
    "logistic_regression": _ui_text("svm_stats.logistic_regression"),
    "majority": _ui_text("svm_stats.majority_baseline"),
    "harmful_svm_plus_local_verdict": _ui_text("svm_stats.derived_disagreement_baseline"),
}


def label(value):
    return TASKS.get(value, ESTIMATORS.get(value, _ui_label(str(value))))


def valid_score(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def score(value):
    return f"{value:.3f}" if valid_score(value) else _ui_text("svm_stats.not_estimated")


def load(app, directory):
    root = Path(directory)
    if not root.is_absolute():
        root = app.results_root / root
    root = root.resolve()
    if not root.is_relative_to(app.results_root.resolve()):
        raise ValueError(_ui_text("svm_stats.study_is_outside_the_results_directory"))

    def read(path):
        path = path.resolve()
        if not path.is_relative_to(root):
            raise ValueError(_ui_text("svm_stats.study_report_is_outside_its_directory"))
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError(
                _ui_text("svm_stats.study_report_is_too_large_for_an_interactive_summary")
            )
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(_ui_text("svm_stats.study_report_is_not_an_object"))
        return value

    saved = read(root / "result.json")
    evaluation = saved.get("stages", {}).get("evaluation")
    report = read(Path(evaluation) / "result.json") if evaluation else saved
    if not isinstance(report.get("experiments", []), list):
        raise ValueError(_ui_text("svm_stats.study_experiments_are_unavailable"))
    return root, saved, report


def studies(app):
    """Explicit references plus console jobs; do not scan the run tree."""
    records = app.db._query("SELECT * FROM svm_studies ORDER BY title,directory")
    jobs = app.db._query(
        "SELECT j.*,m.campaign_id FROM jobs j LEFT JOIN campaign_members m "
        "ON m.member_kind='job' AND m.member_id=j.job_id WHERE j.command='response_svm' ORDER BY j.started_at"
    )
    if records is None or jobs is None:
        raise ValueError(_ui_text("svm_stats.svm_study_index_unavailable"))
    result = {}

    def add(directory, title, owners, job=""):
        root = Path(directory)
        if not root.is_absolute():
            root = app.repo_root / root if job else app.results_root / root
        root = root.resolve()
        if not root.is_relative_to(app.results_root.resolve()):
            return
        key = root.relative_to(app.results_root.resolve()).as_posix()
        item = result.setdefault(key, dict(key=key, title=title, campaigns=set(), job=job))
        item["campaigns"].update(owners)
        if job:
            item["job"] = job

    for row in records:
        add(row["directory"], row["title"], json.loads(row["campaigns"]))
    for row in jobs:
        argv = json.loads(row["argv"])
        if "--study" not in argv and "--evaluate" not in argv:
            continue
        directory = argument(argv, "--out")
        if directory:
            owners = [argv[i + 1] for i, value in enumerate(argv[:-1]) if value == "--campaign"]
            if row["campaign_id"]:
                owners.append(row["campaign_id"])
            add(
                directory,
                _ui_text("svm_stats.classifier_study") + row["job_id"],
                owners,
                row["job_id"],
            )
    return list(result.values())


def selected_rows(report, query):
    rows = report.get("experiments", []) + report.get("derived_disagreement_baselines", [])
    protocols = list(dict.fromkeys(str(r.get("protocol", "unknown")) for r in rows))
    protocol = query.get("protocol") or (
        "group_holdout" if "group_holdout" in protocols else next(iter(protocols), "")
    )
    task = query.get("task", "")
    if (protocol and protocol not in protocols) or (task and task not in TASKS):
        raise ValueError(_ui_text("svm_stats.choose_a_recorded_evaluation_split_and_task"))
    return (
        [r for r in rows if r.get("protocol") == protocol and (not task or r.get("task") == task)],
        protocols,
        protocol,
    )


def metrics_csv(rows, metadata=None):
    metadata = metadata or {}
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        [
            *metadata,
            "task",
            "protocol",
            "features",
            "estimator",
            "status",
            "macro_f1",
            "ci95_low",
            "ci95_high",
            "average_precision",
            "test_responses",
            "test_groups",
            "class_0",
            "class_1",
        ]
    )
    for row in rows:
        metric = row.get("test", {})
        support = row.get("support", {}).get("test", row.get("support", {}))
        ci = metric.get("macro_f1_cluster_ci95") or [None, None]
        values = [
            *metadata.values(),
            *[row.get(k, "") for k in ("task", "protocol", "features", "estimator", "status")],
        ]
        values += [
            metric.get("macro_f1"),
            *ci,
            metric.get("average_precision"),
            support.get("responses"),
            support.get("groups"),
            support.get("classes", {}).get("0"),
            support.get("classes", {}).get("1"),
        ]
        writer.writerow(
            ["'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v for v in values]
        )
    return stream.getvalue().encode("utf-8")


def figure(rows, *, scope=""):
    rows = [
        r
        for r in rows
        if r.get("estimator") == "linear_svm" and valid_score(r.get("test", {}).get("macro_f1"))
    ]
    height = 60 + len(rows) * 90
    marks = []
    for i, row in enumerate(rows):
        y = 34 + i * 90
        metric = row["test"]
        value = metric["macro_f1"]
        caption = label(row.get("task")) + " / " + label(row.get("features", ""))
        marks.append(
            f"<text x='16' y='{y}'>{html.escape(caption)}</text>"
            f"<rect class='chart-track' x='16' y='{y + 12}' width='360' height='18'/>"
            f"<rect x='16' y='{y + 12}' width='{360 * value:.3f}' height='18' style='fill:var(--viz-series-1,#2563eb)'/>"
            f"<text x='16' y='{y + 54}'>{html.escape(_ui_text('svm_stats.macro_f1_value', value=score(value)))}</text>"
        )
        ci = metric.get("macro_f1_cluster_ci95")
        if (
            isinstance(ci, list)
            and len(ci) == 2
            and all(valid_score(v) for v in ci)
            and ci[0] <= ci[1]
        ):
            lo, hi = [16 + 360 * v for v in ci]
            marks.append(
                (
                    "<path d='M "
                    + f"{lo:.3f}"
                    + " "
                    + f"{y + 17}"
                    + " v 8 M "
                    + f"{lo:.3f}"
                    + " "
                    + f"{y + 21}"
                    + " H "
                    + f"{hi:.3f}"
                    + " M "
                    + f"{hi:.3f}"
                    + " "
                    + f"{y + 17}"
                    + " v 8' fill='none' stroke='var(--ink,#111827)' stroke-width='2'/><text x='180' y='"
                    + f"{y + 54}"
                    + _ui_template("'>[[text:svm_stats.95_ci]] ")
                    + f"{score(ci[0])}"
                    + " - "
                    + f"{score(ci[1])}"
                    + "</text>"
                )
            )
    return (
        (
            "<svg xmlns='http://www.w3.org/2000/svg' class='campaign-figure' style='max-width:560px' role='img' viewBox='0 0 410 "
            + f"{height}"
            + _ui_template(
                "' aria-label='[[attr:svm_stats.svm_held_out_macro_f1]]'><title>[[text:svm_stats.svm_held_out_macro_f1]]</title><desc>[[text:svm_stats.scale_zero_to_one_lines_show_recorded_input_cluster_bootstrap_95]] "
            )
        )
        + html.escape(scope)
        + "</desc>"
        "<style>"
        + CHART_STYLE
        + "</style>"
        + "".join(marks)
        + f"<text x='16' y='{height - 8}'>0</text><text x='196' y='{height - 8}'>0.5</text><text x='376' y='{height - 8}'>1</text></svg>"
    )


def table(rows):
    cells = []
    for row in rows:
        metric = row.get("test", {})
        support = row.get("support", {}).get("test", row.get("support", {}))
        ci = metric.get("macro_f1_cluster_ci95")
        interval = (
            " - ".join(score(v) for v in ci)
            if isinstance(ci, list) and len(ci) == 2
            else _ui_text("svm_stats.not_estimated")
        )
        classes = support.get("classes", {})
        class_counts = " / ".join(str(classes.get(str(i), "unknown")) for i in (0, 1))
        values = [
            label(row.get("task", "")),
            label(row.get("features", "")),
            label(row.get("estimator", "")),
            label(row.get("reason") or row.get("status", "unknown")),
            score(metric.get("macro_f1")),
            interval,
            score(metric.get("average_precision")),
            str(support.get("responses", "unknown")),
            str(support.get("groups", "unknown")),
            class_counts,
        ]
        cells.append("<tr>" + "".join("<td>" + html.escape(v) + "</td>" for v in values) + "</tr>")
    headers = [
        _ui_text("svm_stats.task"),
        _ui_text("svm_stats.features"),
        _ui_text("svm_stats.estimator_baseline"),
        _ui_text("svm_stats.status"),
        _ui_text("svm_stats.test_macro_f1"),
        _ui_text("svm_stats.95_interval"),
        _ui_text("svm_stats.average_precision"),
        _ui_text("svm_stats.test_answers"),
        _ui_text("svm_stats.test_input_groups"),
        _ui_text("svm_stats.test_classes_0_1"),
    ]
    return (
        '<div class="scroll"><table><thead><tr>'
        + "".join("<th>" + h + "</th>" for h in headers)
        + "</tr></thead><tbody>"
        + "".join(cells)
        + "</tbody></table></div>"
    )


def figure_html(rows):
    """Keep text at the reader's font size; scale only the plotted marks."""
    blocks = []
    for row in rows:
        metric = row.get("test", {})
        if row.get("estimator") != "linear_svm" or not valid_score(metric.get("macro_f1")):
            continue
        value = metric["macro_f1"]
        ci = metric.get("macro_f1_cluster_ci95")
        marks = f"<rect x='0' y='4' width='100' height='10' fill='var(--soft)'/><rect x='0' y='4' width='{100 * value:.3f}' height='10' fill='var(--viz-series-1,#2563eb)'/>"
        text = _ui_text("svm_stats.macro_f1") + score(value)
        if (
            isinstance(ci, list)
            and len(ci) == 2
            and all(valid_score(v) for v in ci)
            and ci[0] <= ci[1]
        ):
            low, high = [100 * v for v in ci]
            marks += f"<path d='M {low:.3f} 6 v 6 M {low:.3f} 9 H {high:.3f} M {high:.3f} 6 v 6' fill='none' stroke='var(--ink)' stroke-width='.6'/>"
            text += _ui_text("svm_stats.95_interval_copy") + score(ci[0]) + " - " + score(ci[1])
        else:
            text += _ui_text("svm_stats.interval_not_estimated")
        caption = label(row.get("task")) + " / " + label(row.get("features", ""))
        blocks.append(
            '<figure style="margin:1.1rem 0"><figcaption>' + html.escape(caption) + "</figcaption>"
            '<svg aria-hidden="true" viewBox="0 0 100 18" preserveAspectRatio="none" style="width:100%;height:2rem">'
            + marks
            + '</svg><p class="note" style="margin:0">'
            + html.escape(text)
            + "</p></figure>"
        )
    return (
        _ui_template(
            '<div role="img" aria-label="[[attr:svm_stats.svm_held_out_macro_f1]]" style="max-width:680px"><p class="note">[[text:svm_stats.macro_f1_scale_0_to_1_lines_show_recorded_95_intervals]]</p>'
        )
        + "".join(blocks)
        + "</div>"
        if blocks
        else ""
    )


def response(app, query):
    inventory = studies(app)
    owner = query.get("campaign_id", "")
    if owner:
        app.db.require_workspace(owner)
        inventory = [s for s in inventory if owner in s["campaigns"]]
    selected = query.get("study") or (inventory[-1]["key"] if inventory else "")
    item = next((s for s in inventory if s["key"] == selected), None)
    if selected and item is None:
        raise ValueError(_ui_text("svm_stats.choose_an_indexed_svm_study_in_the_selected_campaign"))
    body = _ui_template("<h1>[[text:svm_stats.stats]]</h1>") + app._work_view_tabs("stats", "svm")
    body += _ui_template(
        '<section class="card"><h2>[[text:svm_stats.svm_results]]</h2><p>[[text:svm_stats.predictions_of_recorded_judge_labels_not_model_safety_scores_or_i]] '
    )
    body += _ui_template(
        "[[text:svm_stats.studies_input_populations_tasks_and_evaluation_splits_are_kept_se]]</p>"
    )
    if not item:
        body += _ui_template(
            '<p>[[text:svm_stats.no_indexed_svm_studies_in_this_selection_start_a_study_from_a_cam]]</p><div class="action-row"><a href="/stats?view=svm">[[text:svm_stats.show_studies_from_all_campaigns]]</a></div></section>'
        )
        return (
            200,
            "text/html; charset=utf-8",
            _page(_ui_text("svm_stats.svm_results"), body, active=_ui_text("svm_stats.stats")),
        )
    try:
        root, saved, report = load(app, item["key"])
    except (OSError, ValueError, TypeError) as exc:
        body += (
            _ui_template(
                '<p class="notice amber">[[text:svm_stats.saved_results_are_not_available_yet]] '
            )
            + html.escape(str(exc))
            + "</p>"
        )
        if item["job"]:
            body += (
                '<a href="/jobs/'
                + quote(item["job"])
                + _ui_template('">[[text:svm_stats.open_analysis_job]]</a>')
            )
        # Keep the study selector usable even if the latest study is unfinished.
        report = {}
        saved = {}
        root = app.results_root / item["key"]
    rows, protocols, protocol = selected_rows(report, query)
    metadata = dict(
        study=item["key"],
        teacher=report.get("teacher"),
        split_seed=report.get("seed"),
        selected_responses=report.get("selected_responses"),
        independent_groups=report.get("independent_groups"),
        bootstrap_draws=report.get("bootstrap_draws"),
    )
    chart_scope = (
        item["title"]
        + _ui_text("svm_stats.evaluation")
        + protocol
        + _ui_text("svm_stats.recorded_teacher")
        + str(report.get("teacher", _ui_text("svm_stats.not_recorded")))
    )
    export = query.get("export")
    if export:
        if export == "csv":
            return 200, "text/csv; charset=utf-8", metrics_csv(rows, metadata)
        if export == "svg":
            return (
                200,
                "image/svg+xml; charset=utf-8",
                figure(rows, scope=chart_scope).encode("utf-8"),
            )
        raise ValueError(_ui_text("svm_stats.unknown_svm_export"))

    def select(name, caption, choices, value):
        return (
            '<label class="campaign-field">'
            + caption
            + '<select aria-label="'
            + caption
            + '" name="'
            + name
            + '">'
            + "".join(
                '<option value="'
                + html.escape(k, quote=True)
                + '"'
                + (" selected" if k == value else "")
                + ">"
                + html.escape(v)
                + "</option>"
                for k, v in choices
            )
            + "</select></label>"
        )

    body += '<form method="get" action="/stats"><input type="hidden" name="view" value="svm"><div class="campaign-grid">'
    body += select(
        "campaign_id",
        _ui_text("svm_stats.campaign"),
        [("", _ui_text("svm_stats.all_campaigns"))]
        + [(r["campaign_id"], r["name"]) for r in app.db.workspaces() or []],
        owner,
    )
    body += select(
        "study",
        _ui_text("svm_stats.saved_study"),
        [(s["key"], s["title"]) for s in inventory],
        selected,
    )
    body += select(
        "protocol",
        _ui_text("svm_stats.evaluation_split"),
        [(p, label(p)) for p in protocols],
        protocol,
    )
    body += select(
        "task",
        _ui_text("svm_stats.task"),
        [("", _ui_text("svm_stats.all_tasks")), *TASKS.items()],
        query.get("task", ""),
    )
    body += _ui_template(
        '</div><div class="action-row"><button>[[text:svm_stats.show_svm_results]]</button></div></form>'
    )
    # A changed population must not retain an incompatible downstream choice.
    body += "<script>(()=>{const f=document.querySelector('select[name=study]').form;f.elements.campaign_id.addEventListener('change',()=>{f.elements.study.value='';f.elements.protocol.value='';});f.elements.study.addEventListener('change',()=>{f.elements.protocol.value='';});})();</script>"
    body += (
        "<p>"
        + html.escape(str(report.get("selected_responses", "unknown")))
        + _ui_text("svm_stats.selected_text_answers")
        + html.escape(str(report.get("independent_groups", "unknown")))
        + _ui_template(" [[text:svm_stats.independent_input_groups]]</p>")
    )
    from .workspace_judge_settings import judge_name

    teacher = str(report.get("teacher", _ui_text("svm_stats.not_recorded")))
    body += (
        _ui_template("<p>[[text:svm_stats.recorded_teacher_2]] ")
        + html.escape(judge_name(teacher))
        + _ui_text("svm_stats.split_seed")
        + html.escape(str(report.get("seed", _ui_text("svm_stats.not_recorded"))))
        + ".</p>"
    )
    body += (
        _ui_template(
            '<details><summary>[[text:svm_stats.exact_teacher_condition]]</summary><p style="overflow-wrap:anywhere">'
        )
        + html.escape(teacher)
        + "</p></details>"
    )
    if saved.get("packaging_reason"):
        body += '<p class="notice amber">' + html.escape(saved["packaging_reason"]) + "</p>"
    if rows:
        body += (
            figure_html(rows)
            + _ui_template(
                '<p class="note">[[text:svm_stats.the_metric_table_scrolls_horizontally_on_small_screens]]</p>'
            )
            + table(rows)
        )
    else:
        body += _ui_template(
            "<p>[[text:svm_stats.no_evaluated_task_in_this_selection_this_is_not_a_score_of_zero]]</p>"
        )
    body += _ui_template(
        "<p>[[text:svm_stats.macro_f1_gives_equal_weight_to_both_classes_intervals_use_input_g]] "
    )
    body += _ui_text("svm_stats.class_1_means_harmful_compliance_over_refusal_or_local_haiku_disa")
    body += _ui_template(
        "[[text:svm_stats.compare_svm_and_baseline_rows_only_within_the_same_study_task_and]]</p>"
    )
    params = dict(
        view="svm", study=selected, protocol=protocol, task=query.get("task", ""), campaign_id=owner
    )
    body += (
        '<div id="campaign-exports" class="action-row">'
        + "".join(
            '<a data-campaign-export download="svm-results.'
            + kind
            + '" href="/stats?'
            + html.escape(urlencode(dict(params, export=kind)), quote=True)
            + _ui_template('">[[text:svm_stats.download]] ')
            + kind.upper()
            + "</a>"
            for kind in ("csv", "svg")
        )
        + "</div>"
    )
    body += '<p id="campaign-export-status" role="status"></p>'
    body += (
        '<div class="action-row"><a href="/artifacts?path='
        + quote((root / "result.json").relative_to(app.results_root.resolve()).as_posix())
        + _ui_template('">[[text:svm_stats.full_study_report]]</a>')
    )
    if item["job"]:
        body += (
            '<a href="/jobs/'
            + quote(item["job"])
            + _ui_template('">[[text:svm_stats.analysis_job]]</a>')
        )
    body += "</div></section>" + EXPORT_SCRIPT
    return (
        200,
        "text/html; charset=utf-8",
        _page(_ui_text("svm_stats.svm_results"), body, active=_ui_text("svm_stats.stats")),
    )
