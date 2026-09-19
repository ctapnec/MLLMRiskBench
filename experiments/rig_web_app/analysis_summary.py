"""Readable saved classifier results; no fitting or artifact reconstruction."""

from .i18n import template as _ui_template, text as _ui_text
import html
import json
from pathlib import Path
from urllib.parse import quote


def render(app, directory):
    root = Path(directory).resolve()
    results = app.results_root.resolve()
    if not root.is_relative_to(results):
        return ""

    def read(path):
        path = Path(path).resolve()
        if (
            not path.is_relative_to(root)
            or not path.is_file()
            or path.stat().st_size > 32 * 1024 * 1024
        ):
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}

    def link(path, label):
        path = Path(path).resolve()
        if not path.is_relative_to(root) or not path.exists():
            return ""
        return (
            '<a href="/artifacts?path='
            + quote(path.relative_to(results).as_posix())
            + '">'
            + html.escape(label)
            + "</a>"
        )

    try:
        saved = read(root / "result.json")
        if not saved:
            return _ui_template(
                "<p>[[text:analysis_summary.analysis_is_not_complete_open_its_job_for_progress_or_recovery]]</p>"
            )
        evaluation = saved.get("stages", {}).get("evaluation")
        report = read(Path(evaluation) / "result.json") if evaluation else saved
        body = _ui_template(
            '<section class="card"><h3>[[text:analysis_summary.analysis_results]]</h3>'
        )
        body += _ui_template(
            "<p>[[text:analysis_summary.recorded_teacher_label_agreement_not_human_validated_model_safety]]</p>"
        )
        if report.get("selected_responses") is not None:
            body += (
                "<p>"
                + html.escape(str(report["selected_responses"]))
                + _ui_text("analysis_summary.selected_text_answers")
            )
            body += html.escape(str(report.get("independent_groups", "unknown"))) + _ui_template(
                " [[text:analysis_summary.independent_input_groups]]</p>"
            )
        if saved.get("packaging_reason"):
            body += '<p class="notice amber">' + html.escape(saved["packaging_reason"]) + "</p>"
        experiments = report.get("experiments", [])
        if experiments:
            body += _ui_template(
                '<div class="scroll"><table><thead><tr><th>[[text:analysis_summary.task]]</th><th>[[text:analysis_summary.evaluation]]</th><th>[[text:analysis_summary.features]]</th><th>[[text:analysis_summary.status]]</th><th>[[text:analysis_summary.test_macro_f1]]</th></tr></thead><tbody>'
            )
            for row in experiments:
                if row.get("estimator") not in {None, "linear_svm"}:
                    continue
                value = row.get("test", {}).get("macro_f1")
                score = (
                    f"{value:.3f}"
                    if isinstance(value, (float, int))
                    else _ui_text("analysis_summary.not_estimated")
                )
                cells = (
                    str(row.get("task", "")).replace("_", " "),
                    str(row.get("protocol", "")).replace("_", " "),
                    str(row.get("features", "")).replace("_", " "),
                    str(row.get("reason") or row.get("status", "unknown")),
                    score,
                )
                body += (
                    "<tr>"
                    + "".join("<td>" + html.escape(cell) + "</td>" for cell in cells)
                    + "</tr>"
                )
            body += _ui_template(
                "</tbody></table></div><p>[[text:analysis_summary.macro_f1_balances_the_two_label_classes_compare_feature_sets_with]]</p>"
            )
        links = [link(root / "result.json", _ui_text("analysis_summary.study_report"))]
        for stage, label in [
            ("dataset", _ui_text("analysis_summary.dataset_and_exclusions")),
            ("evaluation", _ui_text("analysis_summary.metrics_predictions_and_baselines")),
            ("classifiers", _ui_text("analysis_summary.reusable_classifiers")),
        ]:
            if saved.get("stages", {}).get(stage):
                links.append(link(saved["stages"][stage], label))
        body += '<div class="action-row">' + " ".join(filter(None, links)) + "</div></section>"
        return body
    except (OSError, ValueError, TypeError):
        return _ui_template(
            '<p class="notice amber">[[text:analysis_summary.the_saved_analysis_summary_is_unavailable_its_job_and_retained_ar]]</p>'
        )
