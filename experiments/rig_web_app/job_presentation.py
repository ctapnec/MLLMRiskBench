"""Operator work categories based on the executed mode, not the command alone."""

from .i18n import text as _ui_text
from .artifacts import run_kind
from .workspace_store import activity_role


def substantive(command, argv):
    kind = run_kind(command, argv)
    if kind is not None:
        return kind in {"measured", "diagnostic_canary"}
    if command == "campaign_assess":
        return "--execute" in argv
    if command == "response_svm":
        return any(flag in argv for flag in ("--study", "--evaluate", "--predict", "--package"))
    return activity_role(command) in {"collection", "judging", "analysis"}


def work_label(command, argv):
    if command == "campaign_assess":
        return (
            _ui_text("job_presentation.evaluate_saved_answers")
            if "--execute" in argv
            else _ui_text("job_presentation.assessment_preparation")
        )
    if command == "response_svm":
        return (
            _ui_text("job_presentation.svm_analysis")
            if substantive(command, argv)
            else _ui_text("job_presentation.analysis_preparation")
        )
    return {
        "collection": _ui_text("job_presentation.collect_answers"),
        "judging": _ui_text("job_presentation.evaluate_answers"),
        "analysis": _ui_text("job_presentation.analyze_results"),
    }.get(activity_role(command))
