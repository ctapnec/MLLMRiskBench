"""Operator work categories based on the executed mode, not the command alone."""
from .artifacts import run_kind
from .workspace_store import activity_role


def substantive(command, argv):
    kind = run_kind(command, argv)
    if kind is not None:
        return kind in {'measured', 'diagnostic_canary'}
    if command == 'campaign_assess':
        return '--execute' in argv
    if command == 'response_svm':
        return any(flag in argv for flag in ('--study', '--evaluate', '--predict', '--package'))
    return activity_role(command) in {'collection', 'judging', 'analysis'}


def work_label(command, argv):
    if command == 'campaign_assess':
        return 'evaluate saved answers' if '--execute' in argv else 'assessment preparation'
    if command == 'response_svm':
        return 'SVM analysis' if substantive(command, argv) else 'analysis preparation'
    return {'collection':'collect answers', 'judging':'evaluate answers', 'analysis':'analyze results'}.get(activity_role(command))
