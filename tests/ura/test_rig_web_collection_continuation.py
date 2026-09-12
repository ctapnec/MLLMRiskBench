"""Collection continuation actions preserve all repeated program values."""
import html
import re
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.catalog import COMMANDS, build_argv
from experiments.rig_web_app.pages import PagesMixin
from test_rig_web_model_acquisition import _app


def test_collection_command_renders_repeat_controls_for_programs_and_digests(tmp_path):
    app = _app(tmp_path)
    try:
        page = app._command_card('hosted_campaign_execute')
        assert "data-repeat-flag='--program'" in page
        assert "data-repeat-flag='--program-sha256'" in page
        assert page.count('data-repeat-add') == 2
        assert "name='--resume-from'" in page
        document = app._commands_page().decode()
        assert 'var field=commandField(det,key);' in document
        assert "field.name=group.dataset.repeatFlag+(index?'#'+index:'');" in document
        assert 'while(group.querySelectorAll' in document
    finally:
        app.close()


def test_collection_action_preserves_all_programs_and_current_owner(tmp_path):
    values = {'--program': '/prepared/first.json', '--program#1': '/prepared/second.json',
        '--program-sha256': 'a' * 64, '--program-sha256#1': 'b' * 64,
        '--budget-root': '/prepared/money', '--budget-plan-sha256': 'c' * 64,
        '--project-root': '/project', '--expected-commit': 'd' * 40,
        '--out': '/collection/old', '--workers-per-provider': '2'}
    job = Job('original', 'hosted_campaign_execute', build_argv('hosted_campaign_execute', values),
        tmp_path, restored_state='failed')
    owner = SimpleNamespace(commands=COMMANDS,
        db=SimpleNamespace(workspace_for_job=lambda key: 'existing-campaign'))
    page = PagesMixin._collection_continuation_action(owner, job)
    assert 'Opening this form makes no calls' in page
    link = html.unescape(re.search("href='([^']+)'", page).group(1))
    query = parse_qs(urlsplit(link).query, keep_blank_values=True)
    assert query['campaign_id'] == ['existing-campaign']
    assert query['--resume-from'] == ['/collection/old']
    assert query['--out'] == ['']
    for key, value in values.items():
        if key != '--out':
            assert query[key] == [value]
    restored = {key: value[0] for key, value in query.items() if key.startswith('--')}
    restored['--out'] = '/collection/continued'
    argv = build_argv('hosted_campaign_execute', restored)
    assert argv.count('--program') == argv.count('--program-sha256') == 2
    assert '--resume-from' in argv
    app = _app(tmp_path)
    try:
        assert 'Review continuation' in app._job_page(job).decode()
        assert app.jobs == {}
    finally:
        app.close()
    job.restored_state = 'running'
    assert PagesMixin._collection_continuation_action(owner, job) == ''
    job.restored_state = 'unknown'
    assert PagesMixin._collection_continuation_action(owner, job) == ''
    job.command = 'run_matrix'
    assert PagesMixin._collection_continuation_action(owner, job) == ''


def test_unsupported_collection_argv_does_not_offer_a_misleading_action(tmp_path):
    job = Job('bad', 'hosted_campaign_execute', ['python', '-m', 'experiments.hosted_campaign_execute',
        '--unrecognized', 'value'], tmp_path, restored_state='failed')
    owner = SimpleNamespace(commands=COMMANDS)
    assert PagesMixin._collection_continuation_action(owner, job) == ''
