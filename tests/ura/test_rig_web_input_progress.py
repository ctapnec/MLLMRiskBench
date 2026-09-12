"""Loaded source-row coverage stays separate from output and judging totals."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app import workspace_local as subject
from experiments.rig_web_app.storage import ConsoleDB
from test_rig_web_local_publication import append, example


@pytest.mark.parametrize('model', ['ollama:example', 'vllm:example'])
def test_plan_is_visible_before_generation_and_resume_does_not_count_turns_as_inputs(tmp_path, model):
    db, campaign, manifest, dp, record, paths = example(tmp_path, model)
    second = SimpleNamespace(**{**vars(dp), 'id': 'question-2'})
    corpus = [dp, second]

    class Runner:
        def run(self, inputs, **options):
            assert inputs == corpus
            plan = db.workspace_input_totals(campaign)[0]
            assert (plan['planned'], plan['reached']) == (2, 0)
            assert db.workspace_model_totals(campaign) == []
            options['on_response'](record)
            # Another adaptive turn for the same input is another output, not another source row.
            followup = deepcopy(record)
            followup['attempt']['id'] = followup['response']['attempt_id'] = 'attempt-2'
            followup['attempt']['turn_index'] = 1
            followup['response']['output_turns'] = []
            followup['response']['raw']['model_stability_status'] = 'failed_output'
            options['on_response'](followup)
            assert db.workspace_input_totals(campaign)[0]['reached'] == 1
            return 'native result'

    result = subject.run_with_workspace_publication(Runner(), corpus, campaign_id=campaign,
        database=db.path, **paths, run_config=manifest['config']['run'],
        manifest=SimpleNamespace(model_dump=lambda **k: manifest),
        on_response=lambda row: append(paths['response_checkpoint'], row))
    assert result == 'native result' and db.workspace_model_totals(campaign)[0]['assigned'] == 2
    before = dict(db.workspace_input_totals(campaign)[0])
    contents = paths['response_checkpoint'].read_bytes()
    restored = subject.LocalCheckpointPublication(campaign_id=campaign, database=db.path,
        manifest=manifest, corpus=corpus, **paths)
    restored.accept(record, 'response', restored=True)
    restored.close()
    assert dict(db.workspace_input_totals(campaign)[0]) == before
    assert paths['response_checkpoint'].read_bytes() == contents
    assert db.workspace_judging_totals(campaign) == []
    db.close()


def test_input_publication_failure_does_not_cancel_target_and_remains_pending(tmp_path, monkeypatch):
    db, campaign, manifest, dp, record, paths = example(tmp_path, 'ollama:example')
    original = ConsoleDB.publish_workspace_inputs
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError('private failure details')
    monkeypatch.setattr(ConsoleDB, 'publish_workspace_inputs', unavailable)
    publisher = subject.LocalCheckpointPublication(campaign_id=campaign, database=db.path,
        manifest=manifest, corpus=[dp], **paths)
    append(paths['response_checkpoint'], record)
    publisher.accept(record, 'response')
    status = publisher.status_path.read_text()
    assert 'publication_pending' in status and 'private failure details' not in status
    assert db.workspace_model_totals(campaign)[0]['usable'] == 1
    monkeypatch.setattr(ConsoleDB, 'publish_workspace_inputs', original)
    publisher.flush()
    assert db.workspace_input_totals(campaign)[0]['reached'] == 1
    assert json.loads(publisher.status_path.read_text())['status'] == 'published'
    publisher.close()
    db.close()


def test_planned_overview_uses_sqlite_before_any_answer_and_filters_conditions(tmp_path, monkeypatch):
    app = RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state', repo_root=tmp_path)
    campaign = app.db.create_workspace('Local inputs', 'local')
    args = dict(run_id='one', model='vllm:example', condition_id='condition-one',
        evidence_class='measured', planned=10, reached=3)
    app.db.publish_workspace_inputs(campaign, **args)
    app.db.publish_workspace_inputs(campaign, **{**args, 'run_id':'two', 'condition_id':'condition-two', 'planned':5, 'reached':0})
    with pytest.raises(ValueError, match='separate run'):
        app.db.publish_workspace_inputs(campaign, **{**args, 'planned':11})
    with pytest.raises(ValueError, match='counts'):
        app.db.publish_workspace_inputs(campaign, **{**args, 'reached':11})
    assert app.db.workspace_result_models(campaign)[0]['model'] == 'vllm:example'
    totals = app.db.workspace_input_totals(campaign, model='vllm:example', condition='condition-two')[0]
    assert (totals['planned'], totals['reached'], totals['runs']) == (5, 0, 1)
    def no_files(*args, **kwargs):
        pytest.fail('Page rendering must not inspect corpus or result files')
    monkeypatch.setattr(Path, 'open', no_files)
    page = app._workspace_results(campaign, 'overview', {'model':'vllm:example', 'condition':'condition-two'})
    assert 'Native collection input coverage' in page and '<td>5</td><td>0</td><td>5</td>' in page
    assert 'every seed, adaptive turn' in page and 'unknown, not zero' in page
    app.close()
