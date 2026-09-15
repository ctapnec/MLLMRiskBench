"""Real-shaped local judging configurations must not look interchangeable."""
from pathlib import Path

import pytest

from experiments.rig_web_app.workspace_judge_settings import indexed_settings, judge_name, local_settings
from test_workspace_comparison import study, put  # noqa: F401


def settings(guard=False, approximate=False):
    return local_settings(run=dict(judge_names=['rules', 'guardrail'] if guard else ['rules'],
        guardrail_model='meta-llama/Llama-Guard-3-8B' if guard else None,
        guardrail_revision='a'*40 if guard else None, approximate_common_metrics=approximate))


@pytest.fixture
def judge_scope(study):
    app, left, right, query = study
    haiku = 'anthropic:claude-haiku-4-5-20251001:'+'b'*24
    for owner, model, names in [(left,'flash', [('local-cascade-left',settings(True)),(haiku,None)]),
        (right,'qwen',[('local-cascade-rules',settings()),('local-cascade-guard',settings(True,True)),(haiku,None)])]:
        for number, (identity, metadata) in enumerate(names):
            _, row = put(app,owner,model+str(number),'shared',model=model,condition='same',judge=identity)
            if metadata:
                app.db.publish_workspace_results(owner,assignments=[],responses=[],judgments=[dict(row,judge_settings=metadata)])
    # An unrelated model's judge must never leak into the selected Qwen scope.
    put(app,right,'other','other',model='other',condition='same',judge='local-cascade-unrelated')
    query.update(left_model='*',right_model='qwen',left_condition='__best_response__',right_condition='__best_response__',
        left_judge='local-cascade-left',right_judge='local-cascade-rules')
    return app,left,right,query


def test_labels_distinguish_settings_and_do_not_guess():
    assert judge_name('local-cascade-x',settings()) == 'Rules only; approximate metrics off'
    assert judge_name('local-cascade-x',settings(True,True)) == 'Rules + Llama-Guard-3-8B; approximate metrics on'
    assert judge_name('local-cascade-x',settings(True)) == 'Rules + Llama-Guard-3-8B; approximate metrics off'
    assert judge_name('local-cascade-x') == 'Local judge (settings not indexed)'
    assert 'not recorded' in judge_name('local-cascade-x',local_settings(run=dict(judge_names=['rules'])))


def test_persisted_settings_do_not_change_verdicts_or_reopen_files(judge_scope,monkeypatch):
    from experiments.rig_web_app.workspace_comparison import _comparison_body
    app,left,right,query=judge_scope
    before=[tuple(r) for r in app.db._query('SELECT * FROM campaign_judgments',())]
    def forbidden(*args,**kwargs):
        raise AssertionError('Compare must use the index, not artifacts')
    monkeypatch.setattr(Path,'read_text',forbidden)
    page=_comparison_body(app.db,left,query)
    assert 'Rules only; approximate metrics off' in page
    assert 'Rules + Llama-Guard-3-8B; approximate metrics on' in page
    assert 'Rules + Llama-Guard-3-8B; approximate metrics off' in page
    assert 'No model-backed judge is used' in page
    assert "data-judge-settings='left'" in page and "data-judge-settings='right'" in page
    assert 'local-cascade-unrelated' not in page
    assert before == [tuple(r) for r in app.db._query('SELECT * FROM campaign_judgments',())]


def test_conflicting_metadata_rolls_back_without_relabeling(judge_scope):
    app,left,right,query=judge_scope
    row=dict(app.db._query('SELECT * FROM campaign_judgments WHERE campaign_id=? AND judge_id=?',
        (right,'local-cascade-rules'))[0])
    with pytest.raises(ValueError,match='Retained judging settings changed'):
        app.db.publish_workspace_results(right,assignments=[],responses=[],judgments=[dict(row,judge_settings=settings(True))])
    assert indexed_settings(app.db,right)['local-cascade-rules']==settings()
    assert app.db._query('SELECT label FROM campaign_judgments WHERE campaign_id=? AND judge_id=?',
        (right,'local-cascade-rules'))[0]['label']=='safe'


def test_native_metadata_keeps_models_allowance_and_metrics():
    source=dict(judge_cascade=dict(stages=[dict(name='rules',escalate_below=.75),
        dict(name='guardrail',model_id='meta-llama/Llama-Guard-3-8B',max_new_tokens=20,
             revision='a'*40,escalate_below=.75)]),approximate_common_metrics=False)
    value=local_settings(source=source,revision='b'*40)
    assert value['stages']==source['judge_cascade']['stages']
    assert value['approximate_common_metrics'] is False
    assert value['scoring_revision']=='b'*40
