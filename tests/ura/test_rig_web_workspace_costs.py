"""Per-output cost ownership and fast campaign pages with real ledger-shaped states."""
from pathlib import Path

import pytest

from experiments.rig_web import RigWebApp


@pytest.fixture
def app(tmp_path):
    result = RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state', repo_root=tmp_path)
    yield result
    result.close()


def owner(app, kind='api'):
    campaign = app.db.create_workspace(kind, kind)
    app.db.publish_workspace_results(campaign, assignments=[dict(assignment_id='a', model=kind+'-model',
        input_id='input', condition_id='condition', modality='text', framework='replay', corpus='corpus',
        response_id='answer', evidence_class='measured')], responses=[dict(response_id='answer', assignment_id='a',
        condition_id='condition', outcome='usable', truncated=False, source_ref='output.jsonl:1')], judgments=[])
    return campaign


def attempt(**extra):
    return dict(call_id='call', attempt_number=1, assignment_id='a', response_id='answer',
        provider='openai', model='model', role='target', state='settled', cost_microusd=12345,
        input_tokens=100, output_tokens=200, source_ref='budget/ledger.json', **extra)


def test_retries_and_copies_count_once_and_survive_reindex_and_reopen(app):
    campaign = owner(app)
    first = {**attempt(), 'state': 'unknown', 'cost_microusd': None, 'exposure_microusd': 30000,
             'input_tokens': None, 'output_tokens': None}
    second = {**attempt(), 'attempt_number': 2}
    app.db.publish_workspace_costs(campaign, [first, second])
    initial = dict(app.db.workspace_cost_totals(campaign)[0])
    app.db.publish_workspace_costs(campaign, [{**first, 'source_ref': 'copy/ledger.json'}, second])
    assert dict(app.db.workspace_cost_totals(campaign)[0]) == initial
    assert (initial['http_attempts'], initial['cost_microusd'], initial['unknown_attempts'],
            initial['exposure_microusd'], initial['input_tokens'], initial['input_unknown']) == (2, 12345, 1, 30000, 100, 1)
    assert app.db.reindex([], [])
    from experiments.rig_web_app.storage import ConsoleDB
    reopened = ConsoleDB(app.db.path)
    try:
        assert dict(reopened.workspace_cost_totals(campaign)[0]) == initial
    finally:
        reopened.close()


def test_shared_judging_costs_belong_to_each_output_not_both_campaigns(app):
    local, hosted = owner(app, 'local'), owner(app)
    judge = {**attempt(), 'provider': 'anthropic', 'model': 'haiku', 'role': 'judge'}
    app.db.publish_workspace_costs(local, [judge])
    app.db.publish_workspace_costs(hosted, [{**judge, 'call_id': 'different-output'}])
    assert app.db.workspace_cost_totals(local)[0]['http_attempts'] == 1
    assert app.db.workspace_cost_totals(hosted)[0]['http_attempts'] == 1
    with pytest.raises(ValueError, match='already belongs'):
        app.db.publish_workspace_costs(hosted, [judge])


def test_judge_needs_the_exact_output_and_publication_rolls_back(app):
    campaign = owner(app)
    with pytest.raises(ValueError, match='does not belong'):
        app.db.publish_workspace_costs(campaign, [attempt(), {**attempt(), 'call_id': 'judge',
            'role': 'judge', 'response_id': 'input'}])
    assert app.db.workspace_cost_totals(campaign) == []
    with pytest.raises(ValueError, match='judged output'):
        app.db.publish_workspace_costs(campaign, [{**attempt(), 'role': 'judge', 'response_id': None}])


def test_unknown_cost_is_not_zero_and_token_bounds_are_not_usage(app, monkeypatch):
    campaign = owner(app)
    app.db.publish_workspace_costs(campaign, [{**attempt(), 'state': 'bounded_unknown',
        'cost_microusd': None, 'exposure_microusd': 50000, 'input_tokens': None, 'output_tokens': None}])
    row = app.db.workspace_cost_totals(campaign)[0]
    assert row['cost_microusd'] is None and row['input_tokens'] is None
    def forbid(*args, **kwargs):
        pytest.fail('Campaign cost page scanned retained files')
    monkeypatch.setattr(Path, 'open', forbid)
    page = app._workspace_results(campaign, 'costs', {})
    assert '$0.050000' in page and '1 unknown' in page
    assert 'Reported tokens' in page and 'unknown' in page
    assert '$0.000000' not in page


def test_settlement_can_advance_but_never_lose_usage_or_rewrite_a_bill(app):
    campaign = owner(app)
    reserved = {**attempt(), 'state': 'reserved', 'cost_microusd': None,
                'input_tokens': None, 'output_tokens': None}
    app.db.publish_workspace_costs(campaign, [reserved])
    app.db.publish_workspace_costs(campaign, [attempt()])
    assert app.db.workspace_cost_totals(campaign)[0]['settled_attempts'] == 1
    for changed in [reserved, {**attempt(), 'cost_microusd': 3}, {**attempt(), 'input_tokens': None}]:
        with pytest.raises(ValueError):
            app.db.publish_workspace_costs(campaign, [changed])


def test_local_judge_work_is_not_fabricated_as_http_spending(app):
    campaign = owner(app)
    app.db.publish_workspace_costs(campaign, [{**attempt(), 'provider': 'local', 'model': 'guard',
        'role': 'judge', 'state': 'not_billed', 'cost_microusd': 0}])
    row = app.db.workspace_cost_totals(campaign)[0]
    assert row['http_attempts'] == 0 and row['local_evaluations'] == 1
    page = app.handle('GET', '/campaigns/'+campaign+'?section=costs')[2].decode()
    assert 'No API charge' in page and 'electricity and hardware costs are not estimated' in page


def test_cost_role_model_names_are_escaped_and_unknown_index_is_explicit(app):
    campaign = owner(app)
    assert 'not zero' in app._workspace_results(campaign, 'costs', {})
    app.db.publish_workspace_costs(campaign, [{**attempt(), 'model': '<img src=x onerror=alert(1)>'}])
    page = app._workspace_results(campaign, 'costs', {})
    assert '<img src=x' not in page and '&lt;img' in page
