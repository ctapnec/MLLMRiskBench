"""Condition choices must communicate and enforce their campaign/model scope."""
from html.parser import HTMLParser
from urllib.parse import urlencode

import pytest

from test_workspace_comparison import study, put  # noqa: F401


class Selects(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.values, self.selected, self.name = {}, {}, None
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'select':
            self.name = attrs['name']
            self.values[self.name] = []
        elif tag == 'option' and self.name:
            value = attrs.get('value', '')
            if value:
                self.values[self.name].append(value)
            if 'selected' in attrs:
                self.selected[self.name] = value

    def handle_endtag(self, tag):
        if tag == 'select':
            self.name = None


@pytest.fixture
def scoped_study(study):
    app, left, right, query = study
    other = app.db.create_workspace('Different campaign', 'mixed')
    for owner in (left, right, other):
        for model in ('qwen', 'gemma'):
            # Same model and response identifiers in different campaigns, but
            # distinct conditions: an owner leak cannot hide behind the fixture.
            for modality in ('text', 'image'):
                aid = model + '-' + modality
                condition = owner + '-' + aid
                put(app, owner, aid, modality, model=model, condition=condition,
                    modality=modality, corpus=owner + '-source', judge=condition+'-judge',
                    context_tokens=16384 if modality == 'text' else 32768, output_allowance=4096)
            put(app, owner, model+'-probe', 'probe', model=model, condition=owner+'-'+model+'-probe', evidence='diagnostic')
    # The selected response condition, not its superseded assignment setting.
    response, verdict = put(app, right, 'replacement', 'recovered', model='qwen', condition='old',corpus='recovery-source')
    app.db.publish_workspace_results(right, assignments=[dict(assignment_id='replacement', model='qwen',
        input_id='recovered', condition_id='old', modality='text', framework='replay', corpus='recovery-source',
        response_id='replacement-new', evidence_class='measured')],
        responses=[dict(response,response_id='replacement-new',condition_id='recovered')],
        judgments=[dict(verdict,response_id='replacement-new')])
    return app, left, right, other


def expected_conditions(owner, model, right):
    return {owner+'-'+model+'-'+kind for kind in ('image','text')} | ({'recovered'} if owner==right and model=='qwen' else set())


@pytest.mark.parametrize('side', ['left','right'])
def test_condition_choices_are_measured_scoped_and_identifiable(scoped_study, side):
    app, left, right, other = scoped_study
    query = dict(right_campaign=right, left_model='qwen', right_model='qwen', section='compare')
    owner = left if side=='left' else right
    query[side+'_condition'] = owner+'-qwen-image'
    status, _, body = app.handle('GET', '/campaigns/'+left+'?'+urlencode(query))
    text = body.decode()
    assert status == 200
    fields = Selects(text)
    assert set(fields.values[side+'_condition']) == expected_conditions(owner, 'qwen', right)
    assert 'context 32,768; output allowance 4,096' in text
    assert 'context 16,384; output allowance 4,096' in text
    assert 'Condition 1: image;' in text
    assert "data-comparison-scope='"+side+"'" in text
    assert 'Only '+('Local' if side=='left' else 'API')+' / qwen:' in text
    assert 'Corpora: '+owner+'-source' in text
    assert 'Frameworks: replay' in text
    assert other+'-qwen' not in text
    assert owner+'-gemma-image' not in fields.values[side+'_condition']
    # Other result views retain their historical/diagnostic scope unchanged.
    assert owner+'-qwen-probe' in {r['condition_id'] for r in app.db.workspace_result_conditions(owner,model='qwen')}


@pytest.mark.parametrize('side', ['left','right'])
def test_stale_condition_or_all_marker_is_not_a_selected_condition(scoped_study, side):
    app, left, right, other = scoped_study
    owner = left if side=='left' else right
    for stale in ('*', other+'-qwen-text', owner+'-gemma-text', owner+'-qwen-probe', 'old'):
        query = dict(right_campaign=right, left_model='qwen', right_model='qwen', section='compare')
        query.update({side+'_condition':stale, side+'_judge':'judge'})
        status, _, body = app.handle('GET','/campaigns/'+left+'?'+urlencode(query))
        fields = Selects(body.decode())
        assert status==200 and side+'_condition' not in fields.selected and side+'_judge' not in fields.selected
        assert fields.values[side+'_judge']==[]
        assert 'data-comparison-results' not in body.decode().split('<script>')[0]


@pytest.mark.parametrize('side', ['left','right'])
def test_all_explains_campaign_scope_and_separate_conditions(scoped_study,side):
    app,left,right,_ = scoped_study
    query=dict(right_campaign=right,section='compare',**{side+'_model':'*'})
    status,_,body=app.handle('GET','/campaigns/'+left+'?'+urlencode(query))
    text=body.decode()
    assert status==200
    assert 'Only '+('Local' if side=='left' else 'API')+': all indexed models.' in text
    assert 'all measured conditions, compared separately' in text
    assert 'No latest/best response is chosen and scores are not pooled' in text
    assert 'Changing these controls starts no jobs' in text
