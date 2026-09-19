from urllib.parse import parse_qs, urlsplit

from test_operator_operations import app  # noqa: F401
from experiments.rig_web_app import stats_compare
from experiments.rig_web_app.workspace_comparison import coverage_chart


def test_stats_comparison_selects_campaigns_without_pooling_or_calls(app):
    left=app.db.create_workspace('Local','local');right=app.db.create_workspace('API','api')
    status,_,page=app.handle('GET','/stats?view=compare')
    assert status==200 and b'Open matched-input comparison' in page
    status,url,_=stats_compare.response(app,dict(left=left,right=right))
    assert status==303 and urlsplit(url).path=='/campaigns/'+left
    q=parse_qs(urlsplit(url).query)
    assert q['right_campaign']==[right] and q['left_condition']==['*'] and q['right_condition']==['*']
    assert not app.jobs


def test_coverage_chart_uses_input_union_not_only_successful_answers():
    chart=coverage_chart(dict(matched=4,left_only=2,right_only=3,ambiguous=1))
    assert '10 inputs' in chart and 'Matched: 4 (40.0%)' in chart
    assert 'Ambiguous: 1 (10.0%)' in chart and 'not model safety' in chart
    assert coverage_chart(dict(matched=0,left_only=0,right_only=0,ambiguous=0))==''
