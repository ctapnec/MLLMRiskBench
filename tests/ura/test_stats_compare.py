from urllib.parse import parse_qs, urlsplit

from test_operator_operations import app  # noqa: F401
from experiments.rig_web_app import stats_compare
from experiments.rig_web_app.workspace_comparison import coverage_chart
from experiments.rig_web_app.workspace_comparison import judgment_matrix, render_groups


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


def test_judgment_matrix_retains_paired_valid_denominator_and_missingness():
    import xml.etree.ElementTree as ET
    base = dict(match_status='matched', left_status='valid', right_status='valid',
                left_label='violation', right_label='refusal', count=2)
    rows = [base, dict(base, right_label='violation', count=3),
            dict(base, right_status='invalid', count=7),
            dict(base, left_label=None, count=1),
            dict(base, match_status='left_only', count=100),
            dict(base, match_status='ambiguous', count=100)]
    chart = judgment_matrix(rows)
    assert '5 jointly valid judgments out of 13 matched inputs' in chart
    assert '8 matched inputs lack two valid' in chart
    svg = ET.fromstring(chart[chart.index('<svg'):chart.index('</svg>') + 6])
    cells = {(g.attrib['data-left-label'], g.attrib['data-right-label']): int(g.attrib['data-count'])
             for g in svg.findall('{http://www.w3.org/2000/svg}g')}
    assert cells == {('violation', 'refusal'): 2, ('violation', 'violation'): 3}
    assert sum(cells.values()) == 5


def test_judgment_matrix_does_not_invent_zero_scores_and_escapes_labels():
    base = dict(match_status='matched', left_status='invalid', right_status='valid',
                left_label='violation', right_label='refusal', count=4)
    assert '<svg' not in judgment_matrix([base])
    assert '0 jointly valid judgments out of 4 matched inputs' in judgment_matrix([base])
    chart = judgment_matrix([dict(base, left_status='valid', left_label='<script>x</script>')])
    assert '<script>' not in chart and '&lt;script&gt;' in chart


def test_paired_results_render_matrix_beside_original_outcome_table():
    row = dict(corpus='xstest_full', framework='replay', modality='text',
               match_status='matched', left_status='valid', right_status='valid',
               left_label='violation', right_label='refusal', count=2,
               left_outcome='usable', right_outcome='usable', left_truncated=0, right_truncated=1)
    output = render_groups([row])
    assert "aria-label='Paired judging outcomes'" in output
    assert '<th>Left outcome</th>' in output and 'usable; truncated' in output
