import json
import pytest
from test_operator_operations import app  # noqa: F401
from experiments.rig_web_app import stats_jobs
from test_rig_web_busy_browser import browser  # noqa: F401


def seed(app):
    owner=app.db.create_workspace('Job comparison','local')
    for job in ('one','two'):
        directory=app.results_root/job
        with app.db._conn:
            app.db._conn.execute('INSERT INTO runs(job_id,kind,command,out_dir,state,created_at) VALUES(?,?,?,?,?,?)',
                (job,'measured','run_matrix',str(directory),'complete',1))
        app.db.attach_workspace_member(owner,'job',job,'collection')
        for index in range(2):
            identity=job+str(index)
            app.db.publish_workspace_results(owner,assignments=[dict(assignment_id=identity,
                model='test:'+job,input_id='input-'+str(index),condition_id='settings-'+job,
                modality='text',framework='replay',corpus='corpus',response_id=identity,evidence_class='measured')],
                responses=[dict(response_id=identity,assignment_id=identity,condition_id='settings-'+job,
                outcome='usable' if index==0 else 'missing',truncated=index==0,
                source_ref=str(directory/'saved.responses.jsonl')+':'+str(index+1),
                input_tokens=10 if index==0 else None,output_tokens=20 if index==0 else None)],judgments=[])
    return owner


def test_selected_jobs_use_indexed_output_ownership_and_keep_missing_and_tokens(app):
    seed(app)
    roster=stats_jobs.choices(app)
    rows={r['job_id']:stats_jobs.outputs(app,r,roster) for r in roster}
    assert {k:len(v) for k,v in rows.items()}=={'one':2,'two':2}
    assert {r['model'] for r in rows['one']}=={'test:one'}
    counts=stats_jobs.summarize(rows['one'])[0]
    assert counts['outputs']==2 and counts['usable']==counts['missing']==counts['truncated']==counts['usage_known']==1
    assert counts['input_tokens']==10 and counts['output_tokens']==20
    assert stats_jobs.overlap(rows['one'],rows['two'])==dict(matched=2,left_only=0,right_only=0,ambiguous=0)
    assert stats_jobs.overlap(rows['one']*2,rows['two'])['ambiguous']==2
    query=dict(view='compare',scope='jobs',left_job='one',right_job='two')
    code,mime,page=stats_jobs.response(app,query)
    assert code==200 and b'not full scheduled-input coverage' in page and b'Export these job statistics' in page
    assert page.count(b"aria-label='Job outcome composition'")==2
    code,mime,data=stats_jobs.response(app,dict(query,download='csv'))
    assert code==200 and mime.startswith('text/csv') and b'usage_known' in data
    assert len(data.decode('utf-8-sig').splitlines())==3
    assert not app.jobs


def test_job_outcome_plot_counts_missing_and_other_without_double_counting_truncation():
    import xml.etree.ElementTree as ET
    row=dict(side='left',model='model',condition_id='c',corpus='corpus',framework='replay',
        modality='text',outputs=10,usable=4,missing=3,policy=2,other=1,truncated=2)
    chart=stats_jobs.outcome_chart(row)
    svg=ET.fromstring(chart[chart.index('<svg'):chart.index('</svg>')+6])
    counts={r.attrib['data-category']:int(r.attrib['data-count']) for r in svg.findall('{http://www.w3.org/2000/svg}rect')}
    assert counts==dict(usable=4,missing=3,policy=2,other=1)
    assert sum(counts.values())==row['outputs']
    assert 'Truncation overlaps outcomes' in chart and 'not complete planned-input coverage' in chart
    assert stats_jobs.outcome_chart(dict(row,outputs=0))==''


def test_recovery_shared_directory_is_not_counted_as_two_independent_jobs(app):
    seed(app)
    with app.db._conn:
        app.db._conn.execute("UPDATE runs SET out_dir=? WHERE job_id='two'",(str(app.results_root/'one'),))
    roster=stats_jobs.choices(app)
    with pytest.raises(ValueError,match='shares an output history'):stats_jobs.outputs(app,roster[0],roster)


def test_same_prefix_directory_does_not_include_another_jobs_records(app):
    owner=seed(app)
    with app.db._conn:
        app.db._conn.execute("UPDATE campaign_responses SET details=? WHERE response_id='one0'",
            (json.dumps(dict(source_ref=str(app.results_root/'one-other'/'saved.responses.jsonl')+':1')),))
    roster=stats_jobs.choices(app);one=next(r for r in roster if r['job_id']=='one')
    assert [r['response_id'] for r in stats_jobs.outputs(app,one,roster)]==['one1']


def test_scope_cannot_include_diagnostics_or_unknown_jobs(app):
    seed(app)
    with app.db._conn:app.db._conn.execute("UPDATE runs SET kind='diagnostic_canary' WHERE job_id='two'")
    assert [r['job_id'] for r in stats_jobs.choices(app)]==['one']
    with pytest.raises(ValueError,match='indexed measured job'):
        stats_jobs.response(app,dict(left_job='two'))


@pytest.mark.parametrize('width',[390,1440])
def test_job_comparison_browser_selection_and_guarded_export(app,browser,width):
    from urllib.parse import urlsplit,parse_qs
    from experiments.rig_web_app import ui
    seed(app)
    page=browser.new_page(viewport=dict(width=width,height=1000),accept_downloads=True)
    errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
    def route(item):
        url=urlsplit(item.request.url)
        if url.path=='/static/style.css':return item.fulfill(status=200,content_type='text/css',body=ui._STYLE)
        if url.path=='/static/favicon.svg':return item.fulfill(status=204)
        query={k:v[-1] for k,v in parse_qs(url.query).items()}
        status,mime,body=stats_jobs.response(app,query)
        item.fulfill(status=status,content_type=mime,body=body)
    page.route('http://jobs.test/**',route)
    try:
        page.goto('http://jobs.test/stats?view=compare&scope=jobs')
        page.get_by_label('Left job').select_option('one')
        page.get_by_label('Right job').select_option('two')
        page.get_by_role('button',name='Compare job outputs',exact=True).click()
        page.get_by_role('heading',name='Input overlap',exact=True).wait_for()
        page.wait_for_function('!window.uraBusy.isBusy()')
        assert page.locator('body > nav').is_visible()
        assert page.get_by_role('img',name='Job outcome composition',exact=True).count()==2
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        with page.expect_download() as pending:
            page.get_by_role('link',name='Export these job statistics (CSV)',exact=True).click()
        assert pending.value.suggested_filename=='job-comparison.csv'
        page.wait_for_function('!window.uraBusy.isBusy()')
        assert page.locator('#campaign-export-status').inner_text()=='Export prepared.'
        assert not errors and not app.jobs
    finally:page.close()
