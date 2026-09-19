import time
import html
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from test_operator_operations import app  # noqa: F401
from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.job_presentation import substantive


@pytest.mark.parametrize('command,argv,expected', [
    ('run_matrix', ['--preflight-only'], False),
    ('run_matrix', ['--model-acquisition-plan-only','--preflight-only'], False),
    ('run_matrix', ['--attestation-probe'], False),
    ('run_matrix', [], True),
    ('run_matrix', ['--diagnostic-canary'], True),
    ('campaign_assess', ['--kind','haiku'], False),
    ('campaign_assess', ['--execute'], True),
    ('response_svm', ['--export'], False),
    ('response_svm', ['--study'], True),
    ('retained_native_judge_execute', [], True),
    ('hosted_retained_execute', [], True),
])
def test_substantive_work_uses_mode(command, argv, expected):
    assert substantive(command, argv) is expected


def test_work_view_retains_failures_and_links_to_hidden_technical_jobs(app):
    for name, command, argv in [('answers','run_matrix',[]), ('preparation','run_matrix',['--preflight-only']),
                                  ('svm','response_svm',['--study'])]:
        directory=app.state_dir/name;directory.mkdir(parents=True)
        app.jobs[name]=Job(job_id=name,command=command,argv=argv,directory=directory,process=None,
            restored_state='failed',restored_exit=1,started_at=time.time()-10)
    page=app._jobs_page(dict(view='work')).decode()
    assert "href='/jobs/answers'" in page and "href='/jobs/svm'" in page
    assert "href='/jobs/preparation'" not in page
    assert '1 technical stages' in page and '1 are active or need attention' in page
    assert 'SVM analysis' in page and 'Technical - all jobs' in page
    assert "href='/jobs?view=work&amp;state=passed#jobs-history'" in page
    all_jobs=app._jobs_page(dict(view='all')).decode()
    assert "href='/jobs/preparation'" in all_jobs


def test_job_count_navigation_preserves_selected_campaign_and_dates(app):
    owner=app.db.create_workspace('Selected campaign','local')
    page=app._jobs_page(dict(campaign_id=owner,view='work',from_ms='1',to_ms=str(int(time.time()*1000)))).decode()
    links=[parse_qs(urlsplit(html.unescape(link)).query) for link in re.findall("href='([^']+)'",page)]
    cards=[q for q in links if q.get('state')==['passed']]
    assert cards and cards[0]['campaign_id']==[owner] and cards[0]['from_ms']==['1'] and cards[0]['view']==['work']
    assert 'Open technical jobs' in page
    assert any(q.get('view')==['all'] and q.get('campaign_id')==[owner] for q in links)
