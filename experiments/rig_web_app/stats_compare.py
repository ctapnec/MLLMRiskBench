"""Stats entry point for the existing exact-input comparison workflow."""
import html
from urllib.parse import urlencode

from .ui import _page


def response(app, query):
    if query.get('scope')=='jobs':
        from .stats_jobs import response as jobs
        return jobs(app,query)
    rows = app.db.workspaces()
    if rows is None:
        raise ValueError('Campaign index unavailable')
    ids = {r['campaign_id'] for r in rows}
    left, right = query.get('left', ''), query.get('right', '')
    if left or right:
        if left not in ids or right not in ids:
            raise ValueError('Choose two existing campaigns')
        params = dict(section='compare', right_campaign=right, left_model='*', right_model='*',
                      left_condition='*', right_condition='*')
        return 303, '/campaigns/'+left+'?'+urlencode(params), b''
    body = '<h1>Stats</h1>'+app._work_view_tabs('stats','compare')
    body += '<section class="card"><h2>Compare campaigns</h2><p><a href="/stats?view=compare&amp;scope=jobs">Compare individual measured jobs</a></p><p>Select two campaigns, or the same campaign twice to compare its models. '
    body += 'The next screen offers models, generation conditions and judging conditions, with matched-input coverage charts and paired outcome counts.</p>'
    body += '<form method="get" action="/stats"><input type="hidden" name="view" value="compare"><div class="campaign-grid">'
    for side in ('left','right'):
        body += '<label class="campaign-field">'+side.title()+' campaign<select name="'+side+'" aria-label="'+side.title()+' campaign" required><option value="">Choose a campaign</option>'
        body += ''.join('<option value="'+r['campaign_id']+'">'+html.escape(r['name'])+'</option>' for r in rows)
        body += '</select></label>'
    body += '</div><div class="action-row"><button>Open matched-input comparison</button></div></form>'
    body += '<p>Different models, generation conditions, source tasks and judging conditions remain separate. '
    body += 'No scores are pooled and no latest or best answer is silently selected. Standalone job reports remain under Standalone runs; '
    body += 'jobs without indexed input ownership cannot be matched merely by sharing a file name.</p></section>'
    return 200,'text/html; charset=utf-8',_page('Compare campaigns',body,active='Stats')
