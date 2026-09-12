"""Review saved-output Haiku comparisons in Build under their existing funding."""
from __future__ import annotations

from collections import Counter
from decimal import Decimal, InvalidOperation
import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.hosted_retained_inputs import _descriptor
from experiments.retained_response_judge_execute import _write_new
from experiments.retained_response_judge_pair import MAX_PAIR_LIMIT, MAX_COST_MICROUSD, validate_pair_plan

from .builder_collection import prepared_collection, collection_history
from .builder_native_judging import _state
from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


def _choices(app):
    registry=app._load_registry('api-targets.json','rig/api-targets.example.json')
    return sorted(key for key in registry if key.startswith('anthropic:claude-haiku-'))


def prepare_haiku_judging(app,params):
    owner=params.get('campaign_id','')
    receipt=prepared_collection(app,params)
    job=app.db.load_job(params.get('retained_native_judging_job'))
    if (job is None or job['command']!='retained_native_judge_prepare'
        or job['state'] not in {'complete','failed'} or job['exit_code'] not in {0,1}
        or app.db.workspace_for_job(job['job_id'])!=owner):
        raise ValueError('Select this campaign\'s completed saved-output preparation first')
    hosted=Path(argument(json.loads(job['argv']),'--out'))/'result.json'
    native=json.loads(hosted.read_text())
    if not native.get('units') or native.get('programs')!=receipt['programs']:
        # Receipt descriptors may also carry prepared request counts.
        actual=[(row['path'],row['sha256']) for row in native.get('programs',[])]
        expected=[(row['path'],row['sha256']) for row in receipt['programs']]
        if not native.get('units') or actual!=expected:
            raise ValueError('Saved outputs belong to a different collection')
    source=completed_argv(app,params.get('retained_sources_job'),owner,'retained_local_sources')
    forecast=completed_argv(app,params.get('retained_budget_job'),owner,'hosted_campaign_budget')
    model=params.get('retained_haiku_model','')
    if model not in _choices(app):
        raise ValueError('Choose a configured Haiku judge model')
    try:
        limit=int(params.get('retained_haiku_limit','100'))
        seed=int(params.get('retained_haiku_seed','0'))
        cost=Decimal(params.get('retained_haiku_cost','7'))*1_000_000
        if not cost.is_finite() or cost!=cost.to_integral_value():
            raise ValueError('Invalid cost')
        cap=int(cost)
    except (ValueError,InvalidOperation):
        raise ValueError('Use whole-number comparison/seed values and a USD ceiling with at most six decimal places') from None
    if not 1<=limit<=MAX_PAIR_LIMIT or not 1<=cap<=MAX_COST_MICROUSD:
        raise ValueError('Comparison count or judging ceiling is outside the supported range')
    conditions={(argument(unit['runner_argv'],'--source-conformance'),
        argument(unit['runner_argv'],'--source-conformance-sha256')) for unit in native['units']}
    if len(conditions)!=1:
        raise ValueError('These outputs use different source assessments; select their preparations separately')
    condition=next(iter(conditions))
    snapshot,_,_,configs=app._selected_api_config_snapshot(dict(mode='measured',api='',judges='llm',judge_model=model))
    if model not in configs or len(snapshot['routes'])!=1:
        raise ValueError('The selected judge needs an explicit API configuration')
    config=dict(configs[model],max_tokens=512)
    # Native output selection, not a freshly edited target draft, owns this work.
    values={'--local-runner-view':argument(source,'--out'),'--hosted-runner-view':str(hosted),
        '--source-receipt':condition[0],'--source-receipt-sha256':condition[1], '--judge-model':model,
        '--pricing-config':argument(forecast,'--pricing-config'),
        '--pricing-config-sha256':argument(forecast,'--pricing-config-sha256'),
        '--pricing-as-of':argument(forecast,'--pricing-as-of'), '--pair-limit':str(limit),
        '--sample-seed':str(seed),'--max-cost-microusd':str(cap),'--ack-hosted-judge-data-transfer':'on',
        '--shared-budget-root':str(Path(receipt['budget']['path']).parent),
        '--shared-budget-sha256':receipt['budget']['sha256']}
    for index,row in enumerate(receipt['programs']):
        suffix=f'#{index}' if index else ''
        values['--program'+suffix]=row['path']
        values['--program-sha256'+suffix]=row['sha256']
    with app._app_lock:
        previous=collection_history(app,owner,[str(hosted)],command='retained_response_judge_pair',
            input_flag='--hosted-runner-view')
        if previous is not None:
            saved=json.loads(previous['argv'])
            equivalent=all(argument(saved,flag)==value for flag,value in values.items() if '#' not in flag)
            api_path=Path(argument(saved,'--api-config'))
            equivalent=equivalent and json.loads(api_path.read_text())=={model:config}
            if equivalent and _state(app,previous) in {'running','queued','starting','complete'}:
                app._save_build_campaign(dict(params,retained_haiku_job=previous['job_id']))
                return SimpleNamespace(job_id=previous['job_id'])
            if _state(app,previous) in {'running','queued','starting'}:
                raise ValueError('This source selection already has an active Haiku preparation')
            prior_plan=argument(saved,'--out')
            if collection_history(app,owner,[prior_plan],command='retained_response_judge_pair_execute',input_flag='--plan'):
                raise ValueError('Resume the saved judging selection before preparing different comparisons')
        folder=(app.results_root/'rig-web'/'haiku-judging'/uuid4().hex).resolve()
        folder.mkdir(parents=True,mode=0o700)
        api_path=folder/'api-config.json'
        _write_new(api_path,{model:config})
        values.update({'--api-config':str(api_path),'--api-config-sha256':_descriptor(api_path)['sha256'],
            '--out':str(folder/'plan.json')})
        app._save_build_campaign(params)
        launched=app.start_job('retained_response_judge_pair',values,campaign_id=owner)
        app._save_build_campaign(dict(params,retained_haiku_job=launched.job_id))
        return launched


def haiku_judging_review(app,params):
    owner=params.get('campaign_id','')
    app.db.require_workspace(owner)
    argv=completed_argv(app,params.get('retained_haiku_job'),owner,'retained_response_judge_pair')
    plan_path=Path(argument(argv,'--out'))
    plan=validate_pair_plan(json.loads(plan_path.read_text()))
    requests=_descriptor(plan_path.with_suffix('.shared-requests.json'))
    values={flag:argument(argv,flag) for flag in ('--local-runner-view','--hosted-runner-view',
        '--source-receipt','--api-config','--pricing-config','--shared-budget-root','--shared-budget-sha256')}
    values.update({'--plan':str(plan_path),'--shared-requests':requests['path'],
        '--shared-requests-sha256':requests['sha256'],'--out':str(plan_path.parent/'judgments'),
        '--ack-paid-execution':'on','--retain-invalid-verdicts':'on'})
    matching=params.get('retained_source_campaign','')
    app.db.require_workspace(matching)
    if matching!=owner:
        values['--matching-workspace-id']=matching
    history=collection_history(app,owner,[str(plan_path)],command='retained_response_judge_pair_execute',input_flag='--plan')
    if history is not None:
        old=json.loads(history['argv'])
        values['--out']=argument(old,'--out')
        if ('--matching-workspace-id' in old) != ('--matching-workspace-id' in values) or (
            '--matching-workspace-id' in old and argument(old,'--matching-workspace-id')!=matching):
            raise ValueError('Keep the original matching campaign when resuming judgments')
    ticket=app._new_launch_ticket(dict(campaign_id=owner,values=json.dumps(values),
        previous_job=history['job_id'] if history is not None else ''),purpose='matched-haiku-judge')
    counts=Counter((row['cohort'],row['exact_model']) for row in plan['selected'])
    condition=plan['judge_condition']
    rows=''.join('<tr><td>'+html.escape(cohort)+'</td><td>'+html.escape(model)+f'</td><td>{count:,}</td></tr>'
        for (cohort,model),count in sorted(counts.items()))
    body='<h1>Review Haiku judging</h1>'+app._campaign_banner(owner)
    body+=(f"<p>{len(plan['pairs']):,} matched input comparisons; {len(plan['selected']):,} distinct saved answers. "
        'Each answer has its own verdict. A shared local answer is judged once within this selection. '
        'This is a selected comparison, not an assertion that every campaign answer is covered.</p>'
        '<p>Judge: '+html.escape(condition['model'])+f"; 512 output tokens per verdict; "
        f"USD {condition['max_cost_microusd']/1e6:,.6f} selection ceiling under the existing campaign allocation. "
        'This ceiling is not reported spending or an additional allocation. HTTP errors allow three retries; '
        'answers have no automatic retries. Invalid verdicts remain recorded. Saved judgments resume without target regeneration.</p>'
        '<p>Haiku receives the rendered prompt text and each target answer. Images are represented by their '
        'retained text proxy, not sent as image pixels. Missing outputs and excluded source tasks are not given invented verdicts. '
        'The prepared population and exclusions remain available in the plan artifact.</p>'
        "<div class='scroll'><table><tr><th>Population</th><th>Model</th><th>Answers</th></tr>"+rows+'</table></div>'
        "<details><summary>Exact command</summary><pre>"+html.escape(' '.join(build_argv('retained_response_judge_pair_execute',values)))
        +"</pre></details><form method='post' action='/build/judge-retained-haiku'>"
        "<input type='hidden' name='launch_ticket' value='"+html.escape(ticket,quote=True)+"'>"
        '<button type="submit">Start or resume Haiku judging</button></form>'
        +"<p><a href='/build?campaign_id="+owner+"'>Return to Build</a></p>")
    return _page('Review Haiku judging',body,active='Build')


def judge_retained_haiku(app,form):
    if set(form)!={'launch_ticket'}:
        raise ValueError('Review the prepared Haiku selection first')
    params=app._launch_ticket_params(form['launch_ticket'],purpose='matched-haiku-judge')
    if params is None:
        raise ValueError('Haiku review expired or was already used')
    values,owner=json.loads(params['values']),params['campaign_id']
    with app._app_lock:
        history=collection_history(app,owner,[values['--plan']],command='retained_response_judge_pair_execute',input_flag='--plan')
        if (history['job_id'] if history is not None else '')!=params['previous_job']:
            raise ValueError('This selection has a newer launch; open its saved job')
        if history is not None and _state(app,history) in {'running','queued','starting'}:
            raise ValueError('This Haiku selection is already active')
        return app.start_job('retained_response_judge_pair_execute',values,campaign_id=owner)


def haiku_judging_panel(app,params):
    if not params.get('retained_native_judging_job'):
        return ''
    choices=_choices(app)
    chosen=params.get('retained_haiku_model') or next(iter(choices),'')
    body=("<section class='card'><h2>Haiku comparison of saved outputs</h2>"
        '<p>Select input-matched local and hosted answers from the saved preparation above. Preparation '
        'makes no provider calls and uses the existing judging allocation. It does not regenerate targets.</p>'
        "<label class='campaign-field'>Haiku judge<select form='builder' name='retained_haiku_model'>"
        +''.join("<option value='"+html.escape(model,quote=True)+"'"+(' selected' if model==chosen else '')+'>'
            +html.escape(model)+'</option>' for model in choices)+'</select></label>')
    for name,label,default,maximum,step in (
        ('limit','Maximum matched comparisons','100',MAX_PAIR_LIMIT,'1'),
        ('seed','Selection seed','0',None,'1'),('cost','Judging ceiling (USD)','7',MAX_COST_MICROUSD/1e6,'0.000001')):
        body+="<label class='campaign-field'>"+label+"<input type='number' form='builder' name='retained_haiku_"+name+"' step='"+step+"'"+(
            " max='"+str(maximum)+"'" if maximum is not None else '')+" value='"+html.escape(params.get('retained_haiku_'+name,default),quote=True)+"'></label>"
    body+="<button form='builder' formaction='/build/prepare-haiku-judging'>Prepare matched Haiku selection</button>"
    job=params.get('retained_haiku_job','')
    if job:
        body+="<input type='hidden' form='builder' name='retained_haiku_job' value='"+html.escape(job,quote=True)+"'>"
        body+="<p><a href='/jobs/"+html.escape(job,quote=True)+"'>Open selection and exclusions</a></p>"
        body+="<button form='builder' formaction='/build/review-haiku-judging'>Review Haiku judging</button>"
    return body+'</section>'
