"""One campaign action over the existing preparation, collection and assessment jobs.

The operation is durable; it does not introduce another experiment executor.
No real calls occur before the operator starts the reviewed campaign.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import html
import json

from .ui import _page


ACTIVE = {'running', 'queued', 'starting', 'retry_wait', 'retry_waiting'}


def microusd(value):
    try:
        amount = Decimal(value) * 1_000_000
        if not amount.is_finite() or amount <= 0 or amount != amount.to_integral_value():
            raise ValueError()
        return int(amount)
    except (InvalidOperation, ValueError):
        raise ValueError('Enter a positive USD ceiling with at most six decimal places')


def settings(app, params):
    """Validate operator choices before starting even a preparation job."""
    params = dict(params)
    if params.get('campaign_local') == 'on' and not params.get('judge_model') and params.get('judges','') in {'','rules,llm'}:
        params['judges'] = 'rules,guardrail'
    if params.get('campaign_inputs', 'fresh') not in {'fresh', 'saved'}:
        raise ValueError('Choose installed corpora or saved local inputs')
    if params.get('mode') != 'measured':
        raise ValueError('Choose Measured execution for a campaign. Diagnostic runs remain available as single runs.')
    if params.get('api') or ('llm' in params.get('judges','').split(',') and params.get('judge_model') and not params['judge_model'].startswith(('vllm:','ollama:'))):
        microusd(params.get('campaign_collection_cost',''))
    if params.get('campaign_haiku') == 'on':
        from .builder_haiku_judging import _choices
        if params.get('campaign_judge_model') not in _choices(app):
            raise ValueError('Choose a configured Haiku evaluator')
        try:
            cost = Decimal(params.get('campaign_judge_cost', '')) * 1_000_000
            if not cost.is_finite() or cost <= 0 or cost != cost.to_integral_value():
                raise ValueError()
        except (InvalidOperation, ValueError):
            raise ValueError('Enter a positive Haiku assessment ceiling with at most six decimal places')
    if params.get('campaign_inputs', 'fresh') == 'saved':
        from .builder_sources import selected_runs, source_runs
        from .builder_budget import selected_routes
        selected_runs(params, source_runs(app.db, params.get('retained_source_campaign', '')))
        routes, _ = selected_routes(app, params)
        caps = json.loads(params.get('retained_budget_caps') or '{}')
        if not isinstance(caps, dict):
            raise ValueError('Request caps must describe the selected models')
        params['retained_budget_caps'] = json.dumps({route['spec']:caps.get(route['spec'],10) for route in routes})
        if params.get('local'):
            raise ValueError('Saved-input comparison uses hosted targets. The source models stay in the source campaign.')
        params.update(retained_network_counts='on', retained_pricing_date=datetime.now(timezone.utc).date().isoformat(),
                      judges='rules,guardrail', target_answer_retries='0')
        params['deadline'] = params.get('deadline') or '3600'
    return params


def panel(app, params):
    from .builder_haiku_judging import _choices
    escape = lambda value: html.escape(str(value), quote=True)
    saved = params.get('campaign_inputs') == 'saved'
    choices = _choices(app)
    judge = params.get('campaign_judge_model', choices[0] if choices else '')
    return (
        '<section class="card" id="campaign-workflow" data-campaign-only>'
        '<h2>Campaign workflow</h2><input form="builder" type="hidden" name="campaign_flow" value="on">'
        '<p>Choose inputs and evaluation here. Review campaign prepares the workload automatically; '
        'one Start campaign then runs collection, selected assessment and result publication. '
        'Reviewing unchanged choices reopens the existing work, including completed results. '
        'Create a new campaign for an intentional repeat of the same experiment.</p>'
        '<label class="campaign-field">Input selection<select form="builder" name="campaign_inputs">'
        '<option value="fresh"'+('' if saved else ' selected')+'>Installed corpora and attack frameworks</option>'
        '<option value="saved"'+(' selected' if saved else '')+'>Reuse saved local inputs for comparison</option></select></label>'
        '<p>For installed inputs, choose arms and attacks in Pipeline. For saved inputs, choose the source below. '
        'Both choices use the same Review campaign and Start campaign actions.</p>'
        '<label class="campaign-field">API collection ceiling (USD; leave empty for fully local collection)'
        '<input form="builder" name="campaign_collection_cost" type="number" min="0.000001" step="0.000001" value="'+
        escape(params.get('campaign_collection_cost',''))+'"></label>'
        '<p>Covers target calls, necessary diagnostics and inline hosted scoring. The independent Haiku assessment '
        'has its own ceiling below. Request counting may contact the selected provider without generating answers.</p>'
        '<fieldset class="campaign-assessment-options"><legend>Assessment after collection</legend>'
        '<label class="checkrow"><input form="builder" name="campaign_local" type="checkbox"'+
        (' checked' if params.get('campaign_local', 'on') == 'on' else '')+
        '><span>Fill missing original local-evaluator verdicts</span></label>'
        '<label class="checkrow"><input form="builder" name="campaign_haiku" type="checkbox"'+
        (' checked' if params.get('campaign_haiku') == 'on' else '')+
        '><span>Assess saved answers independently with Haiku</span></label>'
        '<div class="campaign-grid" data-campaign-haiku>'
        '<label class="campaign-field">Haiku evaluator<select form="builder" name="campaign_judge_model">'+
        ''.join('<option'+(' selected' if value == judge else '')+'>'+escape(value)+'</option>' for value in choices)+
        '</select></label><label class="campaign-field">Haiku assessment ceiling (USD)'
        '<input form="builder" name="campaign_judge_cost" type="number" min="0.000001" step="0.000001" value="'+
        escape(params.get('campaign_judge_cost', ''))+'"></label></div></fieldset>'
        '<p>Assessment uses saved measured answers in this campaign, including earlier pending answers. '
        'Existing valid verdicts are reused. Source-specific tasks and missing answers remain explicit exclusions. '
        'Haiku image assessment uses the saved text proxy, not image pixels.</p>'
        '<script>document.addEventListener("DOMContentLoaded",()=>{'
        'const mode=document.querySelector("[name=campaign_inputs]");'
        'const haiku=document.querySelector("[name=campaign_haiku]");'
        'const update=()=>{const campaign=document.querySelector("[name=work_kind]:checked")?.value==="campaign";'
        'document.querySelectorAll("[data-campaign-only]").forEach(e=>{e.hidden=!campaign;'
        'e.querySelectorAll("input,select").forEach(i=>i.disabled=!campaign);});'
        'document.querySelectorAll("[data-review-campaign]").forEach(e=>e.textContent=campaign?"Review campaign":"Compose & review");'
        'document.querySelectorAll("[data-saved-inputs]").forEach(e=>{'
        'e.hidden=!campaign||mode.value!=="saved";e.querySelectorAll("input,select,button").forEach(i=>i.disabled=e.hidden);});'
        'document.querySelectorAll("[data-campaign-haiku]").forEach(e=>{e.hidden=!haiku.checked;'
        'e.querySelectorAll("input,select").forEach(i=>i.disabled=e.hidden||!campaign);});};'
        'document.querySelectorAll("[name=work_kind]").forEach(e=>e.addEventListener("change",update));'
        'mode.addEventListener("change",update);haiku.addEventListener("change",update);update();});</script></section>'
    )


def _child(app, operation):
    return app._operations[operation['preparation']]


def advance(app, operation):
    if not operation.get('preparation'):
        params = dict(operation['params'])
        if 'guardrail' in params.get('judges','').split(','):
            from ura.guardrail_setup import resolve_scoring_settings
            params = resolve_scoring_settings(params)
        from .campaign_assessment import prepare_values
        for kind in ('local','haiku'):
            if params.get('campaign_'+kind) == 'on' and not operation.get(kind+'_values'):
                root = (app.results_root/'rig-web'/'campaign-assessment'/operation['id']/kind).resolve()
                operation[kind+'_values'] = prepare_values(app, params['campaign_id'], kind=kind,
                    judge=params.get('campaign_judge_model',''), cost=params.get('campaign_judge_cost',''), root=root)
                operation[kind+'_root'] = str(root)
                app._save_operation(operation)
        params['campaign_operation'] = operation['id']
        if params.get('campaign_inputs', 'fresh') == 'saved':
            kind, snapshot = 'matched', None
        else:
            errors = app._validate_builder(params, preparation=True)
            if errors:
                raise ValueError('; '.join(errors.values()))
            params, snapshot, _ = app._capture_execution_config_snapshot(params)
            params = app._bind_execution_config_bundle_identity(params)
            freeze_spending(app, operation, params)
            kind = 'direct'
        operation['preparation'] = app._start_operation(kind, params, snapshot=snapshot)
        child = _child(app, operation)
        child['campaign_parent'] = operation['id']
        app._save_operation(child)
        app._save_operation(operation)
        return
    child = _child(app, operation)
    if operation['step'] == 0:
        if child['status'] in {'failed', 'stopped'}:
            raise ValueError(child.get('error') or 'Preparation stopped')
        if child['status'] != 'ready':
            return
        if child['kind'] == 'matched':
            from .builder_collection import collection_launch_values
            _, rows, _, _ = collection_launch_values(app, child['params'])
            if sum(row[3] for row in rows)*4 > microusd(operation['params']['campaign_collection_cost']):
                raise ValueError('The selected API requests including three possible HTTP retries exceed your collection ceiling. '
                    'Reduce request caps or change the ceiling in Build and review again. No generations were started.')
        operation.update(status='ready')
        app._save_operation(operation)
        return
    if not operation.get('execution_authorized'):
        raise ValueError('Review and start the campaign before execution')
    if operation['step'] == 1:
        if child['kind'] == 'direct':
            if child.get('awaiting_connections'):
                child.update(execution_authorized=True, awaiting_connections=False, status='preparing')
                app._save_operation(child)
                app._ensure_operation_worker(child['id'])
                return
            if child['status'] in {'failed', 'stopped'}:
                raise ValueError(child.get('error') or 'Collection stopped')
            if child['status'] != 'ready':
                return
            if not child.get('execution_job'):
                from .connection_workflow import launch
                launch(app, child)
            operation['collection_job'] = child['execution_job']
        elif not operation.get('collection_job'):
            from .builder_collection import collection_launch_values
            values, _, _, _ = collection_launch_values(app, child['params'])
            operation['collection_values'] = values
            launch_job(app, operation, 'collection_job', 'hosted_campaign_execute', values)
        job = app.jobs.get(operation['collection_job'])
        require_complete(job, 'Collection')
        if job.state() in ACTIVE:
            return
        operation['step'] = 2
        app._save_operation(operation)
        return
    from pathlib import Path
    for step, kind in ((2, 'local'), (3, 'haiku')):
        if operation['step'] != step:
            continue
        params = operation['params']
        if params.get('campaign_'+kind) != 'on':
            operation['step'] += 1
            app._save_operation(operation)
            return
        key = kind+'_preparation'
        if not operation.get(key):
            launch_job(app, operation, key, 'campaign_assess', operation[kind+'_values'])
            return
        job = app.jobs.get(operation[key])
        require_complete(job, 'Assessment preparation')
        if job.state() in ACTIVE:
            return
        root = Path(operation[kind+'_root'])
        result = json.loads((root/'result.json').read_text())
        operation[kind+'_summary'] = result
        if result['status'] == 'over_budget':
            raise ValueError('Haiku assessment exceeds the reviewed ceiling. Collection is retained. '
                'Use Evaluate saved answers to choose a smaller assessment or a new ceiling; no judge calls were made.')
        if result['selected_outputs']:
            execution = kind+'_execution'
            if not operation.get(execution):
                launch_job(app, operation, execution, 'campaign_assess', {
                    '--execute':'on', '--database':str(app.db.path), '--out':str(root)})
                return
            job = app.jobs.get(operation[execution])
            require_complete(job, kind.capitalize()+' assessment')
            if job.state() in ACTIVE:
                return
        operation['step'] += 1
        app._save_operation(operation)
        return
    operation['status'] = 'complete'
    app._save_operation(operation)


def require_complete(job, label):
    if job is None:
        raise ValueError(label+' is awaiting job recovery; no duplicate will be launched')
    if job.state() not in ACTIVE and (job.state() != 'complete' or job.exit_code() != 0):
        raise ValueError(label+' needs attention. Saved work is retained. '+(job.failure or ''))


def launch_job(app, operation, key, command, values):
    job_id = app._job_id_factory()
    operation[key] = job_id
    app._save_operation(operation)
    return app.start_job(command, values, campaign_id=operation['params']['campaign_id'], reserved_job_id=job_id)


def review(app, operation):
    child = _child(app, operation)
    params = operation['params']
    body = '<h1>Review campaign</h1>'+app._campaign_banner(params['campaign_id'])
    body += '<section class="card"><h2>Collection and evaluation</h2><p>One start runs the required checks, '
    body += 'collects answers and completes the selected assessments. No calls have been made by preparation.</p>'
    body += '<p>Models: '+html.escape(', '.join(filter(None,(params.get('api'),params.get('local')))))+'</p>'
    eligible = True
    if child['kind'] == 'matched':
        from .builder_collection import collection_launch_values
        _, rows, _, _ = collection_launch_values(app, child['params'])
        body += '<div class="scroll"><table><tr><th>Model</th><th>Total requests</th><th>Measured</th><th>Diagnostic</th><th>Unclassified</th><th>Output allowance</th><th>First-attempt bound</th></tr>'
        body += ''.join('<tr><td>'+html.escape(model)+f'</td><td>{count}</td><td>{parts["measured"]}</td><td>{parts["diagnostic"]}</td><td>{parts["unclassified"]}</td><td>{tokens}</td><td>${cost/1e6:.4f}</td></tr>' for model,count,tokens,cost,parts in rows)+'</table></div>'
        body += '<p>Whole source clusters are retained. Diagnostic inputs remain separate from measured results. '
        body += 'Unclassified requests have missing or conflicting saved purposes; no measured count is inferred. '
        body += 'The prepared spending plan also covers eligible HTTP retries.</p>'
    else:
        card, eligible = app._ceilings_card(child['params'])
        body += card
        for item in child.get('connection_operations', []):
            probe = app._operations[item['preparation']]
            card, valid = app._ceilings_card(probe['params'])
            body += '<h3>Additional connection check</h3>'+card
            eligible &= valid
    body += '<ul><li>Local saved-answer assessment: '+('selected' if params.get('campaign_local') == 'on' else 'not selected')+'</li>'
    body += '<li>Independent Haiku assessment: '+(html.escape(params.get('campaign_judge_model',''))+'; maximum $'+html.escape(params.get('campaign_judge_cost','')) if params.get('campaign_haiku') == 'on' else 'not selected')+'</li></ul>'
    body += '<p>Assessment includes pending measured answers in this campaign. Existing valid verdicts are reused; '
    body += 'missing and ineligible answers remain reported. Haiku receives each selected prompt and its particular answer; images use text proxies. '
    body += 'If the assessment cannot fit the ceiling, collection stays saved and assessment pauses before spending.</p></section>'
    if params.get('campaign_collection_cost'):
        body += '<section class="card"><h2>API spending limits</h2><p>Collection allowance: $'+html.escape(params['campaign_collection_cost'])+'.</p>'
        body += '<p>Every Runner API attempt, including HTTP retries and required diagnostics, is covered by the reviewed allowance. '
        body += 'Request counts and configured prices guide admission; these are not a provider invoice. '
        body += 'Independent Haiku judging has the separate ceiling shown above. Conservative unused request allowances are not reported as charges.</p></section>'
    ticket = app._new_launch_ticket(dict(operation=operation['id']), purpose='campaign-start')
    body += '<form class="action-row" method="post" action="/operations/start-campaign"><input type="hidden" name="launch_ticket" value="'+ticket+'"><button'+('' if eligible else ' disabled')+'>Start campaign</button></form>'
    body += '<p><a href="/build?campaign_id='+params['campaign_id']+'">Change campaign settings</a></p>'
    return _page('Review campaign', body, active='Build')


def stop(app, operation):
    operation['status'] = 'stopped'
    app._save_operation(operation)
    child = app._operations.get(operation.get('preparation'))
    if child and child['status'] == 'preparing':
        app._stop_operation(child['id'])
    if child and child.get('execution_job'):
        # A child may have launched just before the parent's next poll.
        # Stopping in this handoff gap must still stop the measured process.
        operation['collection_job'] = child['execution_job']
        app._save_operation(operation)
    for key in ('collection_job', 'local_preparation', 'local_execution', 'haiku_preparation', 'haiku_execution'):
        job = app.jobs.get(operation.get(key))
        if job and job.state() in ACTIVE:
            app.stop_job(job.job_id)


def retry(app, operation):
    child = app._operations.get(operation.get('preparation'))
    stages = ('collection_job', 'local_preparation', 'local_execution', 'haiku_preparation', 'haiku_execution')
    pending = {operation.get(key) for key in stages}
    if child:
        pending.update((child.get('current_job'), child.get('execution_job')))
        for item in child.get('connection_operations', []):
            pending.add(item.get('probe'))
            for key in ('preparation', 'check'):
                nested = app._operations.get(item.get(key))
                if nested:
                    pending.update((nested.get('current_job'), nested.get('execution_job')))
    # Check every owned launch before changing any stage or restarting a worker.
    # The parent may not yet have published a diagnostic's durable launch id.
    for job_id in sorted(key for key in pending if key):
        job = app.jobs.get(job_id)
        if job and job.state() in ACTIVE:
            raise ValueError('The previous job is still active or stopping; wait before resuming')
        if job is None and (app.state_dir/job_id).exists():
            raise ValueError('Saved job files require console recovery before resuming')
    if child and child['kind'] == 'direct':
        for item in child.get('connection_operations', []):
            prepared = app._operations.get(item.get('preparation'))
            probe = app.jobs.get(item.get('probe') or (prepared or {}).get('execution_job'))
            if probe and probe.state() in {'failed','stopped','interrupted'}:
                if prepared is None:
                    raise ValueError('The saved diagnostic preparation is unavailable')
                prepared['resume_job'] = probe.job_id
                prepared.pop('execution_job',None)
                app._save_operation(prepared)
                # Keep the old diagnostic/check in history. Resume the same
                # output, then save its connection record normally.
                item.pop('probe',None)
                item.pop('check',None)
        app._save_operation(child)
    if child and child['status'] in {'failed', 'stopped'}:
        app._retry_operation(child['id'])
    # Successful stages are immutable. Failed execution needs its checkpoint
    # continuation, never a new campaign or a repeated completed collection.
    for key in stages:
        job_id = operation.get(key)
        if not job_id:
            continue
        job = app.jobs.get(job_id)
        if job and job.state() == 'complete' and job.exit_code() == 0:
            continue
        if key == 'collection_job' and child['kind'] == 'direct' and job is not None:
            child['resume_job'] = job_id
            child.pop('execution_job',None)
            app._save_operation(child)
        # A lost no-call preparation can restart at the same deterministic
        # output. Actual assessment execution always resumes that output.
        operation.pop(key, None)
    operation.update(status='preparing', error='')
    app._save_operation(operation)
    app._ensure_operation_worker(operation['id'])


def progress(app, operation):
    if operation['status'] == 'ready':
        return review(app, operation)
    owner = operation['params']['campaign_id']
    labels = ('Preparing campaign', 'Collecting answers', 'Local assessment', 'Haiku assessment', 'Results ready')
    body = '<h1>Campaign progress</h1>'+app._campaign_banner(owner)
    body += '<section class="card"><h2>'+labels[min(operation['step'],4)]+'</h2>'
    if operation['status'] == 'preparing':
        body += '<p role="status">Work continues automatically. You may leave this page and return.</p><form class="action-row" method="post" action="/operations/'+operation['id']+'/stop"><button class="danger">Stop campaign</button></form><script>setTimeout(()=>window.uraBusy.reload(),3000);</script>'
    elif operation['status'] == 'complete':
        body += '<p>Collection and selected assessment stages have finished. Coverage reports retain missing answers, exclusions and invalid verdicts.</p>'
    else:
        body += '<p class="notice amber">'+html.escape(operation.get('error') or 'Campaign stopped.')+'</p><form class="action-row" method="post" action="/operations/'+operation['id']+'/retry"><button>Resume campaign</button></form>'
        body += '<p><a href="/build?campaign_id='+owner+'#campaign-workflow">Change the reported campaign choice</a></p>'
    body += '<p><a href="/campaigns/'+owner+'?section=results">Results</a> | <a href="/campaigns/'+owner+'?section=judging">Judging</a> | <a href="/campaigns/'+owner+'?section=costs">Costs</a></p></section>'
    for kind in ('local', 'haiku'):
        summary = operation.get(kind+'_summary')
        if summary:
            body += '<section class="card"><h2>'+kind.capitalize()+' assessment coverage</h2><p>'+str(summary['selected_outputs'])+' selected answers.</p><ul>'
            body += ''.join('<li>'+html.escape(key.replace('_',' '))+': '+str(value)+'</li>' for key,value in summary['dispositions'].items())+'</ul></section>'
    body += '<details class="card"><summary>Technical jobs</summary><ul>'
    if operation.get('preparation'):
        body += '<li><a href="/operations/'+operation['preparation']+'">Preparation and connection details</a></li>'
    for key in ('collection_job', 'local_preparation', 'local_execution', 'haiku_preparation', 'haiku_execution'):
        if operation.get(key):
            body += '<li><a href="/jobs/'+operation[key]+'">'+html.escape(key.replace('_',' '))+'</a></li>'
    return _page('Campaign progress', body+'</ul></details>', active='Campaigns')


def freeze_spending(app, operation, params):
    from .reports import rate_for
    snapshot, _, _, configs = app._selected_api_config_snapshot(params)
    if not snapshot['routes']:
        return
    pricing = app._load_registry('pricing.json','rig/pricing.example.json')
    routes = []
    for row in snapshot['routes']:
        rate, why = rate_for(pricing, row['provider'], row['model'])
        if rate is None or rate.get('currency') != 'USD':
            raise ValueError('Configure USD pricing for '+row['requested_spec']+': '+why)
        rates = rate['per_million_tokens']
        for key in ('input','output'):
            value = Decimal(str(rates.get(key)))
            if not value.is_finite() or value < 0:
                raise ValueError('Complete nonnegative input/output prices are required')
        routes.append(dict(spec=row['requested_spec'],provider=row['provider'],model=row['model'],
                           config=configs.get(row['requested_spec']),input_price=rates['input'],output_price=rates['output']))
    root = (app.results_root/'rig-web'/'campaign-spending'/operation['id']).resolve()
    root.mkdir(parents=True,exist_ok=True)
    path = root/'policy.json'
    payload = dict(max_microusd=microusd(params.get('campaign_collection_cost','')),routes=routes)
    if path.exists() and json.loads(path.read_text()) != payload:
        raise ValueError('The prepared spending policy changed; review a new campaign operation')
    if not path.exists():
        app._write_private_workflow_file(path,(json.dumps(payload,sort_keys=True)+'\n').encode())
    operation['spending_policy'] = str(path)
    app._save_operation(operation)
