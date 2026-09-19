"""Derive and execute missing diagnostics inside a reviewed experiment."""
import hashlib
import html

from .catalog import _ARM_CATALOG
from .ui import _page


def missing(app, params):
    if params.get('setup_mode') != 'automatic' or params.get('mode') != 'measured':
        return []
    receipts, _ = app._campaign_transport_receipts(params)
    covered = {(model, tuple(sorted(mods))) for r in receipts for model, mods in r['keys']}
    modalities = {arm: tuple(sorted(mods)) for arm, mods, _ in _ARM_CATALOG}
    needed = []
    for field in ('local','api'):
        for model in app._split_list(params.get(field,'')):
            for arm in app._split_list(params.get('corpora','')):
                if arm not in modalities:
                    raise ValueError('No diagnostic modality is recorded for '+arm)
                key = (model, modalities[arm])
                if key in covered:
                    continue
                covered.add(key)
                probe = {k:v for k,v in params.items() if not k.startswith(('_','att_path','att_sha','retained_','t3','hcap','harm_','ideator_','nanogcg_'))}
                probe.update(mode='attestation_probe', local=model if field=='local' else '',
                    api=model if field=='api' else '', corpora=arm, attackers='replay',
                    limit='1', seeds=app._split_list(params.get('seeds','0'))[0],
                    max_queries='1',max_turns='1',defense='none',defense_guard='rules',automatic_caps='on')
                for name in ('max_age','out','exclude_tool_conditioned','reset_open_circuits','local_budget_hours',
                             'defense_guardrail_model','defense_guardrail_revision','defense_guardrail_device'):
                    probe.pop(name,None)
                probe = app._automatic_campaign_setup(probe, refresh=True)
                probe = app._builder_params(probe)
                needed.append(probe)
    return needed


def advance(app, operation):
    """Return True while diagnostics still own the parent's progress page."""
    if operation.get('connections_complete'):
        return False
    if 'connection_operations' not in operation:
        requests = missing(app, operation['params'])
        if not requests:
            operation['connections_complete'] = True
            return False
        # Changing a live registry must not silently change a frozen experiment.
        _, current, _ = app._capture_execution_config_snapshot(operation['params'])
        if current != app._operation_snapshot(operation):
            raise ValueError('Experiment configuration changed. Review the updated experiment before preparing its checks.')
        operation['connection_operations'] = [dict(params=probe) for probe in requests]
        app._save_operation(operation)
    for item in operation['connection_operations']:
        if not item.get('preparation'):
            probe = item['params']
            errors = app._validate_builder(probe)
            if errors:
                raise ValueError('Automatic diagnostic needs a corrected experiment choice: '+ '; '.join(errors.values()))
            probe, snapshot, _ = app._capture_execution_config_snapshot(probe)
            probe = app._bind_execution_config_bundle_identity(probe)
            key = app._start_operation('direct',probe,snapshot=snapshot)
            item['preparation'] = key
            app._save_operation(operation)
            return True
        child = app._operations[item['preparation']]
        if child['status'] in {'failed','stopped'}:
            raise ValueError('A connection check needs attention: '+child.get('error','Preparation stopped'))
        if child['status'] != 'ready':
            return True
    if not operation.get('execution_authorized'):
        operation.update(status='ready', awaiting_connections=True)
        app._save_operation(operation)
        return True
    # Sequential local diagnostics do not compete for the same GPU memory.
    for item in operation['connection_operations']:
        child = app._operations[item['preparation']]
        if not item.get('probe'):
            job = launch(app, child)
            item['probe'] = job.job_id
            item['check'] = app._finish_probe_automatically(job)
            app._save_operation(operation)
            return True
        check = app._operations.get(item.get('check'))
        if check is None:
            # Recovery after launch publication but before connection handoff.
            check_id = app._finish_probe_automatically(app.jobs[item['probe']])
            item['check'] = check_id
            app._save_operation(operation)
            return True
        if check['status'] in {'failed','stopped'}:
            raise ValueError('Connection check failed. The saved probe is retained: '+item['probe']+'. '+check.get('error',''))
        if check['status'] != 'ready':
            return True
    params = dict(operation['params'])
    receipts, _ = app._campaign_transport_receipts(params)
    for key in list(params):
        if key.startswith(('att_path','att_sha')):
            del params[key]
    for i, receipt in enumerate(receipts,1):
        params['att_path'+str(i)] = receipt['path']
        params['att_sha'+str(i)] = receipt['sha256']
    # This reviewed transition adds freshly completed diagnostic evidence.
    # Rebind the combined identities, retaining every individual configuration
    # identity and checking all non-attestation bytes below.
    params.pop('_execution_snapshot_sha256',None)
    params.pop('_execution_config_bundle_sha256',None)
    rebound, snapshot, _ = app._capture_execution_config_snapshot(params)
    previous = app._operation_snapshot(operation)
    if {k:v for k,v in snapshot.items() if not k.startswith('live_attestation_')} != {k:v for k,v in previous.items() if not k.startswith('live_attestation_')}:
        raise ValueError('Experiment configuration changed during diagnostics. Review it again; completed checks are retained.')
    operation['snapshot_manifest'] = {}
    for name, payload in snapshot.items():
        app._write_private_workflow_file(app._operation_root(operation)/('snapshot-'+name+'.bin'),payload)
        operation['snapshot_manifest'][name] = dict(bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest())
    operation['params'] = app._bind_execution_config_bundle_identity(rebound)
    operation.update(connections_complete=True,awaiting_connections=False,refresh_after_connections=True)
    app._save_operation(operation)
    return False


def launch(app, operation):
    """Start once, retaining launch identity before creating the subprocess."""
    if operation.get('execution_job'):
        job = app.jobs.get(operation['execution_job'])
        if job is not None:
            return job
        if (app.state_dir/operation['execution_job']).exists():
            raise ValueError('The reviewed launch is awaiting job recovery; it will not be duplicated')
        # start_job persists its directory and identity before spawning. No
        # directory means the interruption preceded every possible model call.
        operation.pop('execution_job')
        app._save_operation(operation)
    params=operation['params']
    if app._validate_builder(params):
        raise ValueError('Prepared execution is no longer admissible. Reopen the experiment review.')
    _, eligible=app._ceilings_card(params)
    if not eligible:
        raise ValueError('The prepared workload does not fit its execution limits')
    job_id=app._job_id_factory()
    operation['execution_job']=job_id
    app._save_operation(operation)
    if operation['acquisition']:
        return app._start_model_acquisition_run(operation['jobs'][-1],reserved_job_id=job_id)
    snapshot=app._operation_snapshot(operation)
    command, values, params=app._compose_from_builder(params,execution_snapshot=snapshot)
    artifact=app._materialize_prepared_attacker_config(params,snapshot_payload=snapshot.get('attacker_config'),artifact_snapshots=snapshot)
    if artifact:
        values.update({'--attacker-config':str(artifact),'--attacker-config-sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()})
    return app.start_job(command,values,builder_params=params,execution_snapshot=snapshot,reserved_job_id=job_id)


def review(app, operation):
    body='<h1>Review experiment and required checks</h1>'+app._campaign_banner(operation['params'].get('campaign_id',''))
    body+='<p>One start runs the listed connection checks, saves their records, then executes your original measured experiment. Diagnostics remain separate from measured results. No model calls have been made by this preparation.</p>'
    card, eligible=app._ceilings_card(operation['params'])
    body+='<h2>Measured experiment</h2>'+card+'<h2>Additional connection checks</h2>'
    for item in operation['connection_operations']:
        child=app._operations[item['preparation']]
        p=child['params']
        body+='<h3>'+html.escape((p.get('local') or p.get('api'))+' / '+p['corpora'])+'</h3>'
        card, ready=app._ceilings_card(p)
        body+=card
        eligible &= ready
    ticket=app._new_launch_ticket(dict(operation=operation['id']),purpose='experiment-with-checks')
    body+='<form class="action-row" method="post" action="/operations/start-experiment"><input type="hidden" name="launch_ticket" value="'+ticket+'"><button'+('' if eligible else ' disabled')+'>Start experiment including connection checks</button></form>'
    return _page('Review experiment',body,active='Build')
