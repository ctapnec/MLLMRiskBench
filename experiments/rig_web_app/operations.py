"""One operator action over existing preparation jobs, never automatic generation."""
from __future__ import annotations

import hashlib
import html
import importlib
import json
import re
import threading
import time
from pathlib import Path
from uuid import uuid4

from .ui import _page


# These functions already own command construction and artifact semantics.
_STEPS = {
    'campaign': (),
    'attack-capture': (('Preparing attack material', 'operations', 'prepare_transport_check'),),
    'transport-check': (
        ('Waiting for your diagnostic probe', 'operations', 'prepare_transport_check'),
        ('Saving the connection check', 'operations', 'prepare_transport_check'),
    ),
    'matched': (
        ('Selecting saved inputs', 'builder_sources', 'prepare_selected_inputs'),
        ('Calculating workload and costs', 'builder_budget', 'prepare_budget'),
        ('Preparing selected inputs', 'builder_replays', 'prepare_replays'),
        ('Counting and preparing execution', 'builder_programs', 'prepare_programs'),
    ),
    'local-judging': (('Preparing saved answers', 'builder_native_judging', 'prepare_native_judging'),),
    'haiku-judging': (
        ('Preparing saved answers', 'builder_native_judging', 'prepare_native_judging'),
        ('Matching selected outputs', 'builder_judging_inventory', 'prepare_judging_inventory'),
        ('Calculating judging costs', 'builder_judging_inventory', 'prepare_inventory_judging'),
        ('Preparing judging execution', 'builder_inventory_execution', 'prepare'),
    ),
    'paired-haiku': (
        ('Preparing saved answers', 'builder_native_judging', 'prepare_native_judging'),
        ('Matching answers and calculating judging costs', 'builder_haiku_judging', 'prepare_haiku_judging'),
    ),
}
_DIRECT = ('Planning installed models', 'Preparing installed models', 'Checking the workload',
           'Preparing execution', 'Finishing model preparation')
_TITLES = {'direct': 'Prepare run', 'matched': 'Prepare hosted comparison', 'attack-capture':'Prepare attack material',
           'campaign': 'Campaign',
           'local-judging': 'Prepare local judging', 'haiku-judging': 'Prepare Haiku judging',
           'paired-haiku': 'Prepare sampled Haiku comparison', 'transport-check':'Finish diagnostic probe'}


def prepare_transport_check(app, params):
    owner, values, previous = app._transport_check_from_job(params['probe_job'], params.get('campaign_id', ''))
    if previous:
        return app.jobs[previous]
    return app.start_job('live_attestation', values, campaign_id=owner)


def operator_operations(operations, owner):
    """Show owned workflows, not their internal preparation/check handoffs."""
    children = {row.get('preparation') for row in operations.values()}
    for row in operations.values():
        for connection in row.get('connection_operations', []):
            children.update((connection.get('preparation'), connection.get('check')))
    return [row for row in operations.values()
            if row['params'].get('campaign_id', '') == owner and row['id'] not in children
            and not row.get('campaign_parent')]


def operation_contains_job(operations, operation_id, job_id, seen=None):
    """Follow saved ownership so guidance stays on the parent progress page."""
    seen = set() if seen is None else seen
    if operation_id in seen or operation_id not in operations:
        return False
    seen.add(operation_id)
    row = operations[operation_id]
    jobs = list(row.get('jobs', [])) + [row.get(key) for key in (
        'current_job', 'execution_job', 'collection_job', 'local_preparation',
        'local_execution', 'haiku_preparation', 'haiku_execution')]
    if job_id in jobs:
        return True
    children = [row.get('preparation')]
    for connection in row.get('connection_operations', []):
        children.extend((connection.get('preparation'), connection.get('check')))
    return any(operation_contains_job(operations, child, job_id, seen) for child in children)


class _Context:
    """Existing preparers update this operation, not a concurrently edited draft."""
    def __init__(self, app, operation):
        self.app, self.operation = app, operation

    def __getattr__(self, key):
        return getattr(self.app, key)

    def _save_build_campaign(self, params):
        self.operation['params'] = dict(params)
        self.app._save_operation(self.operation)
        return dict(params)

    def start_job(self, command, values, **kwargs):
        job_id = kwargs.get('reserved_job_id') or self.app._job_id_factory()
        kwargs['reserved_job_id'] = job_id
        self.operation['current_job'] = job_id
        self.operation['launch_pending'] = True
        self.app._save_operation(self.operation)
        return self.app.start_job(command, values, **kwargs)


class OperationsMixin:
    def _restore_operations(self):
        self._operations = {}
        self._operation_workers = {}
        self._operation_shutdown = threading.Event()
        base = self.state_dir.resolve() / '.private-operations'
        if base.is_dir():
            for path in base.glob('*/operation.json'):
                try:
                    raw = self._bounded_private_bytes(path, max_bytes=512 * 1024, label='operation')
                    value = json.loads(raw)
                    if (value['kind'] not in _TITLES or value['id'] != path.parent.name
                            or not re.fullmatch('[a-f0-9]{32}', value['id'])
                            or value['status'] not in {'preparing', 'ready', 'failed', 'stopped', 'complete'}
                            or not isinstance(value['params'], dict)
                            or not isinstance(value['jobs'], list)
                            or not isinstance(value['current_job'], str)
                            or not isinstance(value['signature'], str)
                            or type(value['step']) is not int
                            or not 0 <= value['step'] <= len(self._operation_labels(value))):
                        continue
                    self._operations[value['id']] = value
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        for value in self._operations.values():
            if value['status'] == 'preparing':
                self._ensure_operation_worker(value['id'])

    def _operation_root(self, operation):
        return self.state_dir.resolve() / '.private-operations' / operation['id']

    def _save_operation(self, operation):
        root = self._operation_root(operation)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._write_private_workflow_file(root / 'operation.json',
            (json.dumps(operation, sort_keys=True, ensure_ascii=False) + '\n').encode())

    def _operation_snapshot(self, operation):
        if not operation.get('snapshot_manifest'):
            return {}
        return self._workflow_execution_snapshot(dict(operation, root=self._operation_root(operation)))

    def _start_operation(self, kind, params, *, snapshot=None):
        if kind not in _TITLES:
            raise ValueError('Choose a supported operation')
        params = dict(params)
        if kind not in {'direct', 'transport-check', 'attack-capture'} and not params.get('campaign_id'):
            raise ValueError('Save the campaign before preparing this operation')
        # Exact frozen selection: a second click/review reopens existing work.
        identity = {key:value for key,value in params.items()
            if not (kind == 'matched' and key.startswith('retained_') and key.endswith('_job'))}
        signature = hashlib.sha256(json.dumps({'kind':kind, 'params':identity}, sort_keys=True).encode()).hexdigest()
        # Automatic output attempts and discovered connection receipts are
        # preparation results, not new operator selections. Compare original
        # choices as well as the exact frozen signature when reopening a
        # campaign. Manual paths/receipts remain significant; execution still
        # uses the original, unchanged snapshot, never these refreshed values.
        def selection(values):
            if kind != 'campaign' or values.get('setup_mode') != 'automatic':
                return values
            return {key:value for key,value in values.items()
                    if key != 'out' and not key.startswith(('att_path', 'att_sha'))}
        with self._app_lock:
            candidates = self._operations.values()
            if kind == 'campaign':
                # Historical duplicate preparations can precede completed work
                # in filesystem restore order. Never offer another Start just
                # because that unexecuted preparation was restored first.
                candidates = sorted(candidates, key=lambda row: (row['status'] != 'complete', row['created_at']))
            for operation in candidates:
                reusable = operation['status'] == 'preparing' or (
                    operation['status'] in {'ready', 'complete'} and kind in {'direct', 'matched', 'transport-check', 'campaign'})
                same_campaign = (kind == 'campaign' and operation['kind'] == kind
                    and selection(operation.get('original_params', operation['params'])) == selection(params))
                if (reusable and (operation['signature'] == signature or same_campaign)
                        and (kind != 'campaign' or self._campaign_configuration_matches(operation, params))):
                    return operation['id']
            operation = dict(id=uuid4().hex, kind=kind, params=params, signature=signature,
                status='preparing', step=0, current_job='', jobs=[], launch_pending=False, error='',
                created_at=time.time(), failed_jobs=[], snapshot_manifest={})
            operation['original_params'] = dict(params)
            if kind == 'transport-check':
                operation['current_job'] = params['probe_job']
            if kind == 'attack-capture':
                operation['current_job'] = params['capture_job']
                operation['original_params'] = {k:v for k,v in params.items() if k!='capture_job'}
            if kind == 'direct':
                operation['acquisition'] = self._builder_model_acquisition_required(params)
                self._reuse_direct_preparation(operation)
            root = self._operation_root(operation)
            root.mkdir(parents=True, mode=0o700)
            for name, payload in (snapshot or {}).items():
                name = self._workflow_component_name(name)
                self._write_private_workflow_file(root / ('snapshot-'+name+'.bin'), payload)
                operation['snapshot_manifest'][name] = dict(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
            self._operations[operation['id']] = operation
            self._save_operation(operation)
            self._ensure_operation_worker(operation['id'])
            return operation['id']

    def _campaign_configuration_matches(self, operation, params):
        """Do not mistake changed configured generation settings for a reopen.

        Compare the small retained configuration files, not model/corpus files.
        Reopening results requires no live model discovery or inference.
        """
        child = self._operations.get(operation.get('preparation'))
        if child is None:
            return True  # Preparation has not frozen configuration yet.
        try:
            if child['kind'] == 'matched':
                if not child['params'].get('retained_budget_job'):
                    return True
                from .builder_replays import prepared_sources
                prepared_sources(self, dict(child['params'], **params))
                return True
            manifest = child.get('snapshot_manifest', {})
            current = {}
            if 'api_config' in manifest:
                current['api_config'] = self._canonical_json_bytes(self._selected_api_config_snapshot(params)[3])
            if 'source_config' in manifest:
                current['source_config'] = self._canonical_json_bytes(self._selected_source_config_snapshot(params)[2])
            if 'local_config' in manifest:
                specs = self._split_list(params.get('local', ''))
                judge = params.get('judge_model', '')
                if judge.startswith(('vllm:', 'ollama:')) and judge not in specs:
                    specs.append(judge)
                current['local_config'] = self._selected_local_config_payload(specs,
                    default_quantization=params.get('quantization', ''),
                    quantization_overrides={k.removeprefix('quantization::'):v
                        for k,v in params.items() if k.startswith('quantization::')})
            return all(payload == self._bounded_private_bytes(
                self._operation_root(child)/('snapshot-'+name+'.bin'),
                max_bytes=1024*1024, label='retained campaign configuration')
                for name,payload in current.items())
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def _reuse_direct_preparation(self, operation):
        params = operation['params']
        projection, _ = self._read_lane_projection(params)
        if projection is None:
            return
        # A valid exact projection need not be recomputed. Empty positions
        # represent skipped technical stages, not invented jobs.
        operation.update(step=3 if operation['acquisition'] else 1,
            jobs=['', '', ''] if operation['acquisition'] else [])
        if not operation['acquisition']:
            return
        wanted = {k:v for k,v in self._durable_builder_params(params).items() if v}
        for workflow in self._model_acquisition_workflows.values():
            retained = {k:v for k,v in self._durable_builder_params(workflow['params']).items() if v}
            if (workflow['next_stage'] != 'run' or workflow.get('consumed')
                    or retained != wanted):
                continue
            job = self.jobs.get(workflow.get('acquisition_job_id'))
            if job is not None and job.state() == 'complete' and job.exit_code() == 0:
                operation.update(step=5, jobs=['','','',workflow['plan_job_id'],job.job_id])
                return

    def _ensure_operation_worker(self, operation_id):
        existing = self._operation_workers.get(operation_id)
        if existing is not None and existing.is_alive():
            return
        def work():
            while not self._operation_shutdown.is_set():
                with self._app_lock:
                    if self._operation_shutdown.is_set():
                        return
                    operation = self._operations[operation_id]
                    if operation['status'] != 'preparing':
                        return
                    try:
                        self._reconcile_locked()
                        self._advance_operation(operation)
                    except Exception as exc:
                        operation.update(status='failed', error='Preparation could not continue: '+str(exc)[:1200])
                        self._save_operation(operation)
                if self._operation_shutdown.wait(3):
                    return
        worker = threading.Thread(target=work, name='prepare-'+operation_id[:8], daemon=True)
        self._operation_workers[operation_id] = worker
        worker.start()

    @staticmethod
    def _operation_labels(operation):
        if operation['kind'] == 'campaign':
            return ('Preparing campaign', 'Collecting answers', 'Local assessment', 'Haiku assessment', 'Results ready')
        if operation['kind'] == 'direct':
            return _DIRECT if operation.get('acquisition') else ('Checking the workload',)
        return tuple(item[0] for item in _STEPS[operation['kind']])

    def _advance_operation(self, operation):
        if operation['status'] != 'preparing':
            return
        try:
            if operation['kind'] == 'campaign':
                from .campaign_flow import advance
                advance(self, operation)
                return
            if operation['current_job']:
                job = self.jobs.get(operation['current_job'])
                if job is None:
                    raise ValueError('Preparation was interrupted before its job was registered. No next job was started.')
                state = job.state()
                if state in {'running', 'queued', 'starting', 'retry_wait', 'retry_waiting'}:
                    return
                partial_native = (job.command == 'retained_native_judge_prepare'
                    and state == 'failed' and job.exit_code() == 1)
                if not partial_native and (state != 'complete' or job.exit_code() != 0):
                    if job.command == 'hosted_campaign_prepare' and 'whole source cluster for measurement' in (job.failure or ''):
                        raise ValueError('Choose saved source runs and a request cap covering at least two whole input clusters: '
                            'one for the connection check and another for measurement. No paid generation was started. '
                            'Change the selection in Build and prepare the comparison again; continuing the same selection cannot add inputs.')
                    raise ValueError(job.failure or 'The preparation job '+job.job_id+' ended as '+state+'.')
                operation['jobs'].append(job.job_id)
                operation['current_job'] = ''
                operation['launch_pending'] = False
                operation['step'] += 1
                self._save_operation(operation)
            length = len(self._operation_labels(operation))
            if operation['kind'] == 'direct' and operation['step'] == (3 if operation['acquisition'] else 1):
                self._resolve_operation_caps(operation)
                from .connection_workflow import advance
                if advance(self, operation):
                    return
                # A fresh transport binding may require an exact no-call
                # projection before the execution plan can use that binding.
                if operation.get('refresh_after_connections'):
                    operation.pop('refresh_after_connections')
                    operation.update(step=0, jobs=[])
                    self._save_operation(operation)
                    return
            if operation['step'] == length:
                if operation['kind'] == 'direct' and operation.get('execution_authorized'):
                    from .connection_workflow import launch
                    launch(self, operation)
                operation['status'] = 'ready'
                self._publish_operation_selection(operation)
                self._save_operation(operation)
                return
            if operation['kind'] == 'direct':
                job = self._launch_direct_preparation_step(operation)
            else:
                _, module, function = _STEPS[operation['kind']][operation['step']]
                preparer = getattr(importlib.import_module('.'+module, __package__), function)
                job = preparer(_Context(self, operation), dict(operation['params']))
            operation['current_job'] = job.job_id
            operation['launch_pending'] = False
            self._save_operation(operation)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            operation['status'] = 'failed'
            operation['error'] = str(exc)[:1500]
            self._save_operation(operation)

    def _publish_operation_selection(self, operation):
        """Update preparation pointers only if the operator has not edited the draft."""
        if operation['kind']=='attack-capture':
            from .prepared_inputs import capture_result
            operation['params'] = {k:v for k,v in operation['original_params'].items()}
            operation['params'].update(capture_result(self,self.jobs[operation['jobs'][0]]))
        owner = operation['params'].get('campaign_id')
        if owner and operation['kind'] != 'direct':
            saved = self.db.workspace_definition(owner)
            if saved == operation['original_params']:
                self.db.save_workspace_definition(owner, operation['params'])

    def _resolve_operation_caps(self, operation):
        params = operation['params']
        if params.get('automatic_caps') != 'on' or params.get('_caps_resolved') == 'yes':
            return
        projection, why = self._read_lane_projection(params)
        if projection is None:
            raise ValueError('Could not calculate execution limits: '+why)
        for field, key in (('cap_target','target_calls'), ('cap_judge','judge_calls'), ('cap_http','http_attempts')):
            params[field] = str(max(1, int(projection['call_projection'][key])))
        params['_caps_resolved'] = 'yes'
        self._save_operation(operation)

    def _launch_direct_preparation_step(self, operation):
        step = operation['step']
        if not operation['acquisition']:
            snapshot = self._operation_snapshot(operation)
            command, values, params = self._compose_from_builder(operation['params'], execution_snapshot=snapshot)
            try:
                attacker = self._materialize_prepared_attacker_config(params,
                    snapshot_payload=snapshot.get('attacker_config'), artifact_snapshots=snapshot)
                if attacker is not None:
                    values.update({'--attacker-config':str(attacker),
                        '--attacker-config-sha256':hashlib.sha256(attacker.read_bytes()).hexdigest()})
                preflight = self._builder_preflight_values(values, output=self._preflight_output_dir(params))
                return _Context(self, operation).start_job(command, preflight,
                    builder_params=params, execution_snapshot=snapshot)
            except BaseException:
                self._discard_unlaunched_local_config(values)
                raise
        if step in {0, 3}:
            next_stage = 'preflight' if step == 0 else 'run'
            params = dict(operation['params'], _model_acquisition_next=next_stage)
            reserved = self._job_id_factory()
            operation['current_job'] = reserved
            operation['launch_pending'] = True
            self._save_operation(operation)
            job = self._start_model_acquisition_plan(params,
                execution_snapshot=self._operation_snapshot(operation), reserved_job_id=reserved)
            return job
        if step in {1, 4}:
            plan_id = operation['jobs'][0 if step == 1 else 3]
            workflow = self._model_acquisition_workflows[plan_id]
            existing = workflow.get('acquisition_job_id')
            if existing and self.jobs[existing].state() not in {'failed', 'stopped', 'interrupted'}:
                return self.jobs[existing]
            reserved = self._job_id_factory()
            operation.update(current_job=reserved, launch_pending=True)
            self._save_operation(operation)
            return self._start_model_acquisition_download(plan_id, reserved_job_id=reserved)
        # The only automatic run is the no-call preflight. Generation is never
        # a background transition, including probe/canary execution.
        acquisition = operation['jobs'][1]
        if self._model_acquisition_workflows[acquisition]['next_stage'] != 'preflight':
            raise ValueError('Automatic preparation may only execute a no-call preflight')
        reserved = self._job_id_factory()
        operation['current_job'] = reserved
        operation['launch_pending'] = True
        self._save_operation(operation)
        return self._start_model_acquisition_run(acquisition, reserved_job_id=reserved)

    def _stop_operation(self, operation_id):
        with self._app_lock:
            operation = self._operations.get(operation_id)
            if operation is None or operation['status'] != 'preparing':
                raise ValueError('Only an active preparation can be stopped')
            if operation['kind'] == 'campaign':
                from .campaign_flow import stop
                stop(self, operation)
                return
            operation['status'] = 'stopped'
            self._save_operation(operation)  # Prevent the next handoff first.
            for item in operation.get('connection_operations', []):
                for key in ('preparation','check'):
                    child = self._operations.get(item.get(key))
                    if child and child['status'] == 'preparing':
                        self._stop_operation(child['id'])
            job = self.jobs.get(operation['current_job'])
            if job is not None and job.state() == 'running':
                self.stop_job(job.job_id)

    def _retry_operation(self, operation_id):
        with self._app_lock:
            operation = self._operations.get(operation_id)
            if operation is None or operation['status'] not in {'failed', 'stopped'}:
                raise ValueError('Only interrupted preparation can be continued')
            if operation['kind'] == 'campaign':
                from .campaign_flow import retry
                retry(self, operation)
                return
            job = self.jobs.get(operation['current_job'])
            if job is not None and job.state() in {'running', 'queued', 'starting', 'retry_wait', 'retry_waiting'}:
                raise ValueError('The previous preparation is still stopping. Wait for it to finish.')
            if job is None and operation['current_job']:
                # start_job records identity before spawning. A failure before
                # creating its directory is therefore safe to retry; retained
                # launch files require reconciliation, not a duplicate launch.
                if (self.state_dir / operation['current_job']).exists():
                    raise ValueError('The interrupted job has saved launch files. Reopen the console to restore its status before continuing.')
                operation.update(current_job='', launch_pending=False)
            if job is not None and job.state() != 'complete':
                if operation['kind'] in {'transport-check','attack-capture'} and operation['step'] == 0:
                    raise ValueError('The diagnostic probe did not complete. Open its saved job and recover the probe first; connection checking will not regenerate it.')
                # This can only re-enable a failed no-call preflight, never a
                # consumed target-generation workflow.
                if operation['kind'] == 'direct' and operation.get('acquisition') and operation['step'] == 2:
                    workflow = self._model_acquisition_workflows[operation['jobs'][1]]
                    if workflow['next_stage'] != 'preflight':
                        raise ValueError('Only a no-call preflight can be resumed automatically')
                    workflow['consumed'] = False
                    self._persist_model_acquisition_workflow(workflow)
                operation['failed_jobs'].append(job.job_id)
                operation['current_job'] = ''
            for item in operation.get('connection_operations', []):
                for key in ('preparation','check'):
                    child = self._operations.get(item.get(key))
                    if child and child['status'] in {'failed','stopped'}:
                        self._retry_operation(child['id'])
            operation.update(status='preparing', error='')
            self._save_operation(operation)
            # A failed worker may still be returning from its last cycle.
            # It exits only on the status check above; if live, it will resume.
            self._ensure_operation_worker(operation_id)

    def _operation_review(self, operation):
        params = dict(operation['params'])
        if operation.get('campaign_parent'):
            return _page('Campaign preparation ready','<h1>Preparation ready</h1><p>Collection and judging are controlled by your campaign.</p><a href="/operations/'+operation['campaign_parent']+'">Return to campaign progress</a>',active='Campaigns')
        if operation.get('execution_job'):
            return _page('Experiment started','<h1>Experiment started</h1>'+self._campaign_banner(params.get('campaign_id',''))+
                '<p>Connection checks are saved separately. Your measured job is available below.</p><p><a href="/jobs/'+html.escape(operation['execution_job'])+'">Open measured job and results</a></p>',active='Build')
        if operation.get('awaiting_connections'):
            from .connection_workflow import review
            return review(self, operation)
        if operation['kind']=='attack-capture':
            owner=params.get('campaign_id','')
            return _page('Attack material ready','<h1>Attack material ready</h1>'+self._campaign_banner(owner)+
                '<p>Your capture is saved. An unchanged campaign draft is updated automatically; otherwise '
                'choose this capture by name under Attacks. No file paths or checksums need copying.</p>'+
                '<p><a href="/build?campaign_id='+html.escape(owner)+'#prepared-workflows">Return to experiment</a></p>',active='Build')
        if operation['kind'] == 'transport-check':
            return _page('Probe finished', '<h1>Probe and connection check complete</h1>'
                +self._campaign_banner(params.get('campaign_id', ''))
                +'<p>The saved connection check will be selected automatically for matching measured work. '
                'No receipt needs copying.</p><p><a href="/jobs/'+operation['jobs'][0]+'">View the probe result</a></p>', active='Build')
        if operation['kind'] == 'direct':
            if not operation['acquisition']:
                command, values, params = self._compose_from_builder(params, execution_snapshot=self._operation_snapshot(operation))
                try:
                    return self._preview_page(command, values, params, prepared=True,
                        held_snapshot=self._operation_snapshot(operation))
                finally:
                    self._discard_unlaunched_local_config(values)
            acquisition = operation['jobs'][-1]
            workflow = self._model_acquisition_workflows[acquisition]
            ceilings, eligible = self._ceilings_card(workflow['params'])
            mode = params.get('mode', 'measured')
            label = {'attestation_probe':'Start probe', 'diagnostic_canary':'Start canary'}.get(mode, 'Start run')
            if workflow.get('consumed'):
                action = '<p>This prepared run has already been started. Its results remain in this campaign.</p>'
            elif eligible:
                ticket = self._new_launch_ticket({'acquisition_job_id':acquisition}, purpose='acquisition_run')
                action = ('<form class="action-row" method="post" action="/build/model-acquisition/run">'
                    '<input type="hidden" name="launch_ticket" value="'+html.escape(ticket)+'">'
                    '<button>'+label+'</button></form>')
            else:
                action = '<p class="notice amber">The workload exceeds the configured limits. Adjust the limits or selection in Build.</p>'
            experiment = '<section class="card"><h2>Your prepared run</h2><dl>'
            for name, key in [('Models','local'),('Hosted models','api'),('Inputs','corpora'),('Per-arm sample','limit'),('Evaluation','judges')]:
                if params.get(key):
                    experiment += '<dt>'+name+'</dt><dd>'+html.escape(params[key])+'</dd>'
            experiment += '</dl><p>Preparation is complete. Starting makes real model calls; hosted calls may incur charges.</p></section>'
            return _page('Review prepared run', '<h1>Review prepared run</h1>'
                +self._campaign_banner(params.get('campaign_id', ''))+experiment+ceilings+action, active='Build')
        module, function = {
            'matched': ('builder_collection', 'collection_review'),
            'local-judging': ('builder_native_judging', 'native_judging_review'),
            'haiku-judging': ('builder_inventory_execution', 'review'),
            'paired-haiku': ('builder_haiku_judging', 'haiku_judging_review'),
        }[operation['kind']]
        return getattr(importlib.import_module('.'+module, __package__), function)(self, params)

    def _operation_page(self, operation_id):
        operation = self._operations.get(operation_id)
        if operation is None:
            raise ValueError('This operation is unavailable')
        if operation['kind'] == 'campaign':
            from .campaign_flow import progress
            return progress(self, operation)
        if operation['status'] == 'ready':
            return self._operation_review(operation)
        escape = html.escape
        labels = self._operation_labels(operation)
        label = labels[min(operation['step'], len(labels)-1)]
        body = '<h1>'+escape(_TITLES[operation['kind']])+'</h1>'+self._campaign_banner(operation['params'].get('campaign_id', ''))
        body += '<section class="card"><h2>Preparing your selected work</h2><p>'
        body += ('Your explicitly started probe may make real calls. Its connection record is saved automatically afterwards.'
            if operation['kind'] == 'transport-check' else 'Your explicitly started attack capture may invoke its source model. The saved output is attached automatically.'
            if operation['kind'] == 'attack-capture' else
            'The reviewed connection checks and measured experiment run automatically; real model calls may be in progress.'
            if operation.get('execution_authorized') else
            'Preparation runs automatically. No target answers or judge decisions are generated.')
        body += ' You can leave this page and return.</p>'
        if operation['status'] == 'preparing':
            body += '<p role="status">Preparing your selected work...</p><form class="action-row" method="post" action="/operations/'+operation_id+'/stop"><button class="danger">Stop preparation</button></form>'
            body += '<script>setTimeout(()=>window.uraBusy.reload(),3000);</script>'
        else:
            body += '<p class="notice amber">'+escape(operation['error'] or 'Preparation stopped.')+'</p>'
            body += '<form class="action-row" method="post" action="/operations/'+operation_id+'/retry"><button>Continue preparation</button></form>'
            body += '<p>Completed stages and existing installed models are retained. If settings need changing, return to Build.</p>'
        body += '</section><details class="card"><summary>Technical job details</summary><p>'+escape(label)+'</p><ul>'
        for job_id in filter(None, operation.get('failed_jobs', [])+operation['jobs']+([operation['current_job']] if operation['current_job'] else [])):
            body += '<li><a href="/jobs/'+escape(job_id)+'">'+escape(job_id)+'</a></li>'
        return _page('Preparing work', body+'</ul></details>', active='Build')

    def _operation_links(self, owner):
        selected = sorted(operator_operations(self._operations, owner),
            key=lambda row:row.get('created_at', 0))
        if not selected:
            return ''
        body = '<section class="card"><h2>Prepared and active work</h2><ul>'
        for row in selected[-8:][::-1]:
            action = 'Review and start' if row['status'] == 'ready' else 'View progress' if row['status'] in {'preparing','complete'} else 'Inspect problem'
            body += '<li>'+html.escape(_TITLES[row['kind']])+' - '+html.escape(row['status'])+' - <a href="/operations/'+row['id']+'">'+action+'</a></li>'
        return body+'</ul></section>'

    def _finish_probe_automatically(self, job):
        if getattr(job, 'command', '') == 'run_matrix' and '--attestation-probe' in job.argv and '--preflight-only' not in job.argv:
            params = job.builder_params or {}
            return self._start_operation('transport-check', dict(probe_job=job.job_id,
                campaign_id=params.get('campaign_id', '')))
        return None
