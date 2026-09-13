"""Read indexed campaign answers for human review without replaying a Runner grid.

The SQLite snapshot selects outputs; their retained artifacts supply the text
and source context. Post-hoc judgments remain output-specific and are never
represented as a successful original generation grid or pooled across judges.
This reader makes no calls, reconstructs no corpus, and changes no source file.
"""
from collections import Counter, defaultdict
import json
from pathlib import Path
import sqlite3

from experiments import human_audit as audit


def _location(reference, root):
    path, separator, number = reference.rpartition(':')
    if not separator or not number.isdigit():
        path, number = reference, None
    else:
        number = int(number)
        if number < 1:
            raise ValueError('Retained row numbers start at one')
    path = Path(path)
    if not path.is_absolute():
        path = root/path
    path = path.resolve(strict=True)
    if not path.is_file() or not path.is_relative_to(root):
        raise ValueError('Review source is outside the campaign results store')
    return path, number


def _records(references, root):
    """Read each selected file once, stopping at its final requested line."""
    wanted = defaultdict(dict)
    for reference in references:
        path, number = _location(reference, root)
        wanted[path][number] = None
    result = {}
    for path, lines in wanted.items():
        if None in lines:
            if len(lines) != 1:
                raise ValueError('Conflicting JSON and JSONL source references')
            lines[None] = json.loads(path.read_text(encoding='utf-8'))
        else:
            last = max(lines)
            with path.open(encoding='utf-8') as stream:
                for number, line in enumerate(stream, 1):
                    if number in lines:
                        lines[number] = json.loads(line)
                    if number >= last:
                        break
            if any(value is None for value in lines.values()):
                raise ValueError('An indexed retained row is unavailable')
        result.update({(path, number): value for number, value in lines.items()})
    return result


def read_campaign(database: Path, campaign: str, results_root: Path) -> dict:
    root = results_root.resolve(strict=True)
    connection = sqlite3.connect(database.resolve().as_uri()+'?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('BEGIN')
    try:
        owner = connection.execute('SELECT name FROM campaigns WHERE campaign_id=?', (campaign,)).fetchone()
        if owner is None:
            raise ValueError('Unknown review campaign')
        assignments = [dict(row) for row in connection.execute(
            'SELECT a.*,r.outcome,r.truncated,r.details FROM campaign_assignments a '
            'LEFT JOIN campaign_responses r ON r.campaign_id=a.campaign_id '
            'AND r.assignment_id=a.assignment_id AND r.response_id=a.response_id '
            "WHERE a.campaign_id=? AND a.evidence_class='measured' ORDER BY a.assignment_id", (campaign,))]
        # The assignment index is keyed by assignment, not response. Joining
        # every judgment to it makes historical campaigns quadratic in size.
        # The snapshot's selected-response map below performs the exact join.
        judgments = [dict(row) for row in connection.execute(
            'SELECT * FROM campaign_judgments WHERE campaign_id=? ORDER BY response_id,judge_id', (campaign,))]
    finally:
        connection.close()
    dispositions = Counter(row['outcome'] or 'unstarted' for row in assignments)
    selected = {row['response_id']:row for row in assignments if row['outcome']=='usable'}
    if len(selected) != sum(row['outcome']=='usable' for row in assignments):
        raise ValueError('A selected response belongs to multiple assignments')
    judges = defaultdict(list)
    for row in judgments:
        if row['response_id'] in selected:
            judges[row['response_id']].append(row)
    references = {json.loads(row['details'])['source_ref'] for row in selected.values()}
    references.update(row['source_ref'] for group in judges.values() for row in group)
    records = _records(references, root)
    def record(reference):
        return records[_location(reference, root)]
    attempts_by_file = {}
    manifests = {}
    outputs, unavailable = [], []
    for identity, assignment in selected.items():
        details = json.loads(assignment['details']); reference = details['source_ref']
        saved = record(reference); response = saved.get('response', saved)
        if identity != response['run_id']+':'+response['attempt_id'] or response['target']!=assignment['model']:
            raise ValueError('Indexed response differs from its retained identity')
        attempt = saved.get('attempt')
        path = _location(reference, root)[0]
        if attempt is None:
            if not path.name.endswith('.responses.jsonl'):
                raise ValueError('Response source has no retained input')
            attempts_path = path.with_name(path.name.removesuffix('.responses.jsonl')+'.attempts.jsonl')
            if attempts_path not in attempts_by_file:
                with attempts_path.open(encoding='utf-8') as stream:
                    rows = [json.loads(line) for line in stream if line.strip()]
                attempts_by_file[attempts_path] = {(r['run_id'],r['id']):r for r in rows}
                if len(attempts_by_file[attempts_path])!=len(rows):
                    raise ValueError('Retained input identities are duplicated')
            attempt = attempts_by_file[attempts_path][(response['run_id'],response['attempt_id'])]
        if (attempt['run_id'],attempt['id'],attempt['target']) != (response['run_id'],response['attempt_id'],response['target']):
            raise ValueError('Saved input and answer do not match')
        attached, contexts = {}, []
        for item in judges[identity]:
            value = record(item['source_ref']); judgment = value.get('judgment',value)
            if 'response' in value and value['response']!=response:
                raise ValueError('Post-hoc verdict refers to a different saved answer')
            if item['status']=='valid':
                # Hosted post-hoc verdicts retain their generation identity in
                # the wrapper's sample key; the judge itself has no run_id.
                same_run = judgment.get('run_id') == response['run_id'] or (
                    judgment.get('run_id') is None and value.get('sample_key') == audit._record_key(response))
                if not same_run or judgment.get('attempt_id') != response['attempt_id']:
                    raise ValueError('Judgment changed its output identity')
            raw = judgment.get('raw',{})
            if raw.get('source') and raw.get('risk_category'):
                contexts.append(raw)
            attached[item['judge_id']] = dict(status=item['status'], label=item['label'], source_ref=item['source_ref'])
            if item['status']=='valid' and item['label']!=judgment.get('label'):
                raise ValueError('Indexed judgment label differs from its artifact')
        params = attempt['params']; origin=params.get('retained_origin',{}).get('selection',{})
        context = contexts[0] if contexts else {}
        source = params.get('planning_source',origin.get('source',context.get('source')))
        risk = origin.get('risk',context.get('risk_category'))
        expected = params.get('planning_expected_behavior',origin.get('expected_behavior',context.get('expected_behavior')))
        eligible = params.get('planning_common_metrics_eligible',context.get('common_metrics_eligible'))
        evaluable = params.get('policy_evaluable_turn')
        if not source or not risk or expected not in {'refuse','safe_answer','comply_safely'} or type(eligible) is not bool or type(evaluable) is not bool:
            unavailable.append(dict(response_id=identity,reason='source_context_unavailable',source_ref=reference))
            continue
        # Setup turns deliberately have a different turn-level expectation
        # from the corpus's challenge. They are not safety-audit endpoints.
        if not evaluable:
            unavailable.append(dict(response_id=identity,reason='non_evaluable_setup_turn',source_ref=reference))
            continue
        expected = params.get('turn_expected_behavior', expected)
        for other in contexts:
            if (other['source'],other['risk_category'],other.get('expected_behavior')) != (source,risk,expected):
                raise ValueError('Saved judging contexts disagree about the original input')
        visible = audit._dialog_text(response['output_turns'])
        if not any(isinstance(turn.get('content'),str) and turn['content'].strip()
                   for turn in response['output_turns']):
            unavailable.append(dict(response_id=identity,reason='no_visible_response',source_ref=reference))
            continue
        policy = params.get('planning_source_policy',params.get('source_policy'))
        policy_id = policy['policy_id'] if policy else 'unversioned'
        stem=path.name.removesuffix('.responses.checkpoint.jsonl').removesuffix('.responses.jsonl')
        manifest_path=path.with_name(stem+'.manifest.json')
        if manifest_path not in manifests:
            manifests[manifest_path]=json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        run=manifests[manifest_path].get('config',{}).get('run',{})
        meta=dict(run_id=response['run_id'],attempt_id=response['attempt_id'],model=assignment['model'],
            model_spec=assignment['model'],corpus=assignment['corpus'],attacker=assignment['framework'],
            defense=run.get('defense','not_recorded'),generation_condition=assignment['condition_id'],
            source=source,risk_category=risk,expected_behavior=expected,common_metrics_eligible=eligible,
            source_policy_id=policy_id,source_policy_version=policy['version'] if policy else 'unversioned',
            source_policy_intended_metric=policy.get('intended_metric','') if policy else '',
            source_policy_instruction=audit._source_policy_instruction(policy_id,policy),
            datapoint_id=attempt['datapoint_id'],requested_seed=attempt['seed'],
            source_cluster_id=params.get('source_cluster_id',attempt['datapoint_id']),
            effective_modality=assignment['modality'],policy_evaluable_turn=evaluable,
            policy_challenge_index=params.get('policy_challenge_index'),
            policy_challenge_horizon=params.get('policy_challenge_horizon'),
            prepared_prompt=str(audit._csv_safe(audit._dialog_text(attempt['rendered_input']))),
            prepared_response=str(audit._csv_safe(visible)),
            prepared_media_references=audit._portable_media_references(attempt['rendered_input']))
        if not eligible:
            meta['source_task_family']=context.get('source_evaluation',{}).get('family')
            meta['source_task_evaluation']=context.get('source_evaluation')
        outputs.append(dict(response_id=identity,input_id=assignment['input_id'],sample_key=audit._record_key(response),
            metadata=meta,judgments=attached,source_ref=reference,truncated=assignment['truncated'],
            media_bindings=origin.get('media_bindings',[]),generation_metadata=details))
    return dict(campaign_id=campaign,campaign_name=owner['name'],measured_assignments=len(assignments),
        assignment_outcomes=dict(dispositions),outputs=outputs,unavailable=unavailable,
        retained_files_read=len({path for path,_ in records})+len(attempts_by_file)+sum(bool(m) for m in manifests.values()),
        target_calls=0,judge_calls=0,human_ratings=0,source_files_changed=False,
        scope='Assignment-selected measured answers; historical conditions remain distinct')
