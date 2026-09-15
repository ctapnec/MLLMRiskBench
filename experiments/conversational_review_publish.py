"""Publish already-written conversational assessments; never generate judgments."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import re
from pathlib import Path
import sqlite3

from experiments import human_audit as audit
from experiments.rig_web_app.human_review_inventory import _location, _records
from experiments.rig_web_app.storage import ConsoleDB


def publish(*, review_database, console_database, results_root, output_dir, judge_id, display_name):
    root=Path(results_root).resolve(strict=True)
    output=Path(output_dir).resolve()
    if not output.is_relative_to(root):
        raise ValueError('Assessment artifacts must remain in the results store')
    if not judge_id.startswith('conversation:') or not display_name.strip():
        raise ValueError('Use a separate conversation: judging identity and a display name')
    review=sqlite3.connect(Path(review_database).resolve(strict=True).as_uri()+'?mode=ro',uri=True)
    review.row_factory=sqlite3.Row
    try:
        saved=[dict(r) for r in review.execute(
            'SELECT q.id,q.record,p.value presentation,a.value assessment,a.reviewed_at '
            'FROM assessments a JOIN queue q ON q.id=a.id JOIN presentations p ON p.id=q.id ORDER BY q.id')]
        selection=None
        if review.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='review_scope'").fetchone():
            scope=json.loads(review.execute("SELECT value FROM review_scope WHERE id='approved'").fetchone()[0])
            ids=set(scope['selected_review_ids'])
            if len(ids)!=scope['planned_total'] or not {r['id'] for r in saved}<=ids:
                raise ValueError('Saved assessments do not match the approved review selection')
            selection=[json.loads(r['record']) for r in review.execute(
                'SELECT record FROM queue WHERE id IN ('+','.join('?' for _ in ids)+')',sorted(ids))]
            if len(selection)!=len(ids):
                raise ValueError('Approved review selection is incomplete')
    finally:
        review.close()
    settings=dict(display_name=display_name,assessment_method='conversation_based_ai_review',
        reviewer_model_version=None,review_database=str(Path(review_database).resolve()),
        api_judge_calls=0,human_evaluation=False)
    db=ConsoleDB(Path(console_database))
    pending=[];unchanged=0
    try:
        if not db.healthy:
            raise ValueError('Campaign database unavailable')
        for row in saved:
            original=json.loads(row['record']);shown=json.loads(row['presentation']);assessment=json.loads(row['assessment'])
            if not re.fullmatch(r'[A-Za-z0-9_-]+',row['id']) or assessment.get('id')!=row['id'] or shown.get('id')!=row['id']:
                raise ValueError('Review item identities do not match')
            if assessment.get('read_complete') is not True or assessment.get('response_characters')!=len(shown['response']):
                raise ValueError('An assessment does not record complete response inspection')
            if shown.get('media') and assessment.get('media_inspected') is not True:
                raise ValueError('Required media were not inspected')
            if assessment.get('review_kind')!='AI-assisted conversational evaluation' or not assessment.get('rationale','').strip():
                raise ValueError('Assessment provenance or explanation missing')
            eligible=shown.get('policy_evaluable_turn') is not False
            label=assessment.get('task_label') if shown.get('common_metrics_eligible') is False else assessment.get('overall')
            valid=assessment.get('status')=='assessed' and eligible and label not in (None,'','unassessed')
            status,label=('valid',label) if valid else ('invalid',None)
            artifact=output/(row['id']+'.json')
            indexed=dict(response_id=original['response_id'],judge_id=judge_id,status=status,label=label,
                source_ref=str(artifact),judge_settings=settings)
            previous=db._query('SELECT status,label,source_ref FROM campaign_judgments WHERE campaign_id=? '
                'AND response_id=? AND judge_id=?',(original['campaign_id'],original['response_id'],judge_id))
            if previous:
                if tuple(previous[0])!=(status,label,str(artifact)):
                    raise ValueError('A published assessment changed; use an explicitly separate correction')
                if not artifact.is_file():
                    raise ValueError('Published assessment artifact is missing')
                unchanged+=1
                continue
            current=db._query('SELECT a.model,a.evidence_class,r.outcome,r.details FROM campaign_responses r '
                'JOIN campaign_assignments a ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id '
                'WHERE r.campaign_id=? AND r.response_id=?',(original['campaign_id'],original['response_id']))
            if not current or current[0]['model']!=original['model'] or current[0]['outcome']!='usable' or current[0]['evidence_class']!='measured':
                raise ValueError('Review does not match a measured usable campaign response')
            reference=json.loads(current[0]['details'])['source_ref']
            if _location(reference,root)!=_location(original['details']['source_ref'],root):
                raise ValueError('Retained response source changed')
            pending.append((row,original,shown,assessment,reference,indexed,artifact))
        records=_records([p[4] for p in pending],root)
        prepared=[];attempts={}
        for row,original,shown,assessment,reference,indexed,artifact in pending:
            value=records[_location(reference,root)];response=value.get('response',value)
            if (response['run_id']+':'+response['attempt_id'],response['target'])!=(original['response_id'],original['model']):
                raise ValueError('Assessment belongs to a different response identity')
            if audit._dialog_text(response['output_turns'])!=shown['response']:
                raise ValueError('Reviewed text differs from the retained response')
            attempt=value.get('attempt')
            if attempt is None:
                path=_location(reference,root)[0]
                stem=path.name.removesuffix('.responses.checkpoint.jsonl').removesuffix('.responses.jsonl')
                source=path.with_name(stem+'.attempts.jsonl')
                if source not in attempts:
                    with source.open(encoding='utf-8') as stream:
                        entries=[json.loads(line) for line in stream if line.strip()]
                    attempts[source]={(a['run_id'],a['id']):a for a in entries}
                attempt=attempts[source][(response['run_id'],response['attempt_id'])]
            if ((attempt['run_id'],attempt['id'])!=(response['run_id'],response['attempt_id'])
                or audit._dialog_text(attempt['rendered_input'])!=shown['prompt']
                or json.loads(audit._portable_media_references(attempt['rendered_input']))!=shown.get('media',[])):
                raise ValueError('Reviewed input or media differ from the retained request')
            payload=dict(response=response,presentation=shown,assessment=assessment,
                judgment=dict(run_id=response['run_id'],attempt_id=response['attempt_id'],label=indexed['label'],
                    judge=judge_id,raw=dict(assessment_method='conversation_based_ai_review',review_status=assessment['status'])),
                original_source_ref=reference,reviewed_at=row['reviewed_at'])
            prepared.append((original['campaign_id'],indexed,artifact,payload))
        output.mkdir(parents=True,exist_ok=True)
        groups=defaultdict(list)
        for campaign,indexed,artifact,payload in prepared:
            if artifact.exists():
                if json.loads(artifact.read_text(encoding='utf-8'))!=payload:
                    raise ValueError('Assessment artifact already exists with different content')
            else:
                with artifact.open('x',encoding='utf-8') as stream:
                    json.dump(payload,stream,ensure_ascii=False,indent=2)
            groups[campaign].append(indexed)
        for campaign,judgments in groups.items():
            db.publish_workspace_results(campaign,assignments=[],responses=[],judgments=judgments)
        if selection is not None:
            selected=defaultdict(set)
            for row in selection:
                selected[row['campaign_id']].add(row['response_id'])
            with db._lock,db._conn:
                for campaign,identities in selected.items():
                    existing={r[0] for r in db._conn.execute('SELECT response_id FROM campaign_review_selection '
                        'WHERE campaign_id=? AND judge_id=?',(campaign,judge_id))}
                    if existing and existing!=identities:
                        raise ValueError('Published review selection changed; use a separate review series')
                    for response in identities:
                        current=db._conn.execute('SELECT 1 FROM campaign_responses r JOIN campaign_assignments a '
                            'ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id '
                            "WHERE r.campaign_id=? AND r.response_id=? AND r.outcome='usable' AND a.evidence_class='measured'",
                            (campaign,response)).fetchone()
                        if not current:
                            raise ValueError('Selected review output is not an indexed measured usable response')
                        db._conn.execute('INSERT OR IGNORE INTO campaign_review_selection VALUES(?,?,?)',
                            (campaign,judge_id,response))
        return dict(published=len(prepared),already_published=unchanged,campaigns=len(groups),judge_api_calls=0)
    finally:
        db.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('review-database','console-database','results-root','output-dir'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--judge-id',required=True)
    parser.add_argument('--display-name',required=True)
    args=parser.parse_args()
    print(json.dumps(publish(**vars(args))))


if __name__=='__main__':
    main()
