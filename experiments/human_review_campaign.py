"""Prepare and analyse human review of indexed, retained campaign outputs.

This is an achieved-sample agreement report, not a reconstructed Runner grid
or a claim of population validity. It never generates answers or judgments.
"""
import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
from pathlib import Path

from experiments import human_audit as audit
from experiments.human_audit_media import prepare_media_index
from experiments.rig_web_app.human_review_inventory import read_campaign, _location


def _write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')


def _view(outputs):
    predictions, metadata, identities = defaultdict(dict), {}, {}
    for row in outputs:
        key, meta = row['sample_key'], row['metadata']
        if key in metadata:
            raise ValueError('Duplicate campaign review output identity')
        metadata[key] = meta
        # Identity-only input to the existing CSV writer, not a synthetic verdict.
        identities[key] = dict(run_id=meta['run_id'], attempt_id=meta['attempt_id'], raw=dict(model=meta['model']))
        for judge, value in row['judgments'].items():
            predictions.setdefault(judge, {})
            if value['status']=='valid' and value['label'] in audit.VALID_LABELS:
                predictions[judge][key] = value['label']
    return predictions, metadata, identities, {}


def prepare(inventory, output, *, mode, clusters, results_root, media_index=None):
    if mode not in {'common', 'source_task'} or clusters < 0:
        raise ValueError('Choose a review rubric and a non-negative cluster count')
    sidecars = ['.SNAPSHOT.json.gz', '.FRAME.json', '.MEDIA.json', '.MEDIA-REPORT.json', '.INSTRUCTIONS.md']
    if output.exists() or any(output.with_suffix(s).exists() for s in sidecars):
        raise ValueError('Choose a new sample destination; existing review evidence is not overwritten')
    outputs, excluded = [], Counter()
    for row in inventory['outputs']:
        meta = row['metadata']
        if mode=='common' and meta['common_metrics_eligible'] is True:
            outputs.append(row)
        elif mode=='source_task' and meta.get('source_task_family') in audit.SOURCE_TASK_VOCABULARY:
            outputs.append(row)
        else:
            excluded['different_or_unsupported_rubric'] += 1
    if not outputs:
        raise ValueError('No saved outputs support the selected human-review rubric')
    view = _view(outputs)
    producer = audit.prepare_sample if mode=='common' else audit.prepare_source_task_sample
    producer(results_root, output, max(1, clusters), artifact_view=view, minimum_coverage=clusters==0)
    with output.open(encoding='utf-8-sig', newline='') as stream:
        reader=csv.DictReader(stream); fields=reader.fieldnames
        selected_rows = list(reader)
    # The native sampler emits one blank row per output. The actual analysis
    # contract (and the UI store) uses an exact two-rater blank form.
    with output.open('w', encoding='utf-8-sig', newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        writer.writerows(row for row in selected_rows for _ in range(2))
    keys = {row['sample_key'] for row in selected_rows}
    selected = [row for row in outputs if row['sample_key'] in keys]
    snapshot = dict(campaign_id=inventory['campaign_id'], campaign_name=inventory['campaign_name'], mode=mode,
        outputs=selected, prepared_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        assignment_outcomes=inventory['assignment_outcomes'],
        population_outputs=len(outputs), population_clusters=len({(r['metadata']['source'],r['metadata']['source_cluster_id']) for r in outputs}),
        unavailable_reasons=dict(Counter(r['reason'] for r in inventory['unavailable'])),
        excluded_rubrics=dict(excluded), requested_clusters=clusters,
        scope='Deterministic whole-cluster achieved sample; historical generation conditions are distinct; not population representative')
    with gzip.open(output.with_suffix('.SNAPSHOT.json.gz'), 'xt', encoding='utf-8',compresslevel=1) as stream:
        json.dump(snapshot, stream, ensure_ascii=False, sort_keys=True)
    manifest_paths = set()
    for row in selected:
        path = _location(row['source_ref'], results_root.resolve())[0]
        stem = path.name.removesuffix('.responses.checkpoint.jsonl').removesuffix('.responses.jsonl')
        manifest = path.with_name(stem+'.manifest.json')
        if manifest.is_file():
            manifest_paths.add(manifest)
    media = prepare_media_index(results_root, output, media_index, manifest_paths=sorted(manifest_paths))
    report = {k:v for k,v in snapshot.items() if k not in {'outputs','prepared_sha256'}}
    report.update(selected_outputs=len(selected), selected_clusters=len({r['cluster_key'] for r in selected_rows}),
        independent_ratings_required=2*len(selected), media=media,
        target_calls=0, judge_calls=0, human_ratings=0, source_files_changed=False)
    _write(output.with_suffix('.FRAME.json'), report)
    # The operator CSV is identity-bearing. The existing rater UI deliberately
    # hides these columns as well as automated labels and source references.
    with output.with_suffix('.INSTRUCTIONS.md').open('a', encoding='utf-8') as stream:
        stream.write('\nCampaign scope: this is a selected achieved sample, not a population estimate. '
            'The operator CSV retains model identities; use the blinded rater interface to conceal them. '
            'Missing outputs and unavailable contexts remain accounted separately. '
            'Different generation and judge configurations must not be pooled.\n')
    return report


def _agreement(left, right):
    return dict(n=len(left), agreement=sum(a==b for a,b in zip(left,right))/len(left),
                kappa=audit._kappa(left,right), confusion=audit._confusion(left,right))


def analyse(snapshot_path, prepared, labels, output, *, bootstrap_resamples=2000):
    if bootstrap_resamples < 1 or output.exists():
        raise ValueError('Choose a positive bootstrap count and a new report destination')
    with gzip.open(snapshot_path, 'rt', encoding='utf-8') as stream:
        snapshot=json.load(stream)
    mode=snapshot['mode']; rows={r['sample_key']:r for r in snapshot['outputs']}
    fields=audit._RATING_FIELDS if mode=='common' else audit._SOURCE_TASK_RATING_FIELDS
    audit._prepared_rating_form_binding(prepared,snapshot['prepared_sha256'],labels,rating_fields=fields,frame=mode)
    with prepared.open(encoding='utf-8-sig',newline='') as stream:
        blanks=list(csv.DictReader(stream))
    if {r['sample_key'] for r in blanks} != set(rows):
        raise ValueError('Prepared sample differs from the frozen campaign output selection')
    for row in blanks:
        meta=rows[row['sample_key']]['metadata']
        if (row['prompt'],row['response'])!=(meta['prepared_prompt'],meta['prepared_response']):
            raise ValueError('Prepared text differs from the frozen saved output')
    with labels.open(encoding='utf-8-sig',newline='') as stream:
        completed=list(csv.DictReader(stream))
    by_key=defaultdict(list)
    for row in completed:
        by_key[row['sample_key']].append(row)
    report={k:v for k,v in snapshot.items() if k not in {'outputs','prepared_sha256'}}
    report.update(status='completed_human_sample_analysis',rated_outputs=len(rows),independent_ratings=len(completed),
                  target_calls=0,judge_calls=0,raters_are_supplied_not_generated=True)
    if mode=='common':
        by_rater, metadata, audit_info=audit._load_labels(labels)
        gold=audit._consensus(by_rater,metadata)
        if set(gold)!=set(rows):
            raise ValueError('Every selected output requires a resolved human decision')
        for key,label in gold.items():
            audit._endpoint_event(label,rows[key]['metadata']['expected_behavior'])
        dimensions={}
        for field,allowed in audit.DIMENSION_LABELS.items():
            consensus=audit._consensus(audit_info['_dimension_ratings'][field],metadata,
                allowed_labels=allowed,adjudicated_field='adjudicated_'+field)
            if set(consensus)!=set(rows):
                raise ValueError('Every human dimension must be resolved')
            pairs=[sorted(value,key=lambda r:r['rater_id']) for value in by_key.values()]
            dimensions[field]=_agreement([p[0][field] for p in pairs],[p[1][field] for p in pairs])
            dimensions[field]['resolved_labels']=dict(Counter(consensus.values()))
        predictions=_view(list(rows.values()))[0]; comparisons=[]
        for judge,values in sorted(predictions.items()):
            for population,positive in [('harmful_expected_refusal','violation'),('benign_expected_answer','over_refusal')]:
                eligible=[k for k,r in rows.items() if (r['metadata']['expected_behavior']=='refuse')==(positive=='violation')]
                selected=sorted(set(eligible)&values.keys())
                if not eligible:continue
                result=dict(judge=judge,population=population,eligible_outputs=len(eligible),decisive_outputs=len(selected),
                    missing_or_invalid_decisions=len(eligible)-len(selected),coverage=len(selected)/len(eligible))
                if selected:
                    result['agreement']=audit._judge_report([values[k] for k in selected],[gold[k] for k in selected],
                        [rows[k]['metadata']['source']+'|'+rows[k]['metadata']['source_cluster_id'] for k in selected],
                        positive_event_label=positive,n_resamples=bootstrap_resamples)
                comparisons.append(result)
        report.update(dimensions=dimensions,judge_comparisons=comparisons,human_labels=dict(Counter(gold.values())),
            analysis_unit='Saved output turns; clustered by source intent. Not collapsed live-trajectory ASR.')
    else:
        families=defaultdict(list)
        for key,ratings in by_key.items():
            meta=rows[key]['metadata'];family=meta['source_task_family']
            for row in ratings:
                if row['confidence'] not in {'1','2','3','4','5'} or row['task_label'] not in audit.SOURCE_TASK_VOCABULARY[family] or row['parse_status_label'] not in audit._SOURCE_TASK_PARSE_LABELS:
                    raise ValueError('Invalid source-task rating or confidence')
            task,_=audit._resolve_source_task_dimension(ratings,sample_key=key,rating_field='task_label',
                adjudicated_field='adjudicated_task_label',allowed=set(audit.SOURCE_TASK_VOCABULARY[family]))
            parse,_=audit._resolve_source_task_dimension(ratings,sample_key=key,rating_field='parse_status_label',
                adjudicated_field='adjudicated_parse_status_label',allowed=set(audit._SOURCE_TASK_PARSE_LABELS))
            evaluation=meta['source_task_evaluation']
            families[family].append(dict(task=task,parse=parse,reference=evaluation['reference'],
                prediction=evaluation['prediction'] or 'unparsed',ratings=sorted(ratings,key=lambda r:r['rater_id'])))
        report['source_task_families']={family:dict(outputs=len(group),
            human_reference=_agreement([r['task'] for r in group],[r['reference'] for r in group]),
            human_parser=_agreement([r['task'] for r in group],[r['prediction'] for r in group]),
            independent_task=_agreement([r['ratings'][0]['task_label'] for r in group],[r['ratings'][1]['task_label'] for r in group]),
            independent_parse=_agreement([r['ratings'][0]['parse_status_label'] for r in group],[r['ratings'][1]['parse_status_label'] for r in group])) for family,group in families.items()}
    _write(output,report)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path)
    parser.add_argument('--campaign')
    parser.add_argument('--results-root',type=Path)
    parser.add_argument('--mode',choices=['common','source_task'],default='common')
    parser.add_argument('--clusters',type=int,default=0,help='0: minimum deterministic coverage; inspect workload before enrolment')
    parser.add_argument('--media-index',type=Path)
    parser.add_argument('--snapshot',type=Path)
    parser.add_argument('--prepared-rating-form',type=Path)
    parser.add_argument('--labels',type=Path)
    parser.add_argument('--bootstrap-resamples',type=int,default=2000)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--acknowledge-sensitive-content',action='store_true')
    args=parser.parse_args(argv)
    if args.labels:
        if not args.snapshot or not args.prepared_rating_form or any((args.database,args.campaign,args.results_root,args.media_index)):
            parser.error('Analysis requires a frozen snapshot, prepared form and labels; no live campaign inputs')
        result=analyse(args.snapshot,args.prepared_rating_form,args.labels,args.output,bootstrap_resamples=args.bootstrap_resamples)
    else:
        if not args.database or not args.campaign or not args.results_root or not args.acknowledge_sensitive_content or args.snapshot:
            parser.error('Preparation requires campaign, database, results root and sensitive-content acknowledgement')
        inventory=read_campaign(args.database,args.campaign,args.results_root)
        result=prepare(inventory,args.output,mode=args.mode,clusters=args.clusters,results_root=args.results_root,media_index=args.media_index)
    print(json.dumps({k:v for k,v in result.items() if k not in {'judge_comparisons','dimensions','source_task_families'}},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
