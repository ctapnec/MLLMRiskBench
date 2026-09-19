"""Export, evaluate, package or apply retained-response SVMs without provider calls."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")


def checkpoint(path, value):
    """Publish controller metadata only after a complete write."""
    temporary = path.with_suffix('.pending')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def study(args):
    """One user-selected study; preserve completed stages when resuming."""
    from experiments.hosted_retained_inputs import candidates_from_cells
    from experiments.retained_local_sources import read_sources
    root=args.out.resolve()
    root.mkdir(parents=True,exist_ok=True)
    configuration={key:str(value) if isinstance(value,Path) else value
                   for key,value in vars(args).items() if key!='out'}
    configuration['source_root']=[str(p.resolve()) for p in args.source_root]
    request=root/'selection.json'
    if request.exists():
        if json.loads(request.read_text())!=configuration:
            raise ValueError('Resume with the original scientific selection; start a new study for changed settings')
    else:
        checkpoint(request,configuration)
    if (root/'result.json').exists():
        print('This study is already complete; saved results reused.',flush=True)
        return 0
    stages={}
    def stage(name,arguments):
        marker=root/(name+'-complete.json')
        if marker.exists():
            saved=json.loads(marker.read_text())
            destination=Path(saved['directory']).resolve()
            if not destination.is_relative_to(root) or not (destination/'result.json').is_file():
                raise ValueError('A saved analysis stage is unavailable')
        else:
            number=1
            destination=root/(name+'-'+str(number))
            while destination.exists():
                if (destination/'result.json').is_file():
                    # The process may have stopped after the stage finished but
                    # before its controller checkpoint was published.
                    break
                number+=1;destination=root/(name+'-'+str(number))
            if not (destination/'result.json').is_file():
                print(json.dumps(dict(stage=name,status='running')),flush=True)
                code=main([*arguments,'--out',str(destination)])
                if code:raise ValueError(name+' did not complete')
            checkpoint(marker,dict(directory=str(destination)))
        stages[name]=str(destination)
        return destination
    candidates=args.candidates or root/'source-candidates.json'
    if not candidates.exists():
        if args.candidates:raise ValueError('The selected source candidates are unavailable')
        print(json.dumps(dict(stage='saved_inputs',status='running')),flush=True)
        rows=candidates_from_cells(read_sources(args.source_root,args.run_id))
        checkpoint(candidates,rows)
    export=['--export','--database',str(args.database),'--candidates',str(candidates),
        '--matched-campaign',args.matched_campaign,'--judge-condition',args.judge_condition]
    for owner in args.campaign:export+=['--campaign',owner]
    for model in args.exclude_model:export+=['--exclude-model',model]
    dataset=stage('dataset',export)/'dataset.jsonl'
    def finish(*, models=None, reason=None):
        result=dict(status='study_complete',stages=stages,dataset=str(dataset),models=models,
            packaging_status='saved' if models else 'not_applicable',packaging_reason=reason,
            target_calls=0,judge_calls=0,human_validated=False,campaign_judgments_modified=False)
        checkpoint(root/'result.json',result)
        print(json.dumps(result),flush=True)
        return 0
    if not dataset.stat().st_size:
        return finish(reason='No eligible labeled static-text responses; inspect dataset dispositions')
    from ura.response_svm import connected_groups
    with dataset.open(encoding='utf-8') as stream:
        group_count=len(set(connected_groups([json.loads(line) for line in stream if line.strip()])))
    if group_count<5:
        return finish(reason='At least five independent input groups are needed; exported data retained without fitting')
    evaluate=['--evaluate','--dataset',str(dataset),'--seed',str(args.seed),
        '--bootstrap',str(args.bootstrap),'--max-feature-characters',str(args.max_feature_characters)]
    for model in args.holdout_model:evaluate+=['--holdout-model',model]
    for corpus in args.holdout_corpus:evaluate+=['--holdout-corpus',corpus]
    analysis=stage('evaluation',evaluate)
    from ura.response_svm import TASKS, FEATURES
    report=json.loads((analysis/'result.json').read_text())
    supported={(r['task'],r['features']) for r in report['experiments']
               if r.get('status')=='evaluated' and r['protocol']=='group_holdout' and r['estimator']=='linear_svm'}
    if supported!={(task,features) for task in TASKS for features in FEATURES}:
        return finish(reason='Insufficient class-group support for all three classifier tasks; evaluation results retained')
    fitted=stage('classifiers',['--package','--dataset',str(dataset),
        '--study-result',str(analysis/'result.json'),'--study-predictions',str(analysis/'predictions.json')])
    return finish(models=str(fitted/'models.joblib'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--export", action="store_true")
    mode.add_argument("--evaluate", action="store_true")
    mode.add_argument("--package", action="store_true")
    mode.add_argument("--predict", action="store_true")
    mode.add_argument("--study", action="store_true",help="Automatically export, evaluate and save reusable classifiers")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--source-root", type=Path, action="append",default=[])
    parser.add_argument("--run-id", action="append",default=[])
    parser.add_argument("--campaign", action="append", default=[])
    parser.add_argument("--matched-campaign")
    parser.add_argument("--judge-condition")
    parser.add_argument("--exclude-model", action="append", default=[])
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--study-result", type=Path)
    parser.add_argument("--study-predictions", type=Path)
    parser.add_argument("--models", type=Path, help="Trusted fitted model.joblib created by this command; never load untrusted pickle files")
    parser.add_argument("--features", choices=("prompt", "response", "prompt_response"), default="response")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-feature-characters", type=int, default=20000)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--holdout-model", action="append", default=[])
    parser.add_argument("--holdout-corpus", action="append", default=[])
    args = parser.parse_args(argv)
    if args.study:
        if not all((args.database,args.campaign,args.matched_campaign,args.judge_condition)) or not (args.candidates or args.source_root):
            parser.error('Study needs selected campaigns, a judge and saved source inputs')
        return study(args)
    if args.export and not all((args.database, args.candidates, args.campaign,
                                args.matched_campaign, args.judge_condition)):
        parser.error("Export needs database, candidates, campaign, matched-campaign and judge-condition")
    if not args.export and not args.dataset:
        parser.error("Evaluation, packaging and prediction need --dataset")
    if args.package and not (args.study_result and args.study_predictions):
        parser.error("Packaging needs --study-result and --study-predictions")
    if args.predict and not args.models:
        parser.error("Prediction needs --models")
    args.out.mkdir(parents=True, exist_ok=False)
    try:
        if args.export:
            from experiments.response_svm_dataset import export_dataset
            rows, report = export_dataset(database=args.database, candidates=args.candidates,
                campaigns=args.campaign, judge=args.judge_condition,
                matched_campaign=args.matched_campaign, exclude_models=args.exclude_model)
            with (args.out / "dataset.jsonl").open("x", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
        elif args.package or args.predict:
            import joblib
            from ura.response_svm import CLAIM
            from ura.response_svm_models import package_study, predict_models
            with args.dataset.open(encoding="utf-8") as stream:
                rows = [json.loads(line) for line in stream if line.strip()]
            if args.package:
                bundle = package_study(rows, json.loads(args.study_result.read_text(encoding="utf-8")),
                    json.loads(args.study_predictions.read_text(encoding="utf-8")),
                    progress=lambda value: print(json.dumps(value), flush=True))
                path = args.out / "models.joblib"
                joblib.dump(bundle, path)
                # Verify serialization, not only the in-memory fitted object.
                loaded = joblib.load(path)
                held = {r['id'] for r in json.loads(args.study_result.read_text(encoding="utf-8"))['split_membership']
                        if r['split'] == 'test'}
                held_rows = [r for r in rows if r['id'] in held]
                for variant in ("prompt", "response", "prompt_response"):
                    if predict_models(bundle, held_rows, features=variant) != predict_models(loaded, held_rows, features=variant):
                        raise ValueError("Reloaded classifier predictions differ")
                report = dict(status="models_packaged", models=len(bundle['models']),
                    reference_predictions_matched=bundle['reference_predictions_matched'],
                    reload_predictions_equal=True, runtime=bundle['runtime'],
                    fitted_model_path=str(path.resolve()))
            else:
                predictions = predict_models(joblib.load(args.models), rows, features=args.features)
                write_json(args.out / "predictions.json", predictions)
                report = dict(status="prediction_complete", input_responses=len(rows),
                    predictions=sum(r['status'] == 'predicted' for r in predictions),
                    features=args.features, scores="uncalibrated margins, not probabilities")
            report.update(claim_scope=CLAIM, human_validated=False, target_calls=0, judge_calls=0,
                          campaign_judgments_modified=False)
        else:
            from ura.response_svm import evaluate_study
            with args.dataset.open(encoding="utf-8") as stream:
                rows = [json.loads(line) for line in stream if line.strip()]
            def progress(value):
                print(json.dumps(dict(time_utc=datetime.now(timezone.utc).isoformat(), **value)), flush=True)
            report, predictions = evaluate_study(rows, seed=args.seed,
                max_chars=args.max_feature_characters, bootstrap=args.bootstrap,
                holdout_models=args.holdout_model, holdout_corpora=args.holdout_corpus, progress=progress)
            write_json(args.out / "predictions.json", predictions)
        report["time_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(args.out / "result.json", report)
        print(json.dumps({k: v for k, v in report.items() if k not in ("experiments", "split_membership")}), flush=True)
        return 0
    except Exception as exc:
        write_json(args.out / "error.json", dict(status="failed", error_type=type(exc).__name__, error=str(exc)))
        raise


if __name__ == "__main__":
    raise SystemExit(main())
