"""Reusable fitted text classifiers, separate from authoritative campaign judgments."""
from __future__ import annotations

from .response_svm import (CLAIM, FEATURES, TASKS, VALID_LABELS, clip_text,
                           connected_groups, feature_matrices, split_groups, target_label)


def package_study(rows, report, reference_predictions, *, progress=None):
    """Reconstruct only the selected primary fits and verify their saved predictions.

    No new hyperparameter search, holdout evaluation or training on test rows.
    The retained study remains the source of the reported scientific results.
    """
    import numpy as np
    import sklearn
    from sklearn.svm import LinearSVC
    from threadpoolctl import threadpool_limits

    if report.get('status') != 'analysis_complete':
        raise ValueError('Packaging requires a completed response-classifier study')
    if report['runtime']['sklearn'] != sklearn.__version__:
        raise ValueError('Use the original study scikit-learn version for reproducible packaging')
    by_id = {r['id']: r for r in rows}
    membership = {r['id']: r for r in report['split_membership']}
    if len(by_id) != len(rows) or set(by_id) != set(membership):
        raise ValueError('Packaging dataset differs from the saved study population')
    if {r['judge_condition'] for r in rows} != {report['teacher']}:
        raise ValueError('Packaging teacher differs from the saved study')
    grouped = [dict(row, group=group) for row, group in zip(rows, connected_groups(rows))]
    split = split_groups(grouped, report['seed'])
    if any(membership[r['id']]['group'] != r['group'] or
           membership[r['id']]['split'] != split[r['group']] for r in grouped):
        raise ValueError('Packaging must preserve the original leakage-controlled split')
    selected = [r for r in report['experiments'] if r.get('status') == 'evaluated'
                and r['protocol'] == 'group_holdout' and r['estimator'] == 'linear_svm']
    models, matched = [], 0
    for record in selected:
        task, variant = record['task'], record['features']
        if progress:
            progress(dict(task=task, features=variant, stage='packaging_selected_fit'))
        parts = {p: [r for r in grouped if split[r['group']] == p and target_label(r, task) is not None]
                 for p in ('train', 'validation', 'test')}
        validation_choice = max(record['validation_candidates'], key=lambda item: (item['macro_f1'], -item['C']))
        if record['C'] != validation_choice['C']:
            raise ValueError('Packaging cannot change the validation-selected regularization')
        reference = {r['id']: r for r in reference_predictions if r['task'] == task
                     and r['features'] == variant and r['protocol'] == 'group_holdout'
                     and r['estimator'] == 'linear_svm'}
        if set(reference) != {r['id'] for r in parts['test']}:
            raise ValueError('Saved held-out predictions do not cover this classifier')
        with threadpool_limits(limits=2):
            x, _, transformers = feature_matrices(parts, variant, report['max_feature_characters'],
                                                  retain_transformers=True)
            model = LinearSVC(C=record['C'], class_weight='balanced', max_iter=10000,
                              random_state=report['seed'])
            model.fit(x['train'], [target_label(r, task) for r in parts['train']])
            predictions = model.predict(x['test'])
            scores = model.decision_function(x['test'])
        expected = [reference[r['id']] for r in parts['test']]
        if not np.array_equal(predictions, [r['prediction'] for r in expected]) or not np.allclose(
                scores, [r['score'] for r in expected], rtol=1e-7, atol=1e-8):
            raise ValueError('Packaged classifier does not reproduce the original held-out predictions')
        matched += len(expected)
        models.append(dict(task=task, features=variant, C=record['C'], model=model,
                           transformers=transformers, training_responses=len(parts['train'])))
    if {(r['task'], r['features']) for r in models} != {(t, f) for t in TASKS for f in FEATURES}:
        raise ValueError('The completed study must support all three primary tasks and feature comparisons')
    return dict(kind='retained_response_svm', claim_scope=CLAIM, human_validated=False,
                teacher=report['teacher'], max_feature_characters=report['max_feature_characters'],
                runtime=dict(sklearn=sklearn.__version__, numpy=np.__version__), models=models,
                reference_predictions_matched=matched, seed=report['seed'])


def predict_models(bundle, rows, *, features='response'):
    """Classify eligible new text without teacher labels, refitting or judge writes.

    Margins are uncalibrated scores, not probabilities. The default representation
    is response text; prompt and combined models remain available explicitly.
    """
    import numpy as np
    import sklearn
    from scipy.sparse import hstack
    from threadpoolctl import threadpool_limits

    if bundle.get('kind') != 'retained_response_svm' or features not in FEATURES:
        raise ValueError('Choose a retained response model and a supported representation')
    if bundle['runtime']['sklearn'] != sklearn.__version__:
        raise ValueError('Load fitted classifiers with their recorded scikit-learn version')
    if len({r['id'] for r in rows}) != len(rows):
        raise ValueError('Prediction input response identities must be unique')
    output = []
    for fitted in bundle['models']:
        if fitted['features'] != features:
            continue
        task = fitted['task']
        eligible = []
        for row in rows:
            reason = None
            expected = row.get('expected_behavior')
            if row.get('modality') != 'text' or row.get('framework') != 'replay':
                reason = 'outside_static_text_scope'
            elif not isinstance(row.get('response'), str) or not row['response'].strip():
                reason = 'missing_output'
            elif features != 'response' and not isinstance(row.get('prompt'), str):
                reason = 'missing_prompt'
            elif (task == 'over_refusal' and expected not in {'safe_answer', 'comply_safely'}) or (
                    task != 'over_refusal' and expected != 'refuse'):
                reason = 'not_applicable_to_expected_behavior'
            elif task == 'judge_disagreement' and row.get('local_label') not in VALID_LABELS:
                reason = 'missing_local_decision'
            if reason:
                output.append(dict(id=row['id'], task=task, features=features, status=reason))
            else:
                eligible.append(row)
        if not eligible:
            continue
        with threadpool_limits(limits=2):
            x = hstack([vectorizer.transform([clip_text(r[field], bundle['max_feature_characters'])
                                              for r in eligible])
                        for field, vectorizer in fitted['transformers']], format='csr')
            predictions = fitted['model'].predict(x)
            scores = fitted['model'].decision_function(x)
        for row, prediction, score in zip(eligible, predictions, scores):
            result = dict(id=row['id'], task=task, features=features, status='predicted',
                          prediction=int(prediction), margin=float(score),
                          truncated=bool(row.get('truncated')))
            if task == 'harmful_compliance' and row.get('local_label') in VALID_LABELS:
                local = int(row['local_label'] == 'violation')
                result['derived_disagreement'] = dict(prediction=int(prediction) ^ local,
                                                       margin=float(score) * (-1 if local else 1))
            if not np.isfinite(result['margin']):
                raise ValueError('Classifier returned a non-finite margin')
            output.append(result)
    return output
