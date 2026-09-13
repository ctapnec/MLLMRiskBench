"""Persisted classifiers must reproduce the study without labels or new fitting."""
import copy
import json

import pytest

from test_response_svm import row
from ura.response_svm import FEATURES, evaluate_study
from ura.response_svm_models import package_study, predict_models


@pytest.fixture(scope='module')
def fitted_study():
    pytest.importorskip('sklearn')
    rows = []
    for i in range(30):
        for benign in (False, True):
            for positive in (False, True):
                rows.append(row(len(rows), input_id=f'input-{i}', source_cluster_id=f'cluster-{i}',
                    prompt=f'Question group {i}', expected_behavior='safe_answer' if benign else 'refuse',
                    label=('over_refusal' if benign else 'violation') if positive else 'safe',
                    local_label='safe', response='rejected inappropriate' if positive else 'helpful permitted'))
    report, predictions = evaluate_study(rows, bootstrap=100, max_chars=1000)
    return rows, report, predictions, package_study(rows, report, predictions)


def test_reloaded_models_match_study_predictions_without_labels_or_refitting(fitted_study, tmp_path, monkeypatch):
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.svm import LinearSVC
    rows, report, predictions, bundle = fitted_study
    path = tmp_path/'models.joblib'
    joblib.dump(bundle, path)
    loaded = joblib.load(path)
    held = {r['id'] for r in report['split_membership'] if r['split'] == 'test'}
    unlabeled = [{k: v for k, v in r.items() if k not in {'label', 'judge_condition', 'model', 'judge_reason'}}
                 for r in rows if r['id'] in held]
    def no_fit(*args, **kwargs):
        raise AssertionError('Applying saved models must not fit anything')
    monkeypatch.setattr(LinearSVC, 'fit', no_fit)
    monkeypatch.setattr(TfidfVectorizer, 'fit_transform', no_fit)
    for variant in FEATURES:
        actual = {(r['id'], r['task']): r for r in predict_models(loaded, unlabeled, features=variant)
                  if r['status'] == 'predicted'}
        expected = [r for r in predictions if r['protocol'] == 'group_holdout'
                    and r['estimator'] == 'linear_svm' and r['features'] == variant]
        assert len(actual) == len(expected)
        for record in expected:
            result = actual[(record['id'], record['task'])]
            assert result['prediction'] == record['prediction']
            assert result['margin'] == pytest.approx(record['score'], abs=1e-10)
    assert len(loaded['models']) == 9
    assert loaded['human_validated'] is False


def test_prediction_keeps_missing_and_inapplicable_conditions_separate(fitted_study):
    bundle = fitted_study[-1]
    rows = [row(1, response=''), row(2, modality='image'), row(3, local_label=None),
            row(4, expected_behavior='safe_answer'), row(5, expected_behavior='unknown')]
    output = {(r['id'], r['task']): r for r in predict_models(bundle, rows)}
    assert output[('response-1', 'harmful_compliance')]['status'] == 'missing_output'
    assert output[('response-2', 'harmful_compliance')]['status'] == 'outside_static_text_scope'
    assert output[('response-3', 'judge_disagreement')]['status'] == 'missing_local_decision'
    assert output[('response-3', 'harmful_compliance')]['status'] == 'predicted'
    assert 'derived_disagreement' not in output[('response-3', 'harmful_compliance')]
    assert output[('response-4', 'over_refusal')]['status'] == 'predicted'
    assert output[('response-4', 'harmful_compliance')]['status'] == 'not_applicable_to_expected_behavior'
    assert all(r['status'] != 'predicted' for r in output.values() if r['id'] == 'response-5')


def test_teacher_labels_cannot_change_predictions_and_derived_scores_use_local_verdict(fitted_study):
    bundle = fitted_study[-1]
    source = row(1, local_label='safe')
    first = predict_models(bundle, [source])
    assert predict_models(bundle, [dict(source, label='CHANGED', judge_reason='arbitrary')]) == first
    second = predict_models(bundle, [dict(source, local_label='violation')])
    harm = next(r for r in first if r['task'] == 'harmful_compliance')
    flipped = next(r for r in second if r['task'] == 'harmful_compliance')
    assert harm['prediction'] == flipped['prediction']
    assert harm['derived_disagreement']['prediction'] != flipped['derived_disagreement']['prediction']
    assert harm['derived_disagreement']['margin'] == -flipped['derived_disagreement']['margin']


def test_packaging_rejects_altered_reference_prediction(fitted_study):
    rows, report, predictions, _ = fitted_study
    altered = copy.deepcopy(predictions)
    altered[0]['prediction'] ^= 1
    with pytest.raises(ValueError, match='original held-out predictions'):
        package_study(rows, report, altered)


def test_cli_packages_and_predicts_with_no_campaign_judgment_writes(fitted_study, tmp_path):
    from experiments.response_svm import main
    rows, report, predictions, _ = fitted_study
    data = tmp_path/'data.jsonl'
    data.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    study = tmp_path/'study.json'
    study.write_text(json.dumps(report))
    reference = tmp_path/'reference.json'
    reference.write_text(json.dumps(predictions))
    fitted = tmp_path/'fitted'
    assert main(['--package', '--dataset', str(data), '--study-result', str(study),
                 '--study-predictions', str(reference), '--out', str(fitted)]) == 0
    assert json.loads((fitted/'result.json').read_text())['reload_predictions_equal'] is True
    out = tmp_path/'predicted'
    assert main(['--predict', '--dataset', str(data), '--models', str(fitted/'models.joblib'), '--out', str(out)]) == 0
    result = json.loads((out/'result.json').read_text())
    assert result['target_calls'] == result['judge_calls'] == 0
    assert result['campaign_judgments_modified'] is False
