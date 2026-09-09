"""A benign setup turn is not a standalone security-evaluable canary."""
from experiments.hosted_campaign_prepare import _pilot_groups


def test_pilot_does_not_isolate_crescendo_setup_or_remove_last_challenge():
    def row(identity, corpus, datapoint):
        return {'input_identity_sha256': identity, 'corpus': corpus, 'source': corpus,
                'source_cluster_id': datapoint, 'datapoint_id': datapoint,
                'modality': 'text', 'required_modalities': ['text']}
    plan = {'selected': [row('setup', 'harmbench', 'one'), row('challenge', 'harmbench', 'one'),
                         row('direct', 'other', 'two'), row('remaining', 'third', 'three')]}
    groups = _pilot_groups(plan, policy_evaluable_ids={'challenge', 'direct', 'remaining'})
    selected = {key for group in groups for key in group}
    assert 'setup' not in selected
    assert 'challenge' not in selected
    assert selected
    assert 'setup' in {r['input_identity_sha256'] for r in plan['selected']} - selected


def test_canary_may_include_a_complete_multirecord_cluster_with_a_challenge():
    rows = [{'input_identity_sha256': key, 'corpus': 'image-arm', 'source': 'image-arm',
             'source_cluster_id': 'shared-image', 'datapoint_id': key, 'modality': 'image',
             'required_modalities': ['text', 'image']} for key in ['setup', 'challenge']]
    rows.append({'input_identity_sha256': 'rest', 'corpus': 'other', 'source': 'other',
                 'source_cluster_id': 'rest', 'datapoint_id': 'rest', 'modality': 'text',
                 'required_modalities': ['text']})
    groups = _pilot_groups({'selected': rows}, policy_evaluable_ids={'challenge', 'rest'})
    assert all('setup' not in group or 'challenge' in group for group in groups)
