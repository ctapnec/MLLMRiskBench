"""Readable judging settings, indexed at publication rather than page load."""
from __future__ import annotations

import html
import json


def local_settings(*, run=None, source=None, revision=None):
    run, source = run or {}, source or {}
    cascade = source.get('judge_cascade') or {}
    stages = []
    for stage in cascade.get('stages', []):
        stages.append({key: stage[key] for key in
            ('name', 'model_id', 'revision', 'max_new_tokens', 'escalate_below') if stage.get(key) is not None})
    if not stages:
        for name in run.get('judge_names') or []:
            stage = dict(name=name)
            model = run.get('guardrail_model' if name == 'guardrail' else 'judge_model') if name != 'rules' else None
            if model:
                stage['model_id'] = model
            if name == 'guardrail' and run.get('guardrail_revision'):
                stage['revision'] = run['guardrail_revision']
            stages.append(stage)
    result = dict(stages=stages, approximate_common_metrics=source.get(
        'approximate_common_metrics', run.get('approximate_common_metrics')))
    if revision:
        result['scoring_revision'] = revision
    return result


def indexed_settings(db, campaign):
    rows = db._query('SELECT judge_id,settings FROM campaign_judge_settings WHERE campaign_id=?', (campaign,))
    return {row['judge_id']: json.loads(row['settings']) for row in rows or []}


def judge_name(identity, settings=None):
    display = (settings or {}).get('display_name')
    if isinstance(display, str) and display.strip():
        return display
    if not identity.startswith('local-cascade-'):
        name, _, suffix = identity.rpartition(':')
        return name if len(suffix) == 24 and all(c in '0123456789abcdef' for c in suffix) else identity
    if not settings or not settings.get('stages'):
        return 'Local judge (settings not indexed)'
    stages = settings['stages']
    names = []
    for stage in stages:
        name = stage.get('name', 'Unknown stage')
        model = stage.get('model_id')
        names.append('Rules' if name == 'rules' else model.split('/')[-1] if model else name.title())
    label = 'Rules only' if len(stages) == 1 and stages[0].get('name') == 'rules' else ' + '.join(names)
    mode = settings.get('approximate_common_metrics')
    return label + '; approximate metrics ' + ('on' if mode is True else 'off' if mode is False else 'not recorded')


def settings_html(identity, settings, *, side):
    """Always-visible description after selection; technical provenance stays folded."""
    label = judge_name(identity, settings)
    text = '<p>' + html.escape(label) + '.</p>'
    if (settings or {}).get('assessment_method') == 'conversation_based_ai_review':
        text += ('<p>Conversation-based AI assessment, not human evaluation or a fixed API judge. '
                 'The display name does not establish a verified runtime snapshot. '
                 'Coverage may be incomplete; only saved assessments are indexed.</p>')
    if identity.startswith('local-cascade-'):
        stages = (settings or {}).get('stages', [])
        if stages and all(stage.get('name') == 'rules' for stage in stages):
            text += '<p>No model-backed judge is used in this condition.</p>'
        elif not stages:
            text += '<p>The retained configuration has not been indexed. No settings are inferred from its identifier.</p>'
        for stage in stages:
            details = []
            if stage.get('model_id'):
                details.append('Model: ' + stage['model_id'])
            if stage.get('max_new_tokens') is not None:
                details.append('Output allowance: ' + str(stage['max_new_tokens']) + ' tokens')
            if stage.get('escalate_below') is not None:
                details.append('Escalate below confidence: ' + str(stage['escalate_below']))
            if details:
                text += '<p>' + html.escape('; '.join(details)) + '.</p>'
    text += '<p>Distinct judging conditions are kept separate. Matching names do not imply identical settings or coverage.</p>'
    text += '<details><summary>Exact judging identity</summary><p>' + html.escape(identity) + '</p>'
    for stage in (settings or {}).get('stages', []):
        if stage.get('revision'):
            text += '<p>Model revision: ' + html.escape(stage['revision']) + '</p>'
    if (settings or {}).get('scoring_revision'):
        text += '<p>Scoring revision: ' + html.escape(settings['scoring_revision']) + '</p>'
    return ("<section class='card' data-judge-settings='" + side
        + "' style='margin-top:1rem;overflow-wrap:anywhere'><h4>Selected judging settings</h4>"
        + text + '</details></section>')
