"""Judging navigation scales with indexed outputs, not their Cartesian product."""
import pytest

from experiments.rig_web_app.storage import ConsoleDB


@pytest.mark.parametrize('filtered', [False, True])
def test_judging_uses_assignment_identity_with_bounded_sql_work(tmp_path, filtered):
    db = ConsoleDB(tmp_path / 'console.db', repo_root=tmp_path)
    try:
        owner = db.create_workspace('Local', 'local')
        count = 1500
        assignments = [dict(assignment_id=f'a{i}', model='model', input_id=f'i{i}',
            condition_id='initial', modality='text', framework='replay', corpus='corpus',
            response_id=f'r{i}', evidence_class='measured') for i in range(count)]
        responses = [dict(response_id=f'r{i}', assignment_id=f'a{i}', condition_id='initial',
            outcome='usable', truncated=False, source_ref=f'responses.jsonl:{i+1}') for i in range(count)]
        judgments = [dict(response_id=f'r{i}', judge_id='judge', status='valid', label='safe',
            source_ref=f'judgments.jsonl:{i+1}') for i in range(count)]
        db.publish_workspace_results(owner, assignments=assignments, responses=responses, judgments=judgments)
        # A saved predecessor assessment must not enter selected-output totals.
        db.publish_workspace_results(owner, assignments=[], responses=[dict(responses[0],
            response_id='old', condition_id='previous')], judgments=[dict(judgments[0], response_id='old')])
        steps = 0

        def bound_work():
            nonlocal steps
            steps += 1000
            return steps > count * 150

        db._conn.set_progress_handler(bound_work, 1000)
        rows = db.workspace_judging_totals(owner, model='model' if filtered else '',
            condition='initial' if filtered else '')
        assert rows is not None, 'Judging exceeded linear SQL work budget'
        assert [(row['judge_id'], row['status'], row['count']) for row in rows] == [('judge', 'valid', count)]
    finally:
        if db._conn is not None:
            db._conn.set_progress_handler(None, 0)
        db.close()
