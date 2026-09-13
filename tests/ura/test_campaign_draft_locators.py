"""Editable campaign definitions must survive reopening without losing files."""
from pathlib import Path

from experiments.rig_web import RigWebApp


def test_save_reopen_keeps_editable_locators_but_durable_job_state_is_redacted(tmp_path):
    app = RigWebApp(results_root=tmp_path / 'runs', state_dir=tmp_path / 'state',
        repo_root=tmp_path, gpu_hardware={}, system_hardware={})
    digest = 'a' * 64
    fields = {
        'source_conformance': 'source_conformance_sha',
        'project_revision': 'project_revision_sha',
        'engine_runtime_config': 'engine_runtime_config_sha',
        'ideator_manifest': 'ideator_manifest_sha',
        't3_artifact': 't3_artifact_sha',
        'att_path1': 'att_sha1',
    }
    params = dict(work_kind='campaign', campaign_name='Reopen my experiment',
        mode='dry_run', corpora='synth', attackers='replay,ideator,t3mp3st', judges='rules,llm',
        limit='1', sample_seed='0', seeds='0')
    for field, digest_field in fields.items():
        path = tmp_path / (field + '.json')
        path.write_text('{}', encoding='utf-8')
        params[field] = str(path)
        params[digest_field] = digest
    try:
        status, location, _ = app.handle('POST', '/build/save', params)
        assert status == 303
        owner = location.split('/campaigns/', 1)[1].split('?', 1)[0]
        saved = app.db.workspace_definition(owner)
        for field, digest_field in fields.items():
            assert saved[field] == params[field]
            assert Path(saved[field]).is_file()
            assert saved[digest_field] == digest
        assert app.db.load_jobs() == []
        page = app.handle('GET', '/build?campaign_id=' + owner)[2].decode()
        assert 'private-source-conformance@sha256:' not in page
        durable = app._durable_builder_params(saved)
        for field in fields:
            assert durable[field] != saved[field]
            assert durable[field].startswith('private-')
        saved['limit'] = '2'
        app._save_build_campaign(saved)
        assert app.db.workspace_definition(owner)['limit'] == '2'
        assert app.db.workspace_definition(owner)['project_revision'] == params['project_revision']
    finally:
        app.close()


def test_saved_draft_never_accepts_api_key_fields(tmp_path):
    app = RigWebApp(results_root=tmp_path / 'runs', state_dir=tmp_path / 'state',
        repo_root=tmp_path, gpu_hardware={}, system_hardware={})
    try:
        try:
            app._save_build_campaign(dict(work_kind='campaign', campaign_name='No credentials',
                api_key='not-a-real-key'))
        except ValueError:
            pass
        else:
            raise AssertionError('A credential field was accepted in an editable draft')
        for workspace in app.db.workspaces():
            assert 'api_key' not in app.db.workspace_definition(workspace['campaign_id'])
    finally:
        app.close()
