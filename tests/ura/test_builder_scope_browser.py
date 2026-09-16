"""Saved Build scope and discoverable execution controls, using a real browser."""
from urllib.parse import parse_qsl, urlsplit

import pytest

from experiments.rig_web import RigWebApp
from test_rig_web_busy_browser import browser  # noqa: F401


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state',
        repo_root=tmp_path, gpu_hardware={}, system_hardware={})
    monkeypatch.setattr(app, 'start_job', lambda *a, **k: pytest.fail('Editing must not launch'))
    yield app
    app.close()


def test_scope_is_saved_ui_state_not_execution_identity(app):
    base = dict(work_kind='run', mode='dry_run', corpora='synth', judges='rules,llm')
    for scope in ('text,image', ''):
        params = app._builder_params(dict(base, modality_scope=scope))
        assert params['modality_scope'] == scope
        assert app._projection_params(params) == app._projection_params(base)
        ticket = app._new_launch_ticket(params, purpose='build-edit')
        status, _, content = app.handle('POST', '/build/edit', {'edit_ticket': ticket})
        assert status == 200
        for modality in ('text', 'image', 'audio', 'video', 'tool'):
            assert (f"data-mod='{modality}' checked".encode() in content) == (modality in scope.split(','))
    with pytest.raises(ValueError, match='Unknown modality scope'):
        app._builder_params(dict(base, modality_scope='made-up'))


@pytest.mark.parametrize('width', [1440, 390])
@pytest.mark.parametrize('scope', [('text', 'image'), ()])
def test_save_reopen_and_validation_keep_scope_and_execution_controls(browser, app, width, scope):  # noqa: F811
    page = browser.new_page(viewport=dict(width=width, height=900))
    errors, submissions = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))

    def route(route):
        request = route.request
        url = urlsplit(request.url)
        fields = dict(parse_qsl(request.post_data or '', keep_blank_values=True))
        if request.method == 'POST':
            assert url.path in ('/build/save', '/build/review')
            submissions.append((url.path, fields))
        status, mime, body = app.handle(request.method, url.path + ('?'+url.query if url.query else ''), fields)
        if status == 303:
            route.fulfill(status=status, headers={'Location': mime}, body=body)
        else:
            route.fulfill(status=status, content_type=mime, body=body)

    page.route('http://build.test/**', route)

    def selected():
        return tuple(page.locator('.modbox:checked').evaluate_all("ns=>ns.map(n=>n.dataset.mod)"))

    def check_execution():
        page.get_by_role('tab', name='Execution', exact=True).click()
        assert page.locator('#sample-size-control').is_visible()
        assert page.locator('[name=limit]').is_visible()
        assert page.locator('[name=limit]').is_disabled() == (not scope)
        assert page.locator('#sample-arm-prerequisite').is_visible() == (not scope)
        assert not page.locator('.sample-range-field').is_visible(), 'No unvalidated slider maximum'
        for name in ('seeds','max_queries','max_turns','target_answer_retries',
                     'cap_target','cap_judge','cap_http','deadline','local_budget_hours'):
            assert page.locator('[name='+name+']').is_visible(), name
        assert page.locator('#automatic-output-note').is_visible()
        assert not page.locator('[name=out]').is_visible()

    try:
        page.goto('http://build.test/build?work_kind=campaign')
        assert selected() == ('text','image','audio','video','tool')
        page.locator('[name=campaign_name]').fill('Scope regression')
        page.get_by_role('tab', name='Pipeline', exact=True).click()
        for modality in ('text','image','audio','video','tool'):
            page.locator('.modbox[data-mod='+modality+']').set_checked(modality in scope)
        if scope:
            page.locator('.armbox[data-arm=xstest_full]').check()
        for tab in ('Evaluation', 'Admission', 'General', 'Pipeline'):
            page.get_by_role('tab', name=tab, exact=True).click()
            assert selected() == scope
        check_execution()
        page.get_by_role('tab', name='General', exact=True).click()
        page.get_by_role('button', name='Save campaign', exact=True).filter(visible=True).click()
        page.wait_for_url('**/campaigns/*?section=definition')
        owner = page.url.split('/campaigns/')[1].split('?')[0]
        assert app.db.workspace_definition(owner)['modality_scope'] == ','.join(scope)
        assert submissions[-1][1]['modality_scope'] == ','.join(scope)
        page.get_by_role('link', name='Configure in Build', exact=True).click()
        assert selected() == scope
        assert page.locator('.armbox[data-arm=xstest_full]').is_checked() == bool(scope)
        check_execution()
        page.reload()
        assert selected() == scope
        check_execution()
        # Missing target causes an inline validation re-render, not execution.
        page.get_by_role('button', name='Compose & review', exact=True).filter(visible=True).click()
        page.wait_for_url('**/build/review')
        assert selected() == scope
        check_execution()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()
