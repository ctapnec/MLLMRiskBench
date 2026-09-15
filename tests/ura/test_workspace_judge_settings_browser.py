import pytest
from test_workspace_comparison import study  # noqa: F401
from test_workspace_judge_settings import judge_scope  # noqa: F401
from test_workspace_comparison_browser import open_page, ready
from test_rig_web_busy_browser import browser  # noqa: F401


@pytest.mark.parametrize('width',[1440,390])
def test_screenshot_scope_has_readable_judges_and_live_settings(browser,study,judge_scope,width):
    app,left,right,query=judge_scope
    page,requests,errors=open_page(browser,study,width,query)
    try:
        left_options=page.locator('[name=left_judge] option').all_text_contents()
        right_options=page.locator('[name=right_judge] option').all_text_contents()
        assert len(left_options)==3 and len(right_options)==4
        assert any('Rules only; approximate metrics off' in s for s in right_options)
        assert any('Rules + Llama-Guard-3-8B; approximate metrics on' in s for s in right_options)
        assert any('Rules + Llama-Guard-3-8B; approximate metrics off' in s for s in left_options)
        for identity in ['local-cascade-guard','local-cascade-rules','local-cascade-guard']:
            page.locator('[name=right_judge]').select_option(identity)
            ready(page)
            detail=page.locator('[data-judge-settings=right]').inner_text()
            assert ('No model-backed judge' in detail)==identity.endswith('rules')
            assert ('approximate metrics on' in detail)==identity.endswith('guard')
            assert page.locator('[name=left_judge]').input_value()=='local-cascade-left'
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        page.locator('[name=right_condition]').select_option('*')
        ready(page)
        assert page.locator('[name=right_judge]').input_value()=='local-cascade-guard'
        assert 'approximate metrics on' in page.locator('[data-judge-settings=right]').inner_text()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()
