"""Render the real Tools form, including its campaign-ownership block."""
import pytest

from experiments.rig_web_app.ui import _page, _STYLE
from test_rig_web_busy_browser import browser  # noqa: F401
from test_rig_web_model_acquisition import _app


@pytest.mark.parametrize('width',[390,1440])
def test_command_fields_align_after_campaign_selector_and_fit_viewport(browser,tmp_path,width):  # noqa: F811
    app=_app(tmp_path)
    try:
        card=app._command_card('retained_native_judge_prepare')
    finally:
        app.close()
    content=_page('Tools',card).decode().replace(
        "<link rel='stylesheet' href='/static/style.css'>",'<style>'+_STYLE+'</style>')
    page=browser.new_page(viewport={'width':width,'height':1000})
    try:
        page.set_content(content)
        page.locator('details.cmd > summary').click()
        geometry=page.locator('form.cmd').evaluate("""form => {
          const owner=form.querySelector('.campaign-ownership').getBoundingClientRect();
          const label=form.querySelector(':scope > label').getBoundingClientRect();
          const field=form.querySelector(':scope > .fieldwrap').getBoundingClientRect();
          return {ownerBottom:owner.bottom,labelTop:label.top,labelBottom:label.bottom,
            labelX:label.x,fieldX:field.x,fieldTop:field.top,fieldBottom:field.bottom,
            fieldRight:field.right,overflow:document.documentElement.scrollWidth>innerWidth};
        }""")
        assert not geometry['overflow'] and geometry['fieldRight']<=width
        assert geometry['ownerBottom']<=geometry['labelTop']
        if width<640:
            assert abs(geometry['labelX']-geometry['fieldX'])<=1
            assert geometry['labelBottom']<=geometry['fieldTop']
        else:
            assert geometry['labelX']<geometry['fieldX']
            assert geometry['fieldTop']<=geometry['labelTop']<=geometry['fieldBottom']
        checkbox=page.locator('input[name="--include-incomplete"]')
        assert not checkbox.is_checked()
        checkbox.check()
        assert page.locator('form.cmd').evaluate('(form)=>new FormData(form).get("--include-incomplete")')=='on'
    finally:
        page.close()
