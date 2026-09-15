"""Campaign subnavigation must never cover the shared menu while scrolling."""
import pytest
from experiments.rig_web_app import ui
from test_rig_web_busy_browser import browser  # noqa: F401
from test_workspace_comparison import study  # noqa: F401


@pytest.mark.parametrize('width',[390,1440])
def test_campaign_tabs_do_not_occlude_main_header(browser,study,width):
    app,owner,_,_=study
    status,_,body=app.handle('GET','/campaigns/'+owner+'?section=judging')
    assert status==200
    content=body.decode().replace("<link rel='stylesheet' href='/static/style.css'>",'<style>'+ui._STYLE+'</style>')
    content=content.replace('</main>',"<div style='height:2000px'>Scroll content</div></main>")
    page=browser.new_page(viewport=dict(width=width,height=1000))
    page.route('http://ui.test/**',lambda route:route.fulfill(status=200,content_type='text/html',body=content))
    try:
        page.goto('http://ui.test/')
        page.evaluate('window.scrollTo(0,1000)')
        assert page.locator('nav.page-tablist').count()>0
        assert page.locator('nav.page-tablist').evaluate_all("nodes=>nodes.every(n=>getComputedStyle(n).position==='static')")
        assert page.locator('body > nav a').count()==8
        assert page.locator('body > nav a').evaluate_all('''nodes=>nodes.every(n=>{
            const b=n.getBoundingClientRect();
            const top=document.elementFromPoint(b.x+b.width/2,b.y+b.height/2);
            return b.y>=0 && b.bottom<=innerHeight && top && n.contains(top);
        })''')
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:page.close()
