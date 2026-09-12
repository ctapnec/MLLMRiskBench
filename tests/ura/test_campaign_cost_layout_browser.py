"""Long exact model specifications must not hide desktop cost columns."""
from experiments.rig_web import RigWebApp
from experiments.rig_web_app import ui
from test_rig_web_workspace_costs import owner, attempt
from test_rig_web_busy_browser import browser  # noqa: F401


def test_cost_columns_fit_desktop_and_scroll_within_mobile_card(browser, tmp_path):  # noqa: F811
    app = RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,
                   gpu_hardware={},system_hardware={})
    try:
        campaign = owner(app)
        record = dict(attempt(),model='anthropic-fable:claude-fable-5-1;effort=high;max_tokens=8192',
                      provider='anthropic',cost_microusd=16320940,reasoning_tokens=500)
        app.db.publish_workspace_costs(campaign,[record])
        body = "<section class='card'>" + app._workspace_results(campaign,'costs',{}) + '</section>'
        content = ui._page('Campaign costs',body).decode().replace(
            "<link rel='stylesheet' href='/static/style.css'>",'<style>'+ui._STYLE+'</style>')
        page = browser.new_page(viewport={'width':1440,'height':1000})
        page.route('http://ui.test/**',lambda route:route.fulfill(status=200,content_type='text/html',body=content))
        try:
            page.goto('http://ui.test/')
            assert page.locator('.campaign-costs th').count() == 6
            assert '$16.320940' in page.locator('.campaign-costs').inner_text()
            assert record['model'] in page.locator('.campaign-costs').inner_text()
            widths = page.locator('.campaign-costs .scroll').evaluate(
                'node=>({client:node.clientWidth,content:node.scrollWidth})')
            assert widths['content'] <= widths['client'] + 1
            column_share = page.locator('.campaign-costs table').evaluate(
                'node=>node.querySelector("th").getBoundingClientRect().width/node.getBoundingClientRect().width')
            assert column_share <= .30, 'Long model names must not crowd the five accounting columns'
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            assert page.locator('.campaign-costs .scroll').evaluate('node=>node.scrollWidth>node.clientWidth')
            page.locator('.campaign-costs .scroll').evaluate('node=>node.scrollLeft=node.scrollWidth')
            assert page.locator('.campaign-costs th').last.is_visible()
        finally:
            page.close()
    finally:
        app.close()
