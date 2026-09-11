"""Real-browser regressions for the shared console backend-wait guard."""
import os

import pytest

from experiments.rig_web_app.dashboard import DashboardMixin
from experiments.rig_web_app.ui import _page, _STYLE


@pytest.fixture(scope="module")
def browser():
    executable = os.environ.get("URA_UI_CHROMIUM")
    if not executable:
        pytest.skip("Set URA_UI_CHROMIUM for the rig-only browser regressions")
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as driver:
        instance = driver.chromium.launch(executable_path=executable, headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
        yield instance
        instance.close()


@pytest.mark.parametrize('outcome', ['success', 'http_error', 'network_error', 'timeout'])
def test_campaign_export_guards_download_and_releases_on_every_terminal(browser, outcome):
    from experiments.rig_web_app.workspace_charts import EXPORT_SCRIPT
    body = """<div id='campaign-exports'>
<a id='export' data-campaign-export download='campaign.csv' href='/export.csv'>Export counts</a>
</div><p id='campaign-export-status' role='status'></p>"""
    content = _page('Export', body + EXPORT_SCRIPT).decode()
    content = content.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>' + _STYLE + '</style>')
    page = browser.new_page(accept_downloads=True)
    requests, errors, downloads = [], [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('download', lambda download: downloads.append(download))
    def route(request):
        if request.request.url == 'http://ui.test/':
            request.fulfill(status=200, content_type='text/html', body=content)
        elif request.request.url.endswith('favicon.svg'):
            request.fulfill(status=204)
        else:
            requests.append(request)
    page.route('http://ui.test/**', route)
    try:
        page.goto('http://ui.test/')
        if outcome == 'timeout':
            page.evaluate("""() => { const original=window.setTimeout;
                window.setTimeout=(fn,delay,...args)=>original(fn,delay===30000?200:delay,...args); }""")
        state = _burst(page, '#export')
        assert state == {'visible': True, 'inert': True}
        assert len(requests) == 1
        if outcome == 'success':
            requests[0].fulfill(status=200, content_type='text/csv', body='model,count\nA,1\n')
        elif outcome == 'http_error':
            requests[0].fulfill(status=500, body='Failed')
        elif outcome == 'network_error':
            requests[0].abort('failed')
        page.wait_for_function('!window.uraBusy.isBusy()')
        assert not page.locator('#busy-overlay').is_visible()
        assert not page.evaluate("document.querySelector('main').inert")
        if outcome == 'success':
            page.wait_for_function("document.getElementById('campaign-export-status').textContent==='Export prepared.'")
            assert len(downloads) == 1
        else:
            assert not downloads
            assert page.locator('#campaign-export-status').inner_text()
        assert not errors
    finally:
        page.close()


@pytest.fixture
def console_page(browser):
    body = """<a id='navigate' href='/next'>Next section</a>
<a id='anchor' href='#local'>Local panel</a><section id='local'>Local</section>
<form action='/save' method='post'><input name='answer' value='kept'>
<button id='save' type='submit'>Save</button></form>
<a id='detail' href='/detail' data-stats-job='sample'>Statistics</a>
<div id='campaign-stats-modal'><h2 data-stats-modal-title></h2>
<button data-stats-close>Close</button><div data-stats-modal-body></div></div>"""
    content = _page("Test console", body + DashboardMixin._stats_modal_script()).decode()
    content = content.replace("<link rel='stylesheet' href='/static/style.css'>", "<style>" + _STYLE + "</style>")
    page = browser.new_page()
    held = []

    def route(request):
        if request.request.url == "http://ui.test/":
            request.fulfill(status=200, content_type="text/html", body=content)
        elif request.request.url.endswith("favicon.svg"):
            request.fulfill(status=204)
        else:
            held.append(request)

    page.route("http://ui.test/**", route)
    page.goto("http://ui.test/")
    yield page, held, content
    page.close()


def _burst(page, selector):
    state = page.evaluate("""selector => {
        for(let i=0;i<1000;i++) document.querySelector(selector).click();
        return {visible: getComputedStyle(document.getElementById('busy-overlay')).display === 'flex',
                inert: document.querySelector('main').inert};
    }""", selector)
    page.wait_for_timeout(80)
    return state


def test_navigation_blocks_duplicate_requests_and_new_page_clears_spinner(console_page):
    page, requests, content = console_page
    state = _burst(page, "#navigate")
    assert len(requests) == 1
    assert state == {"visible": True, "inert": True}
    requests[0].fulfill(status=200, content_type="text/html", body=content)
    page.wait_for_url("http://ui.test/next")
    page.wait_for_function("!window.uraBusy.isBusy()")
    assert not page.locator("#busy-overlay").is_visible()


def test_all_forms_are_guarded_without_disabling_submitted_fields(console_page):
    page, requests, content = console_page
    state = _burst(page, "#save")
    assert len(requests) == 1
    assert requests[0].request.method == "POST"
    assert requests[0].request.post_data == "answer=kept"
    assert state == {"visible": True, "inert": True}
    requests[0].fulfill(status=500, content_type="text/html", body=content)
    page.wait_for_url("http://ui.test/save")
    page.wait_for_function("!window.uraBusy.isBusy()")


@pytest.mark.parametrize("outcome", ["success", "http_error", "network_error"])
def test_stats_request_blocks_repeats_and_always_releases(console_page, outcome):
    page, requests, _ = console_page
    _burst(page, "#detail")
    assert len(requests) == 1
    assert page.locator("#busy-overlay").is_visible()
    assert page.evaluate("window.uraBusy.reload()") is False
    if outcome == "network_error":
        requests[0].abort("failed")
    else:
        requests[0].fulfill(status=200 if outcome == "success" else 500,
                           content_type="text/html", body="<p>Actual detail</p>")
    page.wait_for_function("!window.uraBusy.isBusy()")
    assert not page.locator("main").evaluate("node => node.inert")
    expected = "Actual detail" if outcome == "success" else "could not be loaded"
    assert expected in page.locator("[data-stats-modal-body]").inner_text()


def test_cancelled_submission_and_client_only_navigation_do_not_stick(console_page):
    page, requests, _ = console_page
    page.evaluate("document.querySelector('form').addEventListener('submit', e => e.preventDefault())")
    page.locator("#save").click()
    page.wait_for_function("!window.uraBusy.isBusy()")
    page.locator("#anchor").click()
    assert not page.evaluate("window.uraBusy.isBusy()")
    assert not requests
    page.evaluate("window.uraBusy.begin('Back navigation test'); window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted:true}));")
    assert not page.evaluate("window.uraBusy.isBusy()")
