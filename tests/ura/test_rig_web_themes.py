"""Browser-local palettes must not change campaign state or contact providers."""
import pytest

from experiments.rig_web_app import ui
from test_rig_web_busy_browser import browser  # noqa: F401


PALETTES = {
    'slate': ('#eef1f4', '#ffffff', '#16191c', '#0e7c96', 'light'),
    'parchment': ('#f2ede2', '#fbf8f1', '#241f18', '#14657d', 'light'),
    'midnight': ('#0e1116', '#161b22', '#e8ecf1', '#35b3d0', 'dark'),
    'ash': ('#1a1a1c', '#232326', '#ececed', '#7aa2c4', 'dark'),
}


def serve(page):
    requests = []
    body = """<section class='card'><h1>Campaign</h1><form id='settings'>
<label class='campaign-field'>Output allowance<input name='max_tokens' value='4096'></label>
<label class='checkrow'><input type='checkbox' name='enabled' checked><span>Enabled</span></label>
<div class='job-date-filters'><input type='datetime-local'></div>
<div class='action-row'><button>Review</button></div></form>
<span class='badge green'>Complete</span><span class='badge amber'>Pending</span></section>"""
    def route(request):
        requests.append((request.request.method, request.request.url))
        assert request.request.method == 'GET'
        if request.request.url.endswith('/static/style.css'):
            request.fulfill(status=200, content_type='text/css', body=ui._STYLE)
        elif request.request.url.endswith('/static/favicon.svg'):
            request.fulfill(status=200, content_type='image/svg+xml', body='<svg xmlns="http://www.w3.org/2000/svg"/>')
        else:
            request.fulfill(status=200, content_type='text/html', body=ui._page('Theme', body))
    page.route('http://ui.test/**', route)
    return requests


def palette(page):
    return page.evaluate("""()=>{const s=getComputedStyle(document.documentElement);
      return ['--bg','--card','--ink','--accent'].map(k=>s.getPropertyValue(k).trim()).concat(s.colorScheme);
    }""")


@pytest.mark.parametrize('width', [390, 1440])
@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_named_palettes_override_os_preference_without_requests_or_form_changes(browser, width, scheme):
    context = browser.new_context(viewport={'width':width, 'height':1000}, color_scheme=scheme)
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    requests = serve(page)
    try:
        page.goto('http://ui.test/first', wait_until='networkidle')
        picker = page.get_by_role('combobox', name='Colour theme')
        picker.wait_for(state='visible')
        assert picker.locator('option').all_text_contents() == ['Slate','Parchment','Midnight','Ash','Harbor']
        initial = page.locator('#settings').evaluate('e=>Array.from(new FormData(e))')
        before = len(requests)
        for name, colors in PALETTES.items():
            picker.select_option(name)
            assert tuple(palette(page)) == colors
            assert page.locator('[type=datetime-local]').evaluate('e=>getComputedStyle(e).colorScheme') == colors[-1]
            assert page.evaluate("localStorage.getItem('ura-theme')") == name
            assert page.locator('#settings').evaluate('e=>Array.from(new FormData(e))') == initial
            assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        picker.select_option('harbor')
        assert palette(page)[0] == ('#10161d' if scheme == 'dark' else '#eef1f5')
        assert len(requests) == before and not errors
    finally:
        context.close()


def test_theme_is_restored_before_styles_on_navigation_and_reload(browser):
    context = browser.new_context()
    page = context.new_page(); serve(page)
    try:
        page.goto('http://ui.test/first')
        page.get_by_role('combobox', name='Colour theme').select_option('parchment')
        page.goto('http://ui.test/second')
        page.reload()
        assert page.get_by_role('combobox', name='Colour theme').input_value() == 'parchment'
        assert tuple(palette(page)) == PALETTES['parchment']
        html = ui._page('Theme', '').decode()
        assert html.index(ui._THEME_INIT) < html.index("<link rel='stylesheet'")
    finally:
        context.close()


@pytest.mark.parametrize('storage', ['blocked', 'invalid'])
def test_unavailable_or_invalid_saved_preference_falls_back_and_picker_still_works(browser, storage):
    context = browser.new_context(color_scheme='dark')
    if storage == 'blocked':
        context.add_init_script("for(const method of ['getItem','setItem'])Storage.prototype[method]=()=>{throw new Error('Storage unavailable')}")
    else:
        context.add_init_script("localStorage.setItem('ura-theme','unknown-theme')")
    page = context.new_page(); errors=[]
    page.on('pageerror', lambda error: errors.append(str(error)))
    serve(page)
    try:
        page.goto('http://ui.test/first')
        assert page.get_by_role('combobox', name='Colour theme').input_value() == 'harbor'
        assert palette(page)[0] == '#10161d'
        page.get_by_role('combobox', name='Colour theme').select_option('slate')
        assert tuple(palette(page)) == PALETTES['slate']
        assert not errors
    finally:
        context.close()


def test_original_palette_still_tracks_system_after_named_selection(browser):
    context = browser.new_context(color_scheme='light')
    page = context.new_page(); serve(page)
    try:
        page.goto('http://ui.test/first')
        assert page.get_by_role('combobox', name='Colour theme').input_value() == 'harbor'
        page.emulate_media(color_scheme='dark')
        assert palette(page)[0] == '#10161d'
        page.get_by_role('combobox', name='Colour theme').select_option('parchment')
        page.emulate_media(color_scheme='light')
        page.emulate_media(color_scheme='dark')
        assert tuple(palette(page)) == PALETTES['parchment']
    finally:
        context.close()
